from fastmcp import FastMCP
import subprocess
import os
import time
import requests
import urllib3
from datetime import datetime, timezone, timedelta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

mcp = FastMCP("collector-server")

WAZUH_URL  = os.environ.get("WAZUH_URL",  "https://wazuh.indexer:9200")
WAZUH_USER = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "SecretPassword")

_cache: dict = {}
_WAZUH_CACHE_TTL = 60

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


def _cache_get(key: str):
    entry = _cache.get(key)
    if entry and time.time() - entry["ts"] < _WAZUH_CACHE_TTL:
        return entry["data"]
    return None


def _cache_set(key: str, data):
    _cache[key] = {"ts": time.time(), "data": data}


def sanitize(keyword: str) -> str:
    return keyword.strip()


def run_cmd(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception as e:
        return f"ERROR: {e}"


def parse_lines(raw: str, source: str) -> list[dict]:
    if not raw or raw.startswith("ERROR:"):
        return []
    return [{"source": source, "raw": line} for line in raw.split("\n") if line.strip()]


def _parse_log_ts(ts_str: str):
    """
    Parse log timestamp string thành datetime.
    Format: "16/May/2026:09:00:00 +0000"
    Dùng datetime thay vì string compare để đúng qua các tháng khác nhau.
    """
    try:
        ts    = ts_str.split(" ")[0]  # bỏ timezone offset
        day, mon_str, rest = ts.split("/")
        year, hour, minute, second = rest.split(":")
        month = _MONTH_MAP.get(mon_str, 0)
        if not month:
            return None
        return datetime(int(year), month, int(day),
                        int(hour), int(minute), int(second))
    except Exception:
        return None


def filter_since(lines: list[str], since: str) -> list[str]:
    """
    Chỉ giữ log lines có timestamp MỚI HƠN since.
    since: "16/May/2026:09:00:00 +0000"
    Dùng datetime parse — đúng kể cả qua tháng khác nhau.
    Trả về tối đa 50 dòng mới nhất.
    """
    if not since:
        return lines[-50:]

    since_dt = _parse_log_ts(since)
    if not since_dt:
        return lines[-50:]

    new_lines = []
    for line in lines:
        try:
            start  = line.index("[") + 1
            end    = line.index("]", start)
            ts_dt  = _parse_log_ts(line[start:end].strip())
            if ts_dt and ts_dt > since_dt:
                new_lines.append(line)
        except (ValueError, IndexError):
            new_lines.append(line)

    return new_lines[-100:]


def last_timestamp(lines: list[str]) -> str:
    """Trả về timestamp string của dòng cuối để track cho lần sau."""
    for line in reversed(lines):
        try:
            start = line.index("[") + 1
            end   = line.index("]", start)
            return line[start:end].strip()
        except (ValueError, IndexError):
            continue
    return ""


@mcp.tool()
def fetch_web_logs(keyword: str, session_id: str = "default", since: str = "") -> dict:
    """Fetch web access log lines matching keyword. since: only return lines newer than this timestamp."""
    kw    = sanitize(keyword)
    raw   = run_cmd(["grep", "-F", kw, "/shared_logs/access.log"])
    lines = [l for l in raw.split("\n") if l.strip()]
    new   = filter_since(lines, since)
    return {
        "session_id":     session_id,
        "events":         parse_lines("\n".join(new), "web"),
        "last_timestamp": last_timestamp(new)
    }


@mcp.tool()
def fetch_container_logs(keyword: str, session_id: str = "default", since: str = "") -> dict:
    """Fetch DVWA container error log lines matching keyword."""
    kw    = sanitize(keyword)
    raw   = run_cmd(["grep", "-F", kw, "/shared_logs/error.log"])
    lines = [l for l in raw.split("\n") if l.strip()]
    new   = filter_since(lines, since)
    return {
        "session_id":     session_id,
        "events":         parse_lines("\n".join(new), "container"),
        "last_timestamp": last_timestamp(new)
    }


@mcp.tool()
def fetch_auth_logs(keyword: str, session_id: str = "default", since: str = "") -> dict:
    """Fetch auth log lines matching keyword."""
    kw    = sanitize(keyword)
    raw   = run_cmd(["grep", "-F", kw, "/var/log/auth.log"])
    lines = [l for l in raw.split("\n") if l.strip()]
    new   = filter_since(lines, since)
    return {
        "session_id":     session_id,
        "events":         parse_lines("\n".join(new), "auth"),
        "last_timestamp": last_timestamp(new)
    }


@mcp.tool()
def fetch_audit_logs(keyword: str, session_id: str = "default", since: str = "") -> dict:
    """Fetch Linux audit log lines matching keyword."""
    kw    = sanitize(keyword)
    raw   = run_cmd(["grep", "-F", kw, "/var/log/audit/audit.log"])
    lines = [l for l in raw.split("\n") if l.strip()]
    new   = filter_since(lines, since)
    return {
        "session_id":     session_id,
        "events":         parse_lines("\n".join(new), "audit"),
        "last_timestamp": last_timestamp(new)
    }


@mcp.tool()
def fetch_db_logs(keyword: str, session_id: str = "default", since_epoch: float = 0.0) -> dict:
    """
    Fetch MySQL container log lines matching keyword.
    since_epoch: Unix timestamp — chỉ lấy log sau thời điểm này.
    """
    kw     = sanitize(keyword)
    cached = _cache_get(f"db:{kw}:{since_epoch}")
    if cached is not None:
        return {"session_id": session_id, "events": cached, "from_cache": True}

    raw   = run_cmd(["docker", "logs", "--tail", "200", "dvwa-mysql"])
    lines = [l for l in raw.split("\n") if kw in l]

    # Docker logs format: "2026-05-16T09:00:00.000000Z message"
    if since_epoch > 0:
        filtered = []
        for line in lines:
            try:
                ts_str = line.split(" ")[0].rstrip("Z")
                ts_dt  = datetime.fromisoformat(ts_str)
                if ts_dt.timestamp() > since_epoch:
                    filtered.append(line)
            except Exception:
                filtered.append(line)
        lines = filtered

    events = parse_lines("\n".join(lines[-20:]), "db")
    # last_epoch là thời điểm hiện tại để lần sau chỉ lấy log mới hơn
    last_epoch = time.time()
    _cache_set(f"db:{kw}:{since_epoch}", events)
    return {"session_id": session_id, "events": events, "last_epoch": last_epoch}


@mcp.tool()
def fetch_firewall_logs(src_ip: str, session_id: str = "default") -> dict:
    """Fetch iptables/ufw firewall drop/reject logs for a source IP."""
    kw  = sanitize(src_ip)
    raw = run_cmd(["grep", "-F", kw, "/var/log/ufw.log"])
    if not raw or raw.startswith("ERROR:"):
        raw = run_cmd(["grep", "-F", kw, "/var/log/kern.log"])
    lines = [l for l in raw.split("\n") if "DPT" in l or "BLOCK" in l or "DROP" in l][-20:]
    return {"session_id": session_id, "events": parse_lines("\n".join(lines), "firewall")}


@mcp.tool()
def fetch_wazuh_alerts(src_ip: str, session_id: str = "default") -> dict:
    """
    Pull raw alert events from Wazuh Indexer by source IP.
    Only fetches alerts from the last 15 minutes to avoid stale data.
    """
    cached = _cache_get(f"wazuh:{src_ip}")
    if cached is not None:
        return {"session_id": session_id, "events": cached,
                "event_count": len(cached), "from_cache": True}

    # Tăng lên 15 phút để không bỏ sót alert gần đây
    since = (datetime.now(timezone.utc) - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")

    query = {
        "size": 20,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since}}}
                ],
                "should": [
                    {"term": {"data.srcip.keyword": src_ip}},
                    {"match": {"data.srcip": src_ip}}
                ],
                "minimum_should_match": 1
            }
        }
    }

    try:
        r = requests.get(
            f"{WAZUH_URL}/wazuh-alerts-*/_search",
            auth=(WAZUH_USER, WAZUH_PASS),
            headers={"Content-Type": "application/json"},
            json=query, verify=False, timeout=30
        )
        if r.status_code != 200:
            return {"error": f"wazuh_indexer_http_{r.status_code}", "events": []}

        hits   = r.json().get("hits", {}).get("hits", [])
        events = []
        for h in hits:
            x = h.get("_source", {})
            events.append({
                "source":           "wazuh",
                "raw":              x.get("full_log", ""),
                "timestamp":        x.get("@timestamp"),
                "rule_description": x.get("rule", {}).get("description"),
                "rule_level":       x.get("rule", {}).get("level"),
                "srcip":            x.get("data", {}).get("srcip"),
                "url":              x.get("data", {}).get("url")
            })

        _cache_set(f"wazuh:{src_ip}", events)
        return {"session_id": session_id, "events": events, "event_count": len(events)}

    except Exception as e:
        return {"error": str(e), "events": []}


@mcp.tool()
def fetch_all_sources(keyword: str, src_ip: str, session_id: str = "default") -> dict:
    """
    Aggregate events from ALL 7 sources (including Wazuh).
    Used by Trigger 1 (Wazuh alert path) — has_wazuh_alert will be True.
    No since filtering — Wazuh trigger always gets full picture.
    """
    all_events = []

    for result in [
        fetch_web_logs(keyword, session_id),
        fetch_auth_logs(keyword, session_id),
        fetch_db_logs(keyword, session_id),
        fetch_audit_logs(keyword, session_id),
        fetch_container_logs(keyword, session_id),
        fetch_firewall_logs(src_ip, session_id),
    ]:
        all_events.extend(result.get("events", []))

    all_events.extend(fetch_wazuh_alerts(src_ip, session_id).get("events", []))

    return {
        "session_id":      session_id,
        "events":          all_events,
        "event_count":     len(all_events),
        "sources_queried": ["web", "auth", "db", "audit", "container", "firewall", "wazuh"]
    }


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
