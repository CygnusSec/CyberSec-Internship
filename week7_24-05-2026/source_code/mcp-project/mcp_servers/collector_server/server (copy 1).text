from fastmcp import FastMCP
import subprocess
import os
import re
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

mcp = FastMCP("collector-server")

WAZUH_URL  = os.environ.get("WAZUH_URL",  "https://wazuh.indexer:9200")
WAZUH_USER = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "SecretPassword")

# Web/container logs không cache — cần fresh data mỗi lần trigger
# Wazuh cache 60s — API call tốn thời gian
_cache: dict = {}
_WAZUH_CACHE_TTL = 60


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


def tail_lines(raw: str, n: int = 20) -> str:
    lines = [l for l in raw.split("\n") if l.strip()]
    return "\n".join(lines[-n:])


@mcp.tool()
def fetch_web_logs(keyword: str, session_id: str = "default") -> dict:
    """Fetch recent web access log lines matching keyword for translator pipeline."""
    kw  = sanitize(keyword)
    raw = run_cmd(["grep", "-F", kw, "/shared_logs/access.log"])
    return {"session_id": session_id, "events": parse_lines(tail_lines(raw), "web")}


@mcp.tool()
def fetch_container_logs(keyword: str, session_id: str = "default") -> dict:
    """
    Fetch recent DVWA container error log lines matching keyword.
    Same volume mount as web logs — /shared_logs/.
    """
    kw  = sanitize(keyword)
    raw = run_cmd(["grep", "-F", kw, "/shared_logs/error.log"])
    return {"session_id": session_id, "events": parse_lines(tail_lines(raw), "container")}


@mcp.tool()
def fetch_auth_logs(keyword: str, session_id: str = "default") -> dict:
    """Fetch recent auth log lines matching keyword for translator pipeline."""
    kw  = sanitize(keyword)
    raw = run_cmd(["grep", "-F", kw, "/var/log/auth.log"])
    return {"session_id": session_id, "events": parse_lines(tail_lines(raw), "auth")}


@mcp.tool()
def fetch_db_logs(keyword: str, session_id: str = "default") -> dict:
    """Fetch recent MySQL container log lines matching keyword for translator pipeline."""
    kw     = sanitize(keyword)
    cached = _cache_get(f"db:{kw}")
    if cached is not None:
        return {"session_id": session_id, "events": cached, "from_cache": True}

    raw    = run_cmd(["docker", "logs", "--tail", "200", "dvwa-mysql"])
    events = parse_lines(tail_lines("\n".join(l for l in raw.split("\n") if kw in l)), "db")
    _cache_set(f"db:{kw}", events)
    return {"session_id": session_id, "events": events}


@mcp.tool()
def fetch_audit_logs(keyword: str, session_id: str = "default") -> dict:
    """Fetch recent Linux audit log lines matching keyword for translator pipeline."""
    kw  = sanitize(keyword)
    raw = run_cmd(["grep", "-F", kw, "/var/log/audit/audit.log"])
    return {"session_id": session_id, "events": parse_lines(tail_lines(raw), "audit")}


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
    Returns normalized event list for translator pipeline.
    No queuing, risk scoring, or AI decision here.
    """
    cached = _cache_get(f"wazuh:{src_ip}")
    if cached is not None:
        return {"session_id": session_id, "events": cached, "event_count": len(cached), "from_cache": True}

    query = {
        "size": 20,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
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
            json=query,
            verify=False,
            timeout=30
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
    Aggregate events from ALL 7 sources in one call (including Wazuh).
    Used by Trigger 1 (Wazuh alert path) — has_wazuh_alert will be True.
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
        "session_id":     session_id,
        "events":         all_events,
        "event_count":    len(all_events),
        "sources_queried": ["web", "auth", "db", "audit", "container", "firewall", "wazuh"]
    }


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
