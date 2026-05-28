from fastmcp import FastMCP
import time
import os
import json
import threading
import math

STORE_FILE = "/app/session_store.json"
mcp = FastMCP("correlator-server")

SESSION_STORE: dict = {}
STORE_LOCK = threading.Lock()

RISK_MAP = {
    "login_attempt": 1,
    "authentication_bypass_attempt": 8,
    "sql_injection": 8,
    "cross_site_scripting_attempt": 5,
    "local_file_inclusion_attempt": 7,
    "remote_file_inclusion_attempt": 9,
    "command_injection_attempt": 10,
    "admin_surface_probe": 3,
    "sensitive_resource_discovery": 4,
    "brute_force_attempt": 4,
    "user_enumeration_attempt": 3,
    "privilege_escalation_attempt": 10,
    "webshell_execution": 10,
    "reverse_shell_attempt": 10,
    "ssrf_attempt": 9,
    "port_scan_detected": 3,
    "wazuh_critical_alert": 10,
    "wazuh_high_alert": 6,
    "sql_injection": 8,
    "page_browse": 0,
    "login_page_visit": 0,
    "logout": 0,
    "api_call": 1,
    "file_access": 1,
    "form_submit": 1,
    "search_query": 0,
    "profile_access": 0,
    "settings_access": 1,
    "unknown": 0,
}

BEHAVIOR_LABEL = {
    "login_attempt": "User authentication attempt detected",
    "authentication_bypass_attempt": "SQL injection authentication bypass attempt",
    "admin_surface_probe": "Admin interface probing detected",
    "sensitive_resource_discovery": "Sensitive resource enumeration detected",
    "privilege_escalation_attempt": "Privilege escalation behavior detected",
    "cross_site_scripting_attempt": "XSS attack detected",
    "local_file_inclusion_attempt": "LFI attack detected",
    "remote_file_inclusion_attempt": "RFI attack detected",
    "command_injection_attempt": "Command injection detected",
    "brute_force_attempt": "Credential brute force detected",
    "user_enumeration_attempt": "User enumeration via SSH detected",
    "webshell_execution": "Webshell execution detected",
    "reverse_shell_attempt": "Reverse shell / C2 callback detected",
    "ssrf_attempt": "SSRF internal probe detected",
    "port_scan_detected": "Port/network scan detected via firewall",
    "wazuh_critical_alert": "Wazuh critical rule triggered",
    "wazuh_high_alert": "Wazuh high severity rule triggered",
    "sql_injection": "SQL injection attack detected",
    "page_browse": "User browsing a normal page",
    "login_page_visit": "User visiting login page",
    "logout": "User logged out",
    "api_call": "User making API call",
    "file_access": "User accessing a file or resource",
    "form_submit": "User submitting a form",
    "search_query": "User performing a search",
    "profile_access": "User accessing profile or account page",
    "settings_access": "User accessing settings",
    "unknown": "User activity — behavior unclassified",
}

THRESHOLD_EVENTS = 30
THRESHOLD_RISK   = 40
TIMEOUT_SEC      = 1800
FLUSH_LOCK_SEC   = 2
FLUSH_WINDOW_SEC = 60
FLUSH_MAX        = 5

_missing_label = set(RISK_MAP) - set(BEHAVIOR_LABEL)
_missing_risk  = set(BEHAVIOR_LABEL) - set(RISK_MAP)
assert not _missing_label, f"Missing BEHAVIOR_LABEL for: {_missing_label}"
assert not _missing_risk,  f"Missing RISK_MAP for: {_missing_risk}"




def save_store():
    tmp = STORE_FILE + ".tmp"
    try:
        with STORE_LOCK:
            snapshot = json.dumps(SESSION_STORE, indent=2)
        with open(tmp, "w") as f:
            f.write(snapshot)
        os.replace(tmp, STORE_FILE)
    except Exception:
        pass


def load_store():
    global SESSION_STORE
    with STORE_LOCK:
        if os.path.exists(STORE_FILE):
            try:
                with open(STORE_FILE, "r") as f:
                    SESSION_STORE = json.load(f)
            except Exception:
                SESSION_STORE = {}


def init_session(user_id: str) -> dict:
    now = time.time()
    if user_id not in SESSION_STORE:
        SESSION_STORE[user_id] = {
            "events": [], "risk": 0.0, "last_update": now,
            "session_stage": "normal_activity", "ai_context": [],
            "forensic_snapshot": [], "last_flush_time": None,
            "pending_cleanup": False, "flush_lock": False,
            "flush_lock_until": 0.0, "flush_counter": 0, "flush_reset": now,
        }
    s = SESSION_STORE[user_id]
    s.setdefault("events", [])
    s.setdefault("risk", 0.0)
    s.setdefault("last_update", now)
    s.setdefault("session_stage", "normal_activity")
    s.setdefault("ai_context", [])
    s.setdefault("forensic_snapshot", [])
    s.setdefault("last_flush_time", None)
    s.setdefault("pending_cleanup", False)
    s.setdefault("flush_lock", False)
    s.setdefault("flush_lock_until", 0.0)
    s.setdefault("flush_counter", 0)
    s.setdefault("flush_reset", now)
    return s


def cleanup_session(session: dict):
    """Giải phóng tất cả trạng thái expired. PHẢI gọi trước should_flush()."""
    now = time.time()

    if session.get("flush_lock") and now >= session.get("flush_lock_until", 0):
        session["flush_lock"] = False

    if now - session.get("flush_reset", 0) > FLUSH_WINDOW_SEC:
        session["flush_counter"] = 0
        session["flush_reset"]   = now

    if session.get("pending_cleanup") and session.get("last_flush_time"):
        if now - session["last_flush_time"] >= TIMEOUT_SEC:
            session["forensic_snapshot"] = []
            session["pending_cleanup"]   = False
            session["last_flush_time"]   = None
            session["flush_lock"]        = False


def detect_session_stage(events: list) -> str:
    actions     = [e.get("action") for e in events]
    multi_stage = any(e.get("multi_stage") for e in events)

    if "reverse_shell_attempt" in actions or "webshell_execution" in actions:
        return "post_exploitation"
    if "privilege_escalation_attempt" in actions:
        return "active_intrusion"
    if "command_injection_attempt" in actions or "remote_file_inclusion_attempt" in actions:
        return "active_intrusion"
    if "authentication_bypass_attempt" in actions:
        return "initial_compromise"
    if multi_stage:
        return "active_intrusion"
    if "sql_injection" in actions and "local_file_inclusion_attempt" in actions:
        return "active_intrusion"

    recon_count = (
        actions.count("admin_surface_probe") +
        actions.count("sensitive_resource_discovery") +
        actions.count("user_enumeration_attempt") +
        actions.count("port_scan_detected")
    )
    if recon_count >= 2:
        return "reconnaissance"

    attack_actions = {a for a in actions if a not in (
        "unknown", "page_browse", "login_page_visit", "logout",
        "api_call", "file_access", "form_submit", "search_query",
        "profile_access", "settings_access", "login_attempt"
    )}
    if attack_actions:
        return "suspicious_activity"

    return "normal_activity"


def update_session(user_id: str, event: dict):
    """Add event vào session."""
    now     = time.time()
    session = init_session(user_id)

    action    = event.get("action", "unknown")
    base_risk = RISK_MAP.get(action, 0)

    time_diff  = now - session["last_update"]
    time_decay = math.exp(-time_diff / 300)

    if session["events"] and session["events"][-1].get("action") == action:
        base_risk *= 1.2
    if event.get("multi_stage"):
        base_risk *= 1.5
    if event.get("severity") == "critical":
        base_risk *= 1.3
    elif event.get("severity") == "high":
        base_risk *= 1.1

    session["events"].append(event)
    session["risk"] = min(session["risk"] * time_decay + base_risk, 100.0)
    session["last_update"] = now
    return True


def should_flush(session: dict) -> bool:
    queue_size = len(session["events"])
    risk       = session["risk"]
    idle_time  = time.time() - session["last_update"]

    if session.get("flush_lock"):
        return False
    if session.get("flush_counter", 0) >= FLUSH_MAX:
        return False

    has_wazuh = any(e.get("source") == "wazuh" for e in session["events"])
    if has_wazuh:
        session["flush_counter"] += 1
        return True

    attack_types = {e.get("action") for e in session["events"]} - {
        "unknown", "login_attempt", "page_browse", "login_page_visit",
        "logout", "api_call", "file_access", "form_submit",
        "search_query", "profile_access", "settings_access"
    }
    if len(attack_types) >= 2:
        session["flush_counter"] += 1
        return True

    if queue_size >= THRESHOLD_EVENTS:
        session["flush_counter"] += 1
        return True

    if risk >= THRESHOLD_RISK:
        session["flush_counter"] += 1
        return True

    if queue_size > 0 and idle_time >= TIMEOUT_SEC:
        session["flush_counter"] += 1
        return True

    return False


def build_story(events: list) -> list:
    story = []
    for i, e in enumerate(events):
        action = e.get("action", "unknown")
        story.append({
            "step": i,
            "action": action,
            "behavior": e.get("behavior_label") or BEHAVIOR_LABEL.get(action, BEHAVIOR_LABEL["unknown"]),
            "is_attack": e.get("is_attack", False),
            "severity": e.get("severity", "low"),
            "confidence": e.get("confidence", 0.0),
            "source": e.get("source", "unknown"),
            "srcip": e.get("srcip"),
            "timestamp": e.get("timestamp"),
            "multi_stage": e.get("multi_stage", False),
            "evidence": e.get("evidence", []),
            "raw_normalized": e.get("raw_normalized", "")[:150],  # giới hạn 150 ký tự
        })
    return story


def build_payload(session: dict, stage: str) -> dict:
    events = session["events"]
    has_wazuh_alert = any(e.get("source") == "wazuh" for e in events)
    attack_events   = [e for e in events if e.get("is_attack")]
    normal_events   = [e for e in events if not e.get("is_attack")]

    return {
        "history": build_story(events),
        "has_wazuh_alert": has_wazuh_alert,
        "metrics": {
            "session_risk":        session["risk"],
            "event_count":         len(events),
            "attack_event_count":  len(attack_events),
            "normal_event_count":  len(normal_events),
            "unique_attack_types": len({e.get("action") for e in attack_events}),
            "critical_count":      sum(1 for e in events if e.get("severity") == "critical"),
            "high_count":          sum(1 for e in events if e.get("severity") == "high"),
            "multi_stage_count":   sum(1 for e in events if e.get("multi_stage")),
        },
        "context_memory": session["ai_context"],
        "session_stage":  stage,
    }


def do_flush(session: dict, user_id: str) -> dict:
    stage = detect_session_stage(session["events"])
    session["session_stage"] = stage
    payload = build_payload(session, stage)

    session["forensic_snapshot"] = [
        {"action": e.get("action"), "severity": e.get("severity"),
         "source": e.get("source"), "timestamp": e.get("timestamp"),
         "is_attack": e.get("is_attack", False), "raw": e}
        for e in session["events"]
    ]

    session["events"]           = []
    session["risk"]             = 0.0
    session["last_flush_time"]  = time.time()
    session["pending_cleanup"]  = True
    session["flush_lock"]       = True
    session["flush_lock_until"] = time.time() + FLUSH_LOCK_SEC
    return payload


def record_ai_result(session: dict, stage: str, ai_result: dict):
    session["ai_context"].append({
        "timestamp":      time.time(),
        "stage":          stage,
        "risk_summary":   ai_result.get("risk_summary", "unknown"),
        "verdict":        ai_result.get("verdict", "unknown"),
        "recommendation": ai_result.get("recommendation", "none"),
        "attack_chain":   ai_result.get("attack_chain", []),
    })
    if len(session["ai_context"]) > 20:
        session["ai_context"] = session["ai_context"][-20:]


@mcp.tool()
def add_event(event: dict, user_id: str) -> dict:
    """Receive a single translated behavioral event."""
    if not event or not isinstance(event, dict):
        return {"error": "invalid_input"}

    with STORE_LOCK:
        session = init_session(user_id)
        cleanup_session(session)
        update_session(user_id, event)
        result = {
            "user_id": user_id,
            "queue_size": len(session["events"]),
            "current_risk": round(session["risk"], 2),
            "session_stage": session["session_stage"],
            "ready_for_ai": False,
        }
        if should_flush(session):
            payload = do_flush(session, user_id)
            result["ready_for_ai"]  = True
            result["session_stage"] = session["session_stage"]
            result["payload_to_ai"] = payload

    save_store()
    return result


@mcp.tool()
def add_event_batch(events: list, user_id: str) -> dict:
    """
    Receive a batch of translated behavioral events.
    Dedup events dựa trên raw content hash — không add event đã có trong queue.
    cleanup_session() gọi TRƯỚC vòng loop.
    """
    if not events or not isinstance(events, list):
        return {"error": "invalid_input"}

    with STORE_LOCK:
        session = init_session(user_id)
        cleanup_session(session)  # TRƯỚC vòng loop

        added_count   = 0
        skipped_count = 0
        for event in events:
            if isinstance(event, dict):
                update_session(user_id, event)
                added_count += 1

        result = {
            "user_id": user_id,
            "queue_size": len(session.get("events", [])),
            "current_risk": round(session.get("risk", 0.0), 2),
            "session_stage": session.get("session_stage", "normal_activity"),
            "ready_for_ai": False,
            "added": added_count,
            "deduped": skipped_count,
        }
        if should_flush(session):
            payload = do_flush(session, user_id)
            result["ready_for_ai"]  = True
            result["session_stage"] = session["session_stage"]
            result["payload_to_ai"] = payload

    save_store()
    return result


@mcp.tool()
def update_ai_context(user_id: str, ai_result: dict) -> dict:
    """Store AI verdict back into session."""
    if not user_id or not isinstance(ai_result, dict):
        return {"error": "invalid_input"}

    with STORE_LOCK:
        session = init_session(user_id)
        stage   = session.get("session_stage", "normal_activity")
        record_ai_result(session, stage, ai_result)

    save_store()
    return {"user_id": user_id, "context_size": len(session["ai_context"]), "status": "ok"}


@mcp.tool()
def get_session_status(user_id: str) -> dict:
    """Return current session state."""
    with STORE_LOCK:
        session = SESSION_STORE.get(user_id)
        if not session:
            return {"error": "session_not_found"}
        now = time.time()
        return {
            "user_id": user_id,
            "queue_size": len(session.get("events", [])),
            "current_risk": round(session.get("risk", 0.0), 2),
            "session_stage": session.get("session_stage", "normal_activity"),
            "pending_cleanup": session.get("pending_cleanup", False),
            "context_memory_size": len(session.get("ai_context", [])),
            "flush_counter": session.get("flush_counter", 0),
            "flush_lock": session.get("flush_lock", False),
            "lock_remaining": round(session.get("flush_lock_until", 0) - now, 1),
            "last_flush_time": session.get("last_flush_time"),
        }


@mcp.tool()
def get_forensic_snapshot(user_id: str) -> dict:
    """Return forensic snapshot retained 30 minutes after AI flush."""
    with STORE_LOCK:
        session = SESSION_STORE.get(user_id)
        if not session:
            return {"error": "session_not_found"}
        return {
            "user_id": user_id,
            "forensic_snapshot": session.get("forensic_snapshot", []),
            "last_flush_time": session.get("last_flush_time"),
            "pending_cleanup": session.get("pending_cleanup", False),
        }


@mcp.tool()
def list_active_sessions() -> dict:
    """Return all active sessions."""
    with STORE_LOCK:
        now      = time.time()
        sessions = []
        for uid, s in SESSION_STORE.items():
            sessions.append({
                "user_id": uid,
                "queue_size": len(s.get("events", [])),
                "risk": round(s.get("risk", 0.0), 2),
                "stage": s.get("session_stage", "normal_activity"),
                "flush_lock": s.get("flush_lock", False),
                "lock_remaining": round(s.get("flush_lock_until", 0) - now, 1),
                "flush_counter": s.get("flush_counter", 0),
            })
    return {"sessions": sessions, "count": len(sessions)}


load_store()

if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
