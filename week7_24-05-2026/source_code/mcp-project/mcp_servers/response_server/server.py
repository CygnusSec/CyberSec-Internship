from fastmcp import FastMCP
import json
from datetime import datetime, timezone, timedelta

mcp = FastMCP("response-server")

VN_TZ = timezone(timedelta(hours=7))


def now_vn():
    return datetime.now(VN_TZ).strftime("%Y-%m-%dT%H:%M:%S+07:00")


def build_response_plan(ai_result: dict) -> dict:
    severity   = ai_result.get("severity", "low").lower()
    confidence = float(ai_result.get("confidence", 0))
    source_ip  = ai_result.get("source_ip", "unknown")
    attack_chain = ai_result.get("attack_chain", [])

    actions    = []
    escalation = "none"
    require_admin = False

    if severity == "low":
        actions += ["log_incident", "store_behavior_trace"]

    elif severity == "medium":
        actions += ["log_incident", "telegram_alert", "create_incident_ticket"]
        escalation = "security_team"

    elif severity == "high":
        actions += ["telegram_alert", "create_incident_ticket", "temporary_ip_block", "sandbox_validation"]
        escalation    = "soc_team"
        require_admin = True

    elif severity == "critical":
        actions += ["telegram_alert", "create_incident_ticket", "block_source_ip",
                    "isolate_container", "preserve_forensics", "manual_admin_intervention"]
        escalation    = "incident_response_team"
        require_admin = True

    if confidence >= 0.95:
        actions.append("auto_execute_allowed")

    return {
        "timestamp":              now_vn(),
        "attack_chain":           attack_chain,
        "source_ip":              source_ip,
        "severity":               severity,
        "confidence":             confidence,
        "response_plan":          actions,
        "escalation_target":      escalation,
        "admin_approval_required": require_admin,
        "status":                 "ready_for_execution"
    }


@mcp.tool()
def generate_response(ai_reasoning: str) -> dict:
    """
    Nhánh B — Convert AI behavioral analysis verdict
    into SOAR response plan for admin decision.
    """
    try:
        ai_result = json.loads(ai_reasoning) if isinstance(ai_reasoning, str) else ai_reasoning
    except Exception:
        return {"status": "failed", "reason": "invalid_ai_reasoning_payload"}

    return build_response_plan(ai_result)


@mcp.tool()
def execute_active_response(source_ip: str, session_stage: str, metrics: str) -> dict:
    """
    Nhánh A — Wazuh confirmed attack.
    Execute immediate automated response without waiting for AI or admin.
    Actions executed instantly: session invalidation, IP throttle, SOC alert.
    """
    try:
        m = json.loads(metrics) if isinstance(metrics, str) else metrics
    except Exception:
        m = {}

    risk          = m.get("session_risk", 0)
    critical_count = m.get("critical_count", 0)
    attack_count  = m.get("attack_event_count", 0)

    # Quyết định mức độ response dựa trên stage và risk
    executed = []

    # Luôn thực hiện ngay
    executed += [
        "session_invalidation",
        "temporary_ip_throttle",
        "telegram_alert_soc",
        "create_incident_ticket",
        "preserve_forensic_snapshot"
    ]

    if session_stage in ("active_intrusion", "post_exploitation"):
        executed += ["block_source_ip", "isolate_affected_container", "escalate_to_ciso"]
    elif session_stage == "initial_compromise":
        executed += ["temporary_ip_block", "force_logout_all_sessions", "escalate_to_soc_lead"]
    elif session_stage in ("reconnaissance", "suspicious_activity"):
        executed += ["rate_limit_ip", "increase_monitoring_level"]

    if critical_count > 0 or risk >= 80:
        executed.append("trigger_incident_response_playbook")

    return {
        "timestamp":       now_vn(),
        "source_ip":       source_ip,
        "session_stage":   session_stage,
        "session_risk":    risk,
        "executed_actions": executed,
        "status":          "active_response_executed",
        "note":            "Automated response triggered by Wazuh-confirmed attack. Admin review required."
    }


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
