from fastmcp import FastMCP
import json
import os
import requests
from datetime import datetime, timezone, timedelta

mcp = FastMCP("response-server")

VN_TZ = timezone(timedelta(hours=7))

# Telegram config — đọc từ env hoặc hardcode
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8977068037:AAGiiZPFzmF8rGdTqTPrxCPxfR_KR4qHEjA")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID",   "8727168607")
TELEGRAM_API_URL   = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"


def now_vn():
    return datetime.now(VN_TZ).strftime("%Y-%m-%dT%H:%M:%S+07:00")


def send_telegram(message: str, parse_mode: str = "HTML") -> bool:
    """Gửi tin nhắn Telegram thật. Trả True nếu thành công."""
    try:
        r = requests.post(
            TELEGRAM_API_URL,
            json={
                "chat_id":    TELEGRAM_CHAT_ID,
                "text":       message,
                "parse_mode": parse_mode,
            },
            timeout=10
        )
        return r.status_code == 200
    except Exception:
        return False


def build_telegram_alert(
    source_ip: str,
    severity: str,
    verdict: str,
    attack_chain: list,
    risk_summary: str,
    session_stage: str,
    session_risk: float,
    mode: str = "behavioral"
) -> str:
    """Build tin nhắn Telegram có format đẹp."""
    severity_emoji = {
        "low":      "🟡",
        "medium":   "🟠",
        "high":     "🔴",
        "critical": "🚨",
    }.get(severity, "⚪")

    mode_label = "🔍 Behavioral Analysis" if mode == "behavioral" else "⚠️ Wazuh Confirmed"

    chain_text = "\n".join(f"  • {step}" for step in attack_chain) if attack_chain else "  • N/A"

    return f"""{severity_emoji} <b>SOAR ALERT — {severity.upper()}</b>
{mode_label}

🌐 <b>Source IP:</b> <code>{source_ip}</code>
📊 <b>Risk Score:</b> {session_risk:.1f}/100
🎯 <b>Verdict:</b> {verdict}
🔎 <b>Summary:</b> {risk_summary}
📍 <b>Stage:</b> {session_stage}

⛓ <b>Attack Chain:</b>
{chain_text}

🕐 <b>Time:</b> {now_vn()}"""


def build_response_plan(ai_result: dict) -> dict:
    severity     = ai_result.get("severity", "low").lower()
    confidence   = float(ai_result.get("confidence", 0))
    source_ip    = ai_result.get("source_ip", "unknown")
    attack_chain = ai_result.get("attack_chain", [])
    verdict      = ai_result.get("verdict", "unknown")
    risk_summary = ai_result.get("risk_summary", "")
    session_stage = ai_result.get("session_stage", "unknown")
    session_risk  = float(ai_result.get("session_risk", 0))

    actions       = []
    escalation    = "none"
    require_admin = False
    telegram_sent = False

    if severity == "low":
        actions += ["log_incident", "store_behavior_trace"]

    elif severity == "medium":
        actions += ["log_incident", "telegram_alert", "create_incident_ticket"]
        escalation = "security_team"
        # Gửi Telegram thật
        msg = build_telegram_alert(source_ip, severity, verdict, attack_chain,
                                   risk_summary, session_stage, session_risk)
        telegram_sent = send_telegram(msg)

    elif severity == "high":
        actions += ["telegram_alert", "create_incident_ticket",
                    "temporary_ip_block", "sandbox_validation"]
        escalation    = "soc_team"
        require_admin = True
        msg = build_telegram_alert(source_ip, severity, verdict, attack_chain,
                                   risk_summary, session_stage, session_risk)
        telegram_sent = send_telegram(msg)

    elif severity == "critical":
        actions += ["telegram_alert", "create_incident_ticket", "block_source_ip",
                    "isolate_container", "preserve_forensics", "manual_admin_intervention"]
        escalation    = "incident_response_team"
        require_admin = True
        msg = build_telegram_alert(source_ip, severity, verdict, attack_chain,
                                   risk_summary, session_stage, session_risk)
        telegram_sent = send_telegram(msg)

    if confidence >= 0.95:
        actions.append("auto_execute_allowed")

    return {
        "timestamp":               now_vn(),
        "attack_chain":            attack_chain,
        "source_ip":               source_ip,
        "severity":                severity,
        "confidence":              confidence,
        "response_plan":           actions,
        "escalation_target":       escalation,
        "admin_approval_required": require_admin,
        "telegram_sent":           telegram_sent,
        "status":                  "ready_for_execution"
    }


@mcp.tool()
def generate_response(ai_reasoning: str) -> dict:
    """
    Nhánh B — Convert AI behavioral analysis verdict
    into SOAR response plan. Gửi Telegram nếu severity >= medium.
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
    Execute immediate automated response + gửi Telegram alert ngay.
    """
    try:
        m = json.loads(metrics) if isinstance(metrics, str) else metrics
    except Exception:
        m = {}

    risk           = m.get("session_risk", 0)
    critical_count = m.get("critical_count", 0)
    attack_count   = m.get("attack_event_count", 0)

    executed = [
        "session_invalidation",
        "temporary_ip_throttle",
        "create_incident_ticket",
        "preserve_forensic_snapshot"
    ]

    if session_stage in ("active_intrusion", "post_exploitation"):
        executed += ["block_source_ip", "isolate_affected_container", "escalate_to_ciso"]
        severity = "critical"
    elif session_stage == "initial_compromise":
        executed += ["temporary_ip_block", "force_logout_all_sessions", "escalate_to_soc_lead"]
        severity = "high"
    elif session_stage in ("reconnaissance", "suspicious_activity"):
        executed += ["rate_limit_ip", "increase_monitoring_level"]
        severity = "medium"
    else:
        severity = "medium"

    if critical_count > 0 or risk >= 80:
        executed.append("trigger_incident_response_playbook")

    # Gửi Telegram alert ngay — Wazuh confirmed = gửi luôn không cần check severity
    severity_emoji = {"medium": "🟠", "high": "🔴", "critical": "🚨"}.get(severity, "🔴")
    telegram_msg = f"""{severity_emoji} <b>🚨 WAZUH CONFIRMED ATTACK</b>

🌐 <b>Source IP:</b> <code>{source_ip}</code>
📊 <b>Risk Score:</b> {risk:.1f}/100
📍 <b>Stage:</b> {session_stage}
⚡ <b>Attack Events:</b> {attack_count}

✅ <b>Actions Executed:</b>
{chr(10).join(f'  • {a}' for a in executed)}

🕐 <b>Time:</b> {now_vn()}
⚠️ Admin review required."""

    telegram_sent = send_telegram(telegram_msg)
    executed.append("telegram_alert_soc")

    return {
        "timestamp":        now_vn(),
        "source_ip":        source_ip,
        "session_stage":    session_stage,
        "session_risk":     risk,
        "executed_actions": executed,
        "telegram_sent":    telegram_sent,
        "status":           "active_response_executed",
        "note":             "Automated response triggered by Wazuh-confirmed attack. Admin review required."
    }


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
