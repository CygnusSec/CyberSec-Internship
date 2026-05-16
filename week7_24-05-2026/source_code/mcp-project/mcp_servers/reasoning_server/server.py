from fastmcp import FastMCP
import requests
import json
import os
import time

mcp = FastMCP("reasoning-server")

AI_PROVIDER = os.environ.get("AI_PROVIDER", "groq")
AI_API_KEY  = os.environ.get("AI_API_KEY",  "")

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
CLAUDE_URL = "https://api.anthropic.com/v1/messages"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"


def build_prompt_behavioral(history, metrics, context_memory, session_stage, source_ip) -> str:
    """
    Nhánh B — không có Wazuh alert.
    AI phân tích toàn bộ behavioral chain kể cả hành động bình thường
    để phát hiện những gì Wazuh bỏ sót.
    """
    chain_text = "\n".join(
        f"  Step {e['step']}: [{e['severity'].upper()}] {e['behavior']} "
        f"| is_attack={e.get('is_attack', False)} "
        f"| source={e['source']} | confidence={e['confidence']:.2f}"
        + (f" | evidence={e['evidence']}" if e.get('evidence') else "")
        for e in history
    )

    context_text = ""
    if context_memory:
        context_text = "\nPrior AI Analysis (context memory):\n" + "\n".join(
            f"  - stage={c.get('stage')}, verdict={c.get('verdict')}, risk={c.get('risk_summary')}"
            for c in context_memory[-3:]
        )

    normal_count = metrics.get("normal_event_count", 0)
    attack_count = metrics.get("attack_event_count", 0)

    return f"""You are a Senior SOAR Security Analyst specializing in behavioral threat detection.
Your job is to detect attacks that signature-based tools like Wazuh MISS.

This queue contains BOTH normal and suspicious actions. Analyze the SEQUENCE and PATTERN,
not just individual events. A series of normal-looking actions can reveal reconnaissance or attack preparation.

Source IP: {source_ip}
Session Stage: {session_stage}
Session Risk Score: {metrics.get('session_risk', 0):.1f}/100
Total Events: {metrics.get('event_count', 0)} (normal={normal_count}, attack_indicators={attack_count})
Critical Events: {metrics.get('critical_count', 0)}
Multi-Stage Indicators: {metrics.get('multi_stage_count', 0)}
{context_text}

Full Behavioral Chain (including normal activity):
{chain_text}

Analyze the PATTERN of behavior:
- Is there a reconnaissance sequence? (robots.txt → admin → login → internal API)
- Are normal actions interspersed with probing?
- Does the timing or sequence suggest automated scanning?
- Even if no attack signatures fired, does the behavior chain look suspicious?

Return ONLY valid JSON, no markdown:
{{
  "is_real_attack": true or false,
  "is_suspicious": true or false,
  "severity": "low" | "medium" | "high" | "critical",
  "confidence": 0.0 to 1.0,
  "verdict": "attack_confirmed" | "probe_detected" | "suspicious" | "benign",
  "risk_summary": "brief label",
  "behavioral_pattern": "description of the behavioral pattern observed",
  "attack_chain": ["action1", "action2"],
  "recommended_action": ["block_ip", "session_invalidation", "sandbox_validation", "monitor_closely", "manual_admin_review", "no_action"],
  "recommendation": "primary action",
  "reasoning": "2-3 sentence explanation focusing on the behavioral pattern"
}}"""


def build_prompt_incident(history, metrics, context_memory, session_stage, source_ip) -> str:
    """
    Nhánh A — Wazuh đã confirm tấn công.
    AI tổng hợp incident report + đề xuất patch.
    """
    chain_text = "\n".join(
        f"  Step {e['step']}: [{e['severity'].upper()}] {e['behavior']} "
        f"| source={e['source']} | confidence={e['confidence']:.2f}"
        + (f" | evidence={e['evidence']}" if e.get('evidence') else "")
        for e in history
    )

    context_text = ""
    if context_memory:
        context_text = "\nPrior Analysis:\n" + "\n".join(
            f"  - stage={c.get('stage')}, verdict={c.get('verdict')}"
            for c in context_memory[-3:]
        )

    return f"""You are a Senior Incident Response Analyst.
Wazuh has CONFIRMED an attack from this IP. Your job is to:
1. Summarize the full attack chain
2. Assess impact and severity
3. Recommend remediation steps
4. Suggest code/config patches if attack type is identifiable

Source IP: {source_ip}
Session Stage: {session_stage}
Session Risk: {metrics.get('session_risk', 0):.1f}/100
Attack Events: {metrics.get('attack_event_count', metrics.get('event_count', 0))}
Critical: {metrics.get('critical_count', 0)} | High: {metrics.get('high_count', 0)}
{context_text}

Confirmed Attack Chain:
{chain_text}

Return ONLY valid JSON, no markdown:
{{
  "is_real_attack": true,
  "is_suspicious": true,
  "severity": "low" | "medium" | "high" | "critical",
  "confidence": 0.95,
  "verdict": "attack_confirmed",
  "risk_summary": "brief label",
  "attack_type": "sqli | xss | lfi | cmdi | rfi | ssrf | brute_force | other",
  "attack_chain": ["step1", "step2"],
  "impact_assessment": "what was potentially accessed or compromised",
  "recommended_action": ["block_ip", "session_invalidation", "sandbox_validation", "telegram_alert", "patch_required"],
  "recommendation": "primary immediate action",
  "patch_suggestion": "specific code or config fix if applicable, or null",
  "reasoning": "2-3 sentence incident summary"
}}"""


def call_groq(prompt: str) -> dict:
    headers = {"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1, "max_tokens": 1500
    }
    r = requests.post(GROQ_URL, headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    return _parse_json(r.json()["choices"][0]["message"]["content"])


def call_gemini(prompt: str) -> dict:
    for attempt in range(3):
        try:
            r = requests.post(
                f"{GEMINI_URL}?key={AI_API_KEY}",
                json={"contents": [{"parts": [{"text": prompt}]}],
                      "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1500}},
                timeout=60
            )
            if r.status_code == 429:
                time.sleep(30 * (attempt + 1))
                continue
            r.raise_for_status()
            return _parse_json(r.json()["candidates"][0]["content"]["parts"][0]["text"])
        except Exception as e:
            if attempt == 2:
                return _error_result(str(e))
            time.sleep(10)
    return _error_result("max retries exceeded")


def call_claude(prompt: str) -> dict:
    headers = {"x-api-key": AI_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    r = requests.post(CLAUDE_URL, headers=headers,
                      json={"model": "claude-sonnet-4-20250514", "max_tokens": 1500,
                            "messages": [{"role": "user", "content": prompt}]}, timeout=60)
    r.raise_for_status()
    return _parse_json(r.json()["content"][0]["text"])


def call_openai(prompt: str) -> dict:
    headers = {"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"}
    r = requests.post(OPENAI_URL, headers=headers,
                      json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.1, "max_tokens": 1500}, timeout=60)
    r.raise_for_status()
    return _parse_json(r.json()["choices"][0]["message"]["content"])


def _parse_json(text: str) -> dict:
    text = text.strip()
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("{"):
                text = part
                break
    return json.loads(text.strip())


def call_ai(prompt: str) -> dict:
    if not AI_API_KEY:
        return _error_result("AI_API_KEY not set")
    try:
        if AI_PROVIDER == "groq":
            return call_groq(prompt)
        elif AI_PROVIDER == "gemini":
            return call_gemini(prompt)
        elif AI_PROVIDER == "claude":
            return call_claude(prompt)
        elif AI_PROVIDER == "openai":
            return call_openai(prompt)
        else:
            return _error_result(f"Unknown AI_PROVIDER: {AI_PROVIDER}")
    except Exception as e:
        return _error_result(str(e))


def _error_result(reason: str) -> dict:
    return {
        "is_real_attack": False, "is_suspicious": False,
        "severity": "unknown", "confidence": 0.0,
        "verdict": "analysis_failed", "risk_summary": "unknown",
        "attack_chain": [], "recommended_action": ["manual_admin_review"],
        "recommendation": "manual_admin_review",
        "reasoning": f"AI error: {reason}"
    }


@mcp.tool()
def reason_about_attack(
    session_id: str,
    source_ip: str,
    behavior_sequence: dict,
    mode: str = "behavioral_analysis"
) -> dict:
    """
    AI reasoning với 2 mode:
    - behavioral_analysis: phân tích chuỗi hành vi, phát hiện attack mà Wazuh bỏ sót
    - incident_report: tổng hợp incident đã confirm, đề xuất patch
    """
    history        = behavior_sequence.get("history", [])
    metrics        = behavior_sequence.get("metrics", {})
    context_memory = behavior_sequence.get("context_memory", [])
    session_stage  = behavior_sequence.get("session_stage", "unknown")

    if not history:
        return _error_result("empty behavioral history")

    if mode == "incident_report":
        prompt = build_prompt_incident(history, metrics, context_memory, session_stage, source_ip)
    else:
        prompt = build_prompt_behavioral(history, metrics, context_memory, session_stage, source_ip)

    result = call_ai(prompt)
    result["session_id"] = session_id
    result["source_ip"]  = source_ip
    result["mode"]       = mode
    return result


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
