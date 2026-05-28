from fastmcp import FastMCP
import requests
import json
import os
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor

mcp = FastMCP("reasoning-server")

AI_PROVIDER = os.environ.get("AI_PROVIDER", "groq")
AI_API_KEY  = os.environ.get("AI_API_KEY",  "")

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
CLAUDE_URL = "https://api.anthropic.com/v1/messages"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"

_executor = ThreadPoolExecutor(max_workers=4)


def build_prompt_behavioral(history, metrics, context_memory, session_stage, source_ip) -> str:
    history = history[-30:]
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
Your job is to detect attacks that signature-based tools like Wazuh MISS by analyzing SEQUENCE and PATTERN.

== CRITICAL ENVIRONMENT CONTEXT ==
This system monitors a DVWA (Damn Vulnerable Web Application) lab environment used for security training.
- Accessing /vulnerabilities/* pages is COMPLETELY NORMAL lab activity — NOT suspicious
- Browsing vulnerability pages repeatedly is expected student/researcher behavior
- "vulnerability_lab" behavior = normal lab usage, NOT an attack
- Only flag as suspicious if there are ACTUAL ATTACK PAYLOADS:
  * SQL injection strings (e.g. ' OR 1=1, UNION SELECT)
  * XSS scripts (e.g. <script>alert()</script>)
  * Path traversal (e.g. ../../etc/passwd)
  * Command injection (e.g. ; whoami, | cat /etc/passwd)
  * Brute force (many failed login attempts with different credentials)
- If attack_indicators=0 and all behaviors are normal/lab browsing → verdict MUST be "benign"
- Do NOT flag as suspicious based on context_memory alone if current events are all normal

== SESSION DATA ==
Source IP: {source_ip}
Session Stage: {session_stage}
Risk Score: {metrics.get('session_risk', 0):.1f}/100
Events: {metrics.get('event_count', 0)} (normal={normal_count}, attack_indicators={attack_count})
{context_text}

== BEHAVIORAL CHAIN ==
{chain_text}

== DECISION RULES ==
- attack_indicators=0 AND all behaviors normal → "benign", is_suspicious=false
- attack_indicators>0 with actual payloads → investigate further
- Prior suspicious verdicts do NOT make current normal activity suspicious

Return ONLY valid JSON, no markdown:
{{
  "is_real_attack": true or false,
  "is_suspicious": true or false,
  "severity": "low" | "medium" | "high" | "critical",
  "confidence": 0.0 to 1.0,
  "verdict": "attack_confirmed" | "probe_detected" | "suspicious" | "benign",
  "risk_summary": "brief label",
  "behavioral_pattern": "pattern observed",
  "attack_chain": ["action1", "action2"],
  "recommended_action": ["block_ip", "session_invalidation", "monitor_closely", "manual_admin_review", "no_action"],
  "recommendation": "primary action",
  "reasoning": "2-3 sentence explanation focusing on whether actual attack payloads were found"
}}"""


def build_prompt_incident(history, metrics, context_memory, session_stage, source_ip) -> str:
    history = history[-30:]
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

    return f"""You are a Senior Incident Response Analyst. Wazuh CONFIRMED an attack.
Summarize the attack chain, assess impact, recommend remediation and patches.

Source IP: {source_ip} | Stage: {session_stage}
Risk: {metrics.get('session_risk', 0):.1f}/100
{context_text}

Attack Chain:
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
  "impact_assessment": "what was potentially compromised",
  "recommended_action": ["block_ip", "session_invalidation", "telegram_alert", "patch_required"],
  "recommendation": "primary action",
  "patch_suggestion": "specific fix or null",
  "reasoning": "2-3 sentence summary"
}}"""


def _call_groq_sync(prompt: str) -> dict:
    headers = {"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1, "max_tokens": 1024
    }
    r = requests.post(GROQ_URL, headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    return _parse_json(r.json()["choices"][0]["message"]["content"])


def _call_gemini_sync(prompt: str) -> dict:
    for attempt in range(3):
        try:
            r = requests.post(
                f"{GEMINI_URL}?key={AI_API_KEY}",
                json={"contents": [{"parts": [{"text": prompt}]}],
                      "generationConfig": {"temperature": 0.1, "maxOutputTokens": 1024}},
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


def _call_claude_sync(prompt: str) -> dict:
    headers = {"x-api-key": AI_API_KEY, "anthropic-version": "2023-06-01",
               "content-type": "application/json"}
    r = requests.post(CLAUDE_URL, headers=headers,
                      json={"model": "claude-sonnet-4-20250514", "max_tokens": 1024,
                            "messages": [{"role": "user", "content": prompt}]}, timeout=60)
    r.raise_for_status()
    return _parse_json(r.json()["content"][0]["text"])


def _call_openai_sync(prompt: str) -> dict:
    headers = {"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"}
    r = requests.post(OPENAI_URL, headers=headers,
                      json={"model": "gpt-4o-mini",
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.1, "max_tokens": 1024}, timeout=60)
    r.raise_for_status()
    return _parse_json(r.json()["choices"][0]["message"]["content"])


async def call_ai_async(prompt: str) -> dict:
    """Chạy HTTP call trong thread pool — không block asyncio event loop."""
    if not AI_API_KEY:
        return _error_result("AI_API_KEY not set")

    loop = asyncio.get_event_loop()
    try:
        if AI_PROVIDER == "groq":
            return await loop.run_in_executor(_executor, _call_groq_sync, prompt)
        elif AI_PROVIDER == "gemini":
            return await loop.run_in_executor(_executor, _call_gemini_sync, prompt)
        elif AI_PROVIDER == "claude":
            return await loop.run_in_executor(_executor, _call_claude_sync, prompt)
        elif AI_PROVIDER == "openai":
            return await loop.run_in_executor(_executor, _call_openai_sync, prompt)
        else:
            return _error_result(f"Unknown AI_PROVIDER: {AI_PROVIDER}")
    except Exception as e:
        return _error_result(str(e))


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
async def reason_about_attack(
    session_id: str,
    source_ip: str,
    behavior_sequence: dict,
    mode: str = "behavioral_analysis"
) -> dict:
    """
    AI reasoning với 2 mode:
    - behavioral_analysis: phân tích behavioral chain, phát hiện attack Wazuh bỏ sót
    - incident_report: tổng hợp incident đã confirm, đề xuất patch
    Dùng async + thread pool để không block FastMCP event loop.
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

    result = await call_ai_async(prompt)
    result["session_id"] = session_id
    result["source_ip"]  = source_ip
    result["mode"]       = mode
    return result


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
