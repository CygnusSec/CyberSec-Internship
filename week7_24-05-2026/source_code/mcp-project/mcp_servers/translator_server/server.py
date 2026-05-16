from fastmcp import FastMCP
import re
import urllib.parse

mcp = FastMCP("translator-server")

# Static assets — bỏ qua hoàn toàn, không có giá trị behavioral
_NOISE_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".svg", ".webp",
    ".map", ".min.js", ".min.css"
)

# Label cho hành động bình thường — AI cần ngữ cảnh đầy đủ
_NORMAL_BEHAVIOR_LABEL = {
    "page_browse":        "User browsing a normal page",
    "login_page_visit":   "User visiting login page",
    "login_attempt":      "User attempting authentication",
    "logout":             "User logged out",
    "api_call":           "User making API call",
    "file_access":        "User accessing a file or resource",
    "form_submit":        "User submitting a form",
    "search_query":       "User performing a search",
    "profile_access":     "User accessing profile or account page",
    "settings_access":    "User accessing settings",
    "unknown":            "User activity — behavior unclassified",
}


def severity_rank(level):
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(level, 0)


def apply_detection(result, action, intent, page, severity, confidence, evidence):
    if severity_rank(severity) >= severity_rank(result["severity"]):
        result["action"] = action
        result["intent"] = intent
        result["page"] = page
        result["severity"] = severity
        result["confidence"] = max(result["confidence"], confidence)

    items = evidence if isinstance(evidence, list) else [evidence]
    for item in items:
        if item not in result["evidence"]:
            result["evidence"].append(item)


def classify_normal_behavior(x: str, method: str) -> str:
    """
    Classify unknown actions into normal behavioral categories
    so AI has full context of what the user is doing.
    """
    if re.search(r"\blogin\b|\bsignin\b|\bauth\b", x):
        return "login_page_visit"
    if re.search(r"\blogout\b|\bsignout\b", x):
        return "logout"
    if re.search(r"\bapi/\b|\bapi/v\d", x):
        return "api_call"
    if re.search(r"\bprofile\b|\baccount\b|\buser\b", x):
        return "profile_access"
    if re.search(r"\bsettings\b|\bpreferences\b|\bconfig\b", x):
        return "settings_access"
    if re.search(r"\bsearch\b|\bquery\b|\bq=\b", x):
        return "search_query"
    if method in ("POST", "PUT", "PATCH"):
        return "form_submit"
    if re.search(r"\.(php|html|htm|jsp|asp)(\?|$)", x):
        return "page_browse"
    if re.search(r"\bdownload\b|\bfile\b|\bexport\b", x):
        return "file_access"
    return "page_browse"


# ── Compile all regex at module load ──────────────────────────────────────

_RE_HTTP_METHOD = re.compile(
    r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+?)\s+HTTP', re.IGNORECASE
)
_RE_HEX = re.compile(r"0x[0-9a-f]+")
_RE_MYSQL_COMMENT = re.compile(r"/\*!\d+\s*")
_RE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/")
_RE_WHITESPACE = re.compile(r"\s+")

_RE_LOGIN = re.compile(r"\blogin\b")
_RE_SSH_BRUTE = re.compile(r"failed password for .* from .* (ssh|port \d+)")
_RE_SSH_ENUM = re.compile(r"invalid user .* from")
_RE_DPT = re.compile(r"dpt=\d+")
_RE_FW_BLOCK = re.compile(r"block|drop|reject")

_SQLI_COMPILED = [re.compile(p) for p in [
    r"or\s+1\s*=\s*1", r"or\s+true", r"and\s+1\s*=\s*1", r"and\s+false",
    r"union\s+(all\s+)?select",
    r"--(\s|$)", r"information_schema", r"sys\.tables", r"pg_catalog",
    r"sleep\s*\(", r"benchmark\s*\(", r"waitfor\s+delay", r"pg_sleep\s*\(",
    r"ascii\s*\(", r"substring\s*\(", r"substr\s*\(", r"mid\s*\(",
    r"if\s*\(", r"case\s+when", r"char\s*\(",
    r"load_file\s*\(", r"into\s+outfile", r"into\s+dumpfile",
    r"database\s*\(", r"version\s*\(", r"user\s*\(", r"current_user\s*\(",
    r"group_concat\s*\(", r"concat\s*\(", r"extractvalue\s*\(", r"updatexml\s*\(",
    r"order\s+by\s+\d+", r"having\s+\d+=\d+",
    r"select\s+.+\s+from", r"insert\s+into", r"drop\s+table", r"alter\s+table",
]]

_LFI_COMPILED = [re.compile(p) for p in [
    r"\.\./", r"\.\.\\",
    r"/etc/passwd", r"/etc/shadow", r"/etc/hosts", r"/proc/self",
    r"boot\.ini", r"win\.ini", r"system32",
    r"php://filter", r"php://input", r"php://stdin",
    r"file://", r"phar://", r"zip://", r"data://",
    r"page=.*include", r"path=.*\.\.",
]]

_RFI_COMPILED = [re.compile(p) for p in [
    r"=https?://[^\s]+\.(php|txt|sh|pl)", r"=ftp://",
]]

_CMDI_COMPILED = [re.compile(p) for p in [
    r";\s*(cat|whoami|id|uname|ls|pwd|wget|curl|bash|sh|nc|python|perl|ruby)\b",
    r"\|\s*(whoami|id|uname|cat|ls|wget|curl|bash|sh|nc)\b",
    r"&&\s*(whoami|id|cat|ls|wget|curl|bash)\b",
    r"`(whoami|id|uname|cat|ls)`",
    r"\$\((whoami|id|uname|cat|ls)\)",
    r";\s*rm\s+-rf", r";\s*chmod\s+", r";\s*chown\s+",
    r";\s*wget\s+http", r";\s*curl\s+http",
    r"/dev/tcp/", r"mkfifo\s+",
]]

_XSS_COMPILED = [re.compile(p) for p in [
    r"<script", r"</script>",
    r"alert\s*\(", r"confirm\s*\(", r"prompt\s*\(",
    r"onerror\s*=", r"onload\s*=", r"onclick\s*=", r"onmouseover\s*=",
    r"onfocus\s*=", r"onblur\s*=", r"onkeyup\s*=", r"onkeydown\s*=",
    r"javascript:", r"vbscript:",
    r"expression\s*\(", r"document\.cookie", r"document\.write",
    r"<iframe", r"<img\s+src\s*=", r"<svg\s+on",
    r"&#x",
]]

_SSRF_COMPILED = [re.compile(p) for p in [
    r"url=https?://(?:127\.|10\.|192\.168\.|169\.254\.|::1)",
    r"url=file://", r"url=dict://", r"url=gopher://",
    r"redirect=https?://", r"next=https?://",
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
]]

_SCAN_COMPILED = [re.compile(p) for p in [
    r"/admin", r"/wp-admin", r"/wp-login", r"/wp-config",
    r"/phpmyadmin", r"/pma", r"/adminer",
    r"/\.git/", r"/\.svn/", r"/\.env", r"/\.htaccess", r"/\.htpasswd",
    r"/config\.php", r"/database\.php", r"/settings\.php",
    r"/robots\.txt", r"/sitemap\.xml",
    r"/backup", r"/dump", r"/db\.sql",
    r"/shell\.php", r"/cmd\.php", r"/webshell",
    r"/actuator", r"/swagger-ui", r"/api/v\d+/swagger",
    r"/\.well-known/",
]]
_ADMIN_COMPILED = [re.compile(p) for p in [r"/admin", r"/wp-admin", r"/phpmyadmin"]]

_WEBSHELL_COMPILED = [re.compile(p) for p in [
    r"eval\s*\(base64_decode", r"eval\s*\(gzinflate",
    r"passthru\s*\(", r"system\s*\(.*\$", r"exec\s*\(.*\$",
    r"shell_exec\s*\(", r"popen\s*\(",
    r"\$_(?:get|post|request|cookie)\s*\[.+\]\s*\(",
    r"assert\s*\(\s*\$_",
]]

_C2_COMPILED = [re.compile(p) for p in [
    r"bash\s+-i\s+>&\s+/dev/tcp/",
    r"nc\s+(-e|-c)\s+/bin/(sh|bash)",
    r"python\s+-c\s+.*socket.*connect",
    r"perl\s+-e\s+.*socket",
    r"ruby\s+-rsocket",
    r"socat\s+.*exec:",
]]

_PRIV_COMPILED = [re.compile(p) for p in [
    r"\bsudo\s+(su|bash|sh|-i)\b", r"\bsudo\s+/bin/(sh|bash)\b",
    r"\bsu\s+root\b", r"\bsu\s+-\b",
    r"pkexec\b", r"\bchmod\s+[0-7]*s\b",
    r"/etc/sudoers", r"visudo\b",
    r"passwd\s+root", r"usermod\s+.*-g\s+sudo",
]]

_ATTACK_MARKERS = [
    "sqli_pattern_detected", "lfi_pattern_detected", "rfi_pattern_detected",
    "command_injection_detected", "xss_pattern_detected", "ssrf_pattern_detected",
    "webshell_detected", "reverse_shell_detected",
    "admin_probe", "sensitive_file_access",
    "failed_password_detected", "invalid_user_detected",
    "privilege_escalation_signal", "firewall_block_detected",
]


def preprocess(raw_log: str) -> tuple[str, str]:
    """Returns (normalized_text, http_method)"""
    m = _RE_HTTP_METHOD.search(raw_log)
    method = m.group(1).upper() if m else "GET"
    x = m.group(2) if m else raw_log

    for _ in range(3):
        decoded = urllib.parse.unquote_plus(x)
        if decoded == x:
            break
        x = decoded

    x = x.lower()
    x = x.replace("'", " ").replace('"', " ")
    x = x.replace("#", " ").replace("--", " -- ")
    x = _RE_MYSQL_COMMENT.sub(" ", x)
    x = _RE_BLOCK_COMMENT.sub(" ", x)

    def hex_decode(m):
        try:
            return bytes.fromhex(m.group()[2:]).decode("latin-1", errors="ignore")
        except Exception:
            return m.group()

    x = _RE_HEX.sub(hex_decode, x)
    x = _RE_WHITESPACE.sub(" ", x).strip()
    return x, method


def normalize_log(event: dict) -> dict:
    raw_log          = event.get("raw", "")
    source           = event.get("source", "unknown")
    timestamp        = event.get("timestamp")
    rule_level       = event.get("rule_level")
    rule_description = event.get("rule_description", "")
    srcip            = event.get("srcip")
    url              = event.get("url", "")

    x, method = preprocess(raw_log + " " + url)

    result = {
        "action": "unknown", "intent": "unknown", "page": "generic",
        "severity": "low", "confidence": 0.25,
        "source": source, "timestamp": timestamp, "srcip": srcip,
        "evidence": [], "raw_normalized": x, "multi_stage": False,
        "is_attack": False,
    }

    # ── LOGIN ─────────────────────────────────────────────────────────────
    if _RE_LOGIN.search(x):
        apply_detection(result, "login_attempt", "authentication", "authentication", "low", 0.40, "login_detected")

    # ── SQL INJECTION ──────────────────────────────────────────────────────
    matched_sqli = [p for p in _SQLI_COMPILED if p.search(x)]
    if matched_sqli:
        result["is_attack"] = True
        apply_detection(result, "authentication_bypass_attempt", "sql_injection", "data_query", "high", 0.97,
                        ["sqli_pattern_detected", f"matched_rules={len(matched_sqli)}"])

    # ── LFI ───────────────────────────────────────────────────────────────
    if any(p.search(x) for p in _LFI_COMPILED):
        result["is_attack"] = True
        apply_detection(result, "local_file_inclusion_attempt", "file_disclosure", "file_access", "high", 0.95, "lfi_pattern_detected")

    # ── RFI ───────────────────────────────────────────────────────────────
    if any(p.search(x) for p in _RFI_COMPILED):
        result["is_attack"] = True
        apply_detection(result, "remote_file_inclusion_attempt", "remote_code_execution", "file_access", "critical", 0.96, "rfi_pattern_detected")

    # ── COMMAND INJECTION ──────────────────────────────────────────────────
    if any(p.search(x) for p in _CMDI_COMPILED):
        result["is_attack"] = True
        apply_detection(result, "command_injection_attempt", "remote_code_execution", "system_command", "critical", 0.98, "command_injection_detected")

    # ── XSS ───────────────────────────────────────────────────────────────
    if any(p.search(x) for p in _XSS_COMPILED):
        result["is_attack"] = True
        apply_detection(result, "cross_site_scripting_attempt", "client_side_attack", "frontend_attack", "high", 0.93, "xss_pattern_detected")

    # ── SSRF ──────────────────────────────────────────────────────────────
    if any(p.search(x) for p in _SSRF_COMPILED):
        result["is_attack"] = True
        apply_detection(result, "ssrf_attempt", "internal_network_probe", "backend_service", "critical", 0.96, "ssrf_pattern_detected")

    # ── SCAN / SENSITIVE PATHS ─────────────────────────────────────────────
    matched_scan = [p for p in _SCAN_COMPILED if p.search(x)]
    if matched_scan:
        result["is_attack"] = True
        is_admin = any(p.search(x) for p in _ADMIN_COMPILED)
        apply_detection(
            result,
            "admin_surface_probe" if is_admin else "sensitive_resource_discovery",
            "privilege_discovery" if is_admin else "reconnaissance",
            "admin_panel" if is_admin else "resource_discovery",
            "medium", 0.80 if is_admin else 0.75,
            ["admin_probe" if is_admin else "sensitive_file_access", f"matched_paths={len(matched_scan)}"]
        )

    # ── WEBSHELL ──────────────────────────────────────────────────────────
    if any(p.search(x) for p in _WEBSHELL_COMPILED):
        result["is_attack"] = True
        apply_detection(result, "webshell_execution", "post_exploitation", "system_command", "critical", 0.99, "webshell_detected")

    # ── REVERSE SHELL / C2 ────────────────────────────────────────────────
    if any(p.search(x) for p in _C2_COMPILED):
        result["is_attack"] = True
        apply_detection(result, "reverse_shell_attempt", "c2_communication", "system_command", "critical", 0.99, "reverse_shell_detected")

    # ── SSH BRUTE FORCE ────────────────────────────────────────────────────
    if _RE_SSH_BRUTE.search(x):
        result["is_attack"] = True
        apply_detection(result, "brute_force_attempt", "credential_attack", "remote_access", "medium", 0.85, "failed_password_detected")

    if _RE_SSH_ENUM.search(x):
        result["is_attack"] = True
        apply_detection(result, "user_enumeration_attempt", "reconnaissance", "remote_access", "medium", 0.80, "invalid_user_detected")

    # ── PRIVILEGE ESCALATION ───────────────────────────────────────────────
    if any(p.search(x) for p in _PRIV_COMPILED):
        result["is_attack"] = True
        apply_detection(result, "privilege_escalation_attempt", "post_exploitation", "system_access", "critical", 0.98, "privilege_escalation_signal")

    # ── FIREWALL BLOCK ─────────────────────────────────────────────────────
    if source == "firewall":
        if _RE_DPT.search(x) or _RE_FW_BLOCK.search(x):
            result["is_attack"] = True
            apply_detection(result, "port_scan_detected", "reconnaissance", "network_perimeter", "medium", 0.78, "firewall_block_detected")

    # ── WAZUH PASSTHROUGH ─────────────────────────────────────────────────
    if source == "wazuh" and rule_level is not None:
        try:
            level = int(rule_level)
        except (ValueError, TypeError):
            level = 0
        if level >= 12:
            result["is_attack"] = True
            apply_detection(result, "wazuh_critical_alert", "wazuh_detection", "siem_alert", "critical", 0.95,
                            [f"wazuh_rule_level={level}", f"wazuh_desc={rule_description[:80]}"])
        elif level >= 7:
            result["is_attack"] = True
            apply_detection(result, "wazuh_high_alert", "wazuh_detection", "siem_alert", "high", 0.85,
                            [f"wazuh_rule_level={level}", f"wazuh_desc={rule_description[:80]}"])

    # ── CONFIDENCE FLOOR ──────────────────────────────────────────────────
    if result["severity"] == "high":
        result["confidence"] = max(result["confidence"], 0.90)
    if result["severity"] == "critical":
        result["confidence"] = max(result["confidence"], 0.95)

    # ── MULTI-STAGE FLAG ──────────────────────────────────────────────────
    detected_types = sum(1 for m in _ATTACK_MARKERS if m in result["evidence"])
    if detected_types >= 2:
        result["evidence"].append(f"multi_stage_detected={detected_types}")
        result["multi_stage"] = True

    # ── CLASSIFY NORMAL BEHAVIOR ───────────────────────────────────────────
    # Nếu không phát hiện attack, phân loại hành động bình thường
    # để AI có đủ ngữ cảnh phân tích behavioral chain
    if result["action"] == "unknown" and not result["is_attack"]:
        normal_action = classify_normal_behavior(x, method)
        result["action"] = normal_action
        result["intent"] = "normal_activity"
        result["page"] = "application"
        result["behavior_label"] = _NORMAL_BEHAVIOR_LABEL.get(normal_action, _NORMAL_BEHAVIOR_LABEL["unknown"])
    else:
        result["behavior_label"] = _NORMAL_BEHAVIOR_LABEL.get(result["action"], result["action"])

    return result


@mcp.tool()
def translate_behavior(event: dict) -> dict:
    """
    Receive a raw event dict from collector and return a normalized
    behavioral event for the correlator. Classifies ALL user actions
    including normal ones so AI can analyze full behavioral chain.
    """
    if not event or not isinstance(event, dict):
        return {"error": "invalid_input", "action": "unknown"}
    return normalize_log(event)


@mcp.tool()
def translate_batch(events: list) -> dict:
    """
    Translate a full batch of raw collector events in one call.
    Only skips static assets (css, js, images) — keeps ALL user behavior
    including normal actions for full behavioral chain analysis.
    """
    results = []
    skipped = 0

    for event in events:
        if not isinstance(event, dict):
            skipped += 1
            continue

        raw = event.get("raw", "").lower()
        url = event.get("url", "").lower()
        path = raw + url

        # Chỉ bỏ static assets — không bỏ hành động người dùng
        if any(ext in path for ext in _NOISE_EXTENSIONS):
            skipped += 1
            continue

        results.append(normalize_log(event))

    return {
        "translated": results,
        "translated_count": len(results),
        "skipped_count": skipped
    }


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
