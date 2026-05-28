import asyncio
import json
import time
from app.wazuh_client import WazuhClient
from app.orchestrator import SOAROrchestrator

POLL_INTERVAL    = 10   # giây poll Wazuh
WEB_LOG_INTERVAL = 30   # giây poll web log để lấy IP mới


async def get_active_ips_from_web_log(orchestrator: SOAROrchestrator) -> set:
    """
    Lấy IP active từ collector MCP — không đọc file trực tiếp.
    Collector đã mount volume đúng, dùng nó để parse web log.
    """
    try:
        result = await orchestrator._call(
            orchestrator.collector_mcp,
            "fetch_web_logs",
            {"keyword": "HTTP/1", "session_id": "ip_scan"}
        )
        ips = set()
        for event in result.get("events", []):
            raw = event.get("raw", "")
            parts = raw.split()
            if parts:
                ip = parts[0]
                if ip.count(".") == 3 and not ip.startswith("127."):
                    ips.add(ip)
        return ips
    except Exception as e:
        print(f"[WEB LOG] Error getting IPs: {e}")
        return set()


async def main():
    import time as _time
    _time.sleep(5)

    wazuh        = WazuhClient()
    orchestrator = SOAROrchestrator()

    processed_alert_ids = set()
    processed_web_ips   = {}  # ip → last_processed_time

    print("[+] SOAR Host started — Dual trigger mode")
    print("[+] Trigger 1: Wazuh alerts (real-time attack detection)")
    print("[+] Trigger 2: Web log polling (behavioral chain monitoring)")
    print()

    last_web_poll = 0.0

    while True:
        # ══════════════════════════════════════════════════════════════════
        # TRIGGER 1 — Wazuh alert (poll mỗi 10s)
        # ══════════════════════════════════════════════════════════════════
        try:
            alert = await wazuh.get_latest_alert()

            if alert:
                alert_id = alert.get("id")
                if alert_id and alert_id not in processed_alert_ids:
                    processed_alert_ids.add(alert_id)
                    if len(processed_alert_ids) > 1000:
                        processed_alert_ids.pop()

                    print("=" * 70)
                    print(f"[!] WAZUH ALERT: {alert_id}")
                    print("=" * 70)

                    result = await orchestrator.process_alert(alert)
                    _print_result(result)

        except Exception as e:
            import traceback
            print(f"[WAZUH ERROR] {e}")
            traceback.print_exc()

        # ══════════════════════════════════════════════════════════════════
        # TRIGGER 2 — Web log polling (poll mỗi 30s)
        # Theo dõi mọi IP dù Wazuh không alert
        # ══════════════════════════════════════════════════════════════════
        now = time.time()
        if now - last_web_poll >= WEB_LOG_INTERVAL:
            last_web_poll = now
            try:
                active_ips = await get_active_ips_from_web_log(orchestrator)

                for ip in active_ips:
                    last_time = processed_web_ips.get(ip, 0)
                    # Xử lý mỗi IP tối đa mỗi 5 phút
                    if now - last_time < 300:
                        continue

                    processed_web_ips[ip] = now
                    print(f"[~] WEB LOG TRIGGER: {ip}")
                    result = await orchestrator.process_web_ip(ip)
                    _print_result(result)

                # Cleanup IP cũ hơn 30 phút
                processed_web_ips = {
                    ip: t for ip, t in processed_web_ips.items()
                    if t > now - 1800
                }

            except Exception as e:
                print(f"[WEB LOG ERROR] {e}")

        await asyncio.sleep(POLL_INTERVAL)


def _print_result(result: dict):
    status    = result.get("status", "unknown")
    branch    = result.get("branch", "")
    source_ip = result.get("source_ip", "?")

    print(f"\n[STATUS] {status}", end="")
    if branch:
        print(f" | branch={branch}", end="")
    print()

    summary = result.get("pipeline_summary")
    if summary:
        print("\n[PIPELINE SUMMARY]")
        print(json.dumps(summary, indent=2, ensure_ascii=False))

    if status == "buffering":
        print(f"  queue_size   : {result.get('queue_size')}")
        print(f"  current_risk : {result.get('current_risk')}")
        print(f"  session_stage: {result.get('session_stage')}")
        print(f"  trigger      : {result.get('trigger_source')}")
        return

    if status == "attack_confirmed":
        imm = result.get("immediate_response", {})
        if imm:
            print("\n[!! IMMEDIATE RESPONSE EXECUTED]")
            print(json.dumps(imm, indent=2, ensure_ascii=False))
        ai = result.get("ai_incident_report", {})
        if ai:
            print("\n[AI INCIDENT REPORT]")
            print(json.dumps(ai, indent=2, ensure_ascii=False))
        print(f"\n[!!] ATTACK CONFIRMED — Active response executed for {source_ip}\n")
        return

    if status == "suspicious_detected":
        ai = result.get("ai_reasoning", {})
        if ai:
            print("\n[AI REASONING — SUSPICIOUS]")
            print(json.dumps(ai, indent=2, ensure_ascii=False))
        plan = result.get("response_plan", {})
        if plan:
            print("\n[SOAR RESPONSE PLAN]")
            print(json.dumps(plan, indent=2, ensure_ascii=False))
        print(f"\n[!] SUSPICIOUS ACTIVITY — Report sent to admin for {source_ip}\n")
        return

    if status == "normal_activity":
        print(f"  verdict   : {result.get('ai_verdict', 'benign')}")
        print(f"  reasoning : {str(result.get('ai_reasoning', ''))[:120]}")
        print(f"  forensic  : {result.get('forensic_note', '')}")
        print(f"  [OK] Normal activity for {source_ip} — forensic queued\n")
        return

    if result.get("error"):
        print(f"  error: {result.get('error')}")
    print(f"\n[✓] Processed {source_ip}\n")


if __name__ == "__main__":
    asyncio.run(main())
