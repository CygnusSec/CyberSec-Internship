import json
from app.mcp_client import MCPClient
from app.ai_engine import AIEngine
from app.response_engine import ResponseEngine


class SOAROrchestrator:
    """
    SOAR pipeline — MCP-native, dual-branch design.

    Trigger 1 (Wazuh alert) → fetch_all_sources (7 nguồn kể cả Wazuh)
      → has_wazuh_alert=True → Nhánh A: active response ngay

    Trigger 2 (web log)     → fetch 6 nguồn (KHÔNG Wazuh)
      → has_wazuh_alert=False → Nhánh B: AI phân tích behavioral chain
    """

    def __init__(self):
        self.collector_mcp   = MCPClient("http://collector_server:8000")
        self.translator_mcp  = MCPClient("http://translator_server:8000")
        self.correlator_mcp  = MCPClient("http://correlator_server:8000")
        self.ai_engine       = AIEngine()
        self.response_engine = ResponseEngine()

    async def _call(self, client: MCPClient, tool: str, payload: dict) -> dict:
        result = await client.call_tool(tool, payload)
        if isinstance(result, str):
            result = json.loads(result)
        return result or {}

    async def _run_pipeline(
        self,
        source_ip: str,
        trigger_source: str,
        alert_id: str,
        url: str,
        rule_description: str,
        collector_result: dict,
    ) -> dict:
        """
        Shared pipeline từ bước translate trở đi.
        collector_result đã được chuẩn bị sẵn bởi caller.
        """
        raw_events = collector_result.get("events", [])
        if not raw_events:
            return {"alert_id": alert_id, "source_ip": source_ip, "status": "no_events_collected"}

        # ── STEP 2: TRANSLATE ─────────────────────────────────────────────
        try:
            translate_result = await self._call(
                self.translator_mcp,
                "translate_batch",
                {"events": raw_events}
            )
        except Exception as e:
            return {"alert_id": alert_id, "source_ip": source_ip, "status": "translator_error", "error": str(e)}

        translated_events = translate_result.get("translated", [])
        if not translated_events:
            return {
                "alert_id": alert_id, "source_ip": source_ip,
                "status": "no_behaviors_detected",
                "skipped_count": translate_result.get("skipped_count", 0)
            }

        # ── STEP 3: CORRELATE ─────────────────────────────────────────────
        try:
            correlation_result = await self._call(
                self.correlator_mcp,
                "add_event_batch",
                {"events": translated_events, "user_id": source_ip}
            )
        except Exception as e:
            return {"alert_id": alert_id, "source_ip": source_ip, "status": "correlator_error", "error": str(e)}

        # ── STEP 4: BUFFER CHECK ──────────────────────────────────────────
        if not correlation_result.get("ready_for_ai"):
            return {
                "alert_id": alert_id, "source_ip": source_ip, "url": url,
                "status": "buffering",
                "queue_size": correlation_result.get("queue_size", 0),
                "current_risk": correlation_result.get("current_risk", 0),
                "session_stage": correlation_result.get("session_stage"),
                "trigger_source": trigger_source,
            }

        payload_to_ai   = correlation_result.get("payload_to_ai", {})
        has_wazuh_alert = payload_to_ai.get("has_wazuh_alert", False)
        session_stage   = correlation_result.get("session_stage", "normal_activity")

        pipeline_summary = {
            "raw_events_collected": len(raw_events),
            "behaviors_translated": len(translated_events),
            "normal_behaviors":  sum(1 for e in translated_events if not e.get("is_attack")),
            "attack_behaviors":  sum(1 for e in translated_events if e.get("is_attack")),
            "skipped_noise":     translate_result.get("skipped_count", 0),
            "sources_queried":   collector_result.get("sources_queried", []),
            "session_stage":     session_stage,
            "session_risk":      correlation_result.get("current_risk", 0),
            "trigger_source":    trigger_source,
        }

        # ══════════════════════════════════════════════════════════════════
        # NHÁNH A — có Wazuh alert → chắc chắn tấn công
        # ══════════════════════════════════════════════════════════════════
        if has_wazuh_alert:
            try:
                immediate_response = await self.response_engine.active_response(
                    source_ip=source_ip,
                    session_stage=session_stage,
                    payload=payload_to_ai
                )
            except Exception as e:
                immediate_response = {"error": str(e), "actions": []}

            try:
                ai_result = await self.ai_engine.analyze_confirmed_attack(
                    behavior_sequence=payload_to_ai,
                    session_id=source_ip,
                    source_ip=source_ip
                )
            except Exception as e:
                ai_result = {"error": str(e), "verdict": "analysis_failed"}

            try:
                await self._call(self.correlator_mcp, "update_ai_context",
                                 {"user_id": source_ip, "ai_result": ai_result})
            except Exception:
                pass

            return {
                "alert_id": alert_id, "source_ip": source_ip,
                "url": url, "rule_description": rule_description,
                "status": "attack_confirmed",
                "branch": "wazuh_confirmed",
                "pipeline_summary": pipeline_summary,
                "immediate_response": immediate_response,
                "ai_incident_report": ai_result,
            }

        # ══════════════════════════════════════════════════════════════════
        # NHÁNH B — không có Wazuh alert → AI phân tích behavioral chain
        # ══════════════════════════════════════════════════════════════════
        try:
            ai_result = await self.ai_engine.analyze_attack_chain(
                behavior_sequence=payload_to_ai,
                session_id=source_ip,
                source_ip=source_ip
            )
        except Exception as e:
            ai_result = {"error": str(e), "verdict": "analysis_failed",
                         "is_suspicious": False, "risk_summary": "unknown"}

        try:
            await self._call(self.correlator_mcp, "update_ai_context",
                             {"user_id": source_ip, "ai_result": ai_result})
        except Exception:
            pass

        verdict       = ai_result.get("verdict", "benign")
        is_suspicious = ai_result.get("is_suspicious", False) or verdict in (
            "attack_confirmed", "probe_detected", "suspicious"
        )

        if is_suspicious:
            try:
                response_plan = await self.response_engine.generate_response_plan(ai_result)
            except Exception as e:
                response_plan = {"error": str(e), "actions": []}

            return {
                "alert_id": alert_id, "source_ip": source_ip, "url": url,
                "status": "suspicious_detected",
                "branch": "behavioral_analysis",
                "pipeline_summary": pipeline_summary,
                "ai_reasoning": ai_result,
                "response_plan": response_plan,
            }

        return {
            "alert_id": alert_id, "source_ip": source_ip,
            "status": "normal_activity",
            "branch": "behavioral_analysis",
            "pipeline_summary": pipeline_summary,
            "ai_verdict": verdict,
            "ai_reasoning": ai_result.get("reasoning", ""),
            "forensic_note": "Queue retained 30 minutes for investigation if needed",
        }

    async def process_alert(self, alert: dict) -> dict:
        """
        Trigger 1 — Wazuh alert.
        Dùng fetch_all_sources (7 nguồn kể cả Wazuh).
        has_wazuh_alert sẽ = True → luôn vào nhánh A.
        """
        data      = alert.get("data", {})
        source_ip = data.get("srcip", "unknown")
        session_id = source_ip

        alert_id         = alert.get("id", "no_alert")
        rule_description = alert.get("rule", {}).get("description", "N/A")
        url              = data.get("url", "/")

        try:
            collector_result = await self._call(
                self.collector_mcp,
                "fetch_all_sources",
                {"keyword": source_ip, "src_ip": source_ip, "session_id": session_id}
            )
        except Exception as e:
            return {"alert_id": alert_id, "source_ip": source_ip,
                    "status": "collector_error", "error": str(e)}

        return await self._run_pipeline(
            source_ip=source_ip,
            trigger_source="wazuh",
            alert_id=alert_id,
            url=url,
            rule_description=rule_description,
            collector_result=collector_result,
        )

    async def process_web_ip(self, source_ip: str) -> dict:
        """
        Trigger 2 — Web log polling.
        CHỈ lấy 6 nguồn — KHÔNG lấy Wazuh alerts.
        has_wazuh_alert sẽ = False → luôn vào nhánh B (behavioral analysis).
        """
        session_id = source_ip
        all_events = []

        for tool, params in [
            ("fetch_web_logs",       {"keyword": source_ip, "session_id": session_id}),
            ("fetch_auth_logs",      {"keyword": source_ip, "session_id": session_id}),
            ("fetch_db_logs",        {"keyword": source_ip, "session_id": session_id}),
            ("fetch_audit_logs",     {"keyword": source_ip, "session_id": session_id}),
            ("fetch_container_logs", {"keyword": source_ip, "session_id": session_id}),
            ("fetch_firewall_logs",  {"src_ip":  source_ip, "session_id": session_id}),
        ]:
            try:
                r = await self._call(self.collector_mcp, tool, params)
                all_events.extend(r.get("events", []))
            except Exception:
                continue

        collector_result = {
            "events": all_events,
            "event_count": len(all_events),
            "sources_queried": ["web", "auth", "db", "audit", "container", "firewall"]
        }

        return await self._run_pipeline(
            source_ip=source_ip,
            trigger_source="web_log",
            alert_id=f"web_{source_ip}",
            url="/",
            rule_description="Web log behavioral trigger",
            collector_result=collector_result,
        )

    async def get_session_status(self, source_ip: str) -> dict:
        return await self._call(self.correlator_mcp, "get_session_status", {"user_id": source_ip})

    async def get_forensic_snapshot(self, source_ip: str) -> dict:
        return await self._call(self.correlator_mcp, "get_forensic_snapshot", {"user_id": source_ip})

    async def list_active_sessions(self) -> dict:
        return await self._call(self.correlator_mcp, "list_active_sessions", {})
