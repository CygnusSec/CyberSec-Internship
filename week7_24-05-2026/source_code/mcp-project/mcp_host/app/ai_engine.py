import json
from app.mcp_client import MCPClient


class AIEngine:

    def __init__(self):
        self.reasoning_mcp = MCPClient("http://reasoning_server:8000", timeout=180)

    async def analyze_attack_chain(self, behavior_sequence, session_id, source_ip):
        """Nhánh B — behavioral analysis, AI phán xét có đáng ngờ không."""
        try:
            result = await self.reasoning_mcp.call_tool(
                "reason_about_attack",
                {
                    "session_id":        session_id,
                    "source_ip":         source_ip,
                    "behavior_sequence": behavior_sequence,
                    "mode":              "behavioral_analysis"
                }
            )
            if isinstance(result, str):
                result = json.loads(result)
            return result or _fallback("empty_response")
        except Exception as e:
            return _fallback(str(e))

    async def analyze_confirmed_attack(self, behavior_sequence, session_id, source_ip):
        """Nhánh A — Wazuh confirmed, AI tổng hợp incident report + đề xuất patch."""
        try:
            result = await self.reasoning_mcp.call_tool(
                "reason_about_attack",
                {
                    "session_id":        session_id,
                    "source_ip":         source_ip,
                    "behavior_sequence": behavior_sequence,
                    "mode":              "incident_report"
                }
            )
            if isinstance(result, str):
                result = json.loads(result)
            return result or _fallback("empty_response")
        except Exception as e:
            return _fallback(str(e))


def _fallback(reason: str) -> dict:
    return {
        "is_real_attack":     False,
        "is_suspicious":      False,
        "severity":           "unknown",
        "confidence":         0.0,
        "verdict":            "analysis_failed",
        "risk_summary":       "unknown",
        "recommended_action": ["manual_admin_review"],
        "attack_chain":       [],
        "reasoning":          f"AI engine error: {reason}"
    }
