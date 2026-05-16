import json
from app.mcp_client import MCPClient


class ResponseEngine:

    def __init__(self):
        self.response_mcp = MCPClient("http://response_server:8000")

    async def generate_response_plan(self, ai_reasoning) -> dict:
        """Nhánh B — tạo response plan từ AI verdict để admin quyết định."""
        payload = json.dumps(ai_reasoning) if isinstance(ai_reasoning, dict) else str(ai_reasoning)
        try:
            result = await self.response_mcp.call_tool(
                "generate_response",
                {"ai_reasoning": payload}
            )
            return json.loads(result) if isinstance(result, str) else result
        except Exception as e:
            return {"status": "failed", "reason": str(e)}

    async def active_response(self, source_ip: str, session_stage: str, payload: dict) -> dict:
        """
        Nhánh A — Wazuh confirmed attack.
        Thực thi response ngay không cần chờ AI hay admin.
        """
        try:
            result = await self.response_mcp.call_tool(
                "execute_active_response",
                {
                    "source_ip":     source_ip,
                    "session_stage": session_stage,
                    "metrics":       json.dumps(payload.get("metrics", {}))
                }
            )
            return json.loads(result) if isinstance(result, str) else result
        except Exception as e:
            return {"status": "failed", "reason": str(e), "actions": []}
