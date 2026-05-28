import asyncio
from mcp import ClientSession
from mcp.client.sse import sse_client


class MCPClient:

    def __init__(self, server_url: str, timeout: float = 120.0):
        self.server_url = server_url.rstrip("/")
        self.timeout    = timeout

    async def call_tool(self, tool_name: str, payload: dict):
        """
        Generic MCP tool caller với timeout 120s.
        Đủ cho Groq xử lý prompt lớn mà không treo vô thời hạn.
        """
        try:
            async with sse_client(
                f"{self.server_url}/sse",
                timeout=self.timeout
            ) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await asyncio.wait_for(
                        session.call_tool(tool_name, payload),
                        timeout=self.timeout
                    )
                    if result and result.content:
                        return result.content[0].text
                    return "{}"
        except asyncio.TimeoutError:
            raise Exception(f"MCP timeout ({tool_name}) after {self.timeout}s")
        except Exception as e:
            raise Exception(f"MCP call failed ({tool_name}): {str(e)}")
