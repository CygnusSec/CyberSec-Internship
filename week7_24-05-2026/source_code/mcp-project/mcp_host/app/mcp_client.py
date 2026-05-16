from mcp import ClientSession
from mcp.client.sse import sse_client


class MCPClient:

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip("/")

    async def call_tool(self, tool_name: str, payload: dict):
        """
        Generic MCP tool caller
        """

        try:
            async with sse_client(
                f"{self.server_url}/sse"
            ) as (read, write):

                async with ClientSession(
                    read,
                    write
                ) as session:

                    await session.initialize()

                    result = await session.call_tool(
                        tool_name,
                        payload
                    )

                    if result and result.content:
                        return result.content[0].text

                    return "{}"

        except Exception as e:
            raise Exception(
                f"MCP call failed ({tool_name}): {str(e)}"
            )
