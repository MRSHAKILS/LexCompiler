import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from lexcompiler_agents.mcp_client import McpClient, McpTool  # noqa: E402


class StubClient(McpClient):
    """Records tool calls and returns canned MCP results."""

    def __init__(self, server_id: str, tools: dict[str, object]):
        super().__init__(server_id, base_url="http://stub")
        self.tools = tools
        self.calls: list[tuple[str, dict]] = []

    def list_tools(self):
        return [McpTool(n, f"{n} tool", {"type": "object", "properties": {}}) for n in self.tools]

    def call_tool_json(self, name, arguments=None):
        return json.loads(self.call_tool(name, arguments))

    def call_tool(self, name, arguments=None, limit=8000):
        self.calls.append((name, arguments or {}))
        value = self.tools[name]
        value = value(arguments or {}) if callable(value) else value
        return value if isinstance(value, str) else json.dumps(value)


@pytest.fixture
def stub():
    return StubClient
