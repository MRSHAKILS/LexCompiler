"""agent-horizon-scanner: CrewAI role-based crew over the statute-ingest MCP tools."""
from __future__ import annotations

import os

from crewai import LLM, Agent, Crew, Task
from crewai.tools import BaseTool

from .mcp_client import AgentOutput, McpClient


def mcp_tools(client: McpClient) -> list[BaseTool]:
    tools = []
    for t in client.list_tools():
        class _Tool(BaseTool):
            name: str = t.name
            description: str = t.description or t.name

            def _run(self, **kwargs) -> str:  # noqa: D401 - CrewAI tool contract
                return client.call_tool(self.name, kwargs)

        tools.append(_Tool())
    return tools


def run(client: McpClient | None = None, model: str | None = None) -> AgentOutput:
    client = client or McpClient("lex-statute-ingest-mcp")
    llm = LLM(model=model or os.environ.get("LEXCOMPILER_CREWAI_MODEL", "gemini/gemini-2.5-flash"))
    scanner = Agent(
        role="Regulatory horizon scanner",
        goal="Find regulatory changes that affect the active clauses",
        backstory="You monitor EUR-Lex and the U.S. Federal Register for amendments.",
        tools=mcp_tools(client),
        llm=llm,
    )
    task = Task(description="Fetch the live regulatory feed and report items that affect the active clauses.", expected_output="AgentOutput JSON", agent=scanner, output_pydantic=AgentOutput)
    return Crew(agents=[scanner], tasks=[task]).kickoff().pydantic
