"""agent-z3-formal-critic: Pydantic-AI agent with typed output over the Z3 prover MCP tools."""
from __future__ import annotations

from pydantic_ai import Agent, Tool

from .mcp_client import AgentOutput, McpClient


def build_agent(model, client: McpClient) -> Agent:
    def make(tool):
        def call(**kwargs) -> str:
            return client.call_tool(tool.name, kwargs)

        call.__name__ = tool.name
        return Tool(call, name=tool.name, description=tool.description, takes_ctx=False)

    tools = [make(t) for t in client.list_tools()]
    return Agent(
        model,
        output_type=AgentOutput,
        tools=tools,
        system_prompt="You are LexCompiler's Z3 formal critic. Prove the repository against the active clauses with the tools and report UNSAT cores and counterexamples. Never invent results.",
    )


def run(model, client: McpClient | None = None, task: str = "Prove the repository against every active clause.") -> AgentOutput:
    agent = build_agent(model, client or McpClient("lex-z3-prover-mcp"))
    return agent.run_sync(task).output
