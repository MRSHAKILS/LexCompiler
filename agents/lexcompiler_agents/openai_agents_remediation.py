"""agent-remediation-pr-enforcer: OpenAI Agents SDK (the successor of Swarm) with a handoff to a reviewer."""
from __future__ import annotations

import os

from agents import Agent, FunctionTool, Model, Runner

from .mcp_client import AgentOutput, McpClient


def mcp_function_tools(client: McpClient) -> list[FunctionTool]:
    def make(tool):
        async def invoke(_ctx, args_json: str) -> str:
            import json

            return client.call_tool(tool.name, json.loads(args_json or "{}"))

        schema = tool.input_schema or {"type": "object", "properties": {}}
        return FunctionTool(name=tool.name, description=tool.description, params_json_schema=schema, on_invoke_tool=invoke, strict_json_schema=False)

    return [make(t) for t in client.list_tools()]


def run(client: McpClient | None = None, model: str | Model | None = None) -> AgentOutput:
    client = client or McpClient("lex-remediation-pr-mcp")
    model = model or os.environ.get("LEXCOMPILER_OPENAI_AGENTS_MODEL", "gpt-4o")
    reviewer = Agent(name="PR gate reviewer", instructions="Check that the post-patch Z3 status is SAT_COMPLIANT and summarise the patch.", model=model, output_type=AgentOutput)
    # Typed on both agents: a model that answers without handing off must still return AgentOutput.
    synthesizer = Agent(
        name="Remediation synthesizer",
        instructions="Synthesize and verify the remediation with the tools, then hand off to the reviewer.",
        model=model,
        tools=mcp_function_tools(client),
        handoffs=[reviewer],
        output_type=AgentOutput,
    )
    return Runner.run_sync(synthesizer, "Remediate the repository and verify the patch.").final_output
