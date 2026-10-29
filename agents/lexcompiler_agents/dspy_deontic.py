"""agent-deontic-extractor: DSPy ReAct program with a typed signature over the deontic-compiler tools."""
from __future__ import annotations

import os

import dspy

from .mcp_client import AgentOutput, McpClient


class DeonticExtraction(dspy.Signature):
    """Compile a legal clause into deontic logic using the compiler tools, then summarise the obligations."""

    clause: str = dspy.InputField()
    result: AgentOutput = dspy.OutputField()


def run(clause: str, client: McpClient | None = None, model: str | None = None) -> AgentOutput:
    client = client or McpClient("lex-deontic-compiler-mcp")
    dspy.configure(lm=dspy.LM(model or os.environ.get("LEXCOMPILER_DSPY_MODEL", "anthropic/claude-sonnet-4-5")))

    def make(tool):
        def call(**kwargs) -> str:
            return client.call_tool(tool.name, kwargs)

        call.__name__ = tool.name
        call.__doc__ = tool.description
        return dspy.Tool(call, name=tool.name, desc=tool.description, args=tool.input_schema.get("properties", {}))

    program = dspy.ReAct(DeonticExtraction, tools=[make(t) for t in client.list_tools()])
    return program(clause=clause).result
