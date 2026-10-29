"""agent-polyglot-ast-mapper: Hermes-style function calling on a local Ollama model (Qwen2.5-Coder)."""
from __future__ import annotations

import json
import os
import re
import urllib.request

from .mcp_client import AgentOutput, McpClient

TOOL_CALL = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)


def _chat(base: str, model: str, messages: list[dict], tools: list[dict]) -> dict:
    body = json.dumps({"model": model, "messages": messages, "tools": tools, "stream": False, "options": {"temperature": 0}}).encode()
    req = urllib.request.Request(f"{base.rstrip('/')}/api/chat", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=300) as res:
        return json.loads(res.read())["message"]


def parse_tool_calls(message: dict) -> list[tuple[str, dict]]:
    """Ollama's native tool_calls, or Hermes <tool_call>{"name":…,"arguments":…}</tool_call> tags in the text."""
    calls = [(c["function"]["name"], c["function"].get("arguments") or {}) for c in message.get("tool_calls") or []]
    for m in TOOL_CALL.finditer(message.get("content") or ""):
        obj = json.loads(m.group(1))
        calls.append((obj["name"], obj.get("arguments") or {}))
    return calls


def run(client: McpClient | None = None, model: str | None = None, base: str | None = None, max_turns: int = 4) -> AgentOutput:
    client = client or McpClient("lex-polyglot-ast-mcp")
    model = model or os.environ.get("LEXCOMPILER_HERMES_MODEL", "qwen2.5-coder:7b")
    base = base or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    tools = [{"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.input_schema}} for t in client.list_tools()]
    messages = [
        {"role": "system", "content": "You map polyglot repositories to compliance constructs. Call a tool with <tool_call>{\"name\": ..., \"arguments\": {...}}</tool_call>. "
         f"When done, answer with JSON: {json.dumps(AgentOutput.model_json_schema())}"},
        {"role": "user", "content": "Scan the repository and list the compliance-relevant constructs."},
    ]
    for _ in range(max_turns):
        msg = _chat(base, model, messages, tools)
        calls = parse_tool_calls(msg)
        messages.append({"role": "assistant", "content": msg.get("content") or "", **({"tool_calls": msg["tool_calls"]} if msg.get("tool_calls") else {})})
        if not calls:
            text = msg.get("content") or ""
            return AgentOutput.model_validate_json(text[text.find("{"): text.rfind("}") + 1])
        for name, args in calls:
            messages.append({"role": "tool", "content": client.call_tool(name, args)})
    raise RuntimeError("Hermes agent did not finish")
