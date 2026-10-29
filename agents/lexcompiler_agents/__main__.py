"""python -m lexcompiler_agents <agent-id> [--model MODEL] [--query TEXT]"""
from __future__ import annotations

import argparse
import importlib

from .mcp_client import AGENTS, McpClient


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("agent", choices=sorted(AGENTS))
    p.add_argument("--model", default=None)
    p.add_argument("--query", default="Which code constructs violate the active clauses?")
    p.add_argument("--clause", default="PII must be encrypted at rest and purged within 72 hours.")
    a = p.parse_args()
    server, module = AGENTS[a.agent]
    mod = importlib.import_module(f".{module}", __package__)
    client = McpClient(server)
    if module == "langgraph_rag":
        out = mod.run(a.query, client)
    elif module == "dspy_deontic":
        out = mod.run(a.clause, client, a.model)
    elif module == "pydantic_ai_critic":
        out = mod.run(a.model or "openai:gpt-4o", client)
    else:
        out = mod.run(client=client, model=a.model)
    print(out.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
