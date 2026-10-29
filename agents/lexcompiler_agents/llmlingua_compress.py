"""LLMLingua-2 prompt compression sidecar: JSON {"texts": [...], "rate": 0.5} on stdin -> {"texts": [...]}.

Requires `pip install llmlingua` and the model (default microsoft/llmlingua-2-xlm-roberta-large-meetingbank,
override with LEXCOMPILER_LLMLINGUA_MODEL). Deontic operators, numbers and citations are force-kept.
"""
from __future__ import annotations

import json
import os
import sys


def main() -> None:
    # Bytes, not text: text-mode stdin uses the locale code page (cp1252 on Windows), not UTF-8.
    req = json.load(sys.stdin.buffer)
    from llmlingua import PromptCompressor

    compressor = PromptCompressor(
        model_name=os.environ.get("LEXCOMPILER_LLMLINGUA_MODEL", "microsoft/llmlingua-2-xlm-roberta-large-meetingbank"),
        use_llmlingua2=True,
        device_map=os.environ.get("LEXCOMPILER_LLMLINGUA_DEVICE", "cpu"),
    )
    keep = ["must", "shall", "not", "never", "prohibited", "within", "hours", "days", "Art.", "§", "%"]
    out = [
        compressor.compress_prompt(t, rate=float(req.get("rate", 0.5)), force_tokens=keep, drop_consecutive=True)["compressed_prompt"]
        for t in req["texts"]
    ]
    json.dump({"texts": out}, sys.stdout)


if __name__ == "__main__":
    main()
