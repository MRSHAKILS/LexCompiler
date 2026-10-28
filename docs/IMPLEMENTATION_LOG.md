# LexCompiler — Implementation Log

This log has two parts:

1. **What's new**: work completed on branch `claude/compassionate-hypatia-3mjhsk`, step by step.
2. **To complete in a local environment**: items that couldn't be fully built in the cloud session (they need services, credentials, or infrastructure it doesn't have), with what remains to be done for each.

Finding IDs (S1, V2, …) refer to [`LIMITATIONS_REPORT.md`](./LIMITATIONS_REPORT.md).

---

## Part 1 — What's New

### Step 1 · P0 security and honesty fixes (commit `fe29e6d`)
- **S1, S3 — API lockdown** (`server/security.ts`): the server binds to loopback by default and refuses a non-loopback `HOST` without `LEXCOMPILER_API_TOKEN`. Requests go through a CORS allowlist, an optional bearer token, a DNS-rebinding `Host` check, and a required `X-LexCompiler-Client` header. The UI adds the header automatically (`src/apiClient.ts`).
- **S1 — no path traversal:** `writeTargetRepoFile` only writes existing, scanned source files inside the target repository.
- **S2 — runtime sandbox is opt-in** (`LEXCOMPILER_ENABLE_RUNTIME_SANDBOX=1`). It runs on a temp copy with `python3 -I`, an empty environment, and rlimits.
- **V1 — PR gate:** a PR is `BLOCKED_UNRESOLVED` unless every clause is SAT after patching. `apply-pr` and `apply-node` return `409` for a blocked PR, and the UI shows the real result.
- **L4, C4 — labelling:** built-in demo clauses and feed items are tagged illustrative, and the attestation wording was corrected.

### Step 2 · Analyzer, prover, compiler, remediation rewrite
- **A3 — SQL parser** (`server/analyzer/astAnalyzer.ts`): a real tokenizer and statement parser replaces the line regexes. It handles multi-line columns, table constraints (`PRIMARY KEY (...)`, `FOREIGN KEY ... REFERENCES ... ON DELETE`), quoted and schema-qualified names, `ALTER TABLE ... ADD COLUMN / ADD FOREIGN KEY`, `retention_days` columns, ciphertext columns (`*_encrypted BYTEA`), and syntax errors (unbalanced parentheses, unterminated strings).
- **A2 — Python constant folding:** `24 * 30`, references to earlier constants, and `int(os.getenv("X", 72))` defaults are evaluated, and TTL units come from the identifier (`_SECONDS`, `_MINUTES`, `_DAYS`, `_WEEKS`, …). A literal TTL passed to `setex`/`expire`/`set(ex=)` is also read. Assumed units are flagged with `retentionUnitAssumed`.
- **A4 — Python taint analysis:** PII-named parameters, attributes (`payload.ssn`), and dict keys (`row["email"]`) seed taint. Taint propagates through assignments to a fixpoint and is checked at every log sink (`logger.*`, `logging.*`, `print`, …). Sanitizer calls (`redact*`, `mask*`, `hash*`, `hmac*`, …) stop it. `x = payload.ssn; logger.info(x)` is now caught, and `email_count=` is no longer a false positive.
- **A2 — TypeScript constant folding:** arithmetic, parentheses, unary minus, `as const`, `satisfies`, template literals, and references to earlier constants are evaluated. Confidence values written as percentages (`85`) are normalised.
- **A1 — per-instance findings:** the analyzer emits one finding per table, endpoint, leaking log call, retention constant, AI engine, and egress region, each with exact edit anchors (UTF-safe columns).
- **V2, V3, V4, V6, V7, V8 — prover rewrite** (`server/prover/z3Engine.ts`):
  - **Real unsat cores (V2):** this `z3-solver` build has no `assertAndTrack`, so the previous "unsat cores" were the hand-written fallbacks. Assertions are now guarded by assumption literals and checked with `check(...assumptions)`, so cores come from Z3.
  - **Every instance checked (V8):** each invariant of each construct instance is re-checked under its own assumption subset, so every violating table, endpoint, cache, AI engine, foreign key, or egress region is reported.
  - **Missing constructs (V7):** an absent construct is now "not applicable" (and flagged for review where relevant), never a default violation. This also fixes the BYOC phantom-table false positives (B1).
  - **Unknown and timeouts (V7):** `unknown` → `UNKNOWN_NEEDS_REVIEW` with Z3's reason, and the solver has a 10 s timeout.
  - **Cross-border in Z3 (V6):** region membership is decided by Z3 over an enumerated region universe, using the clause's own allowed regions.
  - **Executed formula shown (V4):** `smtLib2Executed` is the solver's actual assertion set plus `check-sat-assuming`, and the hash is taken over that.
  - **Review reasons:** default bounds, LLM-extracted bounds, ambiguous durations, negations, illustrative clauses, and vacuous results are listed on each proof.
  - **Shared context and Merkle tree (P3, C2):** one shared Z3 context is used and solvers are released. The proof hashes now form a real binary SHA-256 Merkle tree.
- **L1, L5, L2 — compiler** (`server/compiler/legalCompiler.ts`):
  - **Strictest duration:** every duration in the clause is found, and the strictest (shortest) one is used. "90 days … within 3 days" → 72 h, with a review note.
  - **Number words:** "seventy-two hours" → 72 h, and "one week" → 168 h.
  - **Negation:** "need not use tenant-isolated keys" no longer requires them, and "logging is permitted" no longer compiles a ban.
  - **Strictest confidence gate:** when several confidence values appear, the highest is used.
  - **LLM fallback validation:** the LLM only fills a missing numeric bound, values are range-checked (85 → 0.85), and it never overrides booleans or regions.
- **R1, R2, R5 — remediation** (`server/remediation/prSynthesizer.ts`):
  - **Anchor edits:** an anchor-based edit engine rewrites only the exact source spans, applied back to front.
  - **Repair loop:** up to 4 rounds driven by the Z3 repair targets; when clauses disagree, the strictest value wins.
  - **New edit types:** it can add retention or KMS columns, mark column encryption, add `ON DELETE CASCADE`, rewrite shared-key encrypt calls with the in-scope tenant id, wrap leaked PII arguments in `redact_pii(...)`, raise confidence gates (fraction or percent), flip flags, and pin regions.
  - **Syntax check:** every patched file is re-parsed (Python `ast`, TypeScript parser, SQL tokenizer), and a failure blocks the PR.
  - **Safe helpers (R2):** `redact_pii` is a keyed HMAC (`PII_REDACTION_KEY`), and `encrypt_with_tenant_kms` fails closed until `TENANT_KMS_CLIENT` is configured (no plaintext prefix).
- **AI5 — LLM availability:** `runRealLlmInference` reports `available: false` with zero counts when no model answers, instead of fabricated throughput.
- **A5 — any repository** (`server/analyzer/repoBaseline.ts`): `LEXCOMPILER_TARGET_REPO` points the scanner at any directory, and every `.py`/`.ts`/`.sql` file is scanned. A real repository is never reset, never gets a sandbox Git history, and never has its `.git` touched.
- **T3, T4 — tests and CLIs on scratch copies:**
  - **Scratch copies:** tests (`vitest.config.ts` + `server/test-setup.ts`) and both CLIs run on a scratch copy of the fixture, so `target-repo/` is never modified (`--in-place` opts out).
  - **`verify:cli` is a real gate:** on a real repository it exits 1 when any clause is not SAT. On the fixture it asserts detection plus remediation.
  - **`verify:realworld` asserts every stage** and exits 1 on failure.

---

## Part 2 — To Complete in a Local Environment

| # | Item | Why it couldn't be finished here | What remains |
| :-- | :--- | :--- | :--- |
| L-1 | **OPA Rego evaluation (V5)** | No OPA binary or Rego WASM in this environment | Install `opa` (v1.x), migrate the generated Rego to v1 syntax (`deny contains msg if { ... }`), evaluate it with `opa eval` (or compile to WASM and use `@open-policy-agent/opa-wasm`) against the analyzer facts, and fill `opaRegoTriggeredDenials` from real OPA output. |
| L-2 | **6-agent crew (AI1)** — CrewAI, DSPy, Hermes, LangGraph, Pydantic-AI, OpenAI Swarm with Claude / DeepSeek / GPT-4o / Gemini / Llama / Qwen | Needs provider API keys, Python agent frameworks, and local GGUF models | Implement each agent as a real service calling its MCP server, record measured tokens and latencies, and replace the static `buildMultiAgentExecutionReport` trace with the real run log. |
| L-3 | **pgvector + Neo4j Graph RAG (AI2)** | No PostgreSQL/pgvector or Neo4j service | Run Postgres with pgvector (HNSW, 384-d) and Neo4j, index chunks with real `all-minilm` embeddings for retrieval (not only re-ranking), and run the 2-hop Cypher traversal shown in the UI. |
| L-4 | **RAGAS evaluation (AI3)** | Needs an evaluation dataset and a judge LLM | Build a labelled question set over the fixture, run RAGAS (faithfulness, context precision/recall, answer relevance) with a judge model, and replace the constants with measured scores. |
| L-5 | **Token-optimisation benchmark (AI4)** — LLMLingua-2, semantic dedup, KV-cache pinning | Needs a tokenizer, the LLMLingua-2 model, and provider cache telemetry | Count tokens with the target model's tokenizer, run LLMLingua-2 compression, deduplicate by real embedding cosine similarity, read cache-hit tokens from provider usage fields, and drop the ×4 baseline and fixed ratios. |
| L-6 | **Ollama models** (`qwen2.5-coder:0.5b`, `dolphin3`, `all-minilm`) | No Ollama daemon here | Run `ollama serve` and pull the models; the LLM fallback, embeddings, and multi-model pipeline then use them (`available: true`). |
| L-7 | **GitHub pull requests (R4)** | No GitHub credentials for a target repository | Use `GITHUB_TOKEN` to push the remediation branch (`branchName`) and open a real PR via the GitHub API, then store the real PR number in `prNumber` (currently 0 for local bundles). |
| L-8 | **Hardware-backed signing (C1)** | No KMS/HSM available | Load the Ed25519 key from AWS KMS / Cloud KMS / an HSM (or at minimum a mounted key file), publish the public key, and add timestamping (RFC 3161) and revocation. |
| L-9 | **Isolated runtime sandbox (S2, X1)** | Containers can't be launched from this session | Run the target-app execution in an unprivileged container (or gVisor/nsjail/Firecracker) with no network, and execute the TypeScript services for real (transpile + run) instead of re-implementing them in Python. |
| L-10 | **Real PostgreSQL execution (X2)** | No PostgreSQL server | Execute `schema/*.sql` on a disposable PostgreSQL instance instead of SQLite, and run FastAPI/Pydantic/Redis for real instead of shims and mocks. |
| L-11 | **Tree-sitter queries (L3)** | Native Tree-sitter grammars can't be installed here | Add `tree-sitter` with the Python/TypeScript/SQL grammars and execute the generated `astPatternQuery` strings. |
| L-12 | **External MCP servers** (postgres-pgvector, neo4j-cypher, github, filesystem, duckdb, n8n) | The services aren't available here | Run and wire each server, then list them as integrated once they answer `initialize`. |
| L-13 | **EUR-Lex SPARQL ingestion** | The EUR-Lex SPARQL endpoint isn't reachable from this session | Query the CELLAR SPARQL endpoint for amendments to the tracked CELEX numbers and replace the curated excerpts with official text. |
| L-14 | **Docker Ollama service & image check (D1)** | Docker isn't available in this session | Run `docker compose up --build`, enable the Ollama service, and confirm that the health check and non-root image work. |
