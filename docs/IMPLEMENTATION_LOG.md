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

### Step 3 · MCP protocol compliance and persisted clause state
- **M1 — spec-compliant JSON-RPC** (`server/mcp/mcpSuite.ts`, `handleMcpMessage`) shared by Streamable HTTP and stdio:
  - **Methods:** `initialize` negotiates the protocol version (`2025-06-18`, `2025-03-26`), plus `ping`, `tools/list`, `tools/call`, `resources/list`, and `resources/read`.
  - **Notifications** get no response.
  - **Errors:** `-32600` invalid request, `-32601` unknown method, `-32602` unknown tool or invalid arguments (validated against each tool's `inputSchema`), `-32700` parse error (stdio).
  - **Results:** tool failures come back in-band as `isError: true`, results carry `structuredContent`, and request ids are echoed.
- **HTTP transport:** `POST /api/mcp/:id/rpc` is the Streamable HTTP endpoint (notifications get `202`). `GET` returns `405` because no server-initiated SSE stream is offered. `POST /api/mcp/:id/invoke` returns the request/response trace the UI shows.
- **stdio transport:** processes messages in order.
- **M2, P1 — shared, persistent clauses** (`server/state.ts`): active clauses persist to `data/active-clauses.json`, so they survive restarts and the stdio server uses the same amended clauses as the HTTP server.
- **L2 — category inference:** clauses created through `POST /api/clauses/compile` without a category now have it inferred from the text.
- **Tests:** `server/mcp.test.ts` covers version negotiation, notifications, error codes, tools, resources, and stdio ordering.

### Step 4 · Attestation, repository identity, SARIF, side-effect-free reads
- **C1 — persistent signing key** (`server/enterprise/signingKey.ts`): the key comes from `LEXCOMPILER_SIGNING_KEY_PEM`, else `LEXCOMPILER_SIGNING_KEY_PATH`, else `data/ed25519-signing-key.pem` (created with mode 0600). Certificates stay verifiable across restarts. `GET /api/enterprise/public-key` publishes the key and its fingerprint.
- **S4 — trusted key only:** signature verification trusts only the server's key. A caller-supplied public key that differs is rejected as `UNTRUSTED KEY`.
- **C2 — real repository identity:** `commitHash`, branch, and repository name come from Git (read-only), using the sandbox history for the fixture or the repository's own `.git` (`-dirty` when there are uncommitted changes). Without Git, a `content-<hash>` fallback is used.
- **C3 — SARIF:** `semanticVersion` casing is fixed, `originalUriBaseIds` is declared, artifact URIs are relative to the uploading checkout, and `versionControlProvenance` is emitted only with a real remote URL.
- **P2 — side-effect-free reads:** `GET` endpoints no longer append to the SQLite audit ledger; only state-changing requests record a scan.
- **Tests:** `server/attestation.test.ts` covers key persistence and permissions, tamper detection, untrusted-key rejection, the Merkle tree, and SARIF shape.

### Step 5 · AI subsystems now compute their numbers
- **AI4 — token benchmark** (`server/optimization/tokenOptimizer.ts`):
  - **Real tokenizer:** every stage is measured with the o200k BPE tokenizer (`gpt-tokenizer`, pinned 4.0.0).
  - **Baseline:** the static SMT/Rego ontology plus full clause text plus full source files. The ×4 inflation and fixed ratios are gone.
  - **Codeburn** now keeps Python indentation.
  - **Dedup** removes segments with word-trigram Jaccard ≥ 0.8.
  - **Cache stage** bills the measured static prefix at `LEXCOMPILER_CACHE_READ_MULTIPLIER`.
  - **Cost and latency** come from `LEXCOMPILER_INPUT_PRICE_PER_MTOK_USD` and `LEXCOMPILER_PREFILL_TOKENS_PER_SEC`.
  - On the fixture this measures 3417 → 989 tokens (71.1%).
- **AI2 — retrieval** (`server/rag/hybridRagEngine.ts`):
  - **Vectors:** 384-d feature-hashed embeddings (unigrams, bigrams, domain concepts) replace the 16-keyword bag.
  - **BM25** uses correct token-set document frequencies, normalised.
  - **Graph:** real 2-hop traversal of the statute ↔ code knowledge graph from entities named in the query.
  - **Fusion:** real reciprocal rank fusion (k = 60).
  - **HyDE** is built from the compiled clause for the query's inferred category.
  - **With Ollama `all-minilm`:** every chunk is embedded and drives dense ranking (not only re-ranking the top results).
- **AI3 — retrieval metrics:** context precision (AP@k), context recall, faithfulness (answer claims found in the retrieved context), answer relevance, and deontic alignment are computed against category-derived relevance labels, and `evaluationMethod` says so.
- **AI1 — agent pipeline** (`server/agents/multiAgentOrchestrator.ts`): the six-agent report now runs each agent's MCP tool through the JSON-RPC handler. It records measured latency, real token counts of raw and optimized inputs and of the output, `COMPLETED`/`FAILED` status, and a summary built from the tool's result.
- **Tests:** RAG, token, and agent assertions now check computed behaviour instead of constants.

### Step 6 · Runtime, operations, CI
- **S6, P2 — no blocking subprocesses:**
  - **Ledger:** the SQLite ledger runs in-process via Node's built-in `node:sqlite` (no Python subprocess per read or write).
  - **Embeddings:** neural embeddings persist in `neural_vector_store` and are reused across restarts.
  - **Python parsing:** files are parsed concurrently in child processes (`analyzeFullRepositoryAsync`) before analysis, so request handlers no longer block on `python3`.
  - **Sandbox:** the runtime sandbox runs its Python asynchronously.
- **P1 — serialized mutations:** state-changing endpoints (clause edits, presets, locale, apply PR/node, file updates, reset) run one at a time, so file writes and Git commits cannot interleave.
- **D2 — real health check:** `/api/health` runs a Z3 self-test, a `python3` probe, a ledger check, and an MCP ping. It returns `503` when degraded.
- **D1 — production build and Docker:**
  - **Compiled server:** `npm run build` compiles the server to `dist-server/`, and `npm start` runs it with plain Node (`npm run start:tsx` keeps the tsx path).
  - **Image:** the Dockerfile is a multi-stage build with `npm ci --omit=dev`, runs as the non-root `node` user, and keeps a `/app/data` volume.
  - **Compose:** adds the data volume and an optional `ollama` service (`--profile ollama`).
- **T2, T3, C3 — CI** (`.github/workflows/lexcompiler-gate.yml`):
  - **Checks:** `npm ci`, typecheck (client + server), ESLint (`eslint.config.js`, typescript-eslint, react-hooks), tests, the `verify:cli` gate, `verify:realworld`, and the build.
  - **SARIF:** exported via `npm run sarif` and uploaded as a build artifact.
  - **Lint cleanup:** 55 unused imports/variables were removed.

### Step 7 · Real TypeScript execution, GitHub pull requests, UI
- **X1 — real TypeScript execution:**
  - **What runs:** the runtime sandbox now transpiles the TypeScript services with the TypeScript compiler and executes them in a separate Node process under the permission model (`--permission`, read access to the scratch copy only, no child processes). The Python regex re-implementation is gone.
  - **Policy:** violations are judged against the active clauses' confidence gate and allowed regions.
  - **Checks:** `verify:realworld` asserts the AI and replication behaviour before and after remediation.
- **R4 — GitHub pull requests** (`server/remediation/githubPr.ts`):
  - **Flow:** with `LEXCOMPILER_GITHUB_TOKEN` + `LEXCOMPILER_GITHUB_REPO` (optional `LEXCOMPILER_GITHUB_BASE`, `LEXCOMPILER_GITHUB_PATH_PREFIX`), `POST /api/remediation/open-github-pr` creates the remediation branch, commits each patched file through the REST API, and opens a pull request with the Z3 summary.
  - **Gate:** it refuses anything not `READY_TO_MERGE`.
  - **UI:** an "Open GitHub PR" button appears when the integration is configured.
  - **Tests:** `server/githubPr.test.ts` covers the call sequence against a mocked GitHub.
- **UI:** local bundles show their bundle id (`PR-LEX-…`) instead of a fabricated PR number, and static "PR #409" labels were removed.

### Step 8 · OPA Rego evaluation, prover fix, regression tests
- **V5 — real OPA evaluation:**
  - **Policies:** generated policies are Rego v1 (`import rego.v1`, `deny contains msg if`), built from the compiled bounds by `server/policy/regoPolicies.ts`, and iterate over every construct instance.
  - **Evaluation:** `server/policy/opaEvaluator.ts` builds the input document from the analyzer facts and runs `opa eval` whenever an `opa` binary is available (`LEXCOMPILER_OPA_BIN` or PATH). `opaRegoTriggeredDenials` then holds OPA's own output (`policyDenialSource: 'opa'`); without OPA they are derived from Z3 (`'z3-derived'`).
  - **Where OPA comes from:** CI installs OPA 1.4.2 (`open-policy-agent/setup-opa`), and the Docker image copies `opa` from the official `openpolicyagent/opa:1.4.2-static` image.
- **Prover fix:** an assumption literal could share its name with a law variable (e.g. `law_requires_tenant_kms`), which wrongly refuted any clause whose boolean law value was `false`. Law values now use a `__value` suffix. This was found by the new BYOC regression test.
- **A4 — taint origin:** leaked fields report the original PII field even through aliases (`x = payload.ssn` → `ssn`).
- **T1 — regression tests:**
  - **`server/analysis.test.ts`:** the compiler (strictest duration, number words, negation, LLM validation), the analyzer (constant folding, TTL units, taint through aliases, false-positive avoidance, multi-line SQL / constraints / ALTER TABLE), the prover (every instance reported, missing constructs not applicable, executed SMT), BYOC, and remediation (edit engine, user code kept, safe helpers).
  - **`server/opa.test.ts`:** OPA agreement with Z3 before and after remediation; it runs wherever OPA is installed (CI).

### Step 9 · Real Tree-sitter structural queries (L3)
- **Queries:** `astPatternQuery` is no longer pseudo-syntax. `server/analyzer/treeSitter.ts` generates real Tree-sitter S-expression queries per rule category, with one section per grammar (`;; @language python|typescript`), using grouped `#match?` predicates.
- **Execution:** the queries run with the WebAssembly Python and TypeScript grammars from `@vscode/tree-sitter-wasm@0.3.1`, so no native build is needed. Each match reports its file, line, and named captures.
- **Where they run:** the full scan report (`structuralQueryMatches`, per clause) and the AST MCP tool.
- **Test:** `server/analysis.test.ts` checks that each clause's query finds the construct it constrains in the fixture (the Redis TTL, the logger calls, the confidence threshold, and the egress region).

---

## Part 2 — To Complete in a Local Environment

| # | Item | Why it couldn't be finished here | What remains |
| :-- | :--- | :--- | :--- |
| L-1 | **OPA Rego evaluation (V5)** | Running a downloaded OPA binary was not permitted in this session | Implemented (Step 8): Rego v1 policies, the `opa eval` integration, OPA in CI and Docker. Remaining: run `npm test` locally with `opa` on PATH (or check the CI run) to confirm `server/opa.test.ts` passes against real OPA. |
| L-2 | **6-agent crew (AI1)** — CrewAI, DSPy, Hermes, LangGraph, Pydantic-AI, OpenAI Swarm with Claude / DeepSeek / GPT-4o / Gemini / Llama / Qwen | Needs provider API keys, Python agent frameworks, and local GGUF models | Each agent already calls its real MCP tool with measured latency and tokens (Step 5). Remaining: put the named framework and LLM in front of each tool call (agent reasoning, tool selection, structured outputs). |
| L-3 | **pgvector + Neo4j Graph RAG (AI2)** | No PostgreSQL/pgvector or Neo4j service | Retrieval, 2-hop traversal, and neural dense ranking now run in memory (Step 5). Remaining: persist chunk vectors in pgvector (HNSW, 384-d), store the knowledge graph in Neo4j, and run the traversal as Cypher. Add a BGE cross-encoder reranker. |
| L-4 | **RAGAS evaluation (AI3)** | Needs an evaluation dataset and a judge LLM | Metrics are now computed against category-derived labels (Step 5). Remaining: a hand-labelled question set and RAGAS with a judge LLM. |
| L-5 | **Token-optimisation benchmark (AI4)** — LLMLingua-2, semantic dedup, KV-cache pinning | Needs the LLMLingua-2 model and provider cache telemetry | Real tokenizer and measured stages are done (Step 5). Remaining: run LLMLingua-2 compression, dedup by neural embedding cosine similarity, and read cache-hit tokens from provider usage fields. |
| L-6 | **Ollama models** (`qwen2.5-coder:0.5b`, `dolphin3`, `all-minilm`) | No Ollama daemon here | Run `ollama serve` and pull the models; the LLM fallback, embeddings, and multi-model pipeline then use them (`available: true`). |
| L-7 | **GitHub pull requests (R4)** | No GitHub credentials for a target repository | Implemented and tested against a mocked API (Step 7). Remaining: set `LEXCOMPILER_GITHUB_TOKEN` / `LEXCOMPILER_GITHUB_REPO`, open one real PR end to end, and optionally persist the returned PR number. |
| L-8 | **Hardware-backed signing (C1)** | No KMS/HSM available | The key now persists in a file or an env PEM and is published (Step 4). Remaining: keep the Ed25519 key in AWS KMS / Cloud KMS / an HSM, and add RFC 3161 timestamping and revocation. |
| L-9 | **Isolated runtime sandbox (S2, X1)** | Containers can't be launched from this session | TypeScript now runs for real under Node's permission model, and Python under rlimits (Steps 1, 7). Remaining: run both in an unprivileged container (or gVisor/nsjail/Firecracker) with no network access. |
| L-10 | **Real PostgreSQL execution (X2)** | No PostgreSQL server | Execute `schema/*.sql` on a disposable PostgreSQL instance instead of SQLite, and run FastAPI/Pydantic/Redis for real instead of shims and mocks. |
| L-11 | **Tree-sitter queries (L3)** | The WASM grammar bundle has no SQL grammar | Python and TypeScript queries now run for real (Step 9). Remaining: add a SQL grammar (e.g. `tree-sitter-sql` built to WASM) and run DDL queries over `schema/*.sql` instead of matching embedded `CREATE TABLE` strings. |
| L-12 | **External MCP servers** (postgres-pgvector, neo4j-cypher, github, filesystem, duckdb, n8n) | The services aren't available here | Run and wire each server, then list them as integrated once they answer `initialize`. |
| L-15 | **GitHub code-scanning upload** | Enabling code scanning is a repository setting | CI already produces `lexcompiler.sarif`. Enable code scanning, add `security-events: write`, and add `github/codeql-action/upload-sarif` for scans of real repositories (not the intentionally non-compliant fixture). |
| L-13 | **EUR-Lex SPARQL ingestion** | The EUR-Lex SPARQL endpoint isn't reachable from this session | Query the CELLAR SPARQL endpoint for amendments to the tracked CELEX numbers and replace the curated excerpts with official text. |
| L-14 | **Docker image verification (D1)** | Docker isn't available in this session | The Dockerfile and compose file are written (Step 6). Remaining: run `LEXCOMPILER_API_TOKEN=… docker compose --profile ollama up --build`, pull the models, and confirm the health check and the non-root image. |
