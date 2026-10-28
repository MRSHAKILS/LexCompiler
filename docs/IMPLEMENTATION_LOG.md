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

### Step 10 · Documentation and licensing
- **README:** new sections cover the developer scripts, scanning your own repository (`LEXCOMPILER_TARGET_REPO`), OPA, Tree-sitter queries, GitHub pull requests, and a full configuration reference. The API table now lists `open-github-pr` and `verify-signature`, and the certificate row reflects the persistent key.
- **`.env.example`:** lists every new environment variable.
- **`LICENSE`:** MIT, matching the README; `package.json` declares `"license": "MIT"`.

### Step 11 · Server-side cloud key, limitations status
- **S5:** cloud mode now prefers the server's `OPENAI_API_KEY`, so the browser never has to send a key. The console offers a "Cloud: OpenAI (server OPENAI_API_KEY)" option; a key typed in the UI is still accepted over the authenticated API.
- **`docs/LIMITATIONS_REPORT.md`:** a new §0 records the status of every finding on this branch, with the step that addressed it or the Part 2 item that completes it.

### Step 12 · PostgreSQL, real FastAPI / Pydantic / Redis in the sandbox (L-10)
- **PostgreSQL:** `server/sandbox/postgresSandbox.ts` executes `schema/postgres_pii.sql` on PostgreSQL 18 (PGlite, in-process WASM build of PostgreSQL), or on a real server when `LEXCOMPILER_POSTGRES_URL` is set (inside a throwaway schema). SQLite is gone from the sandbox.
- **Behaviour exercised on PostgreSQL:**
  - columns and defaults read from `information_schema`;
  - a sample record inserted;
  - the retention purge (`DELETE … WHERE created_at < now() - retention_ttl_hours * interval '1 hour'`) removes an expired record;
  - Art. 17 erasure checks that deleting a patient removes every dependent row, or reports the foreign-key error.
- **Remediation gate:** a patched SQL file must also execute on PostgreSQL.
- **Python frameworks:** `npm run setup:sandbox` creates `.venv` with the pinned packages in `requirements-sandbox.txt`.
  - **FastAPI and Pydantic:** the intake endpoint is called over HTTP (httpx ASGI transport), so routing, Pydantic validation and header binding are real.
  - **Redis:** the worker writes to fakeredis, or to a real server via `LEXCOMPILER_REDIS_URL`, and the stored TTL is read back from Redis.
  - **Fallback:** without `.venv`, shims are used, and the report says so.
- **CI and Docker:** CI runs `npm run setup:sandbox`, and the Docker image builds the same `.venv`. A `.dockerignore` keeps local artefacts out of the build context.
- **Tests:** `server/postgres.test.ts` covers the schema run, the retention purge, the erasure cascade, a RESTRICT foreign key, and invalid DDL. `verify:realworld` gained PostgreSQL, HTTP and Redis TTL checks.

### Step 13 · pgvector, Neo4j Graph RAG, cross-encoder reranking (L-3)
- **pgvector:** `server/rag/vectorStore.ts` keeps chunk vectors in PostgreSQL with pgvector 0.8 and an HNSW cosine index.
  - **Where:** PGlite persisted in `data/pgvector`, or a PostgreSQL server via `LEXCOMPILER_PGVECTOR_URL`.
  - **Separation:** each embedding model gets its own table (feature hashing and `all-minilm` vectors are never mixed).
  - **Sync:** rows are synced by content hash; changed chunks are re-embedded, and removed ones are deleted.
  - **Search:** runs through the index, with `hnsw.ef_search` widened to cover `k`.
  - **Concurrency:** a pid lock stops two processes opening the same PGlite directory; a second process uses an in-memory database.
- **Neo4j:** `server/rag/graphStore.ts` loads the statute ↔ code entity graph into Neo4j (`LEXCOMPILER_NEO4J_URL`, `_USER`, `_PASSWORD`, `_DATABASE`). The 2-hop traversal runs as Cypher (`MATCH p = (s)-[:LEX_REL*0..2]-(m) RETURN m.key, min(length(p))`). Without Neo4j, an in-memory graph applies the same semantics.
- **Reranker:** `server/rag/reranker.ts` runs a BGE cross-encoder (`LEXCOMPILER_RERANKER_MODEL`, e.g. `Xenova/bge-reranker-base`, through transformers.js). When it is enabled, it reorders the fused top 2 × k candidates.
- **Wiring:** `/api/rag/query`, the AI overview and the MCP RAG tool use the store-backed pipeline. `vectorDbBackend` and `graphDbBackend` report the backend that actually served the query.
- **Tests:** `server/rag.test.ts` covers the pgvector ordering, refreshes and deletions, more than 40 results, and dimension checks. It also proves that the store-backed pipeline (pgvector plus the Cypher graph store) ranks exactly as the in-process pipeline does, and that a cross-encoder decides the final order.

### Step 14 · Tree-sitter SQL grammar (L-11)
- **Grammar:** `server/analyzer/grammars/tree-sitter-sql.wasm` is built from the C sources of `@derekstride/tree-sitter-sql@0.3.11` with clang (wasm32) and wasm-ld, as a position-independent side module.
  - **Rebuild:** `npm run build:sql-grammar` reproduces the file byte for byte (sha256 `3a9005e3…220d`).
  - **What the build runs:** it only uses `npm pack --ignore-scripts`, so nothing from the package is executed. The libc functions the grammar calls are imported from the Tree-sitter runtime.
- **Queries:** SQL sections (`;; @language sql`) now run over `schema/*.sql`:
  - retention columns and their defaults;
  - PII and key columns per table, for encryption at rest;
  - `REFERENCES … ON DELETE <action>` foreign keys, for erasure cascades.
- **Build:** `npm run build` copies the grammar into `dist-server`.
- **Test:** `server/analysis.test.ts` checks the retention default (720), the PII columns, and the `patient_id → patient_records ON DELETE CASCADE` foreign key.

### Step 15 · Five new rule categories (L-17)
- **New categories:**
  - `CONSENT_LAWFUL_BASIS` (GDPR Art. 6–7)
  - `BREACH_NOTIFICATION` (Art. 33)
  - `DPIA_REQUIRED` (Art. 35)
  - `DATA_MINIMISATION` (Art. 5(1)(c))
  - `PURPOSE_LIMITATION` (Art. 5(1)(b))
- **End to end:** each category has category inference, bound extraction, a compiled deontic / FOL / SMT summary, a Rego v1 policy (with OPA input), a Tree-sitter query, per-instance Z3 invariants with unsat cores, and remediation:
  - **Consent:** the Python AST now records each function's calls and annotated arguments. A handler that takes PII or a PII model must call a consent / lawful-basis check. Remediation inserts `require_consent(<subject>)` plus a fail-closed helper that raises until `CONSENT_REGISTRY` is configured.
  - **Breach notification:** module constants such as `BREACH_NOTIFICATION_WINDOW_DAYS` are converted to hours and checked against the limit (48h is extracted from "within 48 hours"; the default is 72h). A repository that processes PII with no deadline at all is a violation. Remediation tightens the constant or adds `BREACH_NOTIFICATION_DEADLINE_HOURS`.
  - **DPIA:** automated decision-making needs a `DPIA_REFERENCE` that points at a file in the repository. A DPIA is a document, so it is reported but never generated; the remediation stays unresolved.
  - **Data minimisation:** fields of a Pydantic model that are PII but never read in the module (and not serialised wholesale) are violations, and remediation removes them. The fixture's `full_name` is one.
  - **Purpose limitation:** each PII handler needs a declared `PROCESSING_PURPOSE`, and it must be one of the permitted purposes. Z3 checks this over an enumerated universe, as for regions. Remediation applies only when the law permits exactly one purpose; otherwise it needs a decision.
- **Remediation engine:** identical edits from several findings in one file (for example the same helper) are applied once.
- **Tests:** `server/governance.test.ts` (9 tests) covers inference, extraction, facts, the OPA input, and refute → remediate → `SAT_COMPLIANT` for four categories. It also checks the breach deadline being tightened, the fail-closed consent check, and that a DPIA is satisfied only by a referenced file that exists.

### Step 16 · Symbolic program semantics and inter-procedural taint (L-16)
- **Symbolic execution:** the analyzer symbolically executes the functions behind logging sinks, PII handlers, AI decisions and egress. This uses the TypeScript compiler AST (`server/analyzer/symbolicTs.ts`) and the Python `ast` script.
  - Module constants are folded, and parameters and their fields are free symbols.
  - `if` and `?:` split paths, and each path records its condition, returned fields, and the ordered calls it makes (with the PII each receives).
  - Anything outside the modelled subset is left unconstrained and listed as an approximation, so a proof is never claimed over code that was skipped.
- **Prover:** `server/prover/behaviour.ts` translates the paths to Z3 (reals, booleans, strings as an enumerated table) and asks for a violating input. A `sat` answer comes with a counterexample from the model; `unsat` is a proof over every input. The verdict enters the clause proof as a fact, so unsat cores name it.
  - **AI decisions:** is any input with confidence below the legal minimum decided autonomously? Compliant constants no longer hide hard-coded autonomous branches (for example `requestedCreditLimit < 1000`).
  - **Egress:** does any input select a region outside the allowed set? A data-dependent region is refuted with the input that selects it (`event.tenantId = "tenant-us-01"`).
  - **PII logging:** a leaking log call on a branch no input can reach (`if DEBUG_PII:` with `DEBUG_PII = False`) is not a violation.
  - **Consent:** a check is required on every path. A check on only some paths is refuted with the path condition (`x_tenant_id = "internal"`).
- **Inter-procedural taint:** a module function whose parameter reaches a log sink (directly, through local aliases, or through another such function, to a fixpoint) is treated as a sink. A call that passes PII into it is reported at the call site, and remediation wraps the argument (`audit(redact_pii(payload.email))`).
- **Note:** the OPA policies evaluate the extracted facts; the Z3 proof additionally applies the path-sensitive verdicts.
- **Tests:** `server/symbolic.test.ts` (7 tests).

### Step 17 · OIDC sign-in, roles, and projects (L-18)
- **OIDC:** `server/auth/oidc.ts` is an OpenID Connect relying party.
  - **Browser sign-in:** the authorization-code flow with PKCE (S256), plus single-use state and a nonce. It opens server-side sessions in an HttpOnly, SameSite=Lax cookie, which is Secure behind https.
  - **API clients:** bearer JWTs are verified against the issuer's JWKS (signature, `iss`, `aud`, `exp`).
  - **Roles:** a roles claim (`LEXCOMPILER_OIDC_ROLES_CLAIM`) maps `LEXCOMPILER_OIDC_ADMIN_ROLE` to the global admin role.
  - **Endpoints:** `/api/auth/config`, `/login`, `/callback`, `/logout`, `/me`.
- **Guard:** with OIDC configured, every `/api` route needs a session, an OIDC bearer, or the API token.
  - Cookie sessions also need the client header on writes (CSRF).
  - The single-repository endpoints act on the `default` project with `LEXCOMPILER_DEFAULT_PROJECT_ROLE` (viewer by default; writes need editor or admin).
  - A non-loopback bind is allowed with OIDC alone.
  - Loopback and API-token behaviour are unchanged.
- **Projects:** `server/projects/` keeps a project registry with members and roles (viewer < editor < owner; admins act as owners). Each project has its own repository, clauses, and scan ledger (`scans.jsonl`), and projects are invisible to non-members.
  - Repository paths must lie inside `LEXCOMPILER_PROJECT_REPOS_ROOT`.
  - The last owner cannot be removed.
  - **API:** `GET/POST /api/projects`, `GET/DELETE /api/projects/:id`, `PUT /api/projects/:id/members`, `GET/POST/DELETE /api/projects/:id/clauses`, `POST /api/projects/:id/scan`, `GET /api/projects/:id/scans`.
- **UI:** a 401 that carries a `loginUrl` sends the browser to sign-in, and requests carry the session cookie.
- **Tests:** `server/access.test.ts` runs a real local OpenID provider (discovery, JWKS, a PKCE-checking token endpoint, RS256 tokens) and checks:
  - forged and wrong-audience tokens are rejected;
  - the full code flow works, and its state is single-use;
  - the CSRF header is enforced;
  - default-project roles apply;
  - membership isolates projects, and roles are enforced;
  - repository paths cannot escape the projects root;
  - per-project clause compilation, scans and the ledger work.

### Step 18 · KMS / HSM signing, key rotation, revocation, RFC 3161 timestamps (L-8)
- **Signers:** `server/enterprise/attestationSigner.ts` defines one signer interface with three backends, selected by `LEXCOMPILER_SIGNER`:
  - `local`: the Ed25519 key file, as before.
  - `gcp-kms`: Google Cloud KMS through `:asymmetricSign`. It supports `EC_SIGN_ED25519` and `EC_SIGN_P256_SHA256`, and the SOFTWARE or HSM protection level (Cloud HSM). The token comes from `LEXCOMPILER_GCP_ACCESS_TOKEN` or the metadata server.
  - `aws-kms`: AWS KMS through the SDK. It uses `ECC_NIST_P256` with `ECDSA_SHA_256`, and the keys never leave the KMS HSMs.
- **Certificates:** each one now carries a `keyId`, the signing backend, and the actual algorithm.
- **Rotation:** every key that has signed is recorded in `data/attestation-keys.json` and stays trusted for verification after rotation. Caller-supplied keys are still rejected.
- **Revocation:** `POST /api/enterprise/revoke` (admin only) adds a certificate id or key id to `data/revocations.json`, which `GET /api/enterprise/revocations` publishes. Verification fails for revoked certificates and for signatures by revoked keys.
- **RFC 3161:** `server/enterprise/timestamp.ts` builds SHA-256 TimeStampReqs (with a nonce and certReq) and posts them to `LEXCOMPILER_TSA_URL`. It verifies tokens with pkijs: the message imprint over the signature, and the CMS signature of the TSA (and its chain, when trusted certificates are given). Certificates embed the token, and `verify-signature` checks it.
- **Tests:** `server/signing.test.ts` covers:
  - a fake Cloud KMS (Ed25519 and P-256, HSM) and a fake AWS KMS client, both backed by real keys;
  - rotation and revocation;
  - a fake TSA built with pkijs (self-signed RSA certificate, signed attributes): the token verifies, and is rejected for other data or after tampering.

### Step 19 · LLM agents, framework adapters, labelled RAG evaluation, model-based token stages (L-2, L-4, L-5)
- **L-2 · LLM agents (TypeScript):** `server/agents/llmClient.ts` speaks two protocols.
  - **OpenAI-compatible:** OpenAI, DeepSeek, Gemini's OpenAI endpoint, Groq/Together/vLLM for Llama, and Ollama `/v1`.
  - **Anthropic Messages:** the system prompt is prompt-cached.
  - **Usage:** both report provider usage, including cached prompt tokens.
  - **Agent loop:** `server/agents/agentRuntime.ts` gives the model the agent's MCP tools (from `tools/list`). Each tool call is executed through the real MCP handler, and the final answer is validated against a JSON schema, with one correction turn.
  - **Configuration:** each agent reads `LEXCOMPILER_AGENT_<ID>_MODEL`, `_PROVIDER`, `_BASE_URL` and `_API_KEY`, falling back to `LEXCOMPILER_LLM_*`.
  - **Orchestrator:** a configured agent runs as `LLM_AGENT` with measured usage; the rest stay `DIRECT_TOOL_CALL`.
- **L-2 · Python framework adapters (`agents/`):** each one drives LexCompiler's MCP servers over streamable HTTP.
  - **The six adapters:** Pydantic-AI (Z3 critic, typed output), LangGraph (RAG state machine: retrieve → CRAG grade → rewrite → answer), Hermes-style function calling on Ollama Qwen (AST mapper), CrewAI (horizon scanner), DSPy ReAct with a typed signature (deontic extractor), and the OpenAI Agents SDK, Swarm's successor, with a reviewer handoff (remediation).
  - **CLI:** `python -m lexcompiler_agents <agent-id>`.
  - **Tested:** pytest covers Pydantic-AI (`TestModel`), LangGraph, and Hermes (stub Ollama), and CI runs it. The LangGraph adapter was also run against a live server.
- **L-4 · Evaluation:** `server/rag/eval/dataset.json` holds 16 hand-labelled questions with graded relevance.
  - **Metrics:** `server/rag/evaluation.ts` computes P@k, R@k, MRR, nDCG@k and hit rate.
  - **Judge:** a RAGAS-style LLM judge scores faithfulness (supported claims ÷ claims) and answer relevancy.
  - **Running it:** `npm run eval:rag`. Measured on the fixture: MRR 0.656, nDCG@5 0.542, hit rate 0.938, now enforced as a regression floor.
- **L-5 · Token stages:**
  - **LLMLingua-2:** a Python sidecar (`agents/lexcompiler_agents/llmlingua_compress.py`, enabled by `LEXCOMPILER_LLMLINGUA_PYTHON`).
  - **Dedup:** by neural-embedding cosine (Ollama `all-minilm`).
  - **Cache hit rate:** measured from provider usage fields (`prompt_tokens_details.cached_tokens`, `prompt_cache_hit_tokens`, `cache_read_input_tokens`).
  - **Wiring:** the AI overview runs the async benchmark, and each stage names the technique that actually ran.
- **Tests:** `server/agents.test.ts`, `server/evaluation.test.ts`, `server/tokens.test.ts`, `agents/tests/`.

### Step 20 · External MCP servers, EUR-Lex SPARQL, code-scanning workflow (L-12, L-13, L-15)
- **L-12 · External MCP clients:** `server/mcp/externalClients.ts` is a real MCP client.
  - **Transports:** stdio (spawned process, newline-delimited JSON-RPC) and streamable HTTP (JSON or SSE replies, the `Mcp-Session-Id` header, `MCP-Protocol-Version`). Both perform the `initialize` / `notifications/initialized` handshake.
  - **Configuration:** servers come from `mcp-servers.json` in the standard `mcpServers` format (`LEXCOMPILER_EXTERNAL_MCP_CONFIG`), with `${VAR}` expanded from the environment. `mcp-servers.example.json` configures all six: postgres, neo4j-cypher, the GitHub MCP, filesystem, MotherDuck/DuckDB, and n8n.
  - **Status:** `/api/mcp/servers` reports each external server as `ONLINE` (it answered `initialize` and `tools/list`, with its live tools), `OFFLINE` (with the error), or `NOT_CONFIGURED`.
  - **Proxy:** `POST /api/mcp/external/:id/call` calls a tool on an external server.
- **L-13 · EUR-Lex:** `server/regulations/eurLex.ts` queries the CELLAR SPARQL endpoint for acts that amend or correct the tracked CELEX numbers (with an injection-safe query builder), and extracts official article text from EUR-Lex's HTML (`eli-subdivision` / `oj-*` markup). The live feed replaces each curated excerpt with the official text when the fetch succeeds (`illustrative: false`) and adds the amendment items. Unreachable sources leave the illustrative items marked as such.
- **L-15 · Code scanning:** `.github/workflows/lexcompiler-scan.yml` is a reusable workflow (`workflow_call` and `workflow_dispatch`) for real repositories. It proves the caller's clauses (`LEXCOMPILER_CLAUSES_FILE`), uploads SARIF to GitHub code scanning (`github/codeql-action/upload-sarif`, `security-events: write`), and then runs the gate. The CLIs gained `LEXCOMPILER_CLAUSES_FILE` and `LEXCOMPILER_SARIF_PATH_PREFIX`. The fixture gate in `lexcompiler-gate.yml` still uploads SARIF only as an artifact, because that repository is intentionally non-compliant.
- **Fix found by the real-repository smoke test:** "Personal data **may** be processed only with consent" was read as a waiver, because the generic negation detector treats "may" as permissive. Consent is now negated only by explicit waivers ("consent is not required", "need not obtain consent"). There is a regression test.
- **Tests:** `server/externalMcp.test.ts` covers stdio against a spawned MCP server, HTTP with SSE and sessions, ONLINE/OFFLINE probing, and env expansion. `server/eurLex.test.ts` covers the SPARQL query and parsing, article extraction, and feed replacement with fallback.

### Step 21 · Container-isolated runtime sandbox (L-9)
- **Container mode:** with `LEXCOMPILER_SANDBOX_CONTAINER=docker` (or `podman`), both sandbox runners execute inside `LEXCOMPILER_SANDBOX_IMAGE` (`Dockerfile.sandbox`: Node 22 with Python and the real sandbox frameworks, running as `nobody`). The Python runner (FastAPI / Pydantic / fakeredis) and the TypeScript runner (still under Node's permission model) both run there.
- **Restrictions:** the container gets:
  - `--network none` and `--read-only`;
  - a read-only mount of the scratch copy at `/work`;
  - `--cap-drop ALL` and `--security-opt no-new-privileges`;
  - pid, memory and CPU limits, and uid 65534;
  - optionally gVisor (`LEXCOMPILER_SANDBOX_OCI_RUNTIME=runsc`).
- **Reporting:** the report's `isolation` field states where the code ran.
- **Tests:** `server/container.test.ts` checks the flags, and runs the full sandbox through a fake container engine that records the invocation and maps `/work`, so the wiring is exercised end to end.

### Step 22 · Local verification on Windows; OPA against the real binary (L-1)
- **Machine:** Windows 11, Node 24.12, Python 3.12.10 (`python`; `python3` is the Microsoft Store stub), OPA 1.4.2 on `PATH`, Docker Desktop 29.6, Ollama 0.13.5.
- **Windows portability fixes** (no test was weakened; each now checks the same property on both platforms):
  - `server/util/python.ts` resolves a Python >= 3.10 (`LEXCOMPILER_PYTHON`, `python3`, `python`, `py -3`) for the analyzer, the sandbox and `/api/health`.
  - The generated signing key gets an owner-only ACL on Windows (`icacls`), where mode `0600` is ignored; the test checks the ACL there and the mode bits elsewhere.
  - The local sandbox applies its CPU, memory and no-child-process limits through a Windows Job Object, because `resource` is POSIX-only.
  - `container.test.ts` runs its fake engine as `node` with the script preloaded through `NODE_OPTIONS` (Windows cannot execute a `#!` script) and parses drive-letter mounts; `tokens.test.ts` uses the resolved Python.
  - `security.test.ts` checks the curated/offline feed with an offline `fetch`, so it no longer depends on EUR-Lex being unreachable from the test host (it failed on any machine with internet access).
- **L-1:** `server/opa.test.ts` no longer skips: both tests pass against OPA 1.4.2, and OPA's decisions agree with Z3 before and after remediation. All seven checks pass (97 tests).

### Step 23 · Local Ollama models (L-6)
- **Models:** `ollama pull` of `all-minilm`, `qwen2.5-coder:0.5b` and `dolphin3` on Ollama 0.13.5.
- **Checked through the app's own functions** (`server/services/realAiServiceMesh.ts`):
  - `getInstalledOllamaModels` lists all three.
  - `computeRealNeuralEmbedding` returns a 384-d `all-minilm:latest` vector (not `fallback-lexical`).
  - `runRealLlmInference` answers with `available: true` and provider `Ollama Local Sovereign Runtime (:11434)` for both `qwen2.5-coder:0.5b` and `dolphin3:latest`.
  - `getLiveServiceMeshTelemetry` reports the Ollama service `ONLINE` with the models and their roles.
- **Observed:** the very first embedding after a pull fell back to lexical because loading the model took longer than the 3.5 s timeout; later calls, including after `ollama stop`, load in about 1.3 s and succeed.

---

## Part 2 — To Complete in a Local Environment

| # | Item | Why it couldn't be finished here | What remains |
| :-- | :--- | :--- | :--- |
| L-1 | **OPA Rego evaluation (V5)** | Running a downloaded OPA binary was not permitted in this session | ✅ Done (Steps 8, 22): `server/opa.test.ts` passes against real OPA 1.4.2 locally. |
| L-2 | **6-agent crew (AI1)** | Needs provider API keys and local GGUF models | Implemented (Step 19). Remaining: set `LEXCOMPILER_LLM_*` / `LEXCOMPILER_AGENT_<ID>_*` (Claude, DeepSeek, GPT-4o, Gemini, Llama, Qwen) and run the pipeline. `pip install -r agents/requirements.txt`, then run `python -m lexcompiler_agents <agent-id>` for the CrewAI, DSPy and OpenAI Agents adapters (Pydantic-AI, LangGraph and Hermes are already tested). |
| L-3 | **pgvector + Neo4j Graph RAG (AI2)** | No Neo4j server, and Hugging Face downloads are blocked here | Implemented (Step 13). Remaining: (1) start Neo4j (`docker run -p 7687:7687 -e NEO4J_AUTH=neo4j/<password> neo4j:5`), set `LEXCOMPILER_NEO4J_URL=bolt://localhost:7687` and the password, and run a RAG query; `graphDbBackend` must read `Neo4j`. (2) Optionally point `LEXCOMPILER_PGVECTOR_URL` at a PostgreSQL server with pgvector. (3) `npm install @huggingface/transformers`, set `LEXCOMPILER_RERANKER_MODEL=Xenova/bge-reranker-base`, run a query, and confirm `evaluationMethod` names the reranker. |
| L-4 | **RAGAS evaluation (AI3)** | Needs a judge LLM | Labelled set, IR metrics and judge implemented (Step 19). Remaining: set `LEXCOMPILER_AGENT_RAG_JUDGE_MODEL` (or `LEXCOMPILER_LLM_*`) and run `npm run eval:rag`; optionally also run the Python `ragas` package on the same dataset. |
| L-5 | **Token-optimisation benchmark (AI4)** | Hugging Face downloads are blocked here | Implemented (Step 19). Remaining: `pip install llmlingua` (downloads the xlm-roberta model) and set `LEXCOMPILER_LLMLINGUA_PYTHON`. Run Ollama with `all-minilm` for neural dedup, and run an LLM agent so cache hits are measured. |
| L-6 | **Ollama models** (`qwen2.5-coder:0.5b`, `dolphin3`, `all-minilm`) | No Ollama daemon here | ✅ Done (Step 23): all three models pulled; embeddings and both LLMs run on Ollama (`available: true`). |
| L-7 | **GitHub pull requests (R4)** | No GitHub credentials for a target repository | Implemented and tested against a mocked API (Step 7). Remaining: set `LEXCOMPILER_GITHUB_TOKEN` / `LEXCOMPILER_GITHUB_REPO`, open one real PR end to end, and optionally persist the returned PR number. |
| L-8 | **Hardware-backed signing (C1)** | No cloud KMS account or TSA reachable here | Implemented (Step 18) and tested against fakes. Remaining: create a KMS key (GCP `EC_SIGN_ED25519` with HSM protection, or AWS `ECC_NIST_P256` SIGN_VERIFY), set `LEXCOMPILER_SIGNER` and the key id, set `LEXCOMPILER_TSA_URL` (e.g. `https://freetsa.org/tsr`), then issue and verify one certificate. |
| L-9 | **Isolated runtime sandbox (S2, X1)** | Containers can't be launched from this session | Implemented (Step 21) and tested with a fake engine. Remaining: run `docker build -f Dockerfile.sandbox -t lexcompiler-sandbox:1 .`, set `LEXCOMPILER_SANDBOX_CONTAINER=docker` (plus `LEXCOMPILER_SANDBOX_OCI_RUNTIME=runsc` if gVisor is installed), and run `npm run verify:realworld`; `isolation` must read `container`. |
| L-10 | **Real PostgreSQL execution (X2)** | — | ✅ Done (Step 12). Optional local check: run `verify:realworld` with `LEXCOMPILER_POSTGRES_URL` and `LEXCOMPILER_REDIS_URL` pointing at real servers. |
| L-11 | **Tree-sitter queries (L3)** | — | ✅ Done (Steps 9, 14): Python, TypeScript and SQL grammars. |
| L-12 | **External MCP servers** | The external services are not available here | Client implemented and tested (Step 20). Remaining: copy `mcp-servers.example.json` to `mcp-servers.json`, start the services (PostgreSQL, Neo4j, n8n; uvx/npx for the stdio servers; a GitHub token), and check that `/api/mcp/servers` lists each as `ONLINE`. |
| L-15 | **GitHub code-scanning upload** | Code scanning is a repository setting | Reusable workflow added (Step 20). Remaining: enable code scanning on a real repository and call `mrshakils/lexcompiler/.github/workflows/lexcompiler-scan.yml@main` from it with a `clauses-file`. |
| L-16 | **Symbolic program semantics (V3)** | — | ✅ Done (Step 16): path-sensitive symbolic execution for TypeScript and Python, Z3 counterexamples, inter-procedural taint within a module. |
| L-17 | **More rule categories (L2)** | — | ✅ Done (Step 15). Optional local check: write a real DPIA for `services/ai_credit_triage.ts` and reference it with `DPIA_REFERENCE`. |
| L-18 | **Multi-tenant users and projects (P1)** | No real identity provider here | Implemented (Step 17) and tested against a local OpenID provider. Remaining: register LexCompiler with your IdP (Keycloak, Entra ID, Okta, Auth0…), set `LEXCOMPILER_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_REDIRECT_URI` and the roles claim, then sign in through `/api/auth/login`. |
| L-19 | **Full verification of real repositories at scale** | No large real-world repositories to benchmark against here | Run `LEXCOMPILER_TARGET_REPO=… npm run verify:cli` on real codebases, measure precision/recall of findings, and tune the analyzer heuristics. |
| L-20 | **Event-loop blocking (S6)** | Not reached in the cloud session | Replace the remaining `execFileSync` calls (sandbox Git history, the sync analyzer fallback, `resolvePython`) with async `execFile`/`spawn`, so a request never blocks the event loop. |
| L-21 | **PII classification beyond names (A1)** | Not reached in the cloud session | Classify PII from types and schemas (Pydantic field types, SQL column comments and constraints, TypeScript interfaces) and from value patterns in fixtures, in addition to identifier names; add precision/recall tests. |
| L-22 | **Frontend accessibility and tests (U1)** | Not reached in the cloud session | Add `@testing-library/react` + jsdom tests for the dashboard, IDE drawer and agent console; fix keyboard focus, ARIA labels and colour contrast; split the largest components. |
| L-13 | **EUR-Lex SPARQL ingestion** | EUR-Lex and CELLAR are blocked from this session (403) | Implemented and tested against recorded responses (Step 20). Remaining: run `GET /api/regulations/live-feed` with internet access and confirm the GDPR Art. 17 / AI Act Art. 14 items show `illustrative: false` with the official text. |
| L-14 | **Docker image verification (D1)** | Docker isn't available in this session | The Dockerfile and compose file are written (Step 6). Remaining: run `LEXCOMPILER_API_TOKEN=… docker compose --profile ollama up --build`, pull the models, and confirm the health check and the non-root image. |

---

## Local verification prompt

Paste this into Claude Code in your local clone (branch `claude/compassionate-hypatia-3mjhsk`):

```text
Pull origin/claude/compassionate-hypatia-3mjhsk. Read docs/IMPLEMENTATION_LOG.md: Part 1 is
what is built, Part 2 lists what still needs this machine. Work through every Part 2 row whose
"What remains" is not ✅ Done, in this order: L-1, L-6, L-14, L-9, L-10, L-3, L-7, L-8, L-18,
L-2, L-4, L-5, L-12, L-13, L-15, L-19, L-20, L-21, L-22.
For each row: tell me what you need to install or which credentials you need and wait for my OK;
do the remaining step; fix anything that breaks in the code (never weaken a test or a claim in
README.md / AGENTS.md); run npm run typecheck, npm run lint, npm test, npm run verify:cli,
npm run verify:realworld, npm run build (and the agents/ pytest suite); mark the row done with a
short note; commit as mrshakils <121shakilahmed@gmail.com> and push to the same branch.
Never commit secrets. At the end, update docs/LIMITATIONS_REPORT.md §0 and summarise.
```

