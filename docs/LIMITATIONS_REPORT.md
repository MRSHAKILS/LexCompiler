# LexCompiler — Project Limitations Report

**Scope:** Entire repository at commit `b91b223` (branch `claude/compassionate-hypatia-3mjhsk`)
**Date:** 2026-10-28
**Method:** Read every server module, the shared types, the target repo, the CI/Docker config, and a sample of the React UI. Ran `npm ci`, `npm test`, both TypeScript projects (`tsc --noEmit`), `vite build`, and a throwaway probe suite (results in [Appendix A](#appendix-a--probe-results)) to check suspected behaviour against the actual code.

---

## 1. Executive Summary

LexCompiler is a working **demo** with a polished UI. Some parts are real: it calls Microsoft Z3 through `z3-solver`, parses TypeScript with the TypeScript Compiler API, parses Python with `ast`, signs with Ed25519, fetches from the Federal Register, and builds real unified diffs. But the whole pipeline only works for **one fixed, built-in sample repository** (5 known files, known identifiers) and **four hard-coded rule templates**. Much of what the README and `AGENTS.md` describe is labelled output, not implemented behaviour: the 6-agent crew, OPA Rego evaluation, "minimal unsat cores", CEGIS, pgvector, Neo4j, RAGAS scores, 384-d embeddings in the default path, and "hardware-backed" signing.

Five issues matter most:

1. **The pre-PR Z3 gate can't fail.** `postPatchZ3Status` is `allResolved ? 'SAT_COMPLIANT' : 'SAT_COMPLIANT'`, and every PR is marked `READY_TO_MERGE`. A probe confirmed a PR reported as `SAT_COMPLIANT` while one clause was still `UNSAT_VIOLATION` after the patch.
2. **Unauthenticated remote code execution.** Any client can write any file (path traversal via `../`) through `POST /api/repo/update-file`. `GET /api/sandbox/verify-runtime` then `exec()`s the target Python files in-process. There is no auth, and CORS is wide open.
3. **The legal compiler is a set of regexes over 4 templates.** It takes the *first* number it finds, ignores negation and exceptions, and can't read words like "seventy-two hours" or "one week". It can quietly produce a weaker rule than the text says, e.g. 90 days instead of 3 days.
4. **The "AST analysis" only knows file names and constant names.** It works only on the 5 bundled files and specific identifiers like `PII_CACHE_TTL_HOURS`. Writing `24 * 30` (720 h) is read as 24 h, a false "compliant".
5. **Many reported metrics are hard-coded constants** (RAGAS scores, agent token counts and latencies, dedup and caching ratios, LLM fallback throughput). The UI and API show them as measurements.

---

## 2. Severity Legend

| Level | Meaning |
| :--- | :--- |
| 🔴 **Critical** | Security hole, or the system reports something false that a user would act on (e.g., "compliant", "verified") |
| 🟠 **High** | Core capability is missing or works only on the demo fixture; documented behaviour doesn't exist |
| 🟡 **Medium** | Correctness or robustness gap with limited blast radius; misleading but secondary output |
| 🔵 **Low** | Quality, maintainability, docs, or UX issue |

---

## 3. Findings at a Glance

| # | Area | Limitation | Severity |
| :-- | :--- | :--- | :--- |
| S1 | Security | Arbitrary file write and path traversal via `/api/repo/update-file` | 🔴 |
| S2 | Security | Unsandboxed `exec()` of repo Python → RCE chain with S1 | 🔴 |
| S3 | Security | No authentication or authorization on any endpoint; `cors()` allows all origins | 🔴 |
| S4 | Security | Signature verify endpoint accepts a caller-supplied public key | 🟠 |
| S5 | Security | User OpenAI API key sent through the backend in request bodies | 🟡 |
| S6 | Security | Synchronous subprocesses block the event loop → easy DoS | 🟡 |
| V1 | Verification | Post-patch Z3 gate is a tautology; PR always `READY_TO_MERGE` | 🔴 |
| V2 | Verification | Unsat cores and counterexample witnesses are hand-built, not taken from Z3 | 🟠 |
| V3 | Verification | Z3 only checks ground constants; no symbolic program semantics | 🟠 |
| V4 | Verification | Displayed and hashed SMT-LIB2 differs from what actually ran | 🟠 |
| V5 | Verification | OPA Rego is generated but never evaluated; "denials" are template strings | 🟠 |
| V6 | Verification | Cross-border axiom hard-codes "non-EU egress forbidden" | 🟡 |
| V7 | Verification | `unknown` solver result treated as `unsat`; defaults for missing facts are inconsistent | 🟡 |
| V8 | Verification | One entity per construct type (`find()`); fixed 5-node graph | 🟠 |
| L1 | Legal compiler | Regex extraction; first-match wins; no negation, exceptions, or number words | 🔴 |
| L2 | Legal compiler | Only 4 rule categories; category supplied by the caller, not inferred | 🟠 |
| L3 | Legal compiler | Generated SMT, Rego, and AST queries are fixed templates naming demo identifiers | 🟠 |
| L4 | Legal compiler | Curated "statute" excerpts contain obligations that aren't in the cited law | 🔴 |
| A1 | AST analysis | Gated on hard-coded file names and identifiers | 🟠 |
| A2 | AST analysis | Only literal constants; expressions mis-read (`24 * 30` → 24) | 🔴 |
| A3 | AST analysis | SQL "parser" is a line regex that depends on comment annotations | 🟠 |
| A4 | AST analysis | No data flow or taint analysis; text matching for PII logging | 🟠 |
| A5 | AST analysis | Only 5 known files are ever read; can't scan an arbitrary repo | 🟠 |
| R1 | Remediation | "CEGIS" patches are whole-file template rewrites that drop user code | 🟠 |
| R2 | Remediation | Patched "encryption" leaks the first 4 plaintext characters | 🟡 |
| R3 | Remediation | AI-triage patch changes business semantics (auto-rejects) | 🟡 |
| R4 | Remediation | No real Git branch or PR; `prNumber: 409` is hard-coded | 🟠 |
| R5 | Remediation | Multiple clauses in the same category: only the first is used to patch | 🟡 |
| B1 | BYOC scanner | Always the retention category; defaults to a violation when no TTL is found | 🟡 |
| B2 | BYOC scanner | Regex "remediation" rewrites every log call in the file | 🟡 |
| X1 | Sandbox | Not isolated; TypeScript never executed; logic duplicated in Python regexes | 🟠 |
| X2 | Sandbox | SQLite stands in for PostgreSQL; FastAPI and Pydantic shimmed | 🟡 |
| C1 | Attestation | Ed25519 key is regenerated every process start; old certs can't be verified | 🟠 |
| C2 | Attestation | "Merkle root" is a flat hash; "commit hash" isn't a Git hash | 🟡 |
| C3 | SARIF | Invalid property casing (`SemanticVersion`); hard-coded repo URI | 🟡 |
| C4 | Attestation | Certificate claims conformity with EU AI Act Art. 43 / SOC 2 | 🟠 |
| AI1 | Agents | The 6-agent "crew" is a static report; no agent framework or LLM is called | 🟠 |
| AI2 | RAG | Default "384-d embeddings" are a 16-dim keyword bag; pgvector and Neo4j absent | 🟠 |
| AI3 | RAG | RAGAS metrics are hard-coded constants (0.991 etc.) | 🟠 |
| AI4 | Tokens | Token-savings benchmark inflates the baseline ×4 and uses fixed ratios | 🟡 |
| AI5 | LLM mesh | Fallbacks fabricate token and throughput numbers when Ollama is down | 🟡 |
| M1 | MCP | Not spec-compliant JSON-RPC/MCP; SSE closes after one event; unknown tool → success | 🟡 |
| M2 | MCP | Stdio server ignores runtime clause state; uses the initial clauses only | 🔵 |
| P1 | Architecture | Global in-memory mutable state; single-tenant; lost on restart | 🟠 |
| P2 | Architecture | Every `GET /api/state` re-parses, runs Z3 twice, and writes the ledger | 🟡 |
| P3 | Architecture | Z3 `Context` created per call and never released | 🔵 |
| T1 | Testing | One test file, 5 happy-path tests; asserts on tautologies and constants | 🟠 |
| T2 | Testing/CI | Client type-check fails; CI doesn't type-check the client or lint | 🟡 |
| T3 | Testing/CI | CLIs never exit non-zero on violations → not a real gate; `verify:cli` not in CI | 🟡 |
| T4 | Testing/CI | CLIs and tests reset and overwrite `target-repo/` on disk | 🔵 |
| D1 | Deployment | Docker image omits Ollama, runs as root, has no volume for `data/` | 🟡 |
| D2 | Deployment | Health check always reports `ok` / `ready` | 🔵 |
| DOC1 | Docs | README and `AGENTS.md` describe features that don't exist | 🟠 |
| DOC2 | Docs | README says MIT but there is no `LICENSE` file; package name differs from the project | 🔵 |
| U1 | Frontend | Minimal accessibility, no frontend tests, very large components | 🔵 |

---

## 4. Detailed Findings

### 4.1 Security

#### S1 🔴 Arbitrary file write with path traversal
`writeTargetRepoFile` (`server/analyzer/repoBaseline.ts:233`) strips leading `/` and then calls `path.join(TARGET_REPO_ROOT, relPath)`. It never checks that the result stays inside `target-repo/`. `POST /api/repo/update-file` (`server/index.ts:618`) passes the request's `filePath` straight in. A probe confirmed that `../server/index.ts` resolves to `/home/user/LexCompiler/server/index.ts`. Any network client can overwrite the server's own source, `package.json`, shell profiles, and so on.

#### S2 🔴 Unsandboxed execution → RCE chain
`executeRealWorldSandboxVerification` (`server/sandbox/realWorldSandbox.ts:196,216`) runs `exec(compile(...))` on `api/fastapi_intake.py` and `workers/redis_cache_worker.py` inside a normal `python3` process. That process runs as the server user, with full filesystem and network access. Combined with S1 (or even a legitimate `update-file` to `api/fastapi_intake.py`), anyone who can reach the port gets code execution:
`POST /api/repo/update-file {filePath:"api/fastapi_intake.py", content:"import os; os.system(...)"}` → `GET /api/sandbox/verify-runtime`.
Calling this a "sandbox" overstates it. There is no container, seccomp, user namespace, or resource limit beyond a 5 s timeout.

#### S3 🔴 No authentication; permissive CORS
None of the 26 endpoints check identity or authorization. `app.use(cors())` (`server/index.ts:63`) lets any web page the user visits call the local server. That includes the state-changing endpoints: file writes, repo reset, applying PRs, Git commits, and changing clauses.

#### S4 🟠 Signature verification accepts an attacker key
`POST /api/enterprise/verify-signature` takes an optional `publicKeyPem` and verifies against it (`server/enterprise/enterpriseSuite.ts`, `verifyEd25519CertificateSignature`). A forger signs any payload with their own key and supplies that key, and the endpoint returns `verified: true`. There is no trust anchor, key pinning, or certificate chain.

#### S5 🟡 Cloud API key passes through the backend
The UI (`src/components/LiveMultiLlmMeshStudio.tsx:49,96`) sends a user-typed OpenAI key in the JSON body of `/api/llm/generate`. Combined with S3, the key travels through an unauthenticated server that any web page can call. Prefer sending it from the browser directly, or storing it server-side.

#### S6 🟡 Event-loop blocking → DoS
`execFileSync('python3', …)` is used for AST parsing (3 s timeout), the sandbox (5 s), and every SQLite ledger read and write (3 s). These calls are synchronous, so each request blocks the whole Node process. A handful of concurrent `GET /api/state` or `/api/sandbox/verify-runtime` calls stalls the server for every user.

### 4.2 Formal Verification (Z3 / OPA)

#### V1 🔴 The pre-PR gate is a tautology
`server/remediation/prSynthesizer.ts:393`:
```ts
postPatchZ3Status: allResolved ? 'SAT_COMPLIANT' : 'SAT_COMPLIANT',
```
`status` is always `'READY_TO_MERGE'` (line 383), `prePatchZ3Status` is always `'UNSAT_VIOLATION'`, and the executive summary always says "all invariants transition from UNSAT → SAT". The probe added a lenient 30-day clause next to the 72-hour clause. The PR reported `SAT_COMPLIANT / READY_TO_MERGE`, but re-verification showed `CLAUSE-DPA-4.2: UNSAT_VIOLATION`. The UI makes it worse: after "Apply PR" it always shows the toast "Microsoft Z3 proved 100% SAT_COMPLIANT" (`src/App.tsx:268–270`), whatever the result. This breaks the main guarantee in `AGENTS.md` §3 ("Every synthesized patch MUST pass the Pre-PR Z3 Sandbox Gate").

#### V2 🟠 Unsat cores and witnesses aren't from Z3
Assertions are added with plain `solver.add(...)`. Nothing uses `assert_and_track` or named assumptions, and the code never calls `solver.unsatCore()` or `solver.model()`. `unsatCoreAssertions` is filled by `if` statements that repeat the comparison in TypeScript (e.g. `postgresRetentionHours > maxHours`), and some core names are string literals (`'ast_fastapi_logs_plaintext_pii_true'`). `counterexampleWitness` is just the input values. The README's "extracts minimal Unsat Core & Counterexample Witness" isn't implemented. The cores aren't minimal either: Postgres retention and KMS are always reported together.

#### V3 🟠 Z3 is evaluating constants
Every code-side variable is pinned to a concrete value (`pgRet.eq(720)`) and every law-side variable to a concrete bound (`sMaxHours.eq(72)`). Each query therefore reduces to checking an inequality like `720 ≤ 72`, which the TypeScript already computes for the explanations. Nothing models program paths, data flow, or quantifiers over entities ("∀ entity ∈ PII_Store"). The first-order formulas shown to users are decoration; nothing checks them.

#### V4 🟠 The SMT text you see isn't what ran
Z3 runs through the programmatic API, while `smtLib2Executed` is a separately built string (`server/prover/z3Engine.ts:122–132`). The two have drifted. For example, the solver asserts `redis_worker_uses_tenant_kms`, but the text never declares or asserts it. `smtFormulaSha256`, and the per-clause "Merkle" hash built from it, hash the *display* text, not the formula that was solved. So the provenance chain doesn't attest to the actual proof.

#### V5 🟠 OPA Rego is never evaluated
There's no OPA binary, WASM module, or Rego library among the dependencies. `opaRegoTriggeredDenials` are hand-written template strings pushed next to the Z3 result. The generated Rego is never even syntax-checked. It also uses pre-v1 syntax (`deny[msg] {` without `contains`/`if`), which current OPA (v1.x) rejects by default.

#### V6 🟡 Cross-border law is hard-coded
`solver.add(sAllowsNonEu.eq(false))` (`server/prover/z3Engine.ts:571`) ignores the clause's own `statutory_allows_non_eu_egress` parameter. A clause that permits US transfers under SCCs still gets the "no non-EU egress" axiom. Region membership is decided in TypeScript (`allowedRegions.includes`), not by the solver.

#### V7 🟡 Unknown results and default facts
- `status: z3Result === 'sat' ? 'SAT_COMPLIANT' : 'UNSAT_VIOLATION'` reports a solver `unknown` (timeout, resource limit) as a proven violation.
- When a construct isn't found, the defaults are inconsistent. A missing Redis worker defaults to 720 h (violation), a missing AI engine to 0.68 (violation), and a missing egress to `us-east-1` (violation). A missing logger, though, defaults to `false` (compliant). If the SQL table is missing, `unencryptedPiiColumns.length ?? 0` makes `postgresEncryptedAtRest = true`.

#### V8 🟠 One instance per construct; fixed topology
Facts are pulled with `astFindings.find(...)` and `sqlTables.find(t => t.tableName === 'patient_records')`. Only the *first* match of each construct type is verified, and any other table, endpoint, or worker is ignored. The architecture graph is a hard-coded list of 5 nodes and 4 edges with fixed labels, payloads, and file paths. The "blast radius" view therefore can't reflect a real codebase.

### 4.3 Legal-to-Logic Compiler

#### L1 🔴 Regex extraction can silently weaken the law
`compileLegalProseToFormalPolicy` (`server/compiler/legalCompiler.ts:25`) uses regexes, not an NLP or LLM model. The probe confirmed:

| Input | Extracted | Problem |
| :--- | :--- | :--- |
| "Backups may be kept 90 days, but PII must be purged within **3 days**." | **2160 h** (90 days) | First match wins, so the result is **30× more lenient** than the law |
| "purged within seventy-two hours" | 720 h | Number words unsupported; falls back to the default |
| "purged within one week" / "Retain records 2 years" | 720 h | Weeks, months, and years unsupported |
| "PII **need not** use tenant-isolated keys…" | `requiresTenantIsolatedKeys: true` | Negation ignored |
| "Logging of email addresses is **permitted**." (`PII_LOGGING_BAN`) | `forbidPlaintextLogging: true` | Category forces prohibition |

Other gaps:
- Hours always win over days, regardless of which one governs.
- Percentages are taken from any `\d{2,3}%` in the text.
- The confidence threshold defaults to 0.70 when none is found.
- Allowed regions are a fixed EU pair, plus `us-east-1` only if certain phrases appear.

Because every output is labelled a "formal proof", a misparse becomes a *proven-compliant* verdict against the wrong rule.

#### L2 🟠 Four categories, chosen by the caller
Only `RETENTION_AND_TENANT_KMS`, `PII_LOGGING_BAN`, `AI_HUMAN_IN_THE_LOOP`, and `CROSS_BORDER_TRANSFER` exist. The category isn't inferred from the text: the API caller or preset sets it, and it defaults to retention. Anything else (consent, purpose limitation, breach notification, DPIA, access rights, minimisation, and so on) can't be expressed. The deontic modality (`O`/`F`/`P`) is fixed per category. `PERMISSION` is never produced.

#### L3 🟠 Generated artifacts are fixed templates
The SMT-LIB2, Rego, and "Tree-sitter" queries are string templates with demo identifiers baked in: `patient_records`, `ingest_patient_pii`, `PII_CACHE_TTL_HOURS`, `evaluateClinicalAndCreditRisk`, `REPLICA_TARGET_REGION`, `/api/v1/patients/intake`. Only the numbers change. The Tree-sitter queries are never run, and Tree-sitter isn't a dependency.

#### L4 🔴 Invented statutory content
Several texts are presented as real law, with official EUR-Lex/eCFR URLs, but contain obligations the cited instruments don't have:
- The "EUR-Lex" EU AI Act excerpt adds "Minimum confidence gate 0.88 (88%)". Art. 14 sets no numeric confidence threshold.
- The "GDPR Art. 17" excerpt says PII must be "purged within 72 hours". GDPR sets no such retention period. The 72 hours in GDPR is the Art. 33 breach-notification deadline.
- The HIPAA fallback "Federal Register" item ("89 FR 104210 … 72h Cache Purge") doesn't match a real rulemaking. Volume 89 is the 2024 volume, but the item is dated 2026-09-18. When a real Federal Register result has no abstract, the code substitutes a made-up excerpt about 72-hour purging (`legalCompiler.ts:730–732`).
- Clause `version`/`lastAmended` values (e.g., `v2026.4-AMENDED`) are invented.

For a compliance product, users can't tell these demo texts apart from real regulatory text. That risks real legal decisions being made from them.

### 4.4 Polyglot AST Analysis

#### A1 🟠 File-name and identifier gating
Python and TypeScript extraction only runs when the path contains `fastapi_intake.py`, `redis_cache_worker.py`, `ai_credit_triage.ts`, or `cross_border_sync.ts`, and it then looks up specific constant and function names. Renaming a constant or moving the logic to another file makes the construct disappear. That doesn't make the code "compliant": the prover then falls back to the defaults described in V7.

#### A2 🔴 Only literal constants; expressions are misread
Python `assignments` record a value only when it's an `ast.Constant`. Otherwise the code falls back to the regex `PII_CACHE_TTL_HOURS\s*=\s*(\d+)`. The probe set `PII_CACHE_TTL_HOURS = 24 * 30` (720 h). It was read as **24 h**, a false **compliant**. The same applies to:
- environment variables (`int(os.getenv(...))`)
- config files
- class attributes
- function arguments such as the TTL passed to `setex()`
- TypeScript `as const`, template literals, and imported constants

The analyzer checks *declared constants*, not runtime behaviour.

#### A3 🟠 SQL "parser" is a line regex
`parseSqlSchemaFile` matches `CREATE TABLE` per line, ends a table at a line starting with `);`, and finds columns with `^name type`. PII, encryption, and retention mostly come from **comment annotations** (`@pii(...)`, `@encrypted(...)`, `@retention_hours(...)`). Any real schema without these annotations is mis-classified. Multi-line columns, constraints, `ALTER TABLE`, quoted identifiers, `CREATE TABLE … AS`, and real Postgres encryption (pgcrypto, TDE) aren't understood. Separately, the cascade "propagation" *overwrites* `patient_records.hasErasureCascade` with whether *any other* table has `ON DELETE CASCADE`.

#### A4 🟠 No data flow or taint tracking
Plaintext-logging detection is a regex over the unparsed `logger.info(...)` call. If no `logger.info` call exists, the regex runs over **the whole file** instead. Aliasing (`s = payload.ssn; logger.info(s)`), other loggers (`print`, `structlog`, `logger.exception`), and indirect formatting are missed. Mentioning `redact_pii` anywhere in the call suppresses detection even if raw PII is also logged. Only the *first* `logger.info` call is examined.

#### A5 🟠 Closed-world file list
`readTargetRepoFiles()` iterates over `INITIAL_REPO_FILES` (5 fixed paths). New files added to `target-repo/` are never scanned, and the tool can't be pointed at another repository or Git URL. The README's positioning as a repo-wide scanner ("hundreds of commits per week") doesn't hold.

### 4.5 Remediation / "CEGIS" PR Synthesis

#### R1 🟠 Whole-file template rewrites, not AST patches
For each violated node, `synthesizeRemediationPullRequest` swaps the **entire file** for a hard-coded "fixed" version, with only the numbers filled in. Any other code the user added to those files is silently deleted. There's no counterexample-guided loop, no candidate generation, and no LLM involvement, so the "CEGIS" label is inaccurate. `offendingLineStart`/`End` are hard-coded (e.g., 4–14, 10–46).

#### R2 🟡 The "fixed" crypto is still insecure
`encrypt_with_tenant_kms` returns `f"enc_kms::{tenant_id}::{plaintext[:4]}***"`: no encryption, and it **leaks the first 4 characters** of SSNs. `redact_pii` uses an unsalted, truncated SHA-256, which is easy to brute-force for low-entropy values like SSNs. These are presented as "COMPLIANT" code.

#### R3 🟡 Patches change behaviour without saying so
The AI-triage patch returns `approved: meetsStatutoryConfidence`. Low-confidence cases come back *rejected* (`approved: false`) instead of being routed to a human with the decision pending, which is itself an autonomous adverse decision. The patches are never compiled, type-checked, or run against tests before being labelled "verified".

#### R4 🟠 No real PR
`prNumber: 409` and the branch name are constants. Nothing calls the GitHub API, and no branch is pushed. "Apply PR" writes files into `target-repo/` and commits to a private `data/sandbox-git` repository. The "GitHub Repository & PR Automation MCP" listed in `/api/mcp/servers` is a descriptor only.

#### R5 🟡 First clause per category wins
Patch parameters come from `clauses.find(c => c.category === …)`. With several retention clauses (the API's `unshift` makes this easy), the patch follows the first one, not the strictest. Combined with V1, the result is false "READY_TO_MERGE" PRs (confirmed by probe).

### 4.6 BYOC Custom Scanner (`executeByocCustomScan`)

#### B1 🟡 Fixed category, defaults to a violation
The scanner always compiles as `RETENTION_AND_TENANT_KMS`. If no TTL-like constant is found, `detectedTtlHours` defaults to **720**. A two-line `def f(x): return x` was reported `UNSAT_VIOLATION: Configured TTL (720h) exceeds contractual mandate (48h)` (probe). The `language` parameter is accepted but never used. Detection is regex only; this path never invokes the real AST parsers.

#### B2 🟡 Regex rewrite breaks logging
`/(logger|logging|console)\.(info|…|log)\(([^)]+)\)/g` replaces the arguments of **every** log call in the file with a constant string, including ones without PII. Because `[^)]+` stops at the first `)`, nested calls like `logger.info(fmt(x))` produce broken code.

### 4.7 "Real-World" Runtime Sandbox

#### X1 🟠 Not isolated, and TypeScript is never executed
Besides S2: the TypeScript services aren't executed. The Python runner regex-scans the `.ts` text and **re-implements** the decision logic itself. Both branches of `if human_gate:` are identical (`realWorldSandbox.ts:243`), so the gate flag has no effect. The 0.85 threshold and test confidence 0.78 are hard-coded, as are the test payload and SSN. The results only reflect the bundled fixture.

#### X2 🟡 Different runtimes from what's claimed
PostgreSQL DDL runs in **SQLite**, which accepts the Postgres types loosely and ignores types and constraints the way Postgres wouldn't. `fastapi` and `pydantic` are replaced by dummy shims when missing, and Redis is a mock object. "Python 3.12" is stated, but whatever `python3` is installed gets used (3.13 here).

### 4.8 Attestation, Certificates & SARIF

#### C1 🟠 Ephemeral signing key
`crypto.generateKeyPairSync('ed25519')` runs at module load (`enterpriseSuite.ts:13`). Every restart creates a new key, so certificates issued earlier can't be verified afterwards, and nothing publishes or pins the key. The issuer string "**Hardware-Backed Root**" is false; the key lives in process memory. There's no X.509, no timestamping authority, and no revocation.

#### C2 🟡 Hash naming is misleading
- **"Merkle audit root"** is `sha256(hash1|hash2|…)`, a flat hash with no tree and no inclusion proofs.
- **`commitHash`** in reports is `sha256(file contents + commitCounter)[:8]`, not the Git commit hash.
- **`repositoryName`** is hard-coded to `finhealth-ai/core-platform`.

#### C3 🟡 SARIF validity
- `tool.driver.SemanticVersion` should be `semanticVersion`. SARIF property names are case-sensitive.
- `versionControlProvenance.repositoryUri` is hard-coded to a fictitious repository.
- `uri` is prefixed `target-repo/`. That only resolves correctly if the scanned repo is this one.

CI never uploads SARIF (no `github/codeql-action/upload-sarif` step), so the "GitHub Advanced Security" integration isn't wired up.

#### C4 🟠 Certificate claims a conformity standard
Certificates name the standard `EU-AI-ACT-ART43 / GDPR-ART32 / HIPAA-164.312 / SOC2-CC6.1` and the verdict `SAT_COMPLIANT_CERTIFIED`. Art. 43 conformity assessment is a defined legal procedure: internal control under Annex VI or a notified body under Annex VII, with technical documentation and a quality management system. A SOC 2 report must be issued by a licensed CPA firm. A self-signed demo certificate built on the limitations above shouldn't be labelled this way.

### 4.9 AI / Agents / RAG / Token Optimisation (Claims vs. Implementation)

#### AI1 🟠 The 6-agent crew isn't implemented
`buildMultiAgentExecutionReport` (`server/agents/multiAgentOrchestrator.ts`) returns a **static array**. Framework names (CrewAI, DSPy, LangGraph, Pydantic-AI, Swarm, Hermes), models (Claude 3.7 Sonnet, DeepSeek-R1, GPT-4o, Gemini 2.5 Flash, Llama-3.3-70B), token counts (640 → 185…), latencies (18.4 ms…), and `status: 'COMPLETED'` are all literals. None of those frameworks is a dependency, and no model is called. `AGENTS.md` §2 describes an architecture that isn't in the code.

#### AI2 🟠 Default "384-d neural embeddings" are a keyword bag
`computeSemanticEmbedding` (`server/rag/hybridRagEngine.ts`) counts keyword hits across **16** hand-picked "domain dimensions" and reports `embeddingDimension: 384`. Real Ollama `all-minilm` embeddings are only used in `executeRealNeuralRagQuery`, and only to *re-score* the top-K chunks the keyword path already picked, so they never change recall. They're computed sequentially, one HTTP call per chunk. The README's pgvector (HNSW) and Neo4j 2-hop Cypher traversal aren't there: Cypher appears only as display strings, and the "vector store" SQLite table is only ever `COUNT(*)`-ed. HyDE is one of 4 fixed SMT strings picked by keyword. CRAG is a threshold label.

#### AI3 🟠 RAGAS metrics are constants
`contextPrecision: 0.964, contextRecall: 0.982, faithfulness: 0.991, answerRelevance: 0.975, …` are literals. The test suite asserts `faithfulness > 0.95`, which tests a constant. No evaluation dataset or judge exists.

#### AI4 🟡 Token-savings benchmark is inflated by design
`runTokenOptimizationBenchmark` (`server/optimization/tokenOptimizer.ts:134–153`):
- **Baseline inflated ×4:** the raw token count is `ceil(len/3.6) * 4` ("simulate amplification").
- **Fixed ratios:** dedup is a fixed `× 0.78` and KV-cache is a fixed `× 0.34`; no deduplication or caching takes place.
- **Heuristic tokens and constant latencies:** token counts use a chars/3.6 heuristic rather than a tokenizer, and `latencySavedMs` values are constants.

The reported ">75 % reduction" mostly comes from these assumptions. "Codeburn" just trims lines, removes comment-only lines, and **drops Python indentation**, so its output isn't valid Python. "Caveman/LLMLingua-2" is a stop-word filter.

#### AI5 🟡 LLM fallbacks fabricate telemetry
When Ollama is unreachable, `runRealLlmInference` returns `tokensPerSecond: 65.0`, `promptTokens: 64`, `completionTokens: 42`, and text like "Verification complete." The UI shows these the same way as real inference. The default "general counsel" model is the same 0.5 B coder model, so legal reasoning quality is very limited even when Ollama is running.

### 4.10 MCP Servers

#### M1 🟡 Not protocol-compliant
- **HTTP RPC:** `POST /api/mcp/:serverId/rpc` ignores `method`. It always does `tools/call` and supports neither `initialize` nor `tools/list`. It returns a wrapper object, not a bare JSON-RPC response, and makes up its own `id` instead of echoing the client's.
- **Unknown server or tool:** returns `isError: false` with empty output.
- **SSE:** `GET …/sse` writes one `notifications/initialized` event and closes the stream, so it can't serve as a transport.
- **stdio:** unknown methods get no response at all (the spec expects `-32601`), and every error is reported as `-32700` (parse error) with `id: null`.
- **Spec version:** the result uses `structuredOutput`, which isn't a field in protocol `2025-03-26` (later versions use `structuredContent`).
- **SDK:** the official `@modelcontextprotocol/sdk` isn't used. There's no capability negotiation, input validation against `inputSchema`, cancellation, or progress.
- **External servers:** the 6 "integrated external MCP servers" (pgvector, Neo4j, GitHub, DuckDB, n8n…) are static descriptors.

#### M2 🔵 Stdio server state
`invokeMcpTool` without `activeClauses` uses `getInitialClauses()`, so stdio clients never see amended clauses.

### 4.11 Architecture, State & Scalability

#### P1 🟠 Global, volatile, single-tenant state
`activeClauses`, `activeAmendmentLabel`, and `commitCounter` are module-level variables in `server/index.ts`. Every user shares and mutates one global state, there's no locking around concurrent file writes and Git commits, and all clause edits are lost on restart. Nothing models users, tenants, projects, or multiple repositories.

#### P2 🟡 Expensive, side-effecting reads
`GET /api/state`, `/api/enterprise/certificate`, and `/api/enterprise/sarif` each re-read files, spawn `python3` for each Python file, run Z3 for all clauses, run Z3 *again* for the post-patch check, and **write a row to the SQLite ledger**. `/api/ai-heavy/overview` and `/api/rag/query` repeat the parsing and Z3 work, without the ledger write. Each ledger write is a separate `python3` subprocess. A `GET` therefore mutates persistent state, which inflates the audit ledger on every UI refresh.

#### P3 🔵 Z3 context lifecycle
`new Context('lexcompiler_prover')` is created on every verification call and never released. In a long-running server this can grow WASM memory. There's also no solver timeout (`solver.set('timeout', …)`).

### 4.12 Testing & CI

#### T1 🟠 Thin, tautological test suite
- **Coverage:** one file (`server/lexcompiler.test.ts`) with 5 tests, all happy-path against the bundled fixture.
- **Tautological assertions:** the tests check `postPatchZ3Status === 'SAT_COMPLIANT'` (always true, V1), `ragasMetrics.faithfulness > 0.95` (a constant, AI3), `totalReductionPercent > 75` (inflated, AI4), and `steps.length === 6` (static, AI1).
- **Untested paths:** negative cases, parser edge cases, Bangla edge cases, HTTP endpoints, MCP stdio, and SARIF schema validation.
- **Frontend:** no tests at all.

#### T2 🟡 Type errors and no linting
`npx tsc -p tsconfig.json --noEmit` fails with 2 errors (`<strike>` isn't a valid JSX intrinsic in `src/components/McpAndAgentsHub.tsx:409`). `vite build` doesn't type-check, so CI passes anyway. There's no ESLint or Prettier config, and `.cursorrules`' "strict TypeScript" rule isn't enforced. The server build emits `dist-server/`, but `npm start` runs `tsx server/index.ts` from source, so the compiled output is never used.

#### T3 🟡 The "gate" doesn't gate
`cli-verify.ts` prints verdicts and always exits `0`. `cli-realworld-demo.ts` fails only if no PR is synthesized; it never fails when violations remain after patching. `AGENTS.md` says to run `npm run verify:cli` before merge, but CI runs `verify:realworld` instead. CI never runs LexCompiler against *this* repository's PR diff either, so it can't block a non-compliant change.

#### T4 🔵 Destructive CLIs and tests
`verify:cli`, `verify:realworld`, and the tests call `resetTargetRepoToBaseline()` / `resetTargetRepoGitHistory()`. These overwrite `target-repo/` and delete `data/sandbox-git`, wiping any local edits or demo state.

### 4.13 Deployment & Operations

#### D1 🟡 Container gaps
- **Missing service:** no Ollama service in `docker-compose.yml`, so LLM and embedding paths always fall back (AI5).
- **No volume:** `data/` (the SQLite ledger and sandbox Git) isn't mounted, so it's lost when the container is recreated.
- **Build and runtime:** the image uses `npm install` instead of `npm ci`, ships devDependencies, and runs as root (which makes S1/S2 worse).
- **Unused tooling:** Git is installed only for the internal sandbox repo.
- **No ops basics:** no configuration surface besides `PORT`/`OLLAMA_HOST`, no structured logging, metrics, or rate limiting.

#### D2 🔵 Health check is static
`/api/health` always returns `status: 'ok'`, `z3Solver: 'ready'`, `mcpServersOnline: 6` without checking Z3, Python, or Ollama. The Docker `HEALTHCHECK` therefore can't detect a broken dependency.

### 4.14 Documentation & Positioning

#### DOC1 🟠 Docs describe a different system
The README and `AGENTS.md` claim CEGIS, minimal unsat cores, OPA evaluation, pgvector + BM25 RRF, Neo4j Graph RAG, RAGAS evaluation, LLMLingua-2, KV-cache pinning, CrewAI/DSPy/LangGraph agents, and "opens PR #409". As sections 4.2–4.10 show, most of these are labels on deterministic templates or constants. The models named in `AGENTS.md` (Claude 3.7 Sonnet, GPT-4o, Gemini 2.5 Flash) are outdated and also unused. Nothing tells users which outputs are simulated.

#### DOC2 🔵 Housekeeping
- **No license file:** the README says "MIT License", but there's no `LICENSE` file.
- **Inconsistent naming:** `package.json` is named `justicesphere-complianceos`, not LexCompiler.
- **Unstated assumptions:** the README's prerequisites don't mention that the system assumes the bundled target repo.

### 4.15 Frontend

#### U1 🔵 UI maintainability and accessibility
- **Accessibility:** only 2 `aria-*`/`role` attributes across the UI.
- **Large components:** `App.tsx` is ~720 lines and `IdeRemediationDrawer.tsx` ~690 lines, with hand-rolled `fetch` calls and no shared data layer or request cancellation.
- **Hard-coded UI text:** `#409` is baked into several components (`App.tsx`, `IdeRemediationDrawer.tsx`, `EnterpriseStartupSuite.tsx`, `McpAndAgentsHub.tsx`), and the merge toast always claims 100 % compliance (see V1).
- **Bundle:** the client is a single ~367 KB JS chunk with no code splitting.

---

## 5. Recommendations (Prioritised)

**P0 — Fix before anyone else runs this**
1. Fix V1: report `allResolved ? 'SAT_COMPLIANT' : 'UNSAT_VIOLATION'`, set `status` from it, and refuse to "apply PR" unless the post-patch check passes. Add a test where the gate must fail.
2. Lock down the server: confine `writeTargetRepoFile` to `target-repo/` (resolve, then check the prefix) and restrict it to known files. Add authentication, restrict CORS, and bind to `127.0.0.1` by default.
3. Run target code only inside a real sandbox (an unprivileged container or gVisor/nsjail/Firecracker with no network), or drop runtime execution.
4. Label demo content clearly: mark invented "statute" excerpts and fallback feed items as **illustrative**, remove the "Hardware-Backed" and "CERTIFIED" wording, and show which metrics are simulated.

**P1 — Make the verification honest**
5. Get unsat cores and models from Z3 (`assert_and_track` / `solver.unsatCore()`, `solver.model()`), and hash the formula that was actually solved (or build it from one SMT-LIB2 source with `Z3.parseSMTLIB2`).
6. Evaluate the generated Rego with OPA (WASM or the `opa eval` CLI), or stop reporting "OPA denials".
7. Handle `unknown` explicitly, set solver timeouts, and pick one safe default for missing facts ("unknown / needs review" instead of compliant or violated).
8. Iterate over *all* findings and tables, and build the graph from the analysis.

**P2 — Generalise beyond the fixture**
9. Replace regex law extraction with a structured pipeline: an LLM or classical NLP with a schema-validated IR, number-word and unit normalisation, negation and exception handling, and human review of the extracted parameters before they become axioms.
10. Use real parsers (Tree-sitter, or `pglast`/`libpg_query` for Postgres) and add basic constant folding and data-flow or taint analysis. Make detection rules configurable instead of keyed to file names.
11. Scan any repository (directory walk or Git URL) and produce minimal AST-level edits that keep surrounding code. Then compile, type-check, and test the patched code.
12. Use a persistent signing key (KMS/HSM or at least a configured key file), publish it, and drop the endpoint that verifies against a caller-supplied key.

**P3 — Engineering hygiene**
13. Replace `execFileSync` with async workers or a long-lived Python process. Make `GET` endpoints free of side effects.
14. Use the official MCP SDK for stdio and Streamable HTTP.
15. Add negative and edge-case tests, client type-checking (`tsc --noEmit`) and ESLint in CI, SARIF upload, and non-zero exit codes on violations.
16. Docker: `npm ci --omit=dev`, a non-root user, a `data/` volume, an optional Ollama service, and a health check that actually tests its dependencies.
17. Bring the README and `AGENTS.md` in line with what's implemented, and add a `LICENSE` file.

---

## Appendix A — Probe Results

These came from a temporary Vitest file run against the unmodified source; the file was deleted afterwards.

```text
"PII must be purged within seventy-two hours."                  -> hours=720 (expected 72)
"PII must be purged within one week."                           -> hours=720 (expected 168)
"PII need not use tenant-isolated keys … within 72 hours."      -> tenantKms=true (negation ignored)
"Backups may be kept 90 days, but PII must be purged within 3 days." -> hours=2160 (expected 72)
"Retain records 2 years."                                       -> hours=720
PII_LOGGING_BAN "Logging of email addresses is permitted."      -> forbidPlaintextLogging=true

Gate tautology (lenient 30-day clause + strict 72h clause):
  PR.postPatchZ3Status = SAT_COMPLIANT, PR.status = READY_TO_MERGE
  Actual post-patch re-verification: CLAUSE-DPA-4.2 = UNSAT_VIOLATION

AST evasion: PII_CACHE_TTL_HOURS = 24 * 30   -> read as 24h (actual 720h) => false COMPLIANT
Path traversal: '../server/index.ts'          -> /home/user/LexCompiler/server/index.ts
BYOC on `def f(x): return x` with 48h clause -> UNSAT_VIOLATION ("Configured TTL (720h) exceeds 48h")
```

## Appendix B — Build & Test Status Observed

| Command | Result |
| :--- | :--- |
| `npm ci` | ✅ |
| `npm test` (vitest) | ✅ 5/5 passed |
| `tsc -p tsconfig.server.json --noEmit` | ✅ |
| `tsc -p tsconfig.json --noEmit` (client) | ❌ 2 errors (`McpAndAgentsHub.tsx:409`, `<strike>`) |
| `vite build` | ✅ (≈367 KB JS, no type-check) |
