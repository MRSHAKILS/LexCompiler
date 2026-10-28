# LexCompiler — Project Limitations Report

**Scope:** Entire repository at `main` commit `51f69ae` (PRs #18–#25 included)
**Previous revision of this report:** commit `b91b223`
**Date:** 2026-10-28
**Method:** I read every server module, the shared types, the target repo, the CI/Docker config, and a sample of the React UI, and ran:
- `npm ci`
- `npm test`
- `tsc --noEmit` for both TypeScript projects
- `vite build`
- a throwaway probe suite that checks suspected behaviour against the actual code ([Appendix A](#appendix-a--probe-results))

Every finding from the previous revision was re-checked against the new code and marked **Fixed**, **Partial**, or **Open**.

---

## 1. Executive Summary

LexCompiler is a working **demo** with a polished UI. Parts of it are real:
- it calls Microsoft Z3 through `z3-solver`, now with tracked assertions, unsat cores read back from the solver, and models
- it parses TypeScript with the TypeScript Compiler API and Python with `ast`
- it signs with Ed25519, fetches from the Federal Register, and builds unified diffs

PRs #18–#25 made real progress:
- **Remediation:** patches are now surgical value edits that keep the rest of the file, and a repair loop re-verifies them.
- **Prover and compiler:** both cover 6 rule categories, and the compiler handles weeks, months and years.
- **Analyzer:** no longer keyed to specific file names.
- **BYOC scanner:** now runs the real pipeline.

Several serious limitations remain:

1. **Unauthenticated remote code execution (unchanged).** Any client can write any file, path traversal included, through `POST /api/repo/update-file`. `GET /api/sandbox/verify-runtime` then `exec()`s the target Python files in-process. There is no auth, and CORS is wide open.
2. **The PR gate still over-claims.** `postPatchZ3Status` is now honest, but every PR is still `READY_TO_MERGE`, and the summary still says "all invariants transition from UNSAT → SAT". `/api/remediation/apply-pr` applies the patch without checking the result. The UI always says "Microsoft Z3 proved 100% SAT_COMPLIANT".
3. **The law parser can still silently weaken the law.** It is first-match regex with no negation handling. "Backups 90 days, but PII purged within 3 days" still compiles to **2160 h** (90 days). LLM fallback values are merged without range checks.
4. **Code analysis is still name- and text-based, not data-flow.**
   - `24 * 30` is read as 24 h.
   - `SESSION_TTL_SECONDS = 3600` is read as **3600 hours**.
   - `x = payload.ssn; logger.info(x)` is missed.
   - Only the 5 bundled files are ever read.
5. **Many reported metrics are still hard-coded constants:** RAGAS scores, agent token counts and latencies, dedup and caching ratios, and LLM fallback throughput. The UI and API present them as measurements.

---

## 2. Severity & Status Legend

| Level | Meaning |
| :--- | :--- |
| 🔴 **Critical** | Security hole, or the system reports something false that a user would act on (e.g., "compliant", "verified") |
| 🟠 **High** | Core capability is missing or works only on the demo fixture; documented behaviour doesn't exist |
| 🟡 **Medium** | Correctness or robustness gap with limited blast radius; misleading but secondary output |
| 🔵 **Low** | Quality, maintainability, docs, or UX issue |

| Status | Meaning |
| :--- | :--- |
| ✅ **Fixed** | Resolved by PRs #18–#25 (kept for traceability) |
| ◐ **Partial** | Improved, but the limitation still applies in some form |
| ⬜ **Open** | Unchanged since `b91b223` |

---

## 3. Findings at a Glance

| # | Area | Limitation | Severity | Status |
| :-- | :--- | :--- | :--- | :--- |
| S1 | Security | Arbitrary file write and path traversal via `/api/repo/update-file` | 🔴 | ✅ Fixed (branch) |
| S2 | Security | Unsandboxed `exec()` of repo Python → RCE chain with S1 | 🔴 | ◐ Partial (branch) |
| S3 | Security | No authentication or authorization on any endpoint; `cors()` allows all origins | 🔴 | ✅ Fixed (branch) |
| S4 | Security | Signature verify endpoint accepts a caller-supplied public key | 🟠 | ⬜ Open |
| S5 | Security | User OpenAI API key passes through an unauthenticated backend | 🟡 | ⬜ Open |
| S6 | Security | Synchronous subprocesses block the event loop → easy DoS | 🟡 | ◐ Partial |
| V1 | Verification | PR gate over-claims: always `READY_TO_MERGE`; apply ignores result; UI says 100 % | 🔴 | ✅ Fixed (branch) |
| V2 | Verification | Unsat cores and models from Z3, but hand-built fallbacks and non-Optimize repair values | 🟡 | ◐ Partial |
| V3 | Verification | Z3 only checks ground constants; no symbolic program semantics | 🟠 | ⬜ Open |
| V4 | Verification | Displayed and hashed SMT-LIB2 differs from what actually ran | 🟠 | ⬜ Open |
| V5 | Verification | OPA Rego is generated but never evaluated; "denials" are template strings | 🟠 | ⬜ Open |
| V6 | Verification | Cross-border axiom hard-codes "non-EU egress forbidden" | 🟡 | ⬜ Open |
| V7 | Verification | `unknown` treated as `unsat`; defaults for missing facts are inconsistent | 🟡 | ⬜ Open |
| V8 | Verification | One entity per construct type; fixed 5-node graph | 🟠 | ◐ Partial |
| L1 | Legal compiler | First-match regex; no negation, exceptions, or number words | 🔴 | ◐ Partial |
| L2 | Legal compiler | Fixed set of categories (now 6); category supplied by caller in the main API | 🟠 | ◐ Partial |
| L3 | Legal compiler | Generated SMT, Rego, and AST queries are fixed templates naming demo identifiers | 🟠 | ⬜ Open |
| L4 | Legal compiler | Curated "statute" excerpts contain obligations that aren't in the cited law | 🔴 | ✅ Fixed (branch, labelled) |
| L5 | Legal compiler | LLM fallback output overrides parsed values without validation | 🟡 | 🆕 New |
| A1 | AST analysis | Detection keyed to name patterns instead of semantics | 🟡 | ◐ Partial |
| A2 | AST analysis | Only literal constants; expressions and units misread | 🔴 | ⬜ Open (worse) |
| A3 | AST analysis | SQL "parser" is a line regex that depends on comment annotations | 🟠 | ◐ Partial |
| A4 | AST analysis | No data-flow or taint tracking; text matching for PII logging | 🟠 | ◐ Partial |
| A5 | AST analysis | Only 5 known files are ever read; can't scan an arbitrary repo | 🟠 | ⬜ Open |
| R1 | Remediation | Whole-file template rewrites that drop user code | 🟠 | ✅ Fixed |
| R2 | Remediation | Generated "encryption" helper leaks the first 4 plaintext characters | 🟡 | ⬜ Open |
| R3 | Remediation | AI-triage patch changed business semantics | 🟡 | ✅ Fixed |
| R4 | Remediation | No real Git branch or PR; `prNumber: 409` is hard-coded | 🟠 | ⬜ Open |
| R5 | Remediation | First clause per category sets the initial patch parameters | 🔵 | ◐ Partial |
| B1 | BYOC scanner | One-file scans always fail on default Postgres/cache facts | 🟡 | ◐ Partial |
| B2 | BYOC scanner | Regex rewrite broke every log call | 🟡 | ✅ Fixed |
| X1 | Sandbox | Not isolated; TypeScript never executed; logic duplicated in Python regexes | 🟠 | ⬜ Open |
| X2 | Sandbox | SQLite stands in for PostgreSQL; FastAPI and Pydantic shimmed | 🟡 | ⬜ Open |
| C1 | Attestation | Ed25519 key regenerated every process start; old certs unverifiable | 🟠 | ◐ Partial (branch) |
| C2 | Attestation | "Merkle root" is a flat hash; "commit hash" isn't a Git hash | 🟡 | ⬜ Open |
| C3 | SARIF | Invalid property casing (`SemanticVersion`); hard-coded repo URI | 🟡 | ⬜ Open |
| C4 | Attestation | Certificate claims conformity with EU AI Act Art. 43 / SOC 2 | 🟠 | ✅ Fixed (branch) |
| AI1 | Agents | The 6-agent "crew" is a static report; no agent framework is called | 🟠 | ⬜ Open |
| AI2 | RAG | Default "384-d embeddings" are a 16-dim keyword bag; pgvector and Neo4j absent | 🟠 | ⬜ Open |
| AI3 | RAG | RAGAS metrics are hard-coded constants (0.991 etc.) | 🟠 | ⬜ Open |
| AI4 | Tokens | Token-savings benchmark inflates the baseline ×4 and uses fixed ratios | 🟡 | ⬜ Open |
| AI5 | LLM mesh | Fallbacks fabricate token and throughput numbers when Ollama is down | 🟡 | ⬜ Open |
| M1 | MCP | Not spec-compliant JSON-RPC/MCP; SSE closes after one event; unknown tool → success | 🟡 | ⬜ Open |
| M2 | MCP | Stdio server ignores runtime clause state | 🔵 | ⬜ Open |
| P1 | Architecture | Global in-memory mutable state; single-tenant; lost on restart | 🟠 | ⬜ Open |
| P2 | Architecture | Reads re-parse, run Z3 repeatedly, and write the ledger | 🟡 | ⬜ Open (heavier) |
| P3 | Architecture | Z3 `Context` created per call and never released; no solver timeout | 🔵 | ⬜ Open |
| T1 | Testing | One test file, 5 happy-path tests; some assert on constants | 🟠 | ⬜ Open |
| T2 | Testing/CI | Client type errors; CI doesn't type-check the client or lint | 🔵 | ◐ Partial |
| T3 | Testing/CI | CLIs never fail on remaining violations; `verify:cli` not in CI | 🟡 | ⬜ Open |
| T4 | Testing/CI | CLIs and tests reset and overwrite `target-repo/` on disk | 🔵 | ⬜ Open |
| D1 | Deployment | Docker image omits Ollama, runs as root, has no volume for `data/` | 🟡 | ⬜ Open |
| D2 | Deployment | Health check always reports `ok` / `ready` | 🔵 | ⬜ Open |
| DOC1 | Docs | README and `AGENTS.md` describe features that don't exist | 🟠 | ⬜ Open |
| DOC2 | Docs | README says MIT but there is no `LICENSE` file; package name differs | 🔵 | ⬜ Open |
| U1 | Frontend | Minimal accessibility, no frontend tests, large components, hard-coded claims | 🔵 | ⬜ Open |

**Tally (`51f69ae`):** 3 fixed · 12 partial · 40 open · 1 new (56 findings).
**Tally (this branch, after the P0 fixes in §6):** 8 fixed · 13 partial · 34 open · 1 new.

---

## 4. Detailed Findings

### 4.1 Security

#### S1 🔴 ⬜ Arbitrary file write with path traversal
`writeTargetRepoFile` (`server/analyzer/repoBaseline.ts:233`) strips leading `/` and then calls `path.join(TARGET_REPO_ROOT, relPath)`, with no check that the result stays inside `target-repo/`. `POST /api/repo/update-file` (`server/index.ts:618`) passes the request's `filePath` straight in. A re-probe on `51f69ae` confirmed `../server/index.ts` → `/home/user/LexCompiler/server/index.ts`. Any network client can overwrite the server's own source, `package.json`, shell profiles, and so on.

#### S2 🔴 ⬜ Unsandboxed execution → RCE chain
`executeRealWorldSandboxVerification` (`server/sandbox/realWorldSandbox.ts:196,216`) runs `exec(compile(...))` on `api/fastapi_intake.py` and `workers/redis_cache_worker.py` inside a plain `python3` process, running as the server user with full filesystem and network access. Combined with S1, or even a legitimate `update-file` call, anyone who can reach the port gets code execution:
`POST /api/repo/update-file {filePath:"api/fastapi_intake.py", content:"import os; os.system(...)"}` → `GET /api/sandbox/verify-runtime`.
There is no container, seccomp, user namespace, or resource limit beyond a 5 s timeout.

#### S3 🔴 ⬜ No authentication; permissive CORS
None of the 26 endpoints check identity or authorization. `app.use(cors())` (`server/index.ts:63`) lets any web page the user visits call the local server, including the state-changing endpoints: file writes, repo reset, applying PRs, Git commits, and clause edits.

#### S4 🟠 ⬜ Signature verification accepts an attacker key
`verifyEd25519CertificateSignature` (`server/enterprise/enterpriseSuite.ts:119`) verifies against an optional caller-supplied `publicKeyPem`. A forger signs any payload with their own key, supplies that key, and gets `verified: true`. There is no trust anchor, key pinning, or certificate chain.

#### S5 🟡 ⬜ Cloud API key passes through the backend
The UI (`src/components/LiveMultiLlmMeshStudio.tsx`) sends a user-typed OpenAI key in the JSON body of `/api/llm/generate`. Combined with S3, the key travels through an unauthenticated server that any web page can call.

#### S6 🟡 ◐ Event-loop blocking → DoS
**Improved:** Python AST results are now cached by content hash (`server/analyzer/astAnalyzer.ts:471`), so unchanged files aren't re-parsed.
**Still open:** `execFileSync('python3', …)` still blocks the whole Node process on every cache miss (3 s timeout), in the sandbox (5 s), and on every SQLite ledger read and write (3 s). The LLM fallback in the compiler adds an awaited network call of up to 8 s to clause compilation.

### 4.2 Formal Verification (Z3 / OPA)

#### V1 🔴 ◐ The PR gate still over-claims
**Improved:**
- `postPatchZ3Status` is now `allResolved ? 'SAT_COMPLIANT' : 'UNSAT_VIOLATION'` (`server/remediation/prSynthesizer.ts:631`).
- A repair loop (up to 3 rounds, line 539) re-patches leftover violations from each proof's `repairTargets`.
- The earlier probe (a lenient 30-day clause next to the strict 72-hour clause) now really reaches `SAT_COMPLIANT` for every clause.

**Still open:**
- `status` is always `'READY_TO_MERGE'` (line 621), even when `postPatchZ3Status` is `UNSAT_VIOLATION`.
- `executiveSummary` always says "confirmed all N statutory invariants transition from UNSAT → SAT".
- `unresolvedClauseIds` and `cegisIterations` exist in the type but are never set.
- `POST /api/remediation/apply-pr` (`server/index.ts:592`) writes every patch to disk and commits without checking `postPatchZ3Status`.
- After applying, the UI always shows "Microsoft Z3 proved 100% SAT_COMPLIANT" (`src/App.tsx:291`).

The `AGENTS.md` §3 rule ("every synthesized patch MUST pass the Pre-PR Z3 Sandbox Gate") is still not enforced.

#### V2 🟡 ◐ Unsat cores and models
**Improved:**
- Assertions are tracked with `assertAndTrack` (`server/prover/z3Engine.ts:38`).
- Cores come from `solver.unsatCore()` (line 48).
- Models come from `solver.model()` (line 58).

**Still open:**
- When the solver returns an empty core, the code falls back to hand-written names (e.g. lines 354–368), and nothing in the proof shows which path was used.
- `Z3RepairTarget` is documented in `shared/types.ts` as "the minimal-change value Z3 Optimize found". But no Optimize call exists: `requiredValue` is just the clause bound (e.g. `requiredValue: maxHours`).
- `counterexampleWitness` is still the input values.

#### V3 🟠 ⬜ Z3 is evaluating constants
Every code-side variable is still pinned to a concrete value and every law-side variable to a concrete bound. Each query reduces to an inequality like `720 ≤ 72`. Nothing models program paths, data flow, or quantifiers over entities; the first-order formulas shown to users are decoration.

#### V4 🟠 ⬜ The SMT text you see isn't what ran
Z3 runs through the programmatic API, while `smtLib2Executed` is assembled separately from the clause's template snippet. For example, the retention template still doesn't declare `redis_worker_uses_tenant_kms`, but the solver asserts it. `smtFormulaSha256`, and the per-clause "Merkle" hash built from it, hash the *display* text, so the provenance chain doesn't attest to the formula that was actually solved.

#### V5 🟠 ⬜ OPA Rego is never evaluated
There is no OPA binary, WASM module, or Rego library among the dependencies. `opaRegoTriggeredDenials` are hand-written template strings. The generated Rego is never syntax-checked, and it uses pre-v1 syntax (`deny[msg] {`), which OPA v1.x rejects by default.

#### V6 🟡 ⬜ Cross-border law is hard-coded
`assertAndTrackNamed(..., 'law_gdpr_ch5_sovereign_residency', sAllowsNonEu.eq(false))` (`server/prover/z3Engine.ts:1121`) ignores the clause's own `statutory_allows_non_eu_egress` value. A clause that permits US transfers under SCCs still gets the "no non-EU egress" axiom. Region membership is still decided in TypeScript.

#### V7 🟡 ⬜ Unknown results and default facts
- `status: extra.z3Result === 'sat' ? 'SAT_COMPLIANT' : 'UNSAT_VIOLATION'` (`server/prover/z3Engine.ts:123`) still reports a solver `unknown` as a proven violation. No solver timeout is set.
- Defaults for missing constructs are still inconsistent:
  - a missing table, cache, or AI engine defaults to a violation (720 h, 0.68, `us-east-1`)
  - a missing logger defaults to compliant
  - a missing SQL table makes `postgresEncryptedAtRest = true`

  This is also the root cause of B1.

#### V8 🟠 ◐ One instance per construct
**Improved:** `pickPiiTable`/`pickFinding` (`server/prover/z3Engine.ts:78–96`) prefer a sensible candidate instead of requiring `patient_records`. The analyzer now emits findings for *every* table and leaking logger call.
**Still open:**
- The prover still verifies only the *first* match of each construct type. A second PII table or a second cache worker is analyzed but never checked.
- The architecture graph is still a fixed set of 5 nodes and 4 edges.

### 4.3 Legal-to-Logic Compiler

#### L1 🔴 ◐ Regex extraction can still silently weaken the law
**Improved** (`server/compiler/legalCompiler.ts`):
- `extractTemporalHoursFromProse` (line 71) understands minutes, days, weeks, months, and years.
- Missing numbers are marked `DETERMINISTIC_DEFAULT` in `extractionProvenance`, and the async path asks an LLM to fill the gap.

**Still open** (probe on `51f69ae`):

| Input | Extracted | Problem |
| :--- | :--- | :--- |
| "Backups may be kept 90 days, but PII must be purged within **3 days**." | **2160 h** (90 days) | First match wins: **30× more lenient** than the law |
| "purged within seventy-two hours" | 720 h (`DETERMINISTIC_DEFAULT`) | Number words unsupported by the deterministic parser |
| "purged within one week" | 720 h (`DETERMINISTIC_DEFAULT`) | "one week" not parsed (though "2 weeks" → 336 h works) |
| "PII **need not** use tenant-isolated keys…" | `requiresTenantIsolatedKeys: true` | Negation ignored |
| "Logging of email addresses is **permitted**." (`PII_LOGGING_BAN`) | `forbidPlaintextLogging: true` | Category forces prohibition |

Hours still always win over days. The default of 720 h when nothing parses still becomes a formal axiom, and the `DETERMINISTIC_DEFAULT` flag isn't surfaced as a warning in the proof or the UI.

#### L2 🟠 ◐ Fixed categories
**Improved:** two more categories (`ENCRYPTION_AT_REST`, `RIGHT_TO_ERASURE_CASCADE`, 6 in total), and `inferRuleCategoryFromProse` (line 106) infers a category from text.
**Still open:**
- Inference is only used by the BYOC scanner. `POST /api/clauses/compile` still takes the category from the caller and defaults to retention.
- Consent, purpose limitation, breach notification, DPIA, access rights, and minimisation still can't be expressed.
- `PERMISSION` is never produced.

#### L3 🟠 ⬜ Generated artifacts are fixed templates
SMT-LIB2, Rego, and "Tree-sitter" queries are still string templates with demo identifiers (`patient_records`, `ingest_patient_pii`, `PII_CACHE_TTL_HOURS`, `REPLICA_TARGET_REGION`, …). Tree-sitter queries are never run.

#### L4 🔴 ⬜ Invented statutory content
Unchanged. These texts are presented as real law, with official EUR-Lex/eCFR URLs, but contain obligations the cited instruments don't have:
- The "EUR-Lex" EU AI Act excerpt adds "Minimum confidence gate 0.88 (88%)" (`legalCompiler.ts:1045`). Art. 14 sets no numeric threshold.
- The "GDPR Art. 17" excerpt says PII must be "purged within 72 hours" (line 1057). GDPR sets no such period; its 72 hours is the Art. 33 breach-notification deadline.
- A Federal Register result with no abstract gets a made-up 72-hour-purge excerpt substituted (lines 1090–1091).
- The fallback HIPAA item "89 FR 104210" (line 1106) doesn't match a real rulemaking: volume 89 is the 2024 volume, but the item is dated 2026-09-18.

#### L5 🟡 🆕 LLM fallback output isn't validated
`mergeLlmBounds` (`legalCompiler.ts:236`) copies every typed field from the LLM's JSON over the deterministic result:
- `requiresTenantIsolatedKeys`, `forbidPlaintextLogging`, and `allowedDataRegions` are overwritten even where the regex parser had evidence.
- There is no range check: e.g. `minAiConfidenceThreshold: 85` would be accepted as-is instead of 0.85.
- The default model is a 0.5 B coder model.

A hallucinated value becomes a "proven" axiom. The provenance records `LLM_JSON_FALLBACK`, but nothing asks a human to confirm it.

### 4.4 Polyglot AST Analysis

#### A1 🟡 ◐ Detection keyed to name patterns
**Improved:** extraction is no longer gated on file names. It scans any `.py`/`.ts` file using regex families over identifiers (`TTL_ASSIGN_NAMES`, `KMS_ASSIGN_NAMES`, `CONFIDENCE_NAMES`, … in `server/analyzer/astAnalyzer.ts:13–27`).
**Still open:** naming decides everything.
- A TTL constant named `KEEP_FOR` is invisible.
- Any number assigned to a name containing `threshold` or `min_score` is read as the AI confidence gate.
- `pickConstant` takes the first match in object order.

#### A2 🔴 ⬜ Only literal constants; expressions and units misread (worse)
Python values are still recorded only for `ast.Constant`. Otherwise the code falls back to a regex (`astAnalyzer.ts:589–595`). Re-probe:
- `PII_CACHE_TTL_HOURS = 24 * 30` (720 h) → read as **24 h**, a false "compliant".
- **New:** `SESSION_TTL_SECONDS = 3600` (1 hour) → read as **3600 hours**, because the wider name match (`ttl…sec`) accepts it but no unit conversion is applied. `SourceEditAnchor.hoursPerUnit` exists in the types but is never set.

Environment variables, config files, class attributes, `setex()` TTL arguments, TypeScript `as const`, template literals, and imported constants are all still ignored.

#### A3 🟠 ◐ SQL "parser" is a line regex
**Improved:**
- PII is now inferred from column-name patterns without annotations (`isInferredPiiColumn`, line 65).
- Foreign keys are tracked per table via `dependentForeignKeys`.
- The previous cascade-overwrite bug is gone.

**Still open:**
- It is still a per-line regex (`CREATE TABLE` on one line, `);` or `)` closes it).
- Encryption and retention still come only from `@encrypted(...)` / `@retention_hours(...)` comments or a `retention_ttl_hours INT DEFAULT n` column.
- Multi-line columns, table constraints, `ALTER TABLE`, quoted identifiers, and real Postgres encryption (pgcrypto, TDE) aren't understood.
- Tables without a retention column default to 720 h in their finding.

#### A4 🟠 ◐ No real taint tracking
**Improved:** all logging sinks (`logger.*`, `logging.*`, `console.*`, `print`) and every leaking call are examined, not just the first `logger.info`.
**Still open:** the "taint analysis" in the docstring is substring matching of PII-looking names inside the unparsed call (`astAnalyzer.ts:607–616`). Re-probe:
- `x = payload.ssn; logger.info(f"rec {x}")` → **missed** (false negative).
- `logger.info(f"email_count={len(rows)}")` → **flagged as a PII leak** (false positive).
- Any `redact_pii` text in the call still suppresses detection, even if raw PII is also logged.

#### A5 🟠 ⬜ Closed-world file list
`readTargetRepoFiles()` (`server/analyzer/repoBaseline.ts`) still iterates over the 5 fixed paths in `INITIAL_REPO_FILES`. New files in `target-repo/` are never scanned, and the tool can't be pointed at another repository. Only BYOC accepts arbitrary input, one file at a time.

### 4.5 Remediation / "CEGIS" PR Synthesis

#### R1 🟠 ✅ Whole-file rewrites — **Fixed**
Patches are now value-level edits at analyzer-provided `SourceEditAnchor`s: retention literals, flags, region strings, log arguments, column insertion points. A re-probe confirmed a custom function appended to `api/fastapi_intake.py` survives patching (+17/−5 lines). Calling the 3-round repair loop "CEGIS" is still generous: there's no candidate synthesis, only re-applying fixed rewrite rules.

#### R2 🟡 ⬜ The "fixed" crypto is still insecure
`TENANT_KMS_HELPER` (`server/remediation/prSynthesizer.ts:21–24`) is inserted into patched files. It returns `f"enc_kms::{tenant_id}::{plaintext[:4]}***"`: no encryption, and it **leaks the first 4 characters** of SSNs. `redact_pii` still uses an unsalted, truncated SHA-256, which is easy to brute-force for low-entropy values. Patched code is still never compiled, type-checked, or tested before being labelled "verified".

#### R3 🟡 ✅ AI-triage semantics — **Fixed**
The TypeScript patch now changes only the three constants (`0.68 → 0.85`, `false → true` ×2) and leaves the decision logic intact.

#### R4 🟠 ⬜ No real PR
`prNumber: 409` and the branch name are still constants. Nothing calls the GitHub API. "Apply PR" writes into `target-repo/` and commits to the private `data/sandbox-git` repository.

#### R5 🔵 ◐ First clause per category sets initial parameters
The first-pass patch still takes `maxHours`, `minAiConf`, and `allowedRegion` from `clauses.find(...)`. The repair loop now fixes the probe case afterwards, which is why the severity is lowered. Two limits remain:
- **Region choice:** `allowedRegion` is always `allowedDataRegions[0]`.
- **Conflicting clauses:** clauses that contradict each other (e.g. two different regions) give up after 3 rounds, yet the PR is still marked `READY_TO_MERGE` (see V1).

### 4.6 BYOC Custom Scanner (`executeByocCustomScan`, `server/enterprise/enterpriseSuite.ts:259`)

#### B1 🟡 ◐ One-file scans always fail on default facts
**Improved:** BYOC now infers categories, compiles them with the real compiler, runs the real analyzer, prover, and synthesizer, and uses the `language` parameter.
**Still open:** a single file has no SQL table, so the prover falls back to its defaults (720 h Postgres retention, no tenant KMS; see V7). Re-probe:
- a two-line `def f(x): return x` with a 48 h clause → `UNSAT_VIOLATION` ("Postgres table 'pii_table' retention (720h > 48h)")
- a cache file with `CACHE_TTL_HOURS = 24` → still `UNSAT_VIOLATION` on that phantom table

#### B2 🟡 ✅ Regex rewrite of every log call — **Fixed**
The regex rewriter has been replaced by the shared surgical synthesizer.

### 4.7 "Real-World" Runtime Sandbox (unchanged)

#### X1 🟠 ⬜ Not isolated, and TypeScript is never executed
Besides S2, the TypeScript services aren't executed. The Python runner regex-scans the `.ts` text and **re-implements** the logic. Both branches of `if human_gate:` are identical (`realWorldSandbox.ts:243`). The 0.85 threshold, test confidence 0.78, payload, and SSN are hard-coded. The sandbox still reads fixed paths, so it doesn't follow the analyzer's generalisation.

#### X2 🟡 ⬜ Different runtimes from what's claimed
- **Database:** PostgreSQL DDL runs in SQLite.
- **Shims:** `fastapi` and `pydantic` are replaced by dummy shims when missing, and Redis is a mock object.
- **Python version:** "Python 3.12" is stated, but whatever `python3` is installed gets used (3.13 here).

### 4.8 Attestation, Certificates & SARIF (unchanged)

#### C1 🟠 ⬜ Ephemeral signing key
`crypto.generateKeyPairSync('ed25519')` runs at module load (`enterpriseSuite.ts:22`). Every restart creates a new key, so earlier certificates can't be verified. The issuer string "**Hardware-Backed Root**" (line 93) is false: the key lives in process memory. There's no X.509, timestamping, or revocation.

#### C2 🟡 ⬜ Hash naming is misleading
- **"Merkle audit root":** `sha256(hash1|hash2|…)`, a flat hash with no tree.
- **`commitHash`:** `sha256(file contents + commitCounter)[:8]`, not the Git commit hash.
- **`repositoryName`:** hard-coded to `finhealth-ai/core-platform`.

#### C3 🟡 ⬜ SARIF validity
- `tool.driver.SemanticVersion` (line 223) should be `semanticVersion`; SARIF property names are case-sensitive.
- `repositoryUri` (line 230) is hard-coded to a fictitious repository.
- `uri` is prefixed `target-repo/`, which only resolves correctly for this repo.
- CI never uploads SARIF.

#### C4 🟠 ⬜ Certificate claims a conformity standard
Certificates name the standard `EU-AI-ACT-ART43 / GDPR-ART32 / HIPAA-164.312 / SOC2-CC6.1` and the verdict `SAT_COMPLIANT_CERTIFIED`. Art. 43 conformity assessment is a defined legal procedure: internal control under Annex VI or a notified body under Annex VII, with technical documentation and a quality management system. A SOC 2 report must come from a licensed CPA firm. A self-signed demo certificate shouldn't be labelled this way.

### 4.9 AI / Agents / RAG / Token Optimisation (unchanged)

#### AI1 🟠 ⬜ The 6-agent crew isn't implemented
`buildMultiAgentExecutionReport` (`server/agents/multiAgentOrchestrator.ts`) returns a static array. Framework names (CrewAI, DSPy, LangGraph, Pydantic-AI, Swarm, Hermes), models, token counts, latencies, and `status: 'COMPLETED'` are all literals. The only real LLM use in the codebase is Ollama/OpenAI in the RAG answer, the multi-model demo endpoint, and the new compiler fallback. `AGENTS.md` §2 describes an architecture that isn't in the code.

#### AI2 🟠 ⬜ Default "384-d neural embeddings" are a keyword bag
`computeSemanticEmbedding` (`server/rag/hybridRagEngine.ts`) counts keyword hits across 16 "domain dimensions" and reports `embeddingDimension: 384`. Real Ollama embeddings are only used to *re-score* the top-K chunks the keyword path already picked, sequentially, one HTTP call per chunk. pgvector, Neo4j, HyDE, and CRAG are display strings or fixed rules.

#### AI3 🟠 ⬜ RAGAS metrics are constants
`contextPrecision: 0.964, contextRecall: 0.982, faithfulness: 0.991, …` are literals. The test suite asserts `faithfulness > 0.95`, which only tests the constant.

#### AI4 🟡 ⬜ Token-savings benchmark is inflated by design
`runTokenOptimizationBenchmark` (`server/optimization/tokenOptimizer.ts:134–153`):
- multiplies the raw token baseline by 4 ("simulate amplification")
- applies dedup as a fixed `× 0.78` and KV caching as a fixed `× 0.34`
- counts tokens with a chars/3.6 heuristic
- reports constant latency savings

"Codeburn" drops Python indentation, so its output isn't valid Python.

#### AI5 🟡 ⬜ LLM fallbacks fabricate telemetry
When Ollama is unreachable, `runRealLlmInference` returns `tokensPerSecond: 65.0`, fixed token counts, and placeholder text. The UI shows these exactly like real inference.

### 4.10 MCP Servers (unchanged)

#### M1 🟡 ⬜ Not protocol-compliant
- **HTTP RPC:** `POST /api/mcp/:serverId/rpc` ignores `method` (always `tools/call`, no `initialize` or `tools/list`). It returns a wrapper instead of a JSON-RPC response and invents its own `id`.
- **Unknown server or tool:** returns `isError: false` with empty output.
- **SSE:** writes one event and closes the stream.
- **stdio:** unknown methods get no response, and every error is `-32700` with `id: null`.
- **Spec version:** results use `structuredOutput`, which isn't a field in protocol `2025-03-26`.
- **SDK:** the official SDK isn't used.

#### M2 🔵 ⬜ Stdio server state
The stdio server uses `getInitialClauses()`, so clients never see amended clauses.

### 4.11 Architecture, State & Scalability

#### P1 🟠 ⬜ Global, volatile, single-tenant state
`activeClauses`, `activeAmendmentLabel`, and `commitCounter` are module-level variables in `server/index.ts`. There's no locking around concurrent file writes and Git commits, and everything is lost on restart.

#### P2 🟡 ⬜ Expensive, side-effecting reads (heavier)
`GET /api/state`, `/api/enterprise/certificate`, and `/api/enterprise/sarif` each:
- re-read the files and run Z3 for every clause
- run the synthesizer, which now re-analyzes and re-verifies **up to 4 times** (initial plus 3 repair rounds)
- **write a row to the SQLite ledger**

`/api/ai-heavy/overview` and `/api/rag/query` repeat the parsing and Z3 work without the ledger write.

#### P3 🔵 ⬜ Z3 context lifecycle
`new Context('lexcompiler_prover')` is still created on every verification call, now up to 5 times per report, and never released. No solver timeout is set.

### 4.12 Testing & CI

#### T1 🟠 ⬜ Thin test suite
Still one file (`server/lexcompiler.test.ts`, unchanged by PRs #18–#25) with 5 happy-path tests:
- **No coverage for the new code:** none of the new behaviour has a test (unit parsing, category inference, unsat cores, anchors, repair loop, BYOC pipeline, LLM fallback).
- **Constant assertions:** the RAGAS, token-reduction, and agent-count assertions still check constants (AI1, AI3, AI4).
- **No negative cases, no endpoint tests, no frontend tests.**

#### T2 🔵 ◐ Type-check & lint
**Fixed:** the client type errors (`<strike>` → `<s>`); `tsc --noEmit` now passes for both projects.
**Still open:** CI still doesn't run a type-check (`vite build` skips it), and there's no ESLint/Prettier config.

#### T3 🟡 ⬜ The "gate" doesn't gate
`cli-verify.ts` always exits `0`. `cli-realworld-demo.ts` fails only if no PR is synthesized. `AGENTS.md` requires `verify:cli`, but CI runs `verify:realworld`, and CI never runs LexCompiler against the PR's own diff.

#### T4 🔵 ⬜ Destructive CLIs and tests
`verify:cli`, `verify:realworld`, and the tests reset `target-repo/` and delete `data/sandbox-git`.

### 4.13 Deployment & Operations (unchanged)

#### D1 🟡 ⬜ Container gaps
- **Missing service:** no Ollama in `docker-compose.yml`, so the LLM paths, including the new compiler fallback, always fall back.
- **No volume:** `data/` isn't mounted, so the ledger and sandbox Git are lost when the container is recreated.
- **Build and runtime:** the image uses `npm install` instead of `npm ci`, ships devDependencies, and runs as root (which makes S1/S2 worse).

#### D2 🔵 ⬜ Health check is static
`/api/health` always returns `status: 'ok'` without checking Z3, Python, or Ollama.

### 4.14 Documentation & Positioning (unchanged)

#### DOC1 🟠 ⬜ Docs describe a different system
README and `AGENTS.md` still claim the 6-agent crew, OPA evaluation, pgvector + Neo4j Graph RAG, RAGAS evaluation, LLMLingua-2, KV-cache pinning, and "opens PR #409". The new genuine features aren't documented: unsat cores, surgical patches, the repair loop, and LLM fallback provenance.

#### DOC2 🔵 ⬜ Housekeeping
- **No license file:** the README says "MIT License", but there's no `LICENSE` file.
- **Inconsistent naming:** `package.json` is named `justicesphere-complianceos`, not LexCompiler.

### 4.15 Frontend

#### U1 🔵 ⬜ UI maintainability and accessibility
- **Accessibility:** minimal `aria-*`/`role` usage.
- **Large components:** `App.tsx` is now ~780 lines (it grew in PR #24 with the collapsible sidebar).
- **Hard-coded text:** `#409` is still baked into several components, and the merge toast always claims 100 % compliance (see V1).
- **Bundle:** a single JS chunk with no code splitting.

---

## 5. Recommendations (Prioritised)

**P0 — Fix before anyone else runs this**
1. **Lock down the server (S1–S3):**
   - confine `writeTargetRepoFile` to `target-repo/` (resolve, then check the prefix) and to known files
   - add authentication
   - restrict CORS and bind to `127.0.0.1` by default
2. **Sandbox or drop runtime execution (S2):** run target code only in a real sandbox (an unprivileged container or gVisor/nsjail with no network), or remove it.
3. **Finish V1:**
   - derive `status` from `postPatchZ3Status`
   - fill in `unresolvedClauseIds`
   - generate the summary from the actual result
   - make `/api/remediation/apply-pr` refuse an unresolved PR
   - show the real result in the UI toast
4. **Label demo content (L4, C1, C4):** mark the invented "statute" excerpts and fallback feed items as **illustrative**, and remove the "Hardware-Backed" and "CERTIFIED" wording.

**P1 — Make the verification honest**
5. **Units and expressions (A2):** constant-fold Python and TypeScript expressions (`24 * 30`), and convert by unit suffix (`_SECONDS`, `_DAYS`) using the existing `hoursPerUnit` field.
6. **Missing facts (V7, B1):** handle missing constructs as "not applicable / needs review" rather than defaulting to 720 h. This fixes BYOC false violations. Treat `unknown` separately and set a solver timeout.
7. **Law-parser bounds (L1, L5):**
   - choose the bound attached to the regulated subject, or the strictest one, instead of the first number
   - detect negation ("need not", "is permitted")
   - validate LLM output ranges, and require confirmation for `LLM_JSON_FALLBACK` / `DETERMINISTIC_DEFAULT` axioms
8. **Rego and SMT text (V4, V5):** evaluate the generated Rego with OPA, or stop reporting "OPA denials". Hash and display the formula that was actually solved.
9. **Cover every instance (V8):** verify every finding of each construct type, not only the first.

**P2 — Generalise beyond the fixture**
10. **Arbitrary repos (A5):** scan any directory or Git URL instead of `INITIAL_REPO_FILES`.
11. **Real analysis (A3, A4):** use real parsers (Tree-sitter, `libpg_query`) and basic intra-procedural data flow for PII.
12. **Signing key (C1, S4):** use a persistent key (KMS/HSM or a configured key file), publish it, and drop the endpoint that verifies against a caller-supplied key.
13. **Insecure helper (R2):** remove `encrypt_with_tenant_kms`'s plaintext prefix, and compile/test patched code.

**P3 — Engineering hygiene**
14. **Responsiveness (S6, P2):** move `execFileSync` to async workers, and make `GET` endpoints free of side effects.
15. **MCP (M1):** use the official MCP SDK.
16. **Tests and CI (T1–T3):**
    - add tests for the PR #18–#25 behaviour and for negative cases
    - add a client type-check and ESLint to CI
    - upload SARIF
    - exit non-zero on remaining violations
17. **Docker (D1, D2):** `npm ci --omit=dev`, a non-root user, a `data/` volume, an optional Ollama service, and a health check that tests its dependencies.
18. **Docs (DOC1, DOC2):** bring the README and `AGENTS.md` in line with what's implemented, and add a `LICENSE` file.

---

## 6. P0 Fixes on This Branch

These changes on `claude/compassionate-hypatia-3mjhsk` address the P0 recommendations. Each is covered by `server/security.test.ts`, and the security behaviour was also checked against a running server.

| Finding | Change |
| :--- | :--- |
| **S1** ✅ | `writeTargetRepoFile` accepts only the tracked target-repo files and rejects any path that resolves outside `target-repo/`; `update-file` returns `400` instead of writing. |
| **S3** ✅ | New `server/security.ts`: the server binds to `127.0.0.1` by default and refuses a non-loopback `HOST` without `LEXCOMPILER_API_TOKEN`. CORS uses an origin allowlist. Every `/api` route except `/api/health` requires a Bearer token when one is set; otherwise it requires a loopback (or allowlisted) `Host` (DNS-rebinding guard) and the `X-LexCompiler-Client` header (blocks cross-site `<img>`/form requests). The UI adds the header automatically and prompts once for a token if needed (`src/apiClient.ts`). |
| **S2** ◐ | `GET /api/sandbox/verify-runtime` is disabled unless `LEXCOMPILER_ENABLE_RUNTIME_SANDBOX=1`. When it runs (HTTP or CLI), it executes on a temp copy of the files with `python3 -I`, an empty environment, and CPU/memory/file-size/process rlimits. Still open: this is not an isolation boundary (no container or network isolation). |
| **V1** ✅ | PR `status` is `BLOCKED_UNRESOLVED` unless every clause is SAT after patching. The PR now includes `unresolvedClauseIds` and `cegisIterations`, and its summary reflects the real result. `apply-pr` and `apply-node` return `409` for a blocked PR. The UI disables the apply buttons, shows the unresolved clauses, and reports the real clause counts. |
| **L4** ✅ | Built-in clauses and curated or offline feed items carry `illustrative: true` and show an `ILLUSTRATIVE` badge. Invented thresholds are bracketed as demo parameters. Missing Federal Register abstracts are no longer invented, and the fake "89 FR 104210" item is now an explicitly illustrative offline fallback. |
| **C4** ✅ / **C1** ◐ | The certificate `standard` now reads as a self-attestation, not an EU AI Act Art. 43 conformity assessment or SOC 2 report. The verdict is `SAT_COMPLIANT_ATTESTED` / `UNSAT_NON_COMPLIANT`. The issuer says the key is ephemeral rather than "Hardware-Backed". Still open (C1): the key is regenerated on every start. |

## Appendix A — Probe Results

These came from a temporary Vitest file run against unmodified source at `51f69ae`; the file was deleted afterwards.

```text
Legal compiler
  "purged within seventy-two hours."                     -> 720h  (DETERMINISTIC_DEFAULT; expected 72)
  "purged within one week."                              -> 720h  (DETERMINISTIC_DEFAULT; expected 168)
  "purged within 2 weeks."                               -> 336h  ✓
  "need not use tenant-isolated keys … within 72 hours"  -> tenantKms=true (negation ignored)
  "Backups 90 days, but PII purged within 3 days."       -> 2160h (expected 72)
  PII_LOGGING_BAN "Logging … is permitted."              -> forbidPlaintextLogging=true

Prover / remediation (lenient 30-day clause + strict 72h clause)
  Unsat cores now come from Z3, e.g. CLAUSE-DPA-4.2:
    [law_max_retention_72h, law_requires_tenant_kms, ast_postgres_retention_720h,
     ast_postgres_tenant_kms_false, ast_fastapi_tenant_kms_false, ast_redis_ttl_720h]
  PR.postPatchZ3Status = SAT_COMPLIANT; actual re-verification: all 5 clauses SAT  ✓
  PR.status = READY_TO_MERGE (hard-coded regardless of result)
  Custom helper appended to fastapi_intake.py survives patching  ✓ (+17/−5 lines)
  Patched file still contains `plaintext[:4]` leak
  AI patch changes only the three constants  ✓

AST analysis
  PII_CACHE_TTL_HOURS = 24 * 30       -> 24h   (actual 720h)  => false COMPLIANT
  SESSION_TTL_SECONDS = 3600          -> 3600h (actual 1h)    => false VIOLATION
  x = payload.ssn; logger.info(x)     -> not detected (false negative)
  logger.info(f"email_count=…")       -> flagged as PII leak (false positive)

Security
  '../server/index.ts'                -> /home/user/LexCompiler/server/index.ts

BYOC
  `def f(x): return x` + 48h clause            -> UNSAT_VIOLATION (phantom Postgres 720h)
  `CACHE_TTL_HOURS = 24` cache file + 48h      -> UNSAT_VIOLATION (phantom Postgres 720h)
```

## Appendix B — Build & Test Status Observed (`51f69ae`)

| Command | Result |
| :--- | :--- |
| `npm ci` | ✅ |
| `npm test` (vitest) | ✅ 5/5 passed |
| `tsc -p tsconfig.server.json --noEmit` | ✅ |
| `tsc -p tsconfig.json --noEmit` (client) | ✅ (was ❌ at `b91b223`) |
| `vite build` | ✅ |
