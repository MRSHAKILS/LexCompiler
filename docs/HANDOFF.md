# LexCompiler handoff

Written October 29, 2026, after PR #36. Judging is on **December 26, 2026**.

This file says where the work stands, how to run it, and what to do next. The full plan is `docs/PRODUCT_GUIDE.md`: section 4 has the build phases, section 5 covers AI, RAG and MCP, and section 7 has the schedule to judging.

## Working rules

- Every change goes branch → pull request with a detailed description → CI green → merge. Don't push to `main` directly.
- Before a merge, run the full check (below). `AGENTS.md` requires at least `npm test` and `npm run verify:cli`.
- Never commit secrets. `data/` (database, GitHub App key, signing key), `.env` and `repos/` are gitignored.
- The 5 untracked files in `server/analyzer/` (`complianceDetectors.ts`, `programIr.ts`, `pythonIr.ts`, `sqlDdl.ts`, `typescriptIr.ts`) are the owner's analyzer rewrite. Don't commit them; they are saved on the branch `wip/analyzer-ir`.

## Where things stand

| PR | What it did |
|---|---|
| #29, #28 via #30 | Reapplied #26; merged the friend's work and finished its leftovers |
| #31 | Phase 1: product database (`server/db`, `server/product`), workspaces, roles, rule versions, sessions, `npm run seed:demo` |
| #32, #33 | Phase 2: GitHub App that checks pull requests; retries and one check run per job |
| #34 | Product guide section 5: AI, RAG, MCP and setup for coding assistants |
| #35 | Phase 2a, part 1: RAG embeddings fixed, duration parser fixed, model labels that match what ran |
| #36 | Phase 2a, part 2: AI gateway, AI setting per workspace, call log, extraction eval |
| MRSHAKILS/LexCompiler #3 | Bangla and test-repository RAG eval sets |
| MRSHAKILS/LexCompiler #4, #5 | Windows test fixes (4 Vitest workers); RAG: stemmed BM25 with identifier parts; graph seeds and HyDE only from evidenced categories |

| Phase | Status |
|---|---|
| 0–2 | Done, tested live on GitHub |
| 2a AI foundation | Done. RAG eval now has a Bangla set and a set for the test repo (see Evals) |
| 3 Lawyer's workspace | Next. The rule API exists; the screens don't |
| 4 Fixes and exceptions | Not started. The `exceptions` table exists, nothing writes to it |
| 4a MCP for coding assistants | Not started. The six demo MCP servers work |
| 5 Evidence and auditor | Not started. The `evidence`, `shares` and `share_views` tables exist, nothing writes to them |
| 6, 7 | Not started |

## What works today

- **GitHub checks.** The App "LexCompiler d16d" (slug `lexcompiler-d16d`) is installed on https://github.com/shahriar-ahmed-seam/finhealth-core-platform and linked to the workspace "FinHealth AI", which has R-1 to R-4 approved. Its PR #1 is red on purpose: "1 new finding (R-1)" at `api/loan_applications.py:20`. It is the test case for the exception flow in Phase 4. A ruleset blocks merging it.
- **Rules API** (Phase 1, no screens yet): `POST /api/workspaces/<id>/rules` creates a draft, `POST .../rule-versions/<versionId>/approve` and `.../reject` decide it (Legal only), `GET .../rules-in-effect` lists what scans use.
- **AI gateway** (`server/ai/gateway.ts`), the only code that calls a model:
  - A workspace's AI is `off` until the owner sets `local` or `cloud` with `PUT /api/workspaces/<id>/ai`, which also sets a daily token budget.
  - Every call is logged in `ai_calls` with the prompt's SHA-256, not its text (`GET /api/workspaces/<id>/ai/calls`).
  - JSON answers are validated, with one correction turn. Calls are retried once after a 429 or 5xx.
  - Keys come only from the server's environment, never from a request.
- **Extraction checks** (`server/ai/extraction.ts`): a model's value is used only when its quote is in the clause and our parser reads the same value from the quote and the whole clause. Otherwise the rule card asks Legal. Phase 3 should use `checkExtraction` and `checkParserOnly` as they are.
- **Extraction eval** on 45 labelled clauses, with no wrong value in any checked mode. The table is in the product guide, section 5.3. Both local models add no correct value the parser lacks, so measure a cloud model before relying on AI drafting.
- **RAG** with Ollama `all-minilm` through `POST /api/rag/query` and the MCP tool `hybrid_contextual_graph_rag_query`.
- **MCP**: six demo servers over HTTP (`POST /api/mcp/<server>/rpc`) and stdio. Section 5.9 of the guide has configurations for Kiro, VS Code, Claude Code, Claude Desktop, Cursor, Codex and Antigravity. None has been tried in a client yet.

## Run it

Needs Node 24, `gh` signed in, and Ollama with `qwen2.5-coder:0.5b` and `all-minilm` (`dolphin3` is optional).

```bash
npm install

# 1. Webhook relay. The channel is the GitHub App's webhook URL
#    (GitHub → Settings → Developer settings → GitHub Apps → LexCompiler d16d).
#    It isn't written here because this repository is public.
npx -y smee-client@5.0.0 --url https://smee.io/<channel> --target http://127.0.0.1:3001/api/github/webhooks

# 2. Server, in another terminal
LEXCOMPILER_PUBLIC_URL=http://localhost:3001 \
LEXCOMPILER_GITHUB_WEBHOOK_URL=https://smee.io/<channel> \
LEXCOMPILER_GITHUB_WEBHOOK_RELAY=smee \
npx tsx server/index.ts
```

- The App's credentials are in `data/github-app.json` (mode 0600). On a new machine, register a new App at `/github/register`, then install it with `/github/install`.
- The dashboard is served at `http://localhost:3001` after `npm run build`, or at `http://localhost:5173` with `npm run dev`.
- `npm run seed:demo -- --activate-builtins` creates the demo workspace with R-1 to R-4. Running it again is safe.
- The server doesn't load `.env` itself. Use `npx tsx --env-file=.env server/index.ts`.
- To run the GitHub test from scratch, follow the product guide, section 3 and the Phase 2 test.

**Full check before a merge:**

```bash
for s in typecheck lint test verify:cli verify:realworld build; do npm run --silent $s || echo "FAILED: $s"; done
```

On `main` after #36: 184 tests pass (2 skipped), lint has 0 errors and 11 old warnings. CI runs one job, "Z3 Law-to-AST Formal Verification & Build Gate", in about 2.5 minutes.

**Evals:**

```bash
npm run eval:extract                       # parser only, no model
npm run eval:extract -- --model local      # LEXCOMPILER_LOCAL_LLM_MODEL on Ollama
npm run eval:extract -- --model cloud      # needs LEXCOMPILER_LLM_MODEL (or OPENAI_API_KEY)
npm run eval:rag                           # 16 questions on the bundled fixture (MRR 0.88, nDCG@5 0.80)
npm run eval:rag -- --dataset bn           # 10 Bangla questions, Bangla clause set (MRR 0.95, nDCG@5 0.76)
LEXCOMPILER_TARGET_REPO=<finhealth-core-platform clone on feat/loan-applications> \
  npm run eval:rag -- --dataset finhealth  # 8 questions (MRR 0.82, nDCG@5 0.69, hit rate 1.0)
```

## Next steps, in order

Dates are from the schedule in the product guide, section 7.

1. **Owner decisions** (blocking AI drafting):
   - Pick the cloud model provider, put its key in `.env`, and run `npm run eval:extract -- --model cloud`.
   - Decide whether to restore PR #15's files (below).
2. ~~**Finish 2a.**~~ Done: `dataset.bn.json` and `dataset.finhealth.json`. The collection-model miss (q11, fh02) is fixed: BM25 stems words and splits identifiers, and a question with no category evidence no longer gets the retention clause's graph seeds and HyDE text. Both models are now in the top 5, at ranks 3 and 4.
3. **Phase 3, the lawyer's workspace** (Nov 9–22). Guide: Phase 3 and 5.4.
   - Upload PDF, DOCX or text (`pdfjs-dist`, `mammoth`), split clauses, mark normative ones.
   - Rule card on the existing rules API: highlighted source, category, values, scope, effective date, questions. Fill values with `checkParserOnly` and, when the workspace has AI on, with the gateway and `checkExtraction`.
   - On approval, queue a scan of `main` for every repo in scope (`enqueueScan` in `server/github/webhooks.ts`). Approval doesn't do this yet.
4. **Phase 4, fixes and exceptions** (Nov 23–29). The webhook ignores `check_run.requested_action` today (`server/github/webhooks.ts`). Exceptions need an API, a Legal inbox, a re-run after approval, and an expiry job. `classifyFindings` already applies approved exceptions.
5. **Phase 4a, the `/mcp` endpoint** (Nov 30–Dec 6): tokens and the six tools in guide 5.8. Then fill in the client test table in 5.9.
6. **Phase 5, evidence and the auditor** (Dec 7–13): `appendEvidence`, share links, `verify.mjs`. The guide has the code.
7. **Phases 6 and 7** (Dec 14–19), then a freeze from Dec 20 to 25.

## Open questions for the owner

- **PR #15.** GitHub shows it as merged, but a force push to `main` at 12:40 UTC on October 28 removed it. Missing from `main`: `docs/WHITEPAPER.md`, `docs/SUBMISSION_GUIDE_425PTS.md`, 4 screenshots in `docs/assets/`, and a change to `server/compiler/legalCompiler.ts` that now conflicts. It is still on the local branch `feat/bangla-localization-and-docs`.
- **Old branches.** 9 local branches whose GitHub copies are gone, plus `revert-26-claude/compassionate-hypatia-3mjhsk` on GitHub. All are fully in `main` except the PR #15 branch.
- **The analyzer rewrite** on `wip/analyzer-ir`: compare it with the current analyzer on real repos before porting its two extra detectors (guide, section 1).

## Things that bite

- **smee re-encodes JSON.** `LEXCOMPILER_GITHUB_WEBHOOK_RELAY=smee` makes the signature check accept that, and check-run summaries stay plain Markdown for the same reason (`server/github/checkRun.ts`).
- **IDs in GitHub's webhook delivery API** (used to redeliver a webhook) can be larger than 2^53. Handle them as strings, not JavaScript numbers.
- **The `gh` user token can't re-request check runs.** Use the App's installation token.
- **Use `localhost`, not `127.0.0.1`,** in the browser: sign-in cookies are tied to the host name.
- **PGlite allows one process per data directory.** A second process with the same `LEXCOMPILER_DATA_DIR` gets an in-memory vector store.
- **`node:sqlite` is a release candidate in Node 24.** Keep all SQL in `server/db` and the stores.
- **Tests never call a model on your machine.** `server/test-setup.ts` points Ollama at a closed port and turns neural embeddings off. Tests that need a model use a fake server.
- **The embedding model accepts 512 tokens.** Longer chunks are cut for their dense vector only.
- **The demo screens and workspaces use separate AI settings.** The demo screens use `LEXCOMPILER_DEMO_AI_MODE` (default `local`). Workspaces use their own setting, which defaults to `off`.
