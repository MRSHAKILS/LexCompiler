# LexCompiler handoff

Written October 29, 2026, after PR #36. Judging is on **December 26, 2026**.

This file says where the work stands, how to run it, and what to do next. The full plan is `docs/PRODUCT_GUIDE.md`: section 4 has the build phases, section 5 covers AI, RAG and MCP, and section 7 has the schedule to judging.

## Submission handover (October 31, 2026)

The CloudCamp BD submission is due **October 31, 11:59 PM GMT+6**, and a teammate is taking over. **Follow `docs/submission/TEAMMATE_CHECKLIST.md`:** it lists what is left, in order, what to check, and which private files must come from Shakil.

Done:
- the demo video (`docs/video/lexcompiler-demo.mp4`);
- the text for every form field (`docs/submission/FORM_NOTES.md`);
- the overview diagram (`docs/submission/lexcompiler-architecture.svg`);
- a fourth local model (DeepSeek-R1);
- the live GitHub checks.

Left:
- decide whether the "one prompt only" rule applies to your track;
- upload the video to YouTube;
- put the diagram in the Figma file and share it;
- fill in the team details;
- choose the live demo URL;
- submit.

The two repositories conflict in 15 files, because both built the same phases separately: see `docs/submission/MERGE_CONFLICTS.md`. Combining them is a decision for both authors, after the submission.

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
| MRSHAKILS/LexCompiler #6 | Phase 3: the lawyer's workspace at `/legal` (documents, clauses, rule cards, approval rescans `main`) |
| MRSHAKILS/LexCompiler #7 | Phase 4: exceptions ("Request exception" on the check, API, Legal inbox, re-run after a decision, expiry job) |
| MRSHAKILS/LexCompiler #8 | Phase 4a: the workspace MCP endpoint `POST /mcp` (personal access tokens, six tools, 2026-07-28 and 2025-06-18), the `/settings` page |
| MRSHAKILS/LexCompiler #9 | Phase 5: the signed evidence log, share links for auditors (`/share/<token>`), the evidence pack with `verify.mjs`, public keys under `/.well-known` |
| MRSHAKILS/LexCompiler #10 | Phase 6: rules proven only on their scope's paths, future effective dates ("Coming up", PR warnings), the regulation feed with "Draft rule change", daily jobs |
| MRSHAKILS/LexCompiler #11 | Phase 7 preparation: proxy trust, HTTPS only, rate limits, daily backups, `deploy/` (Caddy + compose), `docs/DEPLOY.md` |
| MRSHAKILS/LexCompiler #12 | Phase 4 items 1–2: "Open fix PR" (one verified commit through the Git Data API) and `suggestion` review comments on pull requests |
| MRSHAKILS/LexCompiler #13 | Phase 5 item 2: daily RFC 3161 timestamps of the evidence chain (`LEXCOMPILER_TSA_URL`), in share pages and packs |
| MRSHAKILS/LexCompiler #14 | One evidence signing key per workspace (`data/workspace-keys/`), published per workspace, backed up |
| MRSHAKILS/LexCompiler #15 | AI explanations on pull requests (guide 5.5 item 1), after the check, citing only retrieved text |
| MRSHAKILS/LexCompiler #16 | Model-written fix suggestions (5.5 item 2), kept only after parse, Z3 and rescan checks, cloud mode only |
| MRSHAKILS/LexCompiler #31 | HANDOFF: the last live GitHub checks (approval rescan, "Coming up" on a PR, AI explanations) |
| MRSHAKILS/LexCompiler #32 | README: both authors, and the features added since its last update |
| MRSHAKILS/LexCompiler #33 | `npm run voiceover`: the video's narration with ElevenLabs (`server/cli/voiceover.ts`) |
| MRSHAKILS/LexCompiler #34 | DeepSeek-R1 as a local reasoning critic (Pass 4, advisory), the narration, the form notes |
| MRSHAKILS/LexCompiler #35 | The overview diagram (problem, workflow, architecture), shown at the top of the README |
| MRSHAKILS/LexCompiler #17 | OAuth for the MCP endpoint: metadata (RFC 9728, 8414), dynamic registration (RFC 7591), PKCE authorization code, rotating refresh tokens |

| Phase | Status |
|---|---|
| 0–2 | Done, tested live on GitHub |
| 2a AI foundation | Done. RAG eval now has a Bangla set and a set for the test repo (see Evals) |
| 3 Lawyer's workspace | Done and tested locally (`/legal`). The GitHub part of the guide's test needs this machine's App credentials (see Open questions) |
| 4 Fixes and exceptions | Done; tested against a fake GitHub and live on GitHub (October 30, see "Live GitHub run"): scenes 3 and 4, suggestions and expiry |
| 4a MCP for coding assistants | Done; tested in-process and live over HTTP (guide 5.9 results). Claude Code connects but its CLI here isn't signed in; Cursor and VS Code not tried; OAuth not started |
| 5 Evidence and auditor | Done and tested (the pack verifies; the three tamper cases are caught), with daily RFC 3161 timestamps since #13 and one signing key per workspace since #14 |
| 6 Contract and regulation changes | Done and tested (scenes 5 and 6 through the API on the fixture, and the PR warning against a fake GitHub). The live GitHub run needs the App credentials. "Open fix PR" (scene 5 step 4) works since #12 |
| 7 Online for outside testers | Code and configuration ready (#11, `docs/DEPLOY.md`); not deployed. Needs a tunnel or a VPS with a domain, and the GitHub App credentials. The Docker image wasn't rebuilt here (Docker Desktop was off) |

## What works today

- **GitHub checks.** The App "LexCompiler d16d" (slug `lexcompiler-d16d`) is installed on https://github.com/shahriar-ahmed-seam/finhealth-core-platform and linked to the workspace "FinHealth AI", which has R-1 to R-4 approved. Its PR #1 is red on purpose: "1 new finding (R-1)" at `api/loan_applications.py:20`. It is the test case for the exception flow in Phase 4. A ruleset blocks merging it.
- **Lawyer's workspace** at `/legal` (`src/components/legal/LegalWorkspace.tsx`). Upload a PDF, DOCX or text; every clause is listed, normative ones marked; a clause opens a rule card; approve or reject drafts.
  - `POST /api/workspaces/<id>/documents` takes `text`, or `fileName` with `contentBase64` (up to 3 MB). The original file and its SHA-256 are kept (`GET .../documents/<docId>/file`). A Bangla upload in the old Bijoy encoding is refused with a request for Unicode text.
  - `POST .../rule-card` previews a card without saving: category (with a flag when the wording names none), plain reading, highlights with offsets, values with their source (parser, model, Legal, or an open question), questions, SMT-LIB2 and Rego, and the impact on each in-scope repo's last scan of `main`.
  - `POST .../rules` now takes `values` (Legal's numbers, compiled with `compileLegalProseWithOverrides`) and `scope`, and stores the card with the version (`card_json`, migration 4).
  - Approval is refused while a value is an open question, and queues a scan of the default branch of every GitHub repo in scope (`enqueueBranchScan`, trigger `rule_approved`).
  - With AI on, the gateway suggests the numeric value and `checkExtraction` decides whether the card shows it ("Suggested by <model>") or asks.
- **Exceptions** (Phase 4):
  - A pull request check that fails for new findings has a **Request exception** button. A click (`check_run.requested_action`, identifier `request_exception`) creates one request per new finding of that run, attributed to `github:<login>`, and comments "Exception requested by @… — waiting for Legal" on the PR (job `github_comment`). A second click adds nothing.
  - API under `/api/workspaces/<id>/exceptions`:
    - `GET`, optionally with `?status=`.
    - `POST` with `{ scanId, fingerprint | ruleKey + pathGlob, reason }`; engineers can ask.
    - `POST …/<exceptionId>/approve` with `{ note, expiresAt }`; Legal only. The reason and an end date within a year are required.
    - `POST …/<exceptionId>/reject`.
    - `POST …/<exceptionId>/expiry`: the guide's test-only admin action.
  - After a decision, the PR's check runs again (`rerunCheckForException`). A waived finding is a notice, and the summary says "1 finding waived until 30 Nov 2026".
  - An hourly job (`expireExceptions`) marks past exceptions expired; scans ignore them either way.
  - `GET /api/workspaces/<id>/inbox` lists exception requests and rule drafts; `/legal` shows it as the Legal inbox.
- **Evidence and auditors** (Phase 5):
  - `server/evidence/log.ts`: append-only, hash-chained, signed records per workspace (`evidence` table; triggers refuse UPDATE and DELETE). The header (seq, time, type, previous header's SHA-256, body's SHA-256, key id) is canonical JSON signed with the server's attestation key (`getAttestationSigner`: local Ed25519 file, Cloud KMS or AWS KMS). Appends run one at a time.
  - Records (`server/evidence/records.ts`): `scan.completed` (repo, commit, PR, rule versions with hashes, fingerprints per rule and state, waived ones, check run URL), `rule.approved`, `rule.retired`, `exception.approved`/`rejected`/`expired`, `share.created`/`revoked`. Bodies hold fingerprints, never code.
  - The check run summary ends with "Evidence record #n · header SHA-256 …", so GitHub keeps a timestamped copy of each scan's hash (`scans.evidence_seq`, migration 7).
  - Share links: Legal or the owner picks rules, an optional counterparty (its scope picks the repositories), a period and an expiry (at most a year) in the "Share with an auditor" panel on `/legal`. API: `GET/POST /api/workspaces/<id>/shares`, `POST …/shares/<shareId>/revoke`, `GET …/shares/<shareId>/views` (time, IP, browser), `GET …/evidence`. The token (`lexc_share_` + 32 random bytes) is shown once; only its SHA-256 is stored.
  - The auditor's page `/share/<token>` needs no account: summary, rule history with approvers, checks over time with their evidence numbers, findings of the latest default-branch check (no code), exceptions, the pack, and "Verify signatures in this browser" (Web Crypto). Data: `GET /api/share/<token>` and `…/pack.zip`, outside the `/api` guard, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`.
  - The pack: `headers.jsonl` (every header of the period), `bodies.jsonl` (only the bodies about the shared rules and repositories), `rules/`, `exceptions.json`, `sarif/`, `keys.json`, `verify.mjs`, `report.html`, `README.txt`. Zipped by `server/evidence/zip.ts` (Node's zlib; no fflate dependency).
  - Public keys: `GET /.well-known/lexcompiler/<workspaceId>/keys.json` (every key that signed the workspace's records, with validity dates). Auditors should take them from the company's own site, not from LexCompiler.
- **AI explanations on pull requests** (5.5 item 1; `server/github/explanations.ts`): when a workspace has AI on (local or cloud), each new finding (up to 10 per push) gets two or three sentences from the model, after the check result is final; it never changes the result. The model sees retrieved chunks only (rule text, numbered code around the finding, the finding, other findings of the rule in the file) and must cite them by id; other citations are dropped, and an explanation citing nothing retrieved isn't shown. They go into the check run's details (`output.text`, "AI explanations") and the suggestion comment. Calls are logged (`task: explanation`) and stop at the daily budget. Model-written fixes (5.5 item 2, #16; `server/github/aiFixes.ts`): for new findings in the PR diff with no template fix, and only when the owner chose cloud, the model sees the finding's lines and the rule text and proposes replacement lines; the suggestion is posted only if the patched file parses, the finding is gone and the rescan finds nothing new (fingerprints include the code, so a still-failing patch counts as new). Discarded patches are logged with the reason; calls are logged as `fix`, up to 10 per push.
- **Fix PRs and suggested changes** (Phase 4, items 1–2; `server/github/fixes.ts`):
  - "Open fix PR" (owner, Legal, engineers) reads the default branch's head with the installation token, runs the remediation synthesizer on it with the rules in effect (scoped), and opens a PR only for a `READY_TO_MERGE` bundle that Z3 proves (`SAT_COMPLIANT`): blobs, one tree on the base commit's tree, one commit, a `lexcompiler/fix-<sha>` branch, the PR. Otherwise 409 with the unresolved rules. One PR per base commit (`fix_prs`, migration 9); asking again returns it.
  - After each PR check, new findings whose verified fix is one replacement of lines in the PR's diff (`pulls/<n>/files`) get a review (event `COMMENT`) with a `suggestion` block. Fingerprints already commented on are stored per PR (`pr_suggestions`). Fixes that also need code elsewhere (a helper, a KMS client) stay annotations. A failure here is logged and never fails the check.
  - The synthesizer now reuses a `redact_pii` the file already imports (as in the walkthrough's `from api.privacy import redact_pii`) instead of adding its own, so the loan endpoint's R-2 fix is the one-line change on line 21.
- **Contract and regulation changes** (Phase 6):
  - Scope by path: `POST /api/workspaces/<id>/counterparties/<cpId>/scope` with `{ scope: [{ repoId, pathGlob }] }` (Legal). A rule scoped to counterparties is proven only on the files in their paths (`scanFilesScoped` in `server/product/scanner.ts`, used by the GitHub job, local scans and the MCP tools), so shared code must meet the stricter rule. `POST …/rules/<ruleId>/rescope` drafts a new version with another scope. The local-repo scan now applies scopes too (it ignored them before).
  - Effective dates: an approved version dated later doesn't fail anything. PR checks list its findings as warnings ("Coming up" section, "R-3 v2 will fail from 1 January 2027" in the title when nothing is new). `GET …/coming-up` lists what each upcoming version finds on each default branch (`coming_up` table, refreshed by default-branch scans, the nightly job, approval of a future version, and `POST …/coming-up/refresh`). `POST …/rule-versions/<versionId>/effective` with `{ effectiveFrom }` moves the date (Legal; today or earlier puts it in effect and rescans), and writes a `rule.rescheduled` evidence record.
  - Regulation feed: a daily job stores new Federal Register and EUR-Lex items (`feed_items`, migration 8). `GET …/feed`, `POST …/feed/refresh`, and `POST …/feed/<itemId>/draft` ("Draft rule change") makes a regulation document linked to the item (`documents.feed_item_id`, `source_url`) and a draft citing it; change notices are refused (no text to compile). The Legal inbox's `feedDrafts` lists undrafted items of the last 30 days.
  - Daily jobs (`server/product/feed.ts`): the feed, and a scan of every default branch (local folders in-process, GitHub through the job queue with trigger `scheduled`), each with an evidence record. Checked hourly, run once a day, remembered across restarts (`scheduler_runs`). `LEXCOMPILER_SCHEDULER=off` turns them off.
  - `/legal`: a "Changes" panel ("Coming up", the feed, each counterparty's paths), "Move date" on future versions, "Change scope" per rule, and `lang="bn"` on Bangla clause text (the card's plain reading is English).
- **Rules API** (Phase 1): `POST /api/workspaces/<id>/rules` creates a draft, `POST .../rule-versions/<versionId>/approve` and `.../reject` decide it (Legal only), `GET .../rules-in-effect` lists what scans use.
- **AI gateway** (`server/ai/gateway.ts`), the only code that calls a model:
  - A workspace's AI is `off` until the owner sets `local` or `cloud` with `PUT /api/workspaces/<id>/ai`, which also sets a daily token budget.
  - Every call is logged in `ai_calls` with the prompt's SHA-256, not its text (`GET /api/workspaces/<id>/ai/calls`).
  - JSON answers are validated, with one correction turn. Calls are retried once after a 429 or 5xx.
  - Keys come only from the server's environment, never from a request.
- **Extraction checks** (`server/ai/extraction.ts`): a model's value is used only when its quote is in the clause and our parser reads the same value from the quote and the whole clause. Otherwise the rule card asks Legal. Phase 3 should use `checkExtraction` and `checkParserOnly` as they are.
- **Extraction eval** on 45 labelled clauses, with no wrong value in any checked mode. The table is in the product guide, section 5.3. Both local models add no correct value the parser lacks, so measure a cloud model before relying on AI drafting.
- **RAG** with Ollama `all-minilm` through `POST /api/rag/query` and the MCP tool `hybrid_contextual_graph_rag_query`.
- **Workspace MCP endpoint** (Phase 4a): `POST /mcp` (`server/mcp/workspaceServer.ts`, tools in `workspaceTools.ts`).
  - Personal access tokens: `lexc_pat_` + 32 random bytes, SHA-256 stored (`api_tokens`, migration 6). One user, one workspace, that user's current role; 90 days by default (at most 366); revocable; `last_used_at` recorded. A token stops working when its user leaves the workspace. API: `GET/POST /api/workspaces/<id>/tokens`, `POST …/tokens/<tokenId>/revoke`. The page is `/settings` ("Connect a coding assistant"), with a ready configuration for each client in guide 5.9.
  - Protocol: 2026-07-28 (`_meta` protocol version, `MCP-Protocol-Version`/`Mcp-Method`/`Mcp-Name` must match the body, else 400 with -32020; `server/discover`; unknown method 404) and the 2025-06-18 / 2025-03-26 `initialize` handshake. No sessions; `resultType: "complete"`; GET and DELETE get 405.
  - Tools, in this order: `list_rules`, `check_changes`, `explain_finding`, `suggest_fix`, `request_exception` (the only one that writes; engineer or higher; lands in the Legal inbox as "from a coding assistant" with the requested end date), `search_obligations` (BM25 over approved rules and document clauses). Prompt: `check-before-commit`.
  - `check_changes` lays the sent files over the latest scanned default-branch commit (GitHub: downloaded once per commit and kept in memory; local repos: the folder), scans in memory, and classifies against that commit's findings and the active exceptions. 200 files and 2 MB per call. Sent code is not stored.
  - Security: `Origin` outside the allowlist gets 403; missing, revoked or expired tokens get 401; 60 calls a minute per token (429); every request is logged in `mcp_calls` with paths and fingerprints only (`GET /api/workspaces/<id>/mcp/calls`, owners).
- **Demo MCP**: six demo servers over HTTP (`POST /api/mcp/<server>/rpc`) and stdio, unchanged.

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
   - ~~Decide whether to restore PR #15's files~~ The owner doesn't need them (October 30).
2. ~~**Finish 2a.**~~ Done: `dataset.bn.json` and `dataset.finhealth.json`. The collection-model miss (q11, fh02) is fixed: BM25 stems words and splits identifiers, and a question with no category evidence no longer gets the retention clause's graph seeds and HyDE text. Both models are now in the top 5, at ranks 3 and 4.
3. ~~**Phase 3, the lawyer's workspace.**~~ Done (#6). Left for later: the library screen (templates are served by `GET /api/library/templates` but have no screen yet), similar-rule links (guide 5.4 item 6), an LLM rephrasing of the plain reading. The evidence record on approval is written since #9.
4. **Phase 4.** Exceptions are done (#7). Still to do:
   - The live test on finhealth-core-platform PR #1 (guide, Phase 4 test, scene 4 steps 2–4 and Expiry). It needs the App credentials on this machine.
   - ~~Guide items 1–2~~ done (#12): `POST /api/workspaces/<id>/repos/<repoId>/fix-pr` ("Open fix PR" on `/legal`) and suggestions after each PR check (`server/github/fixes.ts`). The old demo endpoint `/api/remediation/open-github-pr` still uses a personal token; the workspace path uses the installation token.
5. **Phase 4a.** Done (#8). Still to do:
   - Sign in to the Claude Code CLI and finish its row in the 5.9 results. Run the client test in Cursor and VS Code (GUI; the configurations are on `/settings`), and in Kiro, Codex, Antigravity and Claude Desktop where they're installed.
   - ~~OAuth~~ done (#17, `server/mcp/oauth.ts`): `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `POST /oauth/register` (public clients; redirect URIs https or localhost, matched exactly), `/oauth/authorize` (dashboard sign-in, a consent page to pick one of your workspaces; S256 PKCE required), `POST /oauth/token` (one-hour access tokens, which are personal access tokens named "OAuth: <client>"; 30-day refresh tokens that rotate; a reused code revokes what it issued). `/mcp`'s 401 names the resource metadata. Needs OIDC sign-in (or the loopback admin) and a public HTTPS URL for Claude Desktop's custom connectors; not tried with a real client yet.
6. **Phase 5.** Done (#9). Still to do:
   - The guide's Phase 5 test on GitHub (step 5: the hash in PR #1's check run). It needs the App credentials on this machine; the fake-GitHub test checks the same thing.
   - ~~RFC 3161 timestamps~~ done (#13): with `LEXCOMPILER_TSA_URL`, a daily job has the TSA vouch for each workspace's newest header (`evidence_timestamps`, migration 10). Share pages list them; packs carry `timestamps/<seq>.tsr` and `<seq>.header` (check with `openssl ts -verify`), and `verify.mjs` checks the stamped header is the one in the chain. Checked against https://freetsa.org/tsr: a token was issued, verifies over the data, and is rejected for other data (the tests use a fake TSA).
   - ~~One key per workspace~~ done (#14): with local signing, each workspace signs its evidence with its own Ed25519 key (`data/workspace-keys/<workspaceId>.pem`, owner-only, created on first use, in backups). `/.well-known/lexcompiler/<id>/keys.json` lists only the keys that signed that workspace's records, each valid from its first record there; records signed earlier with the server key still verify. With `LEXCOMPILER_SIGNER=gcp-kms|aws-kms` the server's KMS key still signs for every workspace (a KMS key per workspace needs per-workspace configuration).
   - `verify.mjs` can't see records removed from before the first or after the last header of a period. Cross-check the numbers with the check runs on GitHub.
7. **Phase 6.** Done (#10). Per-tenant settings inside code (a TTL per tenant) are a later analyzer feature; until then the fix is the strictest value.
8. **Phase 7.** Ready to deploy (#11). Still to do, with the owner:
   - The owner runs it on their own PC for now (Cloudflare quick tunnel); the VPS comes last. Then follow `docs/DEPLOY.md`, including its checklist.
   - Build the Docker image once (`docker compose -f deploy/docker-compose.prod.yml … up -d --build`) and run the checklist against it.
   - Point the GitHub App's webhook and the Keycloak redirect at the public URL.
   Then the freeze from Dec 20 to 25.

## The agent crew (ported from upstream PR #40)

`AGENTS.md` §2 lists six agents, each in its own framework with its own MCP server. The Python code is in `agents/lexcompiler_agents/`; the MCP servers are in `server/mcp/mcpSuite.ts` (`/api/mcp/<server>/rpc`). The agent work from shahriar-ahmed-seam/LexCompiler PR #40 was ported here on October 30; that repository's PRs #37–#39 (its own demo web app, password sign-in, evidence log and workspace MCP) were not, since this fork built those separately.

**How a run works.** `python -m lexcompiler_agents <agent-id>` lists the tools of the agent's MCP server and lets the framework's agent call them. The model call goes to the server's **agent route**, `POST /api/agents/llm/v1/chat/completions` (`relayAgentChat` in `server/ai/gateway.ts`). The route:
- takes the agent id as `model` and uses that agent's `LEXCOMPILER_AGENT_<ID>_*` model;
- keeps the provider key on the server;
- enforces `LEXCOMPILER_AGENT_MAX_DAILY_TOKENS` (default 100,000 cloud tokens per UTC day, all agents together; 429 past it) and logs each call in `ai_calls`;
- accepts only a global admin (the operator token, or loopback without sign-in); signed-in members get 403;
- rewrites JSON-schema output for DeepSeek.

`/api/ai-heavy/overview` no longer runs agent models on page load; `?agentModels=1` opts in.

**Credit.** The DeepSeek balance is about $0.85 (October 30). Keep agent runs to single small tests.

**Next, in order:**
1. ~~Chain the crew~~ done: `server/agents/crew.ts` (`POST /api/agents/crew/runs`, stored in `agent_crew_runs`) and `python -m lexcompiler_agents crew` (stored through `/runs/import`). Guide 5.7 has the handoffs. A live server run (no models, real feed): 13 feed items, 1 matching rule, 3 locations, 1 UNSAT, a 1-file patch, SAT_COMPLIANT. The Python crew with models hasn't run live yet: it needs Hermes on a bigger local model first (next item).
2. ~~Hermes on a bigger local model~~ done with a 3B model: Hermes now defaults to `llama3.2` (3B, already installed). On this laptop (i5-12450HX, 11.7 GB RAM with about 3 GB free, RTX 4050 with 6 GB) a 7B model needs about 4.7 GB of GPU memory while about 1.4 GB is already in use, so it would spill into RAM; the 3B one stays on the GPU (3.6 GB used, peak 64–69 °C, about 70 W). Its first answer wrapped the result in a made-up tool call, so the correction turn now offers no tools and constrains the answer with Ollama's `format` (the schema). Alone it answered in 16 s from the real scan. The `qwen2.5-coder:7b` download stopped at 38%; `ollama pull qwen2.5-coder:7b` resumes it for a machine with more GPU memory.

   **Python crew, live on October 30** (`python -m lexcompiler_agents crew`, bundled repository, five agents on `deepseek-chat` through the agent route, Hermes local): 85 s, gate `PATCH_VERIFIED`, stored as a `python` run with tokens from `ai_calls`: horizon scanner 8,391, deontic extractor 15,114, AST mapper 0 (local), graph RAG 1,130, Z3 critic 4,054, remediation 10,174; 38,863 in all, about 1 cent. The chain did its job: Hermes reported construct types without locations, and the graph RAG and Z3 agents both said its report wasn't supported by their own tool results and gave the file:line locations.
3. ~~Remediation opens a real pull request~~ done: with `openPullRequest`, a crew patch that passes the Z3 gate goes through the product's fix-PR path (`openFixPullRequest`, which proves every rule in effect again and opens one PR per base commit). A refusal is kept in the run as `pullRequestError`.
4. ~~Point the agents at real repositories~~ done: `POST /api/workspaces/<id>/repos/<repoId>/crew-runs` (`runScans`; `useModels` is operator only) runs the crew on the default branch's files with the rules in effect for that repository (`server/agents/workspaceCrew.ts`). The MCP tools and the agent runtime take the files. Runs are listed only to the workspace's members (`GET /api/workspaces/<id>/crew-runs`, migration 13). Live on October 30, as arif on MRSHAKILS/finhealth-core-platform at 858dc92: R-1 to R-4 in effect, 2 touched by the feed, both UNSAT, a 2-file patch SAT_COMPLIANT, and "Already open: pull request #3" (the fix PR for that commit), so no duplicate PR. Rule path scopes apply inside the crew too: rules are grouped by their counterparty paths, and each group's repository tools read only the files those paths match (`scopedCallTool`, as `scanFilesScoped` does). Two groups patching the same file block the patch.
5. ~~Tests for the agent route~~ done: `server/agentRoutes.test.ts` (403 for members and anonymous callers; relayed fields, the 4,096-token cap and the call log; 400/404 refusals; 429 past the daily budget, with local models not counted; `relayBody` for DeepSeek with and without tools; the crew run, import and list routes). The endpoints moved to `server/agents/routes.ts`.
6. **Put the agents into the product screens.** Partly done: the workspace screen (`/legal`) has an "Agent crew" panel (`src/components/legal/AgentCrewPanel.tsx`). Owners, Legal and engineers run the crew on each repository (on GitHub ones, optionally opening a fix PR when Z3 proves the patch); everyone in the workspace sees recent runs with the gate and each agent's step. Regulation watch is done (#29, `server/product/regulationWatch.ts`): for recent feed items it stores, per workspace, the rules each may affect (category from the wording, no model) and a two-sentence summary from the item's own text (task `regulation-watch`, the workspace's AI setting and budget); `POST /api/workspaces/<id>/feed/watch` (Legal) runs it for five items, and the daily job runs it after the feed refresh where the workspace's AI is on. It never drafts or approves: "Draft rule change" stays Legal's click. Live on October 30 on FinHealth AI: 5 items, 2,352 tokens; the AI Act Article 14 item was matched to R-3; GDPR Article 17 was classed as consent (its text mentions consent), so it didn't flag R-1, a limit of the category guesser. The fix agent is done (#30): when the template patch fails the gate on a workspace repository and the workspace's AI is on cloud, the crew asks the model to fix each remaining finding (task `fix`, the checks of #16: the file parses, Z3 no longer finds the rule there, the rescan finds nothing new) and lists the kept fixes in the run and on the panel as suggestions, never committed. Live on October 30 on a local clone of finhealth-core-platform at feat/loan-applications, with `allRules` (new: check every rule in effect, not only those the feed touches): the template patch was blocked, 7 model calls (4,588 tokens), 6 fixes kept and 1 discarded (it added an R-1 finding). **The checks don't prove a fix is right:** two kept fixes call encryption helpers that don't exist in the repository, and two only switch configuration flags. A reviewer has to read them; a check that every called name is defined would catch the first kind.

## Sign-in on this machine (October 30)

`npm run setup:keycloak` started Keycloak 26.4.0 in Docker (container `lexc-keycloak`, port 8080) and set up the realm for `data/live`; its passwords and client secret are in `data/live/keycloak/` (git-ignored). Arif and Nusrat were invited with `seed:demo`. The live server on port 3002 runs with `--env-file=data/live/keycloak/oidc.env` and `LEXCOMPILER_OIDC_REDIRECT_URI=http://localhost:3002/api/auth/callback`. Checked by signing in through Keycloak's login form: `/api/auth/me` shows arif as global admin and nusrat as a member, and `/api/workspaces` gives nusrat the `legal` role in FinHealth AI.

## Open questions for the owner

- ~~GitHub App credentials on the Windows machine~~ Solved differently: this machine has its own App, "LexCompiler 1305" (`lexcompiler-1305`, owned by MRSHAKILS), installed on the fork **MRSHAKILS/finhealth-core-platform** (MRSHAKILS can't install apps on shahriar-ahmed-seam's repo). Its credentials are in `data/live/github-app.json` (git-ignored), with the server's data in `data/live`. Webhooks come through a Cloudflare quick tunnel, whose URL changes when `cloudflared` restarts: update the App's webhook URL then (App settings → Webhook URL), or start the server with `LEXCOMPILER_GITHUB_SYNC_WEBHOOK=1` and it points the App's webhook at `LEXCOMPILER_GITHUB_WEBHOOK_URL` itself (`GitHubApp.syncWebhookUrl`, as the app); or use a named tunnel or the VPS (`docs/DEPLOY.md`). The App needs **Contents: Read and write** for fix PRs (#18; Apps registered from now on ask for it).

## Live GitHub run (October 30, MRSHAKILS/finhealth-core-platform)

Server: `main` at 89aacc6 to ab79e2d, `LEXCOMPILER_DATA_DIR=data/live`, port 3002, webhooks through the tunnel, workspace "FinHealth AI" with R-1 to R-4 approved (`seed:demo --activate-builtins`).

| Step | Result |
|---|---|
| Install and link | `installation.created`; the repo is linked to FinHealth AI; `main` (858dc92) scanned on connect |
| Scene 3: Open fix PR | PR #3 opened by `app/lexcompiler-1305`: one commit, 5 files, R-1 to R-4; its check **success**, "All 4 rules pass". Before #18 it failed with 403 (the App had Contents: read) |
| Gate refusal | With the loan endpoint on `main`, "Open fix PR" answers 409: "No verified fix … R-1 is not proven after the patch" |
| PR from `feat/loan-applications` (PR #1, later #4) | **failure**, "1 new finding (R-1)", failure annotation at `api/loan_applications.py:20`, the 6 `main` findings as warnings; summary names the evidence record and header hash, matching the signed log |
| PR before the redaction commit (PR #2) | **failure**, "2 new findings (R-1, R-2)"; `lexcompiler-1305[bot]` review comment on line 21 with the `redact_pii(...)` suggestion |
| Scene 4: Request exception (PR #4) | `check_run.requested_action` received; request R-1 at line 20 by `github:MRSHAKILS`; bot comment "Exception requested by @MRSHAKILS — waiting for Legal" |
| Legal approves (reason, until 30 Nov) | Check reran: **success**, "No new findings · 6 already on main", "1 finding waived until 30 Nov 2026" |
| Expiry (admin action, then a push) | Next check **failure**, "1 new finding (R-1)" |

Later on October 30, with FinHealth AI's AI on cloud (`deepseek-chat`, 1,182 tokens in all):

| Step | Result |
|---|---|
| Phase 3: Legal approves a rule (R-3 v2, same text, effective 1 January 2027) | Rescan of `main` queued (`trigger: rule_approved`), done in 4 s; check run on 858dc92: "6 findings on main (baseline for pull requests) · R-3 v2 will fail from 1 January 2027" |
| Phase 6: "Coming up" on a real PR (PR #5, the triage threshold lowered to 0.6) | **failure**, "1 new finding (R-3)"; the summary's "Coming up" section: "R-3 v2 takes effect on 1 January 2027: 1 finding here will fail from then"; the template suggestion comment on line 22 |
| AI explanation (second commit on PR #5, threshold 0.55) | "AI explanations" in the check's details: three sentences citing `rule:R-3`, the code chunk and the finding; one `explanation` call (677 in, 183 out) |

The first commit got no explanation: the live settings had `LEXCOMPILER_AGENT_FIX_*` and `…_DRAFTING_*` but nothing for the `explanation` task and no `LEXCOMPILER_LLM_*`, so the call was refused before reaching a model, with no log line. Set `LEXCOMPILER_AGENT_EXPLANATION_*` (or `LEXCOMPILER_LLM_*`) along with the others. Not covered live: a model-written fix on a PR (PR #5's finding had a template fix, so none was asked for). PRs #3, #4 and #5 are closed; R-3 v2 stays approved in the live workspace for 2027.

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
