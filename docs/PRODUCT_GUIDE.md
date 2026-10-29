# LexCompiler: building the full product and testing it on GitHub

> **Progress** (updated as each phase lands on `main`)
>
> | Phase | Status |
> | :--- | :--- |
> | 0. Merge and fix | Done: #29, #28 (via #30); analyzer rewrite saved on `wip/analyzer-ir` |
> | 1. Database | Done: #31 |
> | 2. GitHub App and pull-request checks | Done: #32 |
> | 3. The lawyer's workspace | Next |
> | 4. Fixes and exceptions | Planned |
> | 5. Evidence and the auditor | Planned |
> | 6. Contract and regulation changes | Planned |
> | 7. Online for outside testers | Planned |
>
> The test repository lives on the owner's own account instead of a separate organization. Since Phase 2, sections 3.2 and 3.3 are automated: `/github/register` creates the app from a manifest, and `/github/install` installs and links it (see the README, "GitHub App: Checking Pull Requests").


This guide covers how to build the real-life scenario from the walkthrough (FinHealth, Nusrat, Arif, Tanvir, Lena) and test it on GitHub with real pull requests, a lawyer's workspace and an auditor's view.

- It starts from the code after **PR #29** and **PR #28** are merged.
- Effort is in developer-days for one person. These are rough estimates.
- The screens should follow the earlier "screen mocks" artifact.

---

## 1. Starting point

### Merge order

1. **PR #29** brings back #26. Its CI passed, and GitHub reports it mergeable with no conflicts.
2. **PR #28** is your friend's newer work: 31 commits built on top of #26.
   - Against today's `main` it has 37 conflicts. A direct merge would also silently delete 9 files that #27 removed: `LICENSE`, `githubPr.ts`, `state.ts` and six test and helper files.
   - After #29 it merges cleanly. I checked that locally: type-check, lint (0 errors), 123 tests, `verify:cli` and the build all pass.
   - Do these before merging:
     - Delete the 11 committed `__pycache__/*.pyc` files and add `__pycache__/` to `.gitignore`.
     - `.github/workflows/lexcompiler-scan.yml` checks out `mrshakils/lexcompiler`, his fork. Change it to `shahriar-ahmed-seam/LexCompiler`.
     - Decide about `docs/HANDOFF.md` and `scripts/handoff-local.ps1`. They run an unattended Claude Code session with git and shell access on his Windows machine, tied to his branch. I'd keep them out of `main`.
     - Push one commit to #28 after #29 is merged. Merging #29 alone won't make CI run on #28.

The rest of this guide assumes `main` contains #28.

### What we reuse

| Need | What exists | Where |
|---|---|---|
| Clause text → rule values, English and Bangla, 11 rule categories, review notes | Yes | `server/compiler/legalCompiler.ts` |
| Scan any folder | `readRepositoryFilesAt(root)` | `server/analyzer/repoBaseline.ts` |
| Code → facts: SQL, Python, TypeScript; personal data found from types and values; Tree-sitter | Yes | `server/analyzer/` |
| Proof per rule: every instance is checked; a rule with no matching code is "not applicable"; hashes are stable | `verifyRepositoryAgainstClauses(clauses, sqlTables, astFindings)` | `server/prover/z3Engine.ts` |
| Fix bundles that must pass Z3, otherwise blocked | `synthesizeRemediationPullRequest` | `server/remediation/prSynthesizer.ts` |
| Open a fix PR on GitHub with a personal token | `openGitHubPullRequest` | `server/remediation/githubPr.ts` |
| Signing with a file key, Cloud KMS or AWS KMS; RFC 3161 timestamps | Yes | `server/enterprise/signingKey.ts`, `attestationSigner.ts`, `timestamp.ts` |
| SARIF export | `npm run sarif` | `server/enterprise/enterpriseSuite.ts` |
| Sign-in (OIDC); projects with viewer, editor and owner roles | Yes, but stored in JSON files with sessions in memory | `server/auth/oidc.ts`, `server/projects/` |
| Running inside a customer's CI | A reusable workflow: SARIF upload plus a pass/fail gate | `.github/workflows/lexcompiler-scan.yml` |
| Built-in SQLite | Used for the scan ledger | `node:sqlite` in `server/services/realAiServiceMesh.ts` |
| Regulation feed | EUR-Lex (SPARQL and CELLAR) and the Federal Register | `server/regulations/eurLex.ts`, `legalCompiler.ts` |

### What's missing for the scenario

1. A **GitHub App**: webhooks, check runs on pull requests, and review comments with suggested fixes.
2. A **database** for workspaces, rules, scans, findings, exceptions and evidence.
3. The **lawyer's workflow**: documents, rule cards, approval, versions, scope and effective dates.
4. **Exceptions** that expire.
5. A **signed, append-only evidence log**, a share link for auditors and an offline verifier.
6. **Stable finding fingerprints**, so a PR fails only for problems it adds. Today's SARIF fingerprint is the proof hash, which changes whenever anything changes.
7. A **public URL** for testers outside your machine.

### Bugs still open on #28 (fix them in Phase 0)

- **Ingest button.** It always overwrites DPA §4.2 (`handleIngestLiveFeedItem` in `src/App.tsx`).
- **Category guesser.** `inferRuleCategoryFromProse` reads GDPR Art. 44 as a logging ban and the Bangla DPA clause as right to erasure.
- **MCP tool count.** 25 tools are advertised, but 7 exist (`server/mcp/mcpSuite.ts`).
- **Z3 version.** "v4.13.4" appears in 5 places, but 4.16.0 is installed. Read the version from `node_modules/z3-solver/package.json`.

### Your analyzer rewrite

Commit it to a branch now. I ran 4 tricky inputs through both analyzers:
- Only yours catches an inline `if (result.confidence >= 0.6)` check and a region set inside an object (`{ region: "us-east-1" }`).
- On the other 3 inputs they match.

Port those two detectors after you measure both analyzers on real repos (see section 7).

---

## 2. What we're building

The architecture diagram is in the separate artifact "LexCompiler product architecture".

### Design rules

Each rule prevents a specific failure.

1. **Never run customer code, only parse it.** The runtime sandbox stays a demo feature for the bundled fixture.
2. **A rule is enforced only after someone with the Legal role approves it.** AI output is always a draft.
3. **A pull request fails only for problems it adds.** Problems already on `main` show as warnings. Otherwise every PR is red on day one, and developers turn the check off.
4. **Scans use the compiled rule stored at approval time, not a fresh compile.** A compiler upgrade must not silently change what an approved rule means.
5. **Every scan records the commit, the rule versions with their hashes, and the LexCompiler version.** Re-running it gives the same result.
6. **Evidence is append-only.** Each record is signed and contains the hash of the record before it.
7. **The GitHub App gets only the permissions it uses.** Installation tokens expire after an hour, so fetch one per job and never store it.

### Terms

| Term | Meaning | Example |
|---|---|---|
| Workspace | One subscribing company | FinHealth AI |
| Member | A person in the workspace, with one role: owner, legal, engineer or viewer | Nusrat (legal), Arif (owner) |
| Counterparty | A customer of the workspace whose contract creates rules | Klinikum Spree, Nodi Microfinance |
| Document | A contract or regulation text | Klinikum Spree DPA |
| Rule, rule version | An approved obligation. A change creates a new version | R-1 v1 |
| Scan | One analysis of one commit against the rules in effect | `main` @ 4c1e9a2 |
| Check | The GitHub check run that shows a scan on a commit | `LexCompiler / compliance` |
| Finding | One place where one rule fails, with a stable fingerprint | R-2 at `api/loan_applications.py:21` |
| Exception | Legal's approval to ignore a finding until a date | R-1 on the loan endpoint until 30 November |
| Evidence record | A signed entry in the workspace's log | A scan result, a rule approval |
| Share link | A read-only link for an auditor or customer | For Lena: R-1, March to November |

---

## 3. One-time test setup on GitHub

Use `http://localhost:3001` everywhere, not `127.0.0.1`. Sign-in cookies are tied to the host name.

### 3.1 Test organization and repository

1. Create a free organization at github.com/account/organizations/new, for example `finhealth-demo-seam` (the name must be unique).
2. **Make the test repository public.** On the Free plan, rulesets (which block merging until the check passes) only work on public repositories; private ones need Pro or Team ([GitHub docs](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)). The demo code contains no real data.
3. Copy the fixture into a new folder:

```bash
mkdir -p ~/lexc-test
cp -r ~/Desktop/Projects/buildfest/target-repo ~/lexc-test/core-platform
cd ~/lexc-test/core-platform
```

4. Add `api/privacy.py`. The developer uses it in scene 4:

```python
import hashlib


def redact_pii(value: str) -> str:
    """Replaces a personal value with a short, non-reversible token for logs."""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"[REDACTED:{digest}]"
```

5. Push it:

```bash
git init -b main && git add . && git commit -m "Initial FinHealth demo code"
gh repo create finhealth-demo-seam/core-platform --public --source . --push
```

6. Give your friend's GitHub account write access to `core-platform`. He plays Tanvir.

### 3.2 Forward webhooks to your machine

Get a channel URL at [smee.io/new](https://smee.io/new), which GitHub's own app tutorial uses ([GitHub docs](https://docs.github.com/en/apps/creating-github-apps/guides/setting-up-your-development-environment-to-create-a-github-app)). Then run:

```bash
npx smee-client --url https://smee.io/<your-channel> --target http://127.0.0.1:3001/api/github/webhooks
```

Smee is a public relay: anyone with the channel URL can read the payloads. Use it only with the demo repo.

### 3.3 Register the GitHub App

In the organization, go to **Settings → Developer settings → GitHub Apps → New GitHub App**:

| Field | Value |
|---|---|
| Name | `LexCompiler Dev Seam` (unique across GitHub) |
| Homepage URL | `http://localhost:3001` |
| Setup URL | `http://localhost:3001/github/setup`, with "Redirect on update" ticked |
| Webhook URL | Your smee URL |
| Webhook secret | Output of `openssl rand -hex 32` |
| Repository permissions | Checks: read and write · Contents: read and write · Pull requests: read and write · Metadata: read-only |
| Subscribe to events | Pull request · Push · Check run |
| Where can it be installed | Only on this account |

You don't need to tick installation events: GitHub sends them to every app automatically ([GitHub docs](https://docs.github.com/en/webhooks/webhook-events-and-payloads)).

After creating the app:
1. Note the App ID.
2. Generate a private key. Save the downloaded `.pem` outside the repo, for example `~/.config/lexcompiler/github-app.pem`, and run `chmod 600` on it.
3. Click **Install App** and choose only `core-platform`.

### 3.4 Sign-in for Legal and engineering

PR #28 supports any OIDC provider. Running Keycloak locally in Docker is the quickest way to test:

```bash
docker run -d --name lexc-keycloak -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD='change-me' \
  quay.io/keycloak/keycloak:latest start-dev
```

At http://localhost:8080 (log in as `admin`):
1. Create a realm called `lexcompiler`.
2. Create an OpenID Connect client called `lexcompiler-web`. Turn on client authentication, set the redirect URI to `http://localhost:3001/api/auth/callback`, then copy the client secret.
3. Create users `nusrat` and `arif`, each with an email and a password that isn't marked temporary.

Pin a Keycloak version once this works. Auth0 or Microsoft Entra ID would also work.

### 3.5 Who plays whom

| Persona | Played by | Signs in with |
|---|---|---|
| Arif, engineering manager and workspace owner | You | Keycloak user `arif` |
| Nusrat, Head of Legal | You, in a second browser profile | Keycloak user `nusrat` |
| Tanvir, developer | Your friend's GitHub account | GitHub only; never signs in to LexCompiler |
| Lena, hospital security officer | Anyone, in a private window | The share link; no account |

### 3.6 Settings

```bash
# Sign-in (exists since #28)
LEXCOMPILER_OIDC_ISSUER=http://localhost:8080/realms/lexcompiler
LEXCOMPILER_OIDC_CLIENT_ID=lexcompiler-web
LEXCOMPILER_OIDC_CLIENT_SECRET=<from Keycloak>
LEXCOMPILER_OIDC_REDIRECT_URI=http://localhost:3001/api/auth/callback

# New, added in Phase 2
LEXCOMPILER_GITHUB_APP_ID=<App ID>
LEXCOMPILER_GITHUB_APP_PRIVATE_KEY_PATH=/home/<you>/.config/lexcompiler/github-app.pem
LEXCOMPILER_GITHUB_WEBHOOK_SECRET=<secret from 3.3>
LEXCOMPILER_PUBLIC_URL=http://localhost:3001   # used in links from GitHub back to the dashboard
```

### 3.7 Make the check required (after Phase 2)

Once the check has run once, open `core-platform` → **Settings → Rules → Rulesets → New branch ruleset**:
- target the default branch;
- turn on "Require a pull request before merging";
- turn on "Require status checks to pass" and add `LexCompiler / compliance`;
- set enforcement to Active.

---

## 4. Build phases

Each phase lists what to build, then a test on GitHub that shows it works.

### Phase 0. Merge and fix (1 day)

- Merge #29, then #28 after its cleanup.
- Fix the four open bugs, each with a test.
- Commit your analyzer to a branch.

**Done when** CI is green on `main`.

### Phase 1. Move everything into a database (2–3 days)

This comes first because approvals and the evidence chain need transactions, workspaces must not see each other's data, and sessions must survive a restart.

**Build**

- **Database module.** `server/db/index.ts` opens `data/lexcompiler.db` with `node:sqlite`, sets `PRAGMA journal_mode = WAL` and `PRAGMA foreign_keys = ON`, and applies the numbered files in `server/db/migrations/` once each. Keep all database access in this module: `node:sqlite` is still a release candidate in Node 24 ([Node docs](https://r2.nodejs.org/docs/v24.15.0/api/sqlite.html)), and you may move to Postgres later.
- **Projects.** Keep the API of #28's `ProjectStore` but store the data in the tables below. A project becomes a repo in a workspace.
- **Sessions.** Store sessions in the `sessions` table, keeping only a SHA-256 of each session ID.
- **IDs.** Use `crypto.randomUUID()`, and remove the `Date.now().toString().slice(...)` IDs.
- **Demo seed.** `npm run seed:demo` creates the workspace "FinHealth AI", the counterparties Klinikum Spree and Nodi Microfinance, and the built-in clauses as library templates. `--activate-builtins` approves the four illustrative clauses as R-1 to R-4, which Phase 2 needs before Phase 3 exists.

**First migration (trimmed)**

```sql
CREATE TABLE workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL,
  github_installation_id INTEGER UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE users (id TEXT PRIMARY KEY, oidc_sub TEXT UNIQUE NOT NULL, email TEXT, name TEXT);
CREATE TABLE memberships (workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  role TEXT NOT NULL CHECK (role IN ('owner','legal','engineer','viewer')),
  PRIMARY KEY (workspace_id, user_id));
CREATE TABLE sessions (id_sha256 TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL);
CREATE TABLE repos (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  github_repo_id INTEGER UNIQUE NOT NULL, full_name TEXT NOT NULL, default_branch TEXT NOT NULL);
CREATE TABLE counterparties (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL);
CREATE TABLE counterparty_scope (counterparty_id TEXT NOT NULL REFERENCES counterparties(id),
  repo_id TEXT NOT NULL REFERENCES repos(id), path_glob TEXT NOT NULL DEFAULT '**');
CREATE TABLE documents (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  counterparty_id TEXT REFERENCES counterparties(id), title TEXT NOT NULL, language TEXT,
  file_sha256 TEXT NOT NULL, text TEXT NOT NULL, uploaded_by TEXT NOT NULL, uploaded_at TEXT NOT NULL);
CREATE TABLE rules (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  key TEXT NOT NULL, title TEXT NOT NULL, UNIQUE (workspace_id, key));
CREATE TABLE rule_versions (id TEXT PRIMARY KEY, rule_id TEXT NOT NULL REFERENCES rules(id),
  version INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft','approved','rejected','retired')),
  document_id TEXT REFERENCES documents(id), source_text TEXT NOT NULL,
  clause_json TEXT NOT NULL,      -- the compiled LegalClause, frozen at approval
  clause_sha256 TEXT NOT NULL,
  scope_json TEXT NOT NULL,       -- counterparties, or "all"
  answers_json TEXT,              -- the lawyer's answers to the card's questions
  effective_from TEXT, created_by TEXT NOT NULL, approved_by TEXT, approved_at TEXT,
  UNIQUE (rule_id, version));
CREATE TABLE scans (id TEXT PRIMARY KEY, repo_id TEXT NOT NULL REFERENCES repos(id),
  commit_sha TEXT NOT NULL, trigger TEXT NOT NULL, pr_number INTEGER,
  rules_sha256 TEXT NOT NULL, lexcompiler_version TEXT NOT NULL,
  status TEXT NOT NULL, conclusion TEXT, check_run_id INTEGER,
  facts_json TEXT,                -- sqlTables + astFindings, reused for impact previews
  started_at TEXT, finished_at TEXT);
CREATE TABLE findings (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id),
  rule_version_id TEXT NOT NULL REFERENCES rule_versions(id), fingerprint TEXT NOT NULL,
  file_path TEXT NOT NULL, start_line INTEGER NOT NULL, end_line INTEGER NOT NULL,
  message TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('new','existing','waived')));
CREATE TABLE exceptions (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  rule_id TEXT NOT NULL REFERENCES rules(id), fingerprint TEXT, path_glob TEXT,
  reason TEXT NOT NULL, requested_by TEXT NOT NULL, requested_from TEXT,
  status TEXT NOT NULL CHECK (status IN ('requested','approved','rejected','expired','revoked')),
  decided_by TEXT, decided_at TEXT, expires_at TEXT);
CREATE TABLE evidence (workspace_id TEXT NOT NULL REFERENCES workspaces(id), seq INTEGER NOT NULL,
  header TEXT NOT NULL, header_sha256 TEXT NOT NULL, body TEXT NOT NULL, signature TEXT NOT NULL,
  PRIMARY KEY (workspace_id, seq));
CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence
  BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence
  BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TABLE shares (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  token_sha256 TEXT UNIQUE NOT NULL, counterparty_id TEXT, rule_ids_json TEXT NOT NULL,
  period_from TEXT NOT NULL, period_to TEXT NOT NULL, created_by TEXT NOT NULL,
  expires_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE share_views (share_id TEXT NOT NULL REFERENCES shares(id), at TEXT NOT NULL,
  ip TEXT, user_agent TEXT);
CREATE TABLE jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload_json TEXT NOT NULL,
  status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, run_after TEXT, last_error TEXT);
CREATE TABLE webhook_deliveries (delivery_id TEXT PRIMARY KEY, received_at TEXT NOT NULL);
```

**Who can do what**

| Action | Owner | Legal | Engineer | Viewer |
|---|:-:|:-:|:-:|:-:|
| Connect repos, manage members | ✓ | | | |
| Upload documents, edit and approve rules | | ✓ | | |
| Approve or reject exceptions | | ✓ | | |
| Request exceptions | ✓ | ✓ | ✓ | |
| Create share links | ✓ | ✓ | | |
| View the dashboard, findings and evidence | ✓ | ✓ | ✓ | ✓ |

Keeping rule approval with Legal only means the person who approves a rule isn't the person who merges code. Auditors look for that separation.

**Done when** Arif stays signed in across a server restart, and a second workspace (another Keycloak user) can't see FinHealth's data. Make that second check an automated test.

### Phase 2. Connect GitHub and check pull requests (4–5 days) · scenes 1 and 4

**Build**

1. **App client.** Create `server/github/app.ts` with the `octokit` package. Its `createNodeMiddleware` serves webhooks at `POST /api/github/webhooks` by default ([octokit/app.js](https://github.com/octokit/app.js/blob/main/README.md)).
2. **Route order.** Register the webhook route before `express.json()`, because the middleware needs the raw body to check the signature. Register it before the `/api` guard too, because GitHub sends no browser headers.
3. **Fast webhook handlers.** Handlers only queue a job. GitHub fails any delivery not answered within 10 seconds ([GitHub docs](https://docs.github.com/webhooks/using-webhooks/best-practices-for-using-webhooks)). Skip delivery IDs you've already seen.
4. **Jobs.** Store jobs in the `jobs` table, so they survive restarts. Run one worker at a time, since z3-solver handles one solve at a time anyway, and retry with backoff.
5. **Linking the installation.** On `installation.created` or `installation_repositories.added`, store the repos. The Setup URL page links the installation to the signed-in owner's workspace. GitHub warns that the `installation_id` on that URL can be forged ([GitHub docs](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url)). In production, confirm it with a user access token via `GET /user/installations`. For a test with one trusted owner you can skip that.
6. **Scan job.** For each commit:
   1. Create the check run with status `in_progress`.
   2. Download the commit as a tarball and extract it into a temporary folder. Never run anything from it.
   3. Call `readRepositoryFilesAt` and then `analyzeFullRepositoryAsync`.
   4. Prove the facts against the rule versions in effect.
   5. Do the same for the PR's base commit, cached by commit and rules hash.
   6. Classify each finding as new, existing or waived.
   7. Complete the check run.
   8. Store the scan and its findings, and delete the folder.
7. **Fingerprints.** Use SHA-256 of rule key, file path, construct type and the snippet with whitespace collapsed. Leave line numbers out, so a finding keeps its identity when code above it moves.
8. **Check run content.**
   - Conclusion is `failure` if there are new, unwaived findings, otherwise `success`.
   - Annotations are `failure` for new findings, `warning` for existing ones and `notice` for waived ones.
   - Send at most 50 annotations per request; each further update adds more ([GitHub docs](https://docs.github.com/en/rest/checks/runs)).
   - Add a "Request exception" button. GitHub allows 3 buttons, with labels of up to 20 characters.
9. **Push to the default branch.** Scan `main`. That scan is the baseline that later PRs compare against.
10. **Optional repo config.** A `.lexcompiler.yml` can add personal-data field names (`nid`, `mobile_no`) and ignore paths. Make the analyzer's name list configurable to support it.
11. **Refactors.**
    - Give `buildComplianceReport` a `files` parameter instead of reading the global target repo.
    - Take the commit SHA from the webhook, not from the sandbox git.
    - Record the LexCompiler version (`git rev-parse HEAD` of its checkout) in each scan.
12. **Optional SARIF upload.** You can also send results to GitHub's Security tab by uploading SARIF. That's free on public repos; private repos need GitHub Code Security ([GitHub docs](https://docs.github.com/en/code-security/secure-coding/uploading-a-sarif-file-to-github)).

**Wiring**

```ts
// server/github/app.ts
import fs from 'node:fs';
import { App } from 'octokit';
import { enqueueJob } from '../jobs/queue.js';

export const githubApp = new App({
  appId: Number(process.env.LEXCOMPILER_GITHUB_APP_ID),
  privateKey: fs.readFileSync(process.env.LEXCOMPILER_GITHUB_APP_PRIVATE_KEY_PATH!, 'utf8'),
  webhooks: { secret: process.env.LEXCOMPILER_GITHUB_WEBHOOK_SECRET! },
});

githubApp.webhooks.on(
  ['pull_request.opened', 'pull_request.synchronize', 'pull_request.reopened'],
  async ({ id, payload }) => {
    // Only queue: GitHub expects an answer within 10 seconds.
    enqueueJob('scan', {
      deliveryId: id,
      installationId: payload.installation!.id,
      githubRepoId: payload.repository.id,
      owner: payload.repository.owner.login,
      repo: payload.repository.name,
      headSha: payload.pull_request.head.sha,
      baseSha: payload.pull_request.base.sha,
      prNumber: payload.pull_request.number,
    });
  }
);
```

```ts
// server/index.ts: register this before cors(), express.json() and the /api guard
import { createNodeMiddleware } from 'octokit';
import { githubApp } from './github/app.js';

app.post('/api/github/webhooks', createNodeMiddleware(githubApp));
```

```ts
// server/github/scanJob.ts (core of the job)
const octokit = await githubApp.getInstallationOctokit(job.installationId);
const { data: run } = await octokit.rest.checks.create({
  owner, repo, head_sha: job.headSha, name: 'LexCompiler / compliance', status: 'in_progress',
  details_url: `${process.env.LEXCOMPILER_PUBLIC_URL}/scans/${scanId}`, external_id: scanId,
});

const { data } = await octokit.rest.repos.downloadTarballArchive({ owner, repo, ref: job.headSha });
const work = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'lexc-scan-'));
try {
  const archive = path.join(work, 'src.tar.gz');
  const src = path.join(work, 'src');
  await fs.promises.writeFile(archive, Buffer.from(data as ArrayBuffer));
  await fs.promises.mkdir(src);
  await tar.x({ file: archive, cwd: src, strip: 1 }); // `tar` refuses paths outside cwd
  const { sqlTables, astFindings } = await analyzeFullRepositoryAsync(readRepositoryFilesAt(src));
  head = await verifyRepositoryAgainstClauses(rulesInEffect, sqlTables, astFindings);
} finally {
  await fs.promises.rm(work, { recursive: true, force: true });
}

// ...scan the base commit the same way (cached), classify, then:
await octokit.rest.checks.update({
  owner, repo, check_run_id: run.id,
  conclusion: newFindings.length > 0 ? 'failure' : 'success',
  output: { title, summary, annotations: annotations.slice(0, 50) },
  actions: newFindings.length > 0
    ? [{ label: 'Request exception', description: 'Ask Legal to approve an exception', identifier: 'request_exception' }]
    : [],
});
```

**Test on GitHub**

Seed with `--activate-builtins` so R-1 to R-4 are active. Then, as Tanvir, create branch `feat/loan-applications`, add `api/loan_applications.py` with the content below, and open a PR:

```python
import logging

from fastapi import APIRouter, Header
from pydantic import BaseModel

from api.privacy import redact_pii

logger = logging.getLogger("finhealth.loans")
router = APIRouter()


class LoanApplicant(BaseModel):
    full_name: str
    phone: str
    national_id: str
    requested_amount: int


@router.post("/v1/loan-applications")
async def create_application(applicant: LoanApplicant, x_tenant_id: str = Header(...)):
    logger.info(f"new application phone={applicant.phone} national_id={applicant.national_id}")
    return {"status": "received", "tenant": x_tenant_id}
```

I ran this exact file against #28's analyzer and prover. Expect:

- A red `LexCompiler / compliance` check within a minute or so, with 2 new findings:
  - **R-2, line 21:** "logger.info … writes PII (phone, national_id) to a log sink without redaction."
  - **R-1, line 20:** "'create_application' processes PII without a tenant-isolated KMS envelope." This one is debatable, because the endpoint stores nothing. Keep it: it's your test case for exceptions (Phase 4) and for narrowing scope (Phase 6).
- The 6 problems already on `main` as warnings.
- The merge button blocked once the ruleset from 3.7 is on.

Then:
1. Push a commit that wraps both values in `redact_pii(...)`. The R-2 finding disappears and R-1 remains (also checked).
2. Click **Re-run** in the Checks tab. The result is the same, with no duplicate run.
3. Redeliver a webhook from the App's **Advanced → Recent deliveries** page. No second scan starts.

### Phase 3. The lawyer's workspace (5–6 days) · scene 2

**Build**

1. **Documents.**
   - Accept PDF, DOCX or pasted text. Keep the original file and its SHA-256.
   - Extract text with `pdfjs-dist` (PDF) or `mammoth` (DOCX).
   - Ask for the counterparty and whether it's a contract or a regulation.
   - **Bangla PDFs:** many Bangladeshi documents use the old Bijoy encoding, and extraction then returns Latin letters instead of Bangla. If a Bangla document's text has almost no characters in U+0980–U+09FF, ask for Unicode text instead.
2. **Clauses.**
   - Split on numbered headings: `4.2`, `Section 4`, `Article 17`, `§`, and `ধারা ৪.২` after converting the digits.
   - Mark normative clauses by their wording: must, shall, shall not, prohibited, required, অবশ্যই, করতে হবে, নিষিদ্ধ, যাবে না.
   - Show every clause, so the lawyer sees what was skipped.
3. **Rule card**, following the mock:
   - **Source text** with the matched words highlighted. The extractor functions return the matched text today; extend them to return offsets.
   - **Category:** the guess, with a dropdown so the lawyer can change it.
   - **Plain-language reading** from a fixed template per category. An LLM may suggest a rephrasing, labeled as a suggestion.
   - **Editable values:** hours, key isolation, allowed regions, confidence.
   - **Scope:** which counterparties it applies to.
   - **Effective date:** defaults to the approval date.
   - **Questions:** #26's `reviewNotes` plus a fixed list per category:
     - retention: when does the clock start, and do backups count;
     - logging: are masked values allowed;
     - AI: which decisions count as automated;
     - transfers: which regions are allowed, and do sub-processors count.

     Answers are stored with the version. Only answers that set a value, such as allowed regions, change the check.
   - **Impact preview:** run the prover with the draft against each in-scope repo's stored facts (`scans.facts_json`) and show "N places would fail".
   - **SMT-LIB2 and Rego**, collapsed.
4. **Approve.**
   - Approval stores an immutable `rule_versions` row with the compiled clause, its hash, the approver and the time.
   - It writes an evidence record and queues a scan of `main` for every repo in scope.
   - Editing an approved rule creates a draft v2. v1 stays in force until v2 is approved.
5. **Library.** Templates are the four illustrative clauses plus #28's consent, breach-notification, DPIA, minimisation and purpose rules. A lawyer copies one, edits it and approves it.
6. **LLM setting per workspace.** The options are off, local Ollama, or OpenAI with the server key. Default to off, because contracts are confidential.

**Test on GitHub.** Reset the demo workspace without `--activate-builtins`. Then, as Nusrat:
1. Print the §4.2 text from the walkthrough to PDF and upload it as the Klinikum Spree DPA.
2. The card shows "72 hours" and "tenant-isolated keys" highlighted, the category "Retention and tenant keys", and the clock-start question.
3. The impact preview says 3 places in `core-platform` would fail.
4. Approve. R-1 v1 shows your name and time, and within a minute `main` is rescanned and shows the 3 failures.
5. Edit R-1 to 48 hours. A draft v2 appears as "waiting for approval", while v1 is still enforced on PRs. Reject v2.
6. Copy the three library rules (no personal data in logs, human review below 0.85, EU regions only) and approve them as R-2 to R-4.

### Phase 4. Fixes and exceptions (3–4 days) · scenes 3 and 4

**Build**

1. **Fix PRs for `main`.**
   - Switch `githubPr.ts` from a personal token to the installation token.
   - Create a single commit through the Git Data API (blobs, tree, commit, then update the ref) instead of one commit per file.
   - Only open bundles marked `READY_TO_MERGE`, which is #26's gate. The dashboard gets an "Open fix PR" button.
2. **Suggested changes in PRs.**
   - For a new finding whose fix edits lines the PR changed, post a review (`pulls.createReview`, event `COMMENT`) containing a `suggestion` block.
   - GitHub only accepts review comments on lines in the PR diff, so read the patches from `pulls.listFiles` first. Findings outside the diff stay as annotations.
   - The synthesizer's `TextEdit` ranges (`applyEdits` in `prSynthesizer.ts`) give the exact lines to replace.
   - Store which fingerprints you've already commented on per PR, so new pushes don't repeat comments.
3. **Exceptions.**
   - **From GitHub:** "Request exception" on the check sends a `check_run.requested_action` webhook. Create a request for that run's new findings, attributed to `sender.login`, and comment on the PR: "Exception requested by @… — waiting for Legal".
   - **From the dashboard:** engineers can request one with a reason.
   - **Legal's decision:** approve with a reason and a required expiry date, or reject. An exception covers one fingerprint or a path glob.
   - **Effect:** waived findings show as notices, don't fail the check, and are listed in the evidence.
   - **Re-check:** after approval, run the PR's check again so it turns green.
   - **Expiry:** a daily job expires exceptions, and the next scan fails again.
4. **Legal inbox.** It holds exception requests, drafts from the feed, and rules waiting for approval.

**Test on GitHub**
1. **Scene 3.** As Arif, the dashboard shows 6 findings in 5 files. Click **Open fix PR**. A PR from the app appears in `core-platform` with one commit and a green check. Merge it.
2. **Scene 4.** On Tanvir's PR (rebase it onto `main` first):
   1. A review comment on line 21 suggests the `redact_pii(...)` change. Click **Commit suggestion**, and the R-2 finding clears.
   2. R-1 still fails on line 20. Click **Request exception**.
   3. Nusrat sees it in her inbox and approves it until 30 November, with the reason "Endpoint does not store PII; storage is added in LN-12".
   4. The check re-runs and turns green, with "1 finding waived until 30 Nov" in the summary.
3. **Expiry.** With a test-only admin action, set the exception's expiry to yesterday, then push any commit. The check fails again.

### Phase 5. Evidence and the auditor (4–5 days) · scene 7

**Build**

1. **Evidence log.** Each record has a **header** and a **body**:
   - The header holds the sequence number, time, type, workspace, key ID, the previous header's SHA-256 and the body's SHA-256. The server signs the header.
   - The body holds the details.
     - **Scan records:** repo, commit, PR, rule versions with their hashes, LexCompiler version, results per rule with finding fingerprints, waived fingerprints, and the check run URL.
     - **Other records:** rule approved or retired, exception approved or expired, share created or revoked.
   - **Why split them:** a share link can include every header for the period, so the auditor can see nothing was removed, while including only the bodies about that customer.
2. **Signing.**
   - Reuse `attestationSigner.ts`: a file key for the test, Cloud KMS or AWS KMS in production.
   - Optionally timestamp each day's last header with `timestamp.ts` (RFC 3161).
   - Put the header hash in the check run summary. GitHub keeps that run with its own timestamp, which gives the auditor a second record that LexCompiler doesn't control.
3. **Public keys.** Serve them at `/.well-known/lexcompiler/<workspace-id>/keys.json`, listing key ID, PEM and validity dates. The workspace should also publish them somewhere it controls, such as its website or a `SECURITY.md`. That way the auditor doesn't take the key from the same place as the records.
4. **Share links.**
   - Legal picks the counterparty, rules, period and expiry, and gets `/share/<token>`. Generate the token from 32 random bytes and store only its SHA-256.
   - The pages show a summary, the rule history (each version's text, approver and time), checks over time, exceptions and downloads. No account is needed.
   - Code snippets are hidden by default, because they're the workspace's source code.
   - Each view is logged (time, IP, browser). Legal sees the log and can revoke the link.
5. **Evidence pack.** A zip built with `fflate`, containing:
   - `headers.jsonl` (every header in the period) and `bodies.jsonl` (bodies in scope);
   - `rules/`, `exceptions.json`, the latest SARIF per repo and `keys.json`;
   - `verify.mjs` and a printable `report.html`.
6. **Verify in the browser.** Add a verify button using Web Crypto, which supports Ed25519 in current Chrome, Edge, Firefox and Safari ([overview](https://mojoauth.com/security-guides/generate-keypair-using-ed25519-with-jsf)). That check runs code LexCompiler serves, so the independent check is `verify.mjs` with keys taken from the workspace's own site.

**Writing a record**

```ts
// server/evidence/log.ts (one server process; with several, take a database lock instead)
import crypto from 'node:crypto';
import { db } from '../db/index.js';
import { getWorkspaceSigner } from './signer.js'; // wraps attestationSigner.ts: { keyId, sign(bytes) }

const sha256 = (b: Buffer) => crypto.createHash('sha256').update(b).digest('hex');

/** Deterministic JSON: sorted keys, no whitespace, undefined fields dropped. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

let queue: Promise<unknown> = Promise.resolve();

/** Appends a record. Calls run one at a time, so each header points at the one before it. */
export function appendEvidence(workspaceId: string, type: string, body: object) {
  const run = queue.then(async () => {
    const prev = db
      .prepare('SELECT seq, header_sha256 FROM evidence WHERE workspace_id = ? ORDER BY seq DESC LIMIT 1')
      .get(workspaceId) as { seq: number; header_sha256: string } | undefined;
    const signer = await getWorkspaceSigner(workspaceId);
    const bodyBytes = Buffer.from(canonicalJson(body), 'utf8');
    const header = {
      v: 1, workspace: workspaceId, seq: (prev?.seq ?? 0) + 1, type, at: new Date().toISOString(),
      prev: prev?.header_sha256 ?? null, body_sha256: sha256(bodyBytes), key_id: signer.keyId,
    };
    const headerBytes = Buffer.from(canonicalJson(header), 'utf8');
    const signature = (await signer.sign(headerBytes)).toString('base64');
    db.prepare(
      'INSERT INTO evidence (workspace_id, seq, header, header_sha256, body, signature) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(workspaceId, header.seq, headerBytes.toString('utf8'), sha256(headerBytes), bodyBytes.toString('utf8'), signature);
    return { seq: header.seq, headerSha256: sha256(headerBytes) };
  });
  queue = run.catch(() => undefined);
  return run;
}
```

**The offline verifier shipped in every pack**

```js
// verify.mjs: node verify.mjs <pack folder> <keys.json>
// Take keys.json from the company's own website, not from the pack.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const [dir, keysFile] = process.argv.slice(2);
const keys = new Map(JSON.parse(fs.readFileSync(keysFile, 'utf8'))
  .map((k) => [k.keyId, crypto.createPublicKey(k.publicKeyPem)]));
const rows = (f) => fs.readFileSync(path.join(dir, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const sha256 = (s) => crypto.createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');

const problems = [];
const bodyHash = new Map();
let prevHash = null;
let prevSeq = null;
for (const { header, signature } of rows('headers.jsonl')) { // header = the exact signed JSON text
  const h = JSON.parse(header);
  const key = keys.get(h.key_id);
  if (!key || !crypto.verify(null, Buffer.from(header, 'utf8'), key, Buffer.from(signature, 'base64'))) {
    problems.push(`#${h.seq}: bad signature or unknown key`);
  }
  if (prevSeq !== null && h.seq !== prevSeq + 1) problems.push(`#${h.seq}: records missing before it`);
  if (prevHash !== null && h.prev !== prevHash) problems.push(`#${h.seq}: chain broken`);
  bodyHash.set(h.seq, h.body_sha256);
  prevHash = sha256(header);
  prevSeq = h.seq;
}
let bodies = 0;
for (const { seq, body } of rows('bodies.jsonl')) {
  bodies++;
  if (bodyHash.get(seq) !== sha256(body)) problems.push(`body #${seq}: does not match its signed header`);
}
console.log(problems.length ? problems.join('\n')
  : `OK: ${bodyHash.size} signed headers in an unbroken chain; ${bodies} bodies match.`);
process.exit(problems.length ? 1 : 0);
```

**Test**
1. As Nusrat, create a share for Klinikum Spree: rule R-1, this month, expiring in 7 days.
2. Open the link in a private window. You see the summary, R-1's history with your approval, the scans of `main` and of Tanvir's PR, and the exception. No sign-in is asked for.
3. Download the pack. Save `keys.json` from the `.well-known` URL (pretend it's FinHealth's website), then run `node verify.mjs pack/ keys.json`. Expect `OK`.
4. Tamper with the pack:
   - change one character in `bodies.jsonl`: a body mismatch is reported;
   - delete a line from `headers.jsonl`: "records missing" is reported;
   - edit a header: "bad signature" is reported.
5. Open the PR's check run on GitHub. Its summary shows the same header hash as the record in the pack.
6. Revoke the share. The link stops working, and the view log shows your visit.

### Phase 6. Contract and regulation changes (2–3 days) · scenes 5 and 6

**Build**

1. **Scope by path.**
   - For each counterparty, list the repos and path globs that handle its data, for example:
     - Klinikum: `api/fastapi_intake.py`, `workers/**`, `schema/**`;
     - Nodi: `api/loan_*`, `workers/**`.
   - The prover checks a rule only against facts from files in scope, which also removes the R-1 finding on the loan endpoint.
   - Shared code such as the Redis worker is in scope for both, so it must meet the stricter rule. Each rule is proven separately: a 48-hour rule fails a 72-hour cache while the 72-hour rule passes.
   - Per-customer settings inside code (a TTL per tenant) are a later analyzer feature. Until then, the fix is to use the strictest value.
2. **Bangla.** Split Bangla clauses the same way, show the Bangla text with the English reading next to it, and mark Bangla text with `lang="bn"`.
3. **Effective dates.**
   - A future version doesn't fail PRs. It shows as a warning ("will fail from 1 January") and in a "Coming up" panel computed nightly against `main`.
   - A fix PR can be opened before the date.
4. **Regulation feed.**
   - A daily job stores new Federal Register and EUR-Lex items (`eurLex.ts` from #28).
   - "Draft rule change" turns an item into a draft version linked to its source. Nothing takes effect without approval.
   - Bangladesh Bank circulars have no API, so upload them as documents.
5. **Nightly scan** of `main` for every repo, to catch direct pushes and rules that just took effect. Each scan writes an evidence record.

**Test**
1. **Scene 5.**
   1. Add Nodi Microfinance with scope `core-platform` and paths `api/loan_*` and `workers/**`.
   2. Paste the Bangla "৪৮ ঘণ্টা" addendum (the Bangladesh Bank preset text). The card reads 48 hours.
   3. Approve it as R-5. `main` fails at `workers/redis_cache_worker.py:8`, which is now 72 hours after the scene 3 fix.
   4. Click **Open fix PR**. Its check passes R-1 too, because 48 is within 72.
2. **Scope.** Narrow R-1 to Klinikum's paths. Tanvir's next push no longer shows R-1 on line 20.
3. **Scene 6.**
   1. Create R-3 v2 with a confidence threshold of 0.92, effective in 3 days. "Coming up" lists `services/ai_credit_triage.ts:20`, and PRs show a warning.
   2. Move the date to today. The next scan fails until the fix PR is merged.

### Phase 7. Put it online for outside testers (1–2 days)

- **Quick: Cloudflare tunnel.** `cloudflared tunnel --url http://localhost:3001` gives a temporary public HTTPS URL. Use it for:
  - the App's webhook URL (no smee needed);
  - `LEXCOMPILER_PUBLIC_URL`;
  - the Keycloak redirect URI;
  - `LEXCOMPILER_ALLOWED_HOSTS` and `LEXCOMPILER_ALLOWED_ORIGINS`.
- **Stable: a small VPS.** Run the existing Dockerfile and compose file, keep `data/` (database and keys) on a persistent volume, and put Caddy in front for HTTPS.
- **Before anyone else uses it:**
  - Serve HTTPS only, with `Secure` cookies.
  - With a public `HOST`, #26's guard requires `LEXCOMPILER_API_TOKEN` on every `/api` call. Check that browser sessions from #28's sign-in still get through, and that `/api/github/webhooks` and `/share/*` stay outside the guard.
  - Keep the runtime sandbox off.
  - Keep secrets (App key, webhook secret, OIDC secret, signing key) out of the repo.
  - Back up `data/` daily with `VACUUM INTO`.
  - Rate-limit webhooks, share pages and sign-in.

### Phase 8. Later, to sell it

- **Code stays in the customer's CI.** Build on `lexcompiler-scan.yml`:
  1. The workflow fetches approved rules with a workspace token.
  2. It scans inside the customer's runner.
  3. It uploads only file, line, rule and fingerprint.

  LexCompiler then signs what the runner reported, and the record says so.
- **Billing:** Stripe Checkout in test mode, with plan limits on repos and seats.
- **Company sign-in:** #28's OIDC already works with Entra ID and Okta.
- **Scale:** move to Postgres and a real job queue once you run more than one server process.
- **Personal signatures:** let lawyers sign approvals with their own passkey (WebAuthn), not only the server key.
- **Notifications:** email.

---

## 5. The full test on GitHub (demo script)

| Scene | Who | Do | Expect |
|---|---|---|---|
| 1 | Arif | Install the App on `core-platform`; sign in | Repo listed; `main` scanned; no rules active yet |
| 2 | Nusrat | Upload the DPA PDF; answer the question; approve R-1; copy and approve R-2 to R-4 | R-1 v1 shows her name and time; `main` rescanned |
| 3 | Arif | Dashboard → **Open fix PR** | 6 findings in 5 files; an app PR with one commit and a green check; merge it |
| 4 | Tanvir | Open the loan-endpoint PR | Red check; suggestion on line 21; after committing it and Legal approving the R-1 exception, green |
| 5 | Nusrat | Approve the Bangla 48-hour addendum for Nodi | `main` fails at the Redis worker; fix PR |
| 6 | Nusrat | R-3 v2 at 0.92, effective in 3 days | "Coming up" panel; warnings on PRs; failure once in effect |
| 7 | Lena | Open the share link; download the pack; run `verify.mjs` | Readable without an account; `OK`; tampering is detected |

In the story, Arif rejects the region fix and asks for an exception. In this test the whole fix PR is merged, and the exception flow is exercised in scene 4 instead.

---

## 6. Effort and order

| Phase | Developer-days | What you can show afterwards |
|---|---|---|
| 0 Merge and fix | 1 | A clean `main` |
| 1 Database | 2–3 | Survives restarts; several workspaces |
| 2 GitHub checks | 4–5 | Scenes 1 and 4 (the check) |
| 3 Lawyer workspace | 5–6 | Scene 2 |
| 4 Fixes and exceptions | 3–4 | Scenes 3 and 4 complete |
| 5 Evidence and auditor | 4–5 | Scene 7 |
| 6 Changes over time | 2–3 | Scenes 5 and 6 |
| 7 Online | 1–2 | Testers outside your machine |
| **Total** | **22–29** | All seven scenes |

**With two people, this takes roughly 3–4 weeks.** Split the work:
- one person on GitHub and the backend: phases 1, 2, 4 and 7;
- the other on the lawyer and auditor screens: phases 3, 5 and 6.

Agree on the Phase 1 schema first.

**If judging is close, build a demo cut of about 8–10 developer-days:**
- Phase 0;
- the Phase 1 tables for repos, scans, findings and rule versions;
- Phase 2;
- an "Approve" button on the existing clause screen;
- signed evidence records with a simple share page, without the zip.

That covers scenes 2, 4 and 7 live on GitHub.

---

## 7. Risks to watch

- **Analyzer accuracy on real code is the main risk.** The R-1 finding on the loan endpoint shows it: the endpoint handles personal data but stores nothing.
  - Before selling, measure false alarms and misses per detector on 10–20 real repos (#28 started this with five corpora).
  - Fix the worst detectors first, and compare your analyzer with #28's on the same set.
- **Liability.** The product enforces the lawyer's approved reading of a contract. The terms of service must say it isn't legal advice.
- **Confidential inputs.** Contracts and source code are sensitive. Keep LLM use off by default, delete scan copies after each job, and offer the CI-only mode.
- **GitHub limits.** Answer webhooks within 10 seconds, send at most 50 annotations per request, and fetch a fresh installation token for each job.
