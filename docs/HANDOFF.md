# Overnight handoff between the local and cloud sessions

The two sessions take turns through commits on `claude/compassionate-hypatia-3mjhsk`:

- A commit whose message contains **`[handoff:cloud]`** asks the cloud session to work next.
- A commit whose message contains **`[handoff:local]`** asks the local session to work next.
- Each side writes what it did and what it needs from the other side in the queue below, commits with the other side's tag, and pushes.
- **`[handoff:done]`** means nothing is left for either side; both stop.

The cloud session checks the branch hourly. The local watcher (`scripts/handoff-local.ps1`) checks every 5 minutes.

## Pre-approved for unattended local work

The local session may install or run only what is listed here without asking. Edit this list before you go to sleep.

- OPA (`winget install open-policy-agent.opa`) — for L-1
- `ollama pull qwen2.5-coder:0.5b`, `ollama pull dolphin3`, `ollama pull all-minilm` (only if Ollama is already installed) — for L-6
- `docker build` / `docker compose up` (only if Docker Desktop is already running) — for L-14, L-9
- `npm ci`, `npm run setup:sandbox`, `pip install -r agents/requirements.txt` into `.venv-agents`

Anything that needs an API key, a cloud account, a GitHub token or a new paid service is **skipped** and listed under "Needs the user" below.

## Queue

### For the cloud session
<!-- The local session appends failures it could not fix, with the command and its output. -->

### For the local session
<!-- The cloud session appends what to re-run after its fixes. -->

### Needs the user
<!-- Items waiting for credentials or a decision. -->
- **L-7** GitHub PR end to end: `LEXCOMPILER_GITHUB_TOKEN` and `LEXCOMPILER_GITHUB_REPO` for a repository you own, then open one PR from the drawer.
- **L-8** Hardware-backed signing: a GCP Cloud KMS (`EC_SIGN_ED25519`, HSM) or AWS KMS (`ECC_NIST_P256`) key and credentials; set `LEXCOMPILER_SIGNER`, the key id and `LEXCOMPILER_TSA_URL`.
- **L-18** OIDC: register LexCompiler with your IdP (Keycloak, Entra ID, Okta, Auth0) and set `LEXCOMPILER_OIDC_*`.
- **L-15** Code scanning: enable it on a repository and call the reusable `lexcompiler-scan.yml` workflow.
- **L-2 / L-4 / L-5** Named provider models: API keys for Claude, GPT-4o, DeepSeek, Gemini or a hosted Llama 70B (the agents, the RAG judge and measured prompt-cache hits were verified with local Ollama models only).
- **L-12** The GitHub MCP (token) and n8n (an n8n instance with an MCP Server Trigger workflow); the other four servers are verified.
- **L-17 (optional)** A real DPIA for `services/ai_credit_triage.ts`, which is a document for the owner to write.

### Log
<!-- One line per turn: date, side, commit, what was done. -->
- 2026-10-28/29, local (Windows): `fe49ce7`…`7583c9c`, Steps 22–34. Fixed Windows test portability; verified L-1, L-3, L-6, L-9, L-10, L-13, L-14 locally; fixed and verified L-2, L-4, L-5, L-12 as far as possible without credentials; implemented L-20, L-21, L-22; L-19 on five real-world corpora. Nothing is left for the cloud session.
