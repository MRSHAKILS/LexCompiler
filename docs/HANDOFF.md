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

### Log
<!-- One line per turn: date, side, commit, what was done. -->
