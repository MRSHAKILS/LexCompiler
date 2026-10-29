# Overnight watcher for the local session (Windows PowerShell 5+ / PowerShell 7).
# Run from the repository root:   powershell -ExecutionPolicy Bypass -File scripts\handoff-local.ps1
# Stop it with Ctrl+C, or create a file named .handoff-stop in the repository root.
param(
  [string]$Branch = 'claude/compassionate-hypatia-3mjhsk',
  [int]$PollSeconds = 300,
  [int]$MaxHours = 10
)
$ErrorActionPreference = 'Stop'
$stateFile = '.handoff-state'
$deadline = (Get-Date).AddHours($MaxHours)
$prompt = @"
You are the LOCAL session in the overnight handoff described in docs/HANDOFF.md. Read it first.
1. Do the items under "For the local session", then continue with the Part 2 rows of
   docs/IMPLEMENTATION_LOG.md that are not Done (order: L-1, L-6, L-14, L-9, L-10, L-3, L-19, L-20, L-21, L-22).
2. Install or run only what docs/HANDOFF.md lists as pre-approved. Skip anything needing an API key,
   account or token and add it to "Needs the user". Never commit secrets.
3. Run: npm run typecheck, npm run lint, npm test, npm run verify:cli, npm run verify:realworld, npm run build.
   Fix failures you can; never weaken a test or a README/AGENTS.md claim.
4. Put anything you could not fix (command + output) under "For the cloud session", add a Log line.
5. Commit as: git -c user.name="mrshakils" -c user.email="121shakilahmed@gmail.com" commit
   with "[handoff:cloud]" in the message if the cloud session has work, otherwise "[handoff:done]".
   Push to origin $Branch. Then stop.
"@

Write-Host "Watching origin/$Branch for [handoff:local] until $deadline (Ctrl+C or .handoff-stop to quit)"
while ((Get-Date) -lt $deadline -and -not (Test-Path '.handoff-stop')) {
  git fetch --quiet origin $Branch
  $head = (git rev-parse "origin/$Branch").Trim()
  $message = git log -1 --format=%B "origin/$Branch"
  $last = if (Test-Path $stateFile) { (Get-Content $stateFile -Raw).Trim() } else { '' }
  if ($message -match '\[handoff:done\]') { Write-Host 'Handoff finished ([handoff:done]).'; break }
  if ($head -ne $last -and $message -match '\[handoff:local\]') {
    Write-Host "$(Get-Date -Format s) Local turn for $head"
    git checkout --quiet $Branch
    git pull --quiet --ff-only origin $Branch
    Set-Content $stateFile $head
    # Headless Claude Code run; edits are auto-accepted, shell commands are limited to the list below.
    claude -p $prompt --permission-mode acceptEdits `
      --allowedTools "Read" "Edit" "Write" "Glob" "Grep" "Bash(npm *)" "Bash(npx *)" "Bash(node *)" "Bash(git *)" "Bash(python *)" "Bash(py *)" "Bash(pip *)" "Bash(opa *)" "Bash(winget install open-policy-agent.opa*)" "Bash(ollama *)" "Bash(docker *)"
    Write-Host "$(Get-Date -Format s) Local turn finished"
  }
  Start-Sleep -Seconds $PollSeconds
}
