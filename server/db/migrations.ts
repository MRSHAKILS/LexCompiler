/**
 * Schema migrations for the product database, applied in order, once each. Never edit a
 * migration that has shipped; add a new one instead.
 */
export interface Migration {
  id: number;
  name: string;
  sql: string;
}

const ROLE_CHECK = "CHECK (role IN ('owner','legal','engineer','viewer'))";

export const MIGRATIONS: Migration[] = [
  {
    id: 1,
    name: 'workspaces, rules, scans, evidence',
    sql: `
CREATE TABLE workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_by TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  oidc_sub TEXT UNIQUE NOT NULL,
  email TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  name TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT
);
CREATE INDEX users_email ON users(lower(email));

CREATE TABLE memberships (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL ${ROLE_CHECK},
  created_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, user_id)
);

-- A person invited by email before their first sign-in.
CREATE TABLE invitations (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL ${ROLE_CHECK},
  invited_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  accepted_at TEXT,
  UNIQUE (workspace_id, email)
);

-- Only a SHA-256 of each session id is stored, so a database leak does not leak sessions.
CREATE TABLE sessions (
  id_sha256 TEXT PRIMARY KEY,
  principal_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE github_installations (
  installation_id INTEGER PRIMARY KEY,
  account_login TEXT NOT NULL,
  account_type TEXT NOT NULL,
  workspace_id TEXT REFERENCES workspaces(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  removed_at TEXT
);

-- workspace_id is NULL while a GitHub installation is not linked to a workspace yet.
CREATE TABLE repos (
  id TEXT PRIMARY KEY,
  workspace_id TEXT REFERENCES workspaces(id) ON DELETE CASCADE,
  source TEXT NOT NULL CHECK (source IN ('github','local')),
  installation_id INTEGER REFERENCES github_installations(installation_id),
  github_repo_id INTEGER UNIQUE,
  full_name TEXT NOT NULL,
  default_branch TEXT NOT NULL DEFAULT 'main',
  local_path TEXT,
  created_at TEXT NOT NULL,
  removed_at TEXT
);
CREATE INDEX repos_workspace ON repos(workspace_id);

CREATE TABLE counterparties (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, name)
);

CREATE TABLE counterparty_scope (
  counterparty_id TEXT NOT NULL REFERENCES counterparties(id) ON DELETE CASCADE,
  repo_id TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
  path_glob TEXT NOT NULL DEFAULT '**',
  PRIMARY KEY (counterparty_id, repo_id, path_glob)
);

CREATE TABLE documents (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  counterparty_id TEXT REFERENCES counterparties(id) ON DELETE SET NULL,
  kind TEXT NOT NULL DEFAULT 'contract' CHECK (kind IN ('contract','regulation','policy')),
  title TEXT NOT NULL,
  language TEXT,
  file_sha256 TEXT NOT NULL,
  text TEXT NOT NULL,
  supersedes_id TEXT REFERENCES documents(id),
  uploaded_by TEXT NOT NULL,
  uploaded_at TEXT NOT NULL
);

CREATE TABLE rules (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  title TEXT NOT NULL,
  created_at TEXT NOT NULL,
  retired_at TEXT,
  retired_by TEXT,
  UNIQUE (workspace_id, key)
);

-- clause_json is the compiled LegalClause, frozen when the version is created. Scans use it
-- as stored, so a compiler upgrade never changes what an approved rule means.
CREATE TABLE rule_versions (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft','approved','rejected','retired')),
  document_id TEXT REFERENCES documents(id),
  source_text TEXT NOT NULL,
  clause_json TEXT NOT NULL,
  clause_sha256 TEXT NOT NULL,
  scope_json TEXT NOT NULL DEFAULT '{"all":true}',
  answers_json TEXT,
  effective_from TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  approved_by TEXT,
  approved_at TEXT,
  decision_note TEXT,
  UNIQUE (rule_id, version)
);

CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  repo_id TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
  commit_sha TEXT NOT NULL,
  base_sha TEXT,
  trigger TEXT NOT NULL,
  pr_number INTEGER,
  rules_sha256 TEXT NOT NULL,
  rule_versions_json TEXT NOT NULL,
  lexcompiler_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','in_progress','completed','failed')),
  conclusion TEXT,
  check_run_id INTEGER,
  files_scanned INTEGER,
  facts_json TEXT,
  summary_json TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);
CREATE INDEX scans_repo_commit ON scans(repo_id, commit_sha, rules_sha256);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  rule_version_id TEXT NOT NULL REFERENCES rule_versions(id),
  rule_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  file_path TEXT NOT NULL,
  start_line INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  construct_type TEXT,
  message TEXT NOT NULL,
  snippet TEXT,
  state TEXT NOT NULL CHECK (state IN ('new','existing','waived')),
  exception_id TEXT
);
CREATE INDEX findings_scan ON findings(scan_id);

CREATE TABLE exceptions (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  repo_id TEXT REFERENCES repos(id) ON DELETE CASCADE,
  fingerprint TEXT,
  path_glob TEXT,
  reason TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_from TEXT,
  requested_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('requested','approved','rejected','expired','revoked')),
  decided_by TEXT,
  decided_at TEXT,
  decision_note TEXT,
  expires_at TEXT
);

-- Append-only, hash-chained, signed log per workspace.
CREATE TABLE evidence (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  seq INTEGER NOT NULL,
  header TEXT NOT NULL,
  header_sha256 TEXT NOT NULL,
  body TEXT NOT NULL,
  signature TEXT NOT NULL,
  PRIMARY KEY (workspace_id, seq)
);
CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence
  BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence
  BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;

CREATE TABLE shares (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  token_sha256 TEXT UNIQUE NOT NULL,
  label TEXT,
  counterparty_id TEXT REFERENCES counterparties(id),
  rule_ids_json TEXT NOT NULL,
  period_from TEXT NOT NULL,
  period_to TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE share_views (
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  at TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT
);

CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  dedupe_key TEXT,
  status TEXT NOT NULL CHECK (status IN ('queued','running','done','failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  run_after TEXT NOT NULL,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX jobs_ready ON jobs(status, run_after);
-- At most one queued or running job per dedupe key (e.g. one scan per commit and rule set).
CREATE UNIQUE INDEX jobs_dedupe ON jobs(dedupe_key) WHERE status IN ('queued','running');

CREATE TABLE webhook_deliveries (
  delivery_id TEXT PRIMARY KEY,
  event TEXT NOT NULL,
  action TEXT,
  received_at TEXT NOT NULL
);
`,
  },
  {
    id: 2,
    name: 'scans remember the job that ran them',
    sql: `
ALTER TABLE scans ADD COLUMN job_id TEXT;
CREATE INDEX scans_job ON scans(job_id);
`,
  },
];
