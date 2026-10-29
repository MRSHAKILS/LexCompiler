import { readRepositoryFilesAt, sourceLanguageForPath } from '../analyzer/repoBaseline.js';
import { checkConclusion } from '../github/checkRun.js';
import { splitClauses } from '../product/documents.js';
import { classifyFindings, globMatch, scanFiles, type ClassifiedFinding, type RawFinding } from '../product/scanner.js';
import { can, rulesetSha256, type ProductStore, type Repo, type RuleInEffect, type TokenPrincipal } from '../product/store.js';
import { summarizeFindings } from '../product/summary.js';
import { bm25Tokens } from '../rag/hybridRagEngine.js';
import { synthesizeRemediationPullRequest } from '../remediation/prSynthesizer.js';
import type { TargetRepoFile } from '../../shared/types.js';

/**
 * The six tools of the workspace MCP server (product guide, Phase 4a). They act as the token's
 * user in the token's workspace. Results carry data only (rules, findings, diffs, citations);
 * no tool approves rules or exceptions, edits rules, or reads another workspace.
 */

/** A failure the assistant should see (isError: true), as opposed to a protocol error. */
export class ToolError extends Error {}

export const MAX_CHECK_FILES = 200;
export const MAX_CHECK_BYTES = 2 * 1024 * 1024;

type Schema = Record<string, unknown>;
export interface WorkspaceToolSpec {
  name: string;
  title: string;
  description: string;
  inputSchema: Schema;
  annotations: { title: string; readOnlyHint: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint: boolean };
}

const repoArg = { type: 'string', description: 'Repository, as owner/name or the name shown in LexCompiler (for example "acme/core-platform").' };
const filesArg = {
  type: 'array',
  description: `Changed files with their full new content (at most ${MAX_CHECK_FILES} files and 2 MB in all).`,
  items: {
    type: 'object',
    properties: { path: { type: 'string', description: 'Path from the repository root.' }, content: { type: 'string' } },
    required: ['path', 'content'],
  },
};
const readOnly = (title: string) => ({ title, readOnlyHint: true, openWorldHint: false });

/** In a fixed order, so clients that cache the list see no change between calls. */
export const WORKSPACE_TOOLS: WorkspaceToolSpec[] = [
  {
    name: 'list_rules',
    title: 'List rules in effect',
    description: 'The approved compliance rules that apply to a repository: key, title, plain reading, version, scope and effective date.',
    inputSchema: { type: 'object', properties: { repo: repoArg }, required: ['repo'] },
    annotations: readOnly('List rules in effect'),
  },
  {
    name: 'check_changes',
    title: 'Check changes before commit',
    description:
      'Checks changed files against the rules in effect, over the latest scanned default-branch commit. Returns the findings the pull request check would report, each new, existing or waived, and the conclusion. Sent code is not stored.',
    inputSchema: {
      type: 'object',
      properties: { repo: repoArg, files: filesArg, deleted: { type: 'array', items: { type: 'string' }, description: 'Paths the change deletes.' } },
      required: ['repo', 'files'],
    },
    annotations: readOnly('Check changes before commit'),
  },
  {
    name: 'explain_finding',
    title: 'Explain a finding',
    description: 'The rule behind a finding: its text, approved version and approver, why the code fails, and citations. Give a fingerprint, or rule, path and line.',
    inputSchema: {
      type: 'object',
      properties: {
        fingerprint: { type: 'string' },
        rule: { type: 'string', description: 'Rule key, for example R-1.' },
        path: { type: 'string' },
        line: { type: 'integer' },
      },
    },
    annotations: readOnly('Explain a finding'),
  },
  {
    name: 'suggest_fix',
    title: 'Suggest a verified fix',
    description: 'A unified diff for one finding that passed the Z3 gate (the rule holds after the patch), or "no verified fix".',
    inputSchema: { type: 'object', properties: { repo: repoArg, fingerprint: { type: 'string' }, files: filesArg }, required: ['repo', 'fingerprint', 'files'] },
    annotations: readOnly('Suggest a verified fix'),
  },
  {
    name: 'request_exception',
    title: 'Request an exception',
    description: "Asks Legal to waive one finding until a date. The request waits in Legal's inbox; Legal decides it in LexCompiler. Needs the engineer role or higher.",
    inputSchema: {
      type: 'object',
      properties: {
        fingerprint: { type: 'string' },
        reason: { type: 'string', description: 'Why the finding should be waived.' },
        until: { type: 'string', description: 'Requested end date (ISO 8601), at most a year away.' },
      },
      required: ['fingerprint', 'reason', 'until'],
    },
    annotations: { title: 'Request an exception', readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: 'search_obligations',
    title: 'Search obligations',
    description: "Searches the workspace's approved rules and uploaded documents. Returns passages with citations.",
    inputSchema: { type: 'object', properties: { query: { type: 'string' }, limit: { type: 'integer', description: 'At most 10; default 5.' } }, required: ['query'] },
    annotations: readOnly('Search obligations'),
  },
];

export const CHECK_BEFORE_COMMIT_PROMPT = {
  name: 'check-before-commit',
  title: 'Check before commit',
  description: 'Checks every changed file with LexCompiler before you commit.',
  text: 'Call check_changes with every file I changed. Fix new findings, using suggest_fix when it returns a verified diff. Ask me before requesting an exception.',
};

/** Reads a repository's files at a commit (GitHub archive or local folder). */
export type ReadRepoFiles = (repo: Repo, commitSha: string) => Promise<TargetRepoFile[]>;

/** A finding from a recent check_changes call, so later calls can refer to it by fingerprint. */
interface RecentFinding {
  finding: ClassifiedFinding;
  repoId: string;
  at: number;
}

/** State the tools keep between calls, in memory only. Repository files are cached per commit. */
export class WorkspaceToolState {
  private recent = new Map<string, RecentFinding>();
  private files = new Map<string, Promise<TargetRepoFile[]>>();
  private baselines = new Map<string, RawFinding[]>();

  constructor(private readonly ttlMs = 24 * 3600 * 1000) {}

  remember(workspaceId: string, repoId: string, findings: ClassifiedFinding[]): void {
    const at = Date.now();
    for (const f of findings) {
      this.recent.delete(`${workspaceId}:${f.fingerprint}`);
      this.recent.set(`${workspaceId}:${f.fingerprint}`, { finding: f, repoId, at });
    }
    while (this.recent.size > 5000) this.recent.delete(this.recent.keys().next().value!);
  }

  recall(workspaceId: string, query: FindingQuery): RecentFinding | undefined {
    const fresh = (r: RecentFinding | undefined) => (r && Date.now() - r.at < this.ttlMs ? r : undefined);
    if ('fingerprint' in query) return fresh(this.recent.get(`${workspaceId}:${query.fingerprint}`));
    const hits = [...this.recent.entries()]
      .filter(([k]) => k.startsWith(`${workspaceId}:`))
      .map(([, r]) => r)
      .filter((r) => r.finding.ruleKey === query.ruleKey && r.finding.filePath === query.filePath && r.finding.startLine <= query.line && r.finding.endLine >= query.line);
    return fresh(hits.at(-1));
  }

  /** Files of one commit, downloaded once; the four most recent commits are kept. */
  repoFiles(repo: Repo, sha: string, read: ReadRepoFiles): Promise<TargetRepoFile[]> {
    const key = `${repo.id}:${sha}`;
    let p = this.files.get(key);
    if (!p) {
      p = read(repo, sha);
      p.catch(() => this.files.delete(key));
      this.files.set(key, p);
      while (this.files.size > 4) this.files.delete(this.files.keys().next().value!);
    }
    return p;
  }

  baseline(key: string): RawFinding[] | undefined {
    return this.baselines.get(key);
  }

  setBaseline(key: string, findings: RawFinding[]): void {
    this.baselines.set(key, findings);
    while (this.baselines.size > 16) this.baselines.delete(this.baselines.keys().next().value!);
  }
}

type FindingQuery = { fingerprint: string } | { ruleKey: string; filePath: string; line: number };

export interface ToolContext {
  store: ProductStore;
  principal: TokenPrincipal;
  state: WorkspaceToolState;
  readRepoFiles: ReadRepoFiles;
}

export interface ToolOutcome {
  data: Record<string, unknown>;
  /** For the call log: the repository, and paths and fingerprints (never code). */
  repo?: string | null;
  detail?: Record<string, unknown>;
}

// ---------------------------------------------------------------- arguments

/** Checks required arguments and top-level types; throws ToolError so the assistant can correct the call. */
export function validateToolArguments(spec: WorkspaceToolSpec, args: Record<string, unknown>): void {
  const properties = (spec.inputSchema.properties ?? {}) as Record<string, { type?: string }>;
  for (const key of (spec.inputSchema.required as string[] | undefined) ?? []) {
    if (args[key] === undefined || args[key] === null) throw new ToolError(`Missing required argument "${key}".`);
  }
  for (const [key, value] of Object.entries(args)) {
    const type = properties[key]?.type;
    if (!type || value === undefined || value === null) continue;
    const ok =
      type === 'array' ? Array.isArray(value) : type === 'integer' ? Number.isInteger(value) : type === 'object' ? typeof value === 'object' && !Array.isArray(value) : typeof value === type;
    if (!ok) throw new ToolError(`Argument "${key}" must be ${type === 'integer' ? 'an integer' : `a ${type}`}.`);
  }
}

/** A repository-relative path with forward slashes; refuses absolute paths and "..". */
export function cleanRepoPath(raw: unknown): string {
  const p = String(raw ?? '')
    .replace(/\\/g, '/')
    .replace(/^(\.\/)+/, '');
  if (!p || p.startsWith('/') || /^[A-Za-z]:/.test(p) || p.split('/').some((s) => s === '..' || s === '')) {
    throw new ToolError(`"${String(raw)}" is not a path from the repository root.`);
  }
  return p;
}

function sentFiles(raw: unknown): Array<{ path: string; content: string }> {
  const list = Array.isArray(raw) ? raw : [];
  if (list.length > MAX_CHECK_FILES) throw new ToolError(`At most ${MAX_CHECK_FILES} files per call (got ${list.length}).`);
  let bytes = 0;
  const seen = new Set<string>();
  return list.map((f, i) => {
    const o = (f && typeof f === 'object' ? f : {}) as Record<string, unknown>;
    if (typeof o.content !== 'string') throw new ToolError(`files[${i}].content must be a string.`);
    const path = cleanRepoPath(o.path);
    if (seen.has(path)) throw new ToolError(`${path} is sent twice.`);
    seen.add(path);
    bytes += Buffer.byteLength(o.content, 'utf8');
    if (bytes > MAX_CHECK_BYTES) throw new ToolError('The files are larger than 2 MB in all; send fewer at a time.');
    return { path, content: o.content };
  });
}

// ---------------------------------------------------------------- shared steps

/** A repository of the token's workspace, by owner/name, name or id. */
function resolveRepo(ctx: ToolContext, name: unknown): Repo {
  const wanted = String(name ?? '').trim().toLowerCase();
  const repos = ctx.store.listRepos(ctx.principal.workspaceId);
  const exact = repos.filter((r) => r.fullName.toLowerCase() === wanted || r.id === wanted);
  const matches = exact.length > 0 ? exact : repos.filter((r) => r.fullName.toLowerCase().split('/').pop() === wanted.split('/').pop());
  if (matches.length === 1) return matches[0];
  const known = repos.map((r) => r.fullName).join(', ') || 'none';
  throw new ToolError(matches.length > 1 ? `"${String(name)}" matches several repositories: ${matches.map((r) => r.fullName).join(', ')}.` : `Unknown repository "${String(name)}". This workspace has: ${known}.`);
}

/** Rules in effect for a repository, with the path globs each applies to there. */
function rulesFor(ctx: ToolContext, repo: Repo): { rules: RuleInEffect[]; globs: Map<string, string[]> } {
  const globs = new Map<string, string[]>();
  const rules = ctx.store.rulesInEffect(ctx.principal.workspaceId).filter((r) => {
    const g = ctx.store.ruleScopeGlobs(r.scope, repo.id);
    globs.set(r.ruleKey, g);
    return g.length > 0;
  });
  return { rules, globs };
}

const inScope = (findings: RawFinding[], globs: Map<string, string[]>) => findings.filter((f) => (globs.get(f.ruleKey) ?? ['**']).some((g) => globMatch(g, f.filePath)));

/** The default branch the change is compared with: the latest scanned commit, or a local folder. */
async function baseCommit(ctx: ToolContext, repo: Repo): Promise<{ sha: string; files: TargetRepoFile[]; scanId: string | null; rulesSha256: string | null }> {
  if (repo.source === 'local' && repo.localPath) return { sha: 'working-tree', files: readRepositoryFilesAt(repo.localPath), scanId: null, rulesSha256: null };
  const latest = ctx.store.latestBranchScan(repo.id);
  if (!latest) throw new ToolError(`${repo.fullName} has no scan of ${repo.defaultBranch} yet. It is scanned on the next push to ${repo.defaultBranch} or when Legal approves a rule.`);
  const scan = ctx.store.getScanById(latest.id);
  return { sha: latest.commitSha, files: await ctx.state.repoFiles(repo, latest.commitSha, ctx.readRepoFiles), scanId: latest.id, rulesSha256: scan?.rulesSha256 ?? null };
}

/** The base files with the sent files laid over them and deleted paths removed. Nothing is written to disk. */
function overlay(base: TargetRepoFile[], sent: Array<{ path: string; content: string }>, deleted: string[]): { files: TargetRepoFile[]; ignored: string[] } {
  const byPath = new Map(base.map((f) => [f.path, f]));
  for (const p of deleted) byPath.delete(p);
  const ignored: string[] = [];
  const now = new Date().toISOString();
  for (const f of sent) {
    const language = sourceLanguageForPath(f.path);
    if (!language) {
      ignored.push(f.path);
      continue;
    }
    byPath.set(f.path, { path: f.path, language, description: `${language} source file`, content: f.content, lastModified: now });
  }
  return { files: [...byPath.values()], ignored };
}

/** Findings on the base commit: the stored scan's when it used the same rules, otherwise scanned now (and cached). */
async function baseFindings(ctx: ToolContext, repo: Repo, base: Awaited<ReturnType<typeof baseCommit>>, rules: RuleInEffect[], globs: Map<string, string[]>): Promise<RawFinding[]> {
  const sha = rulesetSha256(rules);
  if (base.scanId && base.rulesSha256 === sha) return ctx.store.listFindings(base.scanId);
  const key = `${repo.id}:${base.sha}:${sha}`;
  const cached = base.sha === 'working-tree' ? undefined : ctx.state.baseline(key);
  if (cached) return cached;
  const findings = inScope((await scanFiles(base.files, rules)).findings, globs);
  if (base.sha !== 'working-tree') ctx.state.setBaseline(key, findings);
  return findings;
}

const findingView = (f: ClassifiedFinding) => ({
  fingerprint: f.fingerprint,
  rule: f.ruleKey,
  state: f.state,
  path: f.filePath,
  startLine: f.startLine,
  endLine: f.endLine,
  message: f.message,
  snippet: f.snippet.slice(0, 400),
});

/** A finding from a recent check_changes call, or else the latest stored scan that has it. */
function lookupFinding(ctx: ToolContext, query: FindingQuery): { finding: ClassifiedFinding; repoId: string; scan: { id: string; prNumber: number | null; headSha: string; baseSha: string | null } | null } {
  const recent = ctx.state.recall(ctx.principal.workspaceId, query);
  if (recent) return { finding: recent.finding, repoId: recent.repoId, scan: null };
  const stored = ctx.store.findStoredFinding(ctx.principal.workspaceId, query);
  if (stored) return { finding: stored, repoId: stored.repoId, scan: { id: stored.scan.id, prNumber: stored.scan.prNumber, headSha: stored.scan.commitSha, baseSha: stored.scan.baseSha } };
  throw new ToolError('No such finding in this workspace. Call check_changes first, then use a fingerprint it returned.');
}

function findingQuery(args: Record<string, unknown>): FindingQuery {
  if (typeof args.fingerprint === 'string' && args.fingerprint) return { fingerprint: args.fingerprint };
  if (typeof args.rule === 'string' && typeof args.path === 'string' && Number.isInteger(args.line)) return { ruleKey: args.rule, filePath: cleanRepoPath(args.path), line: Number(args.line) };
  throw new ToolError('Give a fingerprint, or rule, path and line.');
}

// ---------------------------------------------------------------- search

interface Passage {
  kind: 'rule' | 'document';
  citation: string;
  ruleKey?: string;
  documentId?: string;
  text: string;
}

/** BM25 over the workspace's rules in effect and its documents' clauses. */
export function searchObligations(store: ProductStore, workspaceId: string, query: string, limit = 5): Array<Passage & { score: number }> {
  const passages: Passage[] = store.rulesInEffect(workspaceId).map((r) => {
    const version = store.getRuleVersion(workspaceId, r.versionId);
    return { kind: 'rule', ruleKey: r.ruleKey, citation: `${r.ruleKey} v${r.version} · ${r.clause.citation}`, text: `${r.clause.title}. ${version?.sourceText ?? r.clause.rawLegalText}` };
  });
  for (const doc of store.listDocuments(workspaceId)) {
    const full = store.getDocument(workspaceId, doc.id);
    for (const c of full ? splitClauses(full.text) : []) {
      if (c.text.trim()) passages.push({ kind: 'document', documentId: doc.id, citation: c.number ? `${doc.title} §${c.number}` : doc.title, text: c.text.trim() });
    }
  }
  const terms = [...new Set(bm25Tokens(query))];
  if (terms.length === 0 || passages.length === 0) return [];
  const docs = passages.map((p) => bm25Tokens(`${p.citation} ${p.text}`));
  const avg = docs.reduce((n, d) => n + d.length, 0) / docs.length || 1;
  const df = new Map(terms.map((t) => [t, docs.filter((d) => d.includes(t)).length]));
  const k1 = 1.2;
  const b = 0.75;
  return passages
    .map((p, i) => {
      let score = 0;
      for (const t of terms) {
        const tf = docs[i].filter((x) => x === t).length;
        if (!tf) continue;
        const n = df.get(t)!;
        const idf = Math.log(1 + (passages.length - n + 0.5) / (n + 0.5));
        score += (idf * tf * (k1 + 1)) / (tf + k1 * (1 - b + (b * docs[i].length) / avg));
      }
      return { ...p, text: p.text.slice(0, 800), score: Math.round(score * 1000) / 1000 };
    })
    .filter((p) => p.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, Math.min(Math.max(limit, 1), 10));
}

// ---------------------------------------------------------------- the tools

export async function callWorkspaceTool(name: string, args: Record<string, unknown>, ctx: ToolContext): Promise<ToolOutcome> {
  const spec = WORKSPACE_TOOLS.find((t) => t.name === name);
  if (!spec) throw new ToolError(`Unknown tool "${name}".`);
  validateToolArguments(spec, args);
  const ws = ctx.principal.workspaceId;

  switch (name) {
    case 'list_rules': {
      const repo = resolveRepo(ctx, args.repo);
      const { rules, globs } = rulesFor(ctx, repo);
      return {
        repo: repo.fullName,
        data: {
          repo: repo.fullName,
          rules: rules.map((r) => {
            const v = ctx.store.getRuleVersion(ws, r.versionId);
            const plain = v?.card && typeof v.card.plainReading === 'string' ? v.card.plainReading : r.clause.title;
            return { key: r.ruleKey, title: r.clause.title, plainReading: plain, version: r.version, citation: r.clause.citation, scope: globs.get(r.ruleKey), effectiveFrom: v?.effectiveFrom ?? v?.approvedAt ?? null };
          }),
        },
      };
    }

    case 'check_changes': {
      const repo = resolveRepo(ctx, args.repo);
      const sent = sentFiles(args.files);
      const deleted = (Array.isArray(args.deleted) ? args.deleted : []).slice(0, MAX_CHECK_FILES).map(cleanRepoPath);
      const detail = { paths: sent.map((f) => f.path), deleted };
      const { rules, globs } = rulesFor(ctx, repo);
      if (rules.length === 0) {
        return { repo: repo.fullName, detail, data: { repo: repo.fullName, conclusion: 'neutral', rules: [], findings: [], note: 'No approved rules apply to this repository yet.' } };
      }
      const base = await baseCommit(ctx, repo);
      const { files, ignored } = overlay(base.files, sent, deleted);
      const head = await scanFiles(files, rules);
      const findings = classifyFindings(inScope(head.findings, globs), await baseFindings(ctx, repo, base, rules, globs), ctx.store.activeExceptions(ws, repo.id));
      const summary = summarizeFindings(findings, head.undecidedRuleKeys);
      ctx.state.remember(ws, repo.id, findings);
      // Findings in the sent files first: those are the ones the change can fix.
      const touched = new Set(sent.map((f) => f.path));
      const ordered = [...findings].sort((a, b) => Number(touched.has(b.filePath)) - Number(touched.has(a.filePath)));
      return {
        repo: repo.fullName,
        detail: { ...detail, fingerprints: findings.filter((f) => f.state === 'new').map((f) => f.fingerprint) },
        data: {
          repo: repo.fullName,
          baseCommit: base.sha,
          conclusion: checkConclusion('pull_request', summary),
          summary: { new: summary.newCount, existing: summary.existingCount, waived: summary.waivedCount, undecidedRules: summary.undecidedRuleKeys },
          rules: rules.map((r) => ({ key: r.ruleKey, version: r.version, title: r.clause.title })),
          findings: ordered.map(findingView),
          filesChecked: files.length,
          ...(ignored.length ? { ignoredPaths: ignored } : {}),
        },
      };
    }

    case 'explain_finding': {
      const { finding, repoId } = lookupFinding(ctx, findingQuery(args));
      const version = ctx.store.getRuleVersion(ws, finding.ruleVersionId);
      if (!version) throw new ToolError('The rule version of this finding no longer exists.');
      const approver = version.approvedBy ? ctx.store.listMembers(ws).find((m) => m.userId === version.approvedBy) : undefined;
      const repo = ctx.store.getRepo(repoId);
      const exception = finding.exceptionId ? ctx.store.getException(ws, finding.exceptionId) : undefined;
      return {
        repo: repo?.fullName ?? null,
        detail: { fingerprint: finding.fingerprint },
        data: {
          finding: { ...findingView(finding), repo: repo?.fullName ?? null },
          rule: {
            key: finding.ruleKey,
            title: version.clause.title,
            text: version.sourceText,
            citation: version.clause.citation,
            version: version.version,
            approvedBy: approver ? approver.name ?? approver.email : version.approvedBy,
            approvedAt: version.approvedAt,
          },
          why: finding.message,
          ...(exception ? { exception: { id: exception.id, status: exception.status, expiresAt: exception.expiresAt } } : {}),
          citations: searchObligations(ctx.store, ws, `${version.clause.title} ${finding.message}`, 3),
        },
      };
    }

    case 'suggest_fix': {
      const repo = resolveRepo(ctx, args.repo);
      const { finding } = lookupFinding(ctx, { fingerprint: String(args.fingerprint) });
      const rule = rulesFor(ctx, repo).rules.find((r) => r.ruleKey === finding.ruleKey);
      if (!rule) throw new ToolError(`${finding.ruleKey} does not apply to ${repo.fullName}.`);
      const sent = sentFiles(args.files);
      const base = await baseCommit(ctx, repo);
      const { files } = overlay(base.files, sent, []);
      const detail = { fingerprint: finding.fingerprint, paths: sent.map((f) => f.path) };
      const scan = await scanFiles(files, [rule]);
      if (!scan.findings.some((f) => f.fingerprint === finding.fingerprint)) {
        return { repo: repo.fullName, detail, data: { verified: false, result: 'not found', note: 'This finding is not in the sent files any more.' } };
      }
      const pr = await synthesizeRemediationPullRequest([rule.clause], files, scan.proofs);
      if (!pr || pr.status !== 'READY_TO_MERGE' || pr.postPatchZ3Status !== 'SAT_COMPLIANT') {
        return {
          repo: repo.fullName,
          detail,
          data: { verified: false, result: 'no verified fix', unresolvedRules: pr?.unresolvedClauseIds ?? [rule.ruleKey], validationErrors: pr?.validationErrors ?? [] },
        };
      }
      return {
        repo: repo.fullName,
        detail,
        data: {
          verified: true,
          gate: `Z3: ${finding.ruleKey} is SAT_COMPLIANT after the patch`,
          rule: finding.ruleKey,
          files: pr.filePatches.map((p) => ({ path: p.filePath, summary: p.summary, linesAdded: p.linesAdded, linesRemoved: p.linesRemoved })),
          diff: pr.filePatches.map((p) => p.unifiedDiff).join('\n'),
        },
      };
    }

    case 'request_exception': {
      if (!can(ctx.principal.role, 'requestExceptions')) throw new ToolError(`Your role (${ctx.principal.role}) cannot request exceptions.`);
      const until = new Date(String(args.until));
      if (Number.isNaN(until.getTime())) throw new ToolError('"until" must be a date (ISO 8601).');
      if (until.getTime() <= Date.now()) throw new ToolError('"until" must be in the future.');
      if (until.getTime() > Date.now() + 366 * 24 * 3600 * 1000) throw new ToolError('An exception can last at most one year.');
      const { finding, repoId, scan } = lookupFinding(ctx, { fingerprint: String(args.fingerprint) });
      const repo = ctx.store.getRepo(repoId);
      const { exception, created } = ctx.store.requestException({
        workspaceId: ws,
        ruleId: finding.ruleId,
        repoId,
        fingerprint: finding.fingerprint,
        reason: String(args.reason),
        requestedBy: ctx.principal.userId,
        requestedFrom: 'assistant',
        requestedUntil: until.toISOString(),
        scan,
        finding: { filePath: finding.filePath, startLine: finding.startLine, message: finding.message },
      });
      return {
        repo: repo?.fullName ?? null,
        detail: { fingerprint: finding.fingerprint, exceptionId: exception.id },
        data: { exceptionId: exception.id, status: exception.status, created, rule: exception.ruleKey, path: exception.filePath, requestedUntil: exception.requestedUntil, decidedBy: 'Legal, in the LexCompiler inbox' },
      };
    }

    case 'search_obligations': {
      const results = searchObligations(ctx.store, ws, String(args.query), Number.isInteger(args.limit) ? Number(args.limit) : 5);
      return { data: { query: String(args.query), results } };
    }

    default:
      throw new ToolError(`Tool "${name}" has no implementation.`);
  }
}
