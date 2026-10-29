import type { JobQueue } from '../jobs/queue.js';
import type { ExceptionRecord, ProductStore } from '../product/store.js';
import type { GitHubApp } from './client.js';
import type { ScanJobPayload } from './scanJob.js';

/**
 * Exceptions from GitHub (product guide, Phase 4): the "Request exception" button on a failing
 * check, the comment that tells the PR it is waiting for Legal, and the re-run after Legal decides.
 */

export const REQUEST_EXCEPTION = 'request_exception';

/** The button GitHub shows on a failing pull request check (label ≤ 20, description ≤ 40 characters). */
export const REQUEST_EXCEPTION_ACTION = { label: 'Request exception', description: 'Ask Legal to waive the new findings', identifier: REQUEST_EXCEPTION } as const;

export interface CommentJobPayload {
  installationId: number;
  fullName: string;
  issueNumber: number;
  body: string;
}

/** Posts a comment on a pull request with the installation token. */
export function createCommentJobHandler(deps: { getApp: () => GitHubApp | null }) {
  return async (raw: Record<string, unknown>): Promise<void> => {
    const p = raw as unknown as CommentJobPayload;
    const app = deps.getApp();
    if (!app) throw new Error('The GitHub App is not configured on this server.');
    await app.request(p.installationId, 'POST', `/repos/${p.fullName}/issues/${p.issueNumber}/comments`, { body: p.body });
  };
}

/**
 * A click on "Request exception": one request per new finding of the run's scan, attributed to
 * the GitHub user who clicked. Returns what to tell the webhook caller.
 */
export function requestExceptionsFromCheckRun(
  deps: { store: ProductStore; queue: JobQueue },
  input: { checkRunId: number; installationId: number; login: string; deliveryId: string }
): string {
  const scan = deps.store.getScanByCheckRun(input.checkRunId);
  if (!scan) return 'ignored: no LexCompiler scan for this check run';
  const repo = deps.store.getRepo(scan.repoId);
  if (!repo?.workspaceId) return 'ignored: the repository is not linked to a workspace';
  if (scan.prNumber === null) return 'ignored: exceptions are requested on pull requests';
  const findings = deps.store.listFindings(scan.id).filter((f) => f.state === 'new');
  if (findings.length === 0) return 'ignored: the check has no new findings';
  let created = 0;
  for (const f of findings) {
    const r = deps.store.requestException({
      workspaceId: repo.workspaceId,
      ruleId: f.ruleId,
      repoId: repo.id,
      fingerprint: f.fingerprint,
      reason: `Requested from GitHub by @${input.login} on pull request #${scan.prNumber}`,
      requestedBy: `github:${input.login}`,
      requestedFrom: 'github',
      scan: { id: scan.id, prNumber: scan.prNumber, headSha: scan.commitSha, baseSha: scan.baseSha },
      finding: { filePath: f.filePath, startLine: f.startLine, message: f.message },
    });
    if (r.created) created++;
  }
  if (created > 0) {
    const what = findings.map((f) => `- **${f.ruleKey}** \`${f.filePath}:${f.startLine}\``).join('\n');
    deps.queue.enqueue(
      'github_comment',
      {
        installationId: input.installationId,
        fullName: repo.fullName,
        issueNumber: scan.prNumber,
        body: `Exception requested by @${input.login} — waiting for Legal.\n\n${what}\n\nThe check runs again when Legal decides.`,
      } satisfies CommentJobPayload as unknown as Record<string, unknown>,
      { dedupeKey: `exception-comment:${input.deliveryId}` }
    );
  }
  return created > 0 ? `exception requested for ${created} finding${created === 1 ? '' : 's'}` : 'exception already requested';
}

/** Runs a pull request's check again after Legal decided an exception requested on it. */
export function rerunCheckForException(deps: { store: ProductStore; queue: JobQueue }, exception: ExceptionRecord): string | null {
  if (exception.prNumber === null || !exception.headSha || !exception.repoId) return null;
  const repo = deps.store.getRepo(exception.repoId);
  if (!repo || repo.source !== 'github' || repo.githubRepoId === null || repo.installationId === null) return null;
  const payload: ScanJobPayload = {
    githubRepoId: repo.githubRepoId,
    installationId: repo.installationId,
    kind: 'pull_request',
    trigger: 'rerun',
    headSha: exception.headSha,
    baseSha: exception.baseSha,
    prNumber: exception.prNumber,
  };
  return deps.queue.enqueue('scan', payload as unknown as Record<string, unknown>, { dedupeKey: `exception:${exception.id}:${exception.status}` });
}

/** "1 finding waived until 30 Nov 2026" for the check summary; null when nothing is waived. */
export function waiverLine(scanFindings: Array<{ state: string; exceptionId: string | null }>, expiries: Map<string, string | null>): string | null {
  const waived = scanFindings.filter((f) => f.state === 'waived');
  if (waived.length === 0) return null;
  const dates = [...new Set(waived.map((f) => (f.exceptionId ? expiries.get(f.exceptionId) : null)).filter((d): d is string => Boolean(d)))].sort();
  const fmt = (iso: string) => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
  const n = `${waived.length} finding${waived.length === 1 ? '' : 's'} waived`;
  return dates.length ? `${n} until ${fmt(dates[0])}${dates.length > 1 ? ` (the first of ${dates.length} expiry dates)` : ''}` : n;
}

