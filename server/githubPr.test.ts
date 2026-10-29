import { describe, expect, it } from 'vitest';
import { GitHubPrError, openGitHubPullRequest } from './remediation/githubPr.js';
import type { RemediationPullRequest } from '../shared/types.js';

const pr = {
  prId: 'PR-LEX-abc',
  prNumber: 0,
  title: 'fix(compliance): enforce 72h PII retention',
  branchName: 'lexcompiler/remediate-abc',
  status: 'READY_TO_MERGE',
  postPatchZ3Status: 'SAT_COMPLIANT',
  postPatchVerifyTimeMs: 12,
  cegisIterations: 1,
  cryptographicAttestationHash: 'root',
  executiveSummary: 'summary',
  filePatches: [{ filePath: 'api/a.py', patchedContent: 'x = 1\n', summary: 'set x' }],
} as unknown as RemediationPullRequest;

function fakeGitHub() {
  const calls: Array<{ method: string; url: string; body?: Record<string, unknown> }> = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const method = init?.method || 'GET';
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
    calls.push({ method, url, body });
    const json = (status: number, data: unknown) => new Response(JSON.stringify(data), { status });
    if (method === 'GET' && url.endsWith('/repos/o/r')) return json(200, { default_branch: 'main' });
    if (url.includes('/git/ref/heads/main')) return json(200, { object: { sha: 'base-sha' } });
    if (url.endsWith('/git/refs')) return json(201, {});
    if (method === 'GET' && url.includes('/contents/')) return json(200, { sha: 'file-sha' });
    if (method === 'PUT') return json(200, {});
    if (url.endsWith('/pulls')) return json(201, { number: 42, html_url: 'https://github.com/o/r/pull/42' });
    return json(404, {});
  }) as typeof fetch;
  return { calls, fetchImpl };
}

describe('GitHub pull requests', () => {
  it('creates a branch, commits each patched file, and opens the PR', async () => {
    const { calls, fetchImpl } = fakeGitHub();
    const opened = await openGitHubPullRequest(pr, { token: 't', repository: 'o/r', pathPrefix: 'target-repo/', fetchImpl });
    expect(opened).toEqual({ number: 42, url: 'https://github.com/o/r/pull/42', branch: 'lexcompiler/remediate-abc' });
    const put = calls.find((c) => c.method === 'PUT')!;
    expect(put.url).toContain('/contents/target-repo/api/a.py');
    expect(put.body).toMatchObject({ branch: 'lexcompiler/remediate-abc', sha: 'file-sha' });
    expect(Buffer.from(String(put.body!.content), 'base64').toString()).toBe('x = 1\n');
    expect(calls.find((c) => c.url.endsWith('/git/refs'))!.body).toMatchObject({ sha: 'base-sha' });
    expect(calls.at(-1)!.body).toMatchObject({ head: 'lexcompiler/remediate-abc', base: 'main' });
  });

  it('refuses a remediation that did not pass the Z3 gate', async () => {
    const { fetchImpl } = fakeGitHub();
    await expect(
      openGitHubPullRequest({ ...pr, status: 'BLOCKED_UNRESOLVED' }, { token: 't', repository: 'o/r', fetchImpl })
    ).rejects.toBeInstanceOf(GitHubPrError);
  });
});
