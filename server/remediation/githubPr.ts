import type { RemediationPullRequest } from '../../shared/types.js';

export interface GitHubPrOptions {
  token: string;
  /** "owner/name" of the repository that contains the scanned files. */
  repository: string;
  baseBranch?: string;
  /** Path of the scanned repository inside the GitHub repository (e.g. "target-repo/"). */
  pathPrefix?: string;
  apiUrl?: string;
  fetchImpl?: typeof fetch;
}

export class GitHubPrError extends Error {
  constructor(
    message: string,
    public status?: number
  ) {
    super(message);
  }
}

/** Reads GitHub settings from the environment; null when PR creation is not configured. */
export function githubPrOptionsFromEnv(env: NodeJS.ProcessEnv = process.env): GitHubPrOptions | null {
  const token = env.LEXCOMPILER_GITHUB_TOKEN || env.GITHUB_TOKEN;
  const repository = env.LEXCOMPILER_GITHUB_REPO;
  if (!token || !repository) return null;
  return {
    token,
    repository,
    baseBranch: env.LEXCOMPILER_GITHUB_BASE || undefined,
    pathPrefix: env.LEXCOMPILER_GITHUB_PATH_PREFIX || '',
    apiUrl: env.GITHUB_API_URL || undefined,
  };
}

/**
 * Pushes a READY_TO_MERGE remediation bundle to a new branch through the GitHub REST API
 * (one commit per file) and opens a pull request against the base branch.
 */
export async function openGitHubPullRequest(
  pr: RemediationPullRequest,
  options: GitHubPrOptions
): Promise<{ number: number; url: string; branch: string }> {
  if (pr.status !== 'READY_TO_MERGE') {
    throw new GitHubPrError('Only a remediation that passed the Z3 gate (READY_TO_MERGE) can be opened as a pull request.', 409);
  }
  const doFetch = options.fetchImpl || fetch;
  const api = (options.apiUrl || 'https://api.github.com').replace(/\/$/, '');
  const repo = options.repository;
  const call = async (method: string, route: string, body?: unknown, okStatuses: number[] = []) => {
    const res = await doFetch(`${api}/repos/${repo}${route}`, {
      method,
      headers: {
        Authorization: `Bearer ${options.token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok && !okStatuses.includes(res.status)) {
      const text = await res.text().catch(() => '');
      throw new GitHubPrError(`GitHub ${method} ${route} failed (${res.status}): ${text.slice(0, 300)}`, res.status);
    }
    return { status: res.status, data: res.status === 204 ? {} : ((await res.json().catch(() => ({}))) as Record<string, unknown>) };
  };

  const repoInfo = await call('GET', '');
  const base = options.baseBranch || String(repoInfo.data.default_branch || 'main');
  const baseRef = await call('GET', `/git/ref/heads/${encodeURIComponent(base)}`);
  const baseSha = String((baseRef.data.object as { sha?: string } | undefined)?.sha || '');
  const branch = pr.branchName || `lexcompiler/remediate-${pr.prId.toLowerCase()}`;
  await call('POST', '/git/refs', { ref: `refs/heads/${branch}`, sha: baseSha }, [422]); // 422: branch exists

  for (const patch of pr.filePatches) {
    const filePath = `${options.pathPrefix || ''}${patch.filePath}`;
    const encoded = filePath.split('/').map(encodeURIComponent).join('/');
    const existing = await call('GET', `/contents/${encoded}?ref=${encodeURIComponent(branch)}`, undefined, [404]);
    await call('PUT', `/contents/${encoded}`, {
      message: `fix(compliance): ${patch.summary}`.slice(0, 200),
      content: Buffer.from(patch.patchedContent, 'utf8').toString('base64'),
      branch,
      ...(existing.status === 200 && existing.data.sha ? { sha: existing.data.sha } : {}),
    });
  }

  const body = [
    pr.executiveSummary,
    '',
    `Post-patch Z3 status: **${pr.postPatchZ3Status}** (${pr.postPatchVerifyTimeMs} ms, ${pr.cegisIterations ?? 0} repair round(s)).`,
    `Merkle audit root: \`${pr.cryptographicAttestationHash}\``,
    '',
    '| File | Change |',
    '| :--- | :--- |',
    ...pr.filePatches.map((p) => `| \`${p.filePath}\` | ${p.summary.replace(/\|/g, '\\|')} |`),
  ].join('\n');
  const created = await call('POST', '/pulls', { title: pr.title, head: branch, base, body });
  return { number: Number(created.data.number), url: String(created.data.html_url), branch };
}
