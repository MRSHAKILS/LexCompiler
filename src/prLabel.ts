import type { RemediationPullRequest } from '../shared/types';

/** "PR #123" once a GitHub pull request exists, otherwise the local bundle id. */
export function prLabel(pr: Pick<RemediationPullRequest, 'prNumber' | 'prId'>): string {
  return pr.prNumber > 0 ? `PR #${pr.prNumber}` : pr.prId;
}
