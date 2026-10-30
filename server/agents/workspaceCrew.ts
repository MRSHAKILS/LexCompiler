import { scopedRules } from '../product/repoScan.js';
import { StoreError, type ProductStore, type Repo } from '../product/store.js';
import type { TargetRepoFile } from '../../shared/types.js';
import { runCrew, type CrewPullRequest, type CrewRun, type CrewRunStore } from './crew.js';

/**
 * The crew on a workspace's repository (HANDOFF, agent crew item 4): the rules in effect for that
 * repository, the files of its default branch, and, when asked, a real pull request for a patch
 * that passed the Z3 gate (item 3), opened through the product's fix-PR path.
 */
export interface WorkspaceCrewDeps {
  store: ProductStore;
  runs: CrewRunStore;
  /** The default branch's head commit and files (a local repository's working tree is "working-tree"). */
  readHead: (repo: Repo) => Promise<{ commitSha: string; files: TargetRepoFile[] }>;
  /** Opens the verified fix pull request (openFixPullRequest); absent without a GitHub App. */
  openFixPr?: (repo: Repo, requestedBy: string) => Promise<CrewPullRequest>;
  runCrew?: typeof runCrew;
}

export async function runWorkspaceCrew(
  deps: WorkspaceCrewDeps,
  repo: Repo,
  opts: { useModels: boolean; openPullRequest: boolean; requestedBy: string; triggeredBy: string | null }
): Promise<CrewRun> {
  if (!repo.workspaceId) throw new StoreError('the repository is not linked to a workspace', 409);
  if (opts.openPullRequest && repo.source !== 'github') throw new StoreError('pull requests are opened on GitHub repositories; apply the patch to a local folder by hand', 409);
  if (opts.openPullRequest && !deps.openFixPr) throw new StoreError('the GitHub App is not configured on this server', 503);
  const { rules } = scopedRules(deps.store, repo, deps.store.rulesInEffect(repo.workspaceId));
  if (rules.length === 0) throw new StoreError(`no approved rule is in effect for ${repo.fullName}`, 409);
  const { commitSha, files } = await deps.readHead(repo);
  const run = await (deps.runCrew ?? runCrew)(
    rules.map((r) => r.clause),
    {
      useModels: opts.useModels,
      files,
      triggeredBy: opts.triggeredBy,
      target: { workspaceId: repo.workspaceId, repoId: repo.id, repoFullName: repo.fullName, commitSha },
      openPullRequest: opts.openPullRequest && deps.openFixPr ? () => deps.openFixPr!(repo, opts.requestedBy) : undefined,
    }
  );
  deps.runs.save(run);
  return run;
}
