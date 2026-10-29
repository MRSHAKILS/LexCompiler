import { describe, expect, it } from 'vitest';
import { readTargetRepoFiles, resetTargetRepoToBaseline, writeTargetRepoFile } from './analyzer/repoBaseline.js';
import { commitTargetRepoChanges, resetTargetRepoGitHistory, resolveRepositoryIdentity } from './sandbox/realWorldSandbox.js';
import { resolvePython, resolvePythonAsync } from './util/python.js';

describe('request-path subprocesses do not block the event loop', () => {
  it('runs sandbox Git asynchronously and serialises concurrent commits', async () => {
    resetTargetRepoToBaseline();
    await resetTargetRepoGitHistory();
    const base = await resolveRepositoryIdentity('x');
    expect(base.commitHash).toMatch(/^[0-9a-f]{12}$/);

    const [a, b] = readTargetRepoFiles().filter((f) => f.language === 'python');
    writeTargetRepoFile(a.path, `${a.content}\n# edit 1\n`);
    let ticks = 0;
    const timer = setInterval(() => ticks++, 1);
    const first = commitTargetRepoChanges('test: edit 1');
    writeTargetRepoFile(b.path, `${b.content}\n# edit 2\n`);
    const second = commitTargetRepoChanges('test: edit 2');
    const [h1, h2] = await Promise.all([first, second]);
    clearInterval(timer);

    // The timer kept firing while git ran, so the commits did not block the event loop.
    expect(ticks).toBeGreaterThan(0);
    // Queued, not racing on the index lock: the first commit takes both edits (both were written
    // before its `git add` ran), the second finds nothing to commit, and nothing is left behind.
    expect(h1).toMatch(/^[0-9a-f]{7,}$/);
    expect(h1).not.toBe(base.commitHash.slice(0, h1.length));
    expect(h2).toBe(h1);
    expect((await resolveRepositoryIdentity('x')).dirty).toBe(false);

    // A later edit gets its own commit.
    writeTargetRepoFile(a.path, `${a.content}\n# edit 3\n`);
    const h3 = await commitTargetRepoChanges('test: edit 3');
    expect(h3).not.toBe(h1);
  });

  it('resolves the same Python interpreter asynchronously as synchronously', async () => {
    const asyncPy = await resolvePythonAsync();
    expect(asyncPy).toEqual(resolvePython());
    expect(asyncPy?.version).toMatch(/^Python 3\.\d+\.\d+$/);
  });
});
