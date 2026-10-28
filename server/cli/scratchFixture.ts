import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Points LexCompiler at a throwaway copy of the bundled `target-repo/` fixture so tests
 * and demo CLIs can reset, patch, and commit without touching the working tree.
 * Must run before any module that reads LEXCOMPILER_TARGET_REPO is imported.
 */
export function useScratchFixtureCopy(label: string): string {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), `lexcompiler-${label}-`));
  const repo = path.join(scratch, 'target-repo');
  fs.cpSync(path.resolve(process.cwd(), 'target-repo'), repo, {
    recursive: true,
    filter: (src) => path.basename(src) !== '.git',
  });
  process.env.LEXCOMPILER_TARGET_REPO = repo;
  process.env.LEXCOMPILER_TARGET_REPO_IS_FIXTURE = '1';
  process.env.LEXCOMPILER_SANDBOX_GIT_DIR = path.join(scratch, 'sandbox-git');
  process.env.LEXCOMPILER_DATA_DIR = path.join(scratch, 'data');
  return repo;
}
