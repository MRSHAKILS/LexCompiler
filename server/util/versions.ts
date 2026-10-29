import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
let z3Version: string | null = null;

/** Version of the installed `z3-solver` package, i.e. the Z3 build that actually runs. */
export function z3SolverVersion(): string {
  if (z3Version) return z3Version;
  try {
    // Walk up from the package entry point to its package.json (no reliance on "exports").
    let dir = path.dirname(require.resolve('z3-solver'));
    for (let i = 0; i < 6; i++) {
      const file = path.join(dir, 'package.json');
      if (fs.existsSync(file)) {
        const pkg = JSON.parse(fs.readFileSync(file, 'utf8')) as { name?: string; version?: string };
        if (pkg.name === 'z3-solver' && pkg.version) return (z3Version = pkg.version);
      }
      dir = path.dirname(dir);
    }
  } catch {
    // Fall through: report the version as unknown rather than guessing one.
  }
  return (z3Version = 'unknown');
}

/** Human-readable engine label for reports. z3-solver runs Z3 compiled to WebAssembly. */
export function z3EngineLabel(): string {
  return `Microsoft Z3 ${z3SolverVersion()} (z3-solver, WebAssembly)`;
}

let lexcVersion: string | null = null;

/**
 * The LexCompiler build that produced a scan: the git commit of this checkout, or the package
 * version when not running from a git checkout. Recorded on every scan for reproducibility.
 */
export function lexcompilerVersion(): string {
  if (lexcVersion) return lexcVersion;
  const env = process.env.LEXCOMPILER_VERSION?.trim();
  if (env) return (lexcVersion = env);
  try {
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: process.cwd(), encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (/^[0-9a-f]{40}$/.test(sha)) {
      // A modified checkout is not exactly that commit; the record says so.
      const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], { cwd: process.cwd(), encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      return (lexcVersion = `git:${sha}${dirty ? '-dirty' : ''}`);
    }
  } catch {
    // Not a git checkout (e.g. a Docker image): fall back to the package version.
  }
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8')) as { version?: string };
    return (lexcVersion = `pkg:${pkg.version ?? 'unknown'}`);
  } catch {
    return (lexcVersion = 'unknown');
  }
}
