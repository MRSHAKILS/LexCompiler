import { execFile, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export interface PythonInterpreter {
  /** Executable to spawn. */
  command: string;
  /** Arguments that must precede the script arguments (e.g. `-3` for the Windows `py` launcher). */
  prefixArgs: string[];
  /** e.g. `Python 3.12.10`. */
  version: string;
}

const MIN_MINOR = 10;
const VERSION_SCRIPT = 'import sys; print("%d.%d.%d" % sys.version_info[:3])';

/**
 * Candidates in priority order: LEXCOMPILER_PYTHON, `python3`, `python`, and the Windows
 * `py -3` launcher. On Windows `python3` is often the Microsoft Store alias stub, which
 * exits non-zero, so it is skipped by the version probe.
 */
function candidates(): Array<{ command: string; prefixArgs: string[] }> {
  const list: Array<{ command: string; prefixArgs: string[] }> = [];
  const override = process.env.LEXCOMPILER_PYTHON?.trim();
  if (override) list.push({ command: override, prefixArgs: [] });
  list.push({ command: 'python3', prefixArgs: [] }, { command: 'python', prefixArgs: [] });
  if (process.platform === 'win32') list.push({ command: 'py', prefixArgs: ['-3'] });
  return list;
}

function accept(c: { command: string; prefixArgs: string[] }, out: string): PythonInterpreter | null {
  const [major, minor] = out.trim().split('.').map(Number);
  return major === 3 && minor >= MIN_MINOR ? { command: c.command, prefixArgs: c.prefixArgs, version: `Python ${out.trim()}` } : null;
}

function probe(command: string, args: string[]): Promise<string | null> {
  return new Promise((resolve) =>
    execFile(command, args, { encoding: 'utf8', timeout: 5000, windowsHide: true }, (err, stdout) => resolve(err ? null : stdout))
  );
}

let resolved: PythonInterpreter | null | undefined;
let resolving: Promise<PythonInterpreter | null> | undefined;

/**
 * Finds a Python >= 3.10 interpreter once per process without blocking the event loop;
 * null when none is installed. The server awaits this at startup, so later
 * `resolvePython()` calls are answered from the cache.
 */
export function resolvePythonAsync(): Promise<PythonInterpreter | null> {
  if (resolved !== undefined) return Promise.resolve(resolved);
  resolving ??= (async () => {
    for (const c of candidates()) {
      const out = await probe(c.command, [...c.prefixArgs, '-I', '-c', VERSION_SCRIPT]);
      const found = out && accept(c, out);
      if (found) return (resolved = found);
    }
    return (resolved = null);
  })();
  return resolving;
}

/** Synchronous variant for CLIs and tests; blocks only on the first call of a process. */
export function resolvePython(): PythonInterpreter | null {
  if (resolved !== undefined) return resolved;
  resolved = null;
  for (const c of candidates()) {
    try {
      const out = execFileSync(c.command, [...c.prefixArgs, '-I', '-c', VERSION_SCRIPT], {
        encoding: 'utf8',
        timeout: 5000,
        stdio: ['ignore', 'pipe', 'ignore'],
        windowsHide: true,
      });
      const found = accept(c, out);
      if (found) {
        resolved = found;
        break;
      }
    } catch {
      // not installed, a store stub, or too old: try the next candidate
    }
  }
  return resolved;
}

/**
 * Interpreter for the runtime sandbox: LEXCOMPILER_SANDBOX_PYTHON, then the project's
 * `.venv` (created by `npm run setup:sandbox` with the real FastAPI/Pydantic/Redis
 * packages), then any Python >= 3.10. Probed without blocking the event loop.
 */
export async function resolveSandboxPython(): Promise<PythonInterpreter | null> {
  const explicit = process.env.LEXCOMPILER_SANDBOX_PYTHON?.trim();
  const venv = path.join(process.cwd(), '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  for (const command of [explicit, fs.existsSync(venv) ? venv : undefined]) {
    if (!command) continue;
    const out = await probe(command, ['-c', VERSION_SCRIPT]);
    if (out) return { command, prefixArgs: [], version: `Python ${out.trim()}` };
  }
  return resolvePythonAsync();
}
