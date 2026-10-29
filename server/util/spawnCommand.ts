import fs from 'node:fs';
import path from 'node:path';

export interface SpawnTarget {
  command: string;
  args: string[];
  /** Set when the arguments are already a quoted cmd.exe command line. */
  windowsVerbatimArguments?: boolean;
}

// cmd.exe metacharacters; escaped with ^ (the same set cross-spawn uses).
const CMD_META = /([()\][%!^"`<>&|;, *?])/g;

function quoteForCmd(arg: string, doubleEscape: boolean): string {
  // Quote for the C runtime's argv parser: double the backslashes before quotes and at the end.
  let quoted = `"${arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, '$1$1')}"`;
  quoted = quoted.replace(CMD_META, '^$1');
  // npm's cmd shims re-parse the command line once more.
  return doubleEscape ? quoted.replace(CMD_META, '^$1') : quoted;
}

function findOnPath(command: string, env: NodeJS.ProcessEnv): string | null {
  const exts = (env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  const hasDir = /[\\/]/.test(command);
  const dirs = hasDir ? [''] : (env.PATH || env.Path || '').split(path.delimiter).filter(Boolean);
  const names = path.extname(command) ? [command] : [command, ...exts.map((e) => command + e.toLowerCase())];
  for (const dir of dirs) {
    for (const name of names) {
      const full = dir ? path.join(dir, name) : name;
      try {
        if (fs.statSync(full).isFile() && (path.extname(full) || hasDir)) return full;
      } catch {
        // not here
      }
    }
  }
  return null;
}

/**
 * How to spawn a configured command (e.g. an MCP server's `npx …`) without a shell. On Windows,
 * `npx`, `npm` and other `.cmd` / `.bat` shims cannot be spawned directly (ENOENT / EINVAL), so
 * they run through `cmd.exe /d /s /c` with every argument escaped; `.exe` files run directly.
 * Elsewhere the command is returned unchanged.
 */
export function resolveSpawnCommand(command: string, args: string[], env: NodeJS.ProcessEnv = process.env, platform = process.platform): SpawnTarget {
  if (platform !== 'win32') return { command, args };
  const file = findOnPath(command, env);
  if (!file || !/\.(cmd|bat)$/i.test(file)) return { command: file || command, args };
  const doubleEscape = /node_modules[\\/]\.bin[\\/][^\\/]+\.cmd$/i.test(file);
  const line = [file.replace(CMD_META, '^$1'), ...args.map((a) => quoteForCmd(a, doubleEscape))].join(' ');
  return { command: env.ComSpec || env.COMSPEC || 'cmd.exe', args: ['/d', '/s', '/c', `"${line}"`], windowsVerbatimArguments: true };
}
