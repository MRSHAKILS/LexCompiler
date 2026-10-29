import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { resolveSpawnCommand } from './util/spawnCommand.js';

// Arguments that break naive cmd.exe quoting: spaces, &, |, %VAR%, quotes, ^, trailing backslashes.
const TRICKY = ['plain', 'with space', 'a&b|c', '%PATH%', 'say "hi"', 'caret^', 'C:\\dir\\', 'postgresql://u:p@h:5432/db?x=1&y=2', ''];

describe('spawning configured commands', () => {
  it('leaves commands unchanged off Windows', () => {
    expect(resolveSpawnCommand('npx', ['-y', 'pkg'], {}, 'linux')).toEqual({ command: 'npx', args: ['-y', 'pkg'] });
  });

  it.runIf(process.platform === 'win32')('runs .cmd shims through cmd.exe with every argument intact', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'spawn-cmd-'));
    fs.writeFileSync(path.join(dir, 'echo.js'), 'process.stdout.write(JSON.stringify(process.argv.slice(2)))');
    fs.writeFileSync(path.join(dir, 'echoargs.cmd'), `@"${process.execPath}" "%~dp0echo.js" %*\r\n`);
    const env = { ...process.env, PATH: `${dir}${path.delimiter}${process.env.PATH}` };
    const t = resolveSpawnCommand('echoargs', TRICKY, env);
    expect(t.windowsVerbatimArguments).toBe(true);
    const r = spawnSync(t.command, t.args, { env, encoding: 'utf8', windowsVerbatimArguments: true });
    expect(r.error).toBeUndefined();
    expect(JSON.parse(r.stdout)).toEqual(TRICKY);
    // .exe files on PATH are spawned directly.
    expect(resolveSpawnCommand('node', ['-v'], env).command.toLowerCase()).toMatch(/node\.exe$/);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
