import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { containerRunArgs, containerSandboxFromEnv } from './sandbox/container.js';
import { executeRealWorldSandboxVerification } from './sandbox/realWorldSandbox.js';

const saved = { ...process.env };
afterEach(() => {
  for (const k of ['LEXCOMPILER_SANDBOX_CONTAINER', 'LEXCOMPILER_SANDBOX_IMAGE', 'LEXCOMPILER_SANDBOX_OCI_RUNTIME', 'FAKE_ENGINE_LOG']) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

describe('container sandbox', () => {
  it('locks the container down', () => {
    const args = containerRunArgs({ engine: 'docker', image: 'img:1', ociRuntime: 'runsc' }, '/tmp/w', ['python', '-I']);
    for (const flag of [['--network', 'none'], ['--cap-drop', 'ALL'], ['--security-opt', 'no-new-privileges'], ['--user', '65534:65534'], ['-v', '/tmp/w:/work:ro'], ['--runtime', 'runsc']]) {
      expect(args.join(' ')).toContain(flag.join(' '));
    }
    expect(args).toContain('--read-only');
    expect(args.slice(args.indexOf('img:1') + 1)).toEqual(['python', '-I']);
    expect(containerSandboxFromEnv({})).toBeNull();
  });

  it('runs both runners through the container engine with /work mapped', async () => {
    // Fake engine: records its arguments, maps /work to the mounted directory, and runs the command.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fake-engine-'));
    const engine = path.join(dir, 'engine.mjs');
    const log = path.join(dir, 'calls.jsonl');
    fs.writeFileSync(
      engine,
      `#!${process.execPath}
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FAKE_ENGINE_LOG, JSON.stringify(args) + '\\n');
const mount = args[args.indexOf('-v') + 1].split(':')[0];
const cmd = args.slice(args.indexOf(process.env.LEXCOMPILER_SANDBOX_IMAGE) + 1).map((a) => a === '/work' ? mount : a.replace('=/work', '=' + mount).replace(/^\\/work\\//, mount + '/'));
const bin = cmd[0] === 'python' ? 'python3' : cmd[0] === 'node' ? process.execPath : cmd[0];
const r = spawnSync(bin, cmd.slice(1), { cwd: mount, encoding: 'utf8', maxBuffer: 4 << 20 });
process.stdout.write(r.stdout || '');
process.stderr.write(r.stderr || '');
process.exit(r.status ?? 1);
`
    );
    fs.chmodSync(engine, 0o755);
    Object.assign(process.env, { LEXCOMPILER_SANDBOX_CONTAINER: engine, LEXCOMPILER_SANDBOX_IMAGE: 'lexcompiler-sandbox:test', FAKE_ENGINE_LOG: log });
    const report = await executeRealWorldSandboxVerification();
    expect(report.isolation).toMatch(/^container/);
    const calls = fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as string[]);
    expect(calls).toHaveLength(2);
    expect(calls.every((c) => c.includes('--network') && c.includes('none'))).toBe(true);
    expect(report.pythonFastApiExecution.leakedPlaintextSsnInLogs).toBe(true);
    expect(report.typescriptAiTriageExecution.violatedEuAiActArt14).toBe(true);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
