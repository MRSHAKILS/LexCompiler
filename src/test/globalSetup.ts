import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import type { TestProject } from 'vitest/node';

/**
 * Before the jsdom UI tests: builds a real compliance report and agent run (AST analysis, Z3,
 * remediation) on a scratch copy of the demo fixture, so the components render the data the API
 * actually returns. The build runs in a child process (see buildUiFixtures.ts).
 */
export default async function setup(project: TestProject) {
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lexcompiler-ui-fixtures-')), 'fixtures.json');
  await promisify(execFile)(process.execPath, ['--import', 'tsx', path.join('src', 'test', 'buildUiFixtures.ts'), out], {
    cwd: process.cwd(),
    maxBuffer: 16 * 1024 * 1024,
    timeout: 180_000,
  });
  project.provide('uiFixtures', fs.readFileSync(out, 'utf8'));
  fs.rmSync(path.dirname(out), { recursive: true, force: true });
}

declare module 'vitest' {
  export interface ProvidedContext {
    uiFixtures: string;
  }
}
