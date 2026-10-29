import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { z3EngineLabel, z3SolverVersion } from './util/versions.js';

describe('engine versions', () => {
  it('reports the installed z3-solver version, not a hard-coded one', () => {
    const installed = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), 'node_modules', 'z3-solver', 'package.json'), 'utf8')
    ) as { version: string };
    expect(z3SolverVersion()).toBe(installed.version);
    expect(z3EngineLabel()).toContain(installed.version);
  });
});
