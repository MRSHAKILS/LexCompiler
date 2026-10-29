import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { getLastRepositoryScanCoverage, readRepositoryFilesAt } from './analyzer/repoBaseline.js';

describe('repository scan coverage', () => {
  it('reports when the file limit stops the scan and which large files were skipped', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-coverage-'));
    try {
      fs.mkdirSync(path.join(dir, 'pkg'));
      for (let i = 0; i < 2001; i++) fs.writeFileSync(path.join(dir, 'pkg', `m${String(i).padStart(4, '0')}.py`), 'x = 1\n');
      const files = readRepositoryFilesAt(dir);
      expect(files).toHaveLength(2000);
      expect(getLastRepositoryScanCoverage()).toMatchObject({ filesRead: 2000, truncatedAtLimit: true, maxFiles: 2000, skippedLargeFiles: [] });

      fs.rmSync(path.join(dir, 'pkg'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'big.py'), `# ${'x'.repeat(1024 * 1024 + 10)}\n`);
      fs.writeFileSync(path.join(dir, 'small.py'), 'y = 2\n');
      expect(readRepositoryFilesAt(dir).map((f) => f.path)).toEqual(['small.py']);
      expect(getLastRepositoryScanCoverage()).toMatchObject({ filesRead: 1, truncatedAtLimit: false, skippedLargeFiles: ['big.py'] });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
