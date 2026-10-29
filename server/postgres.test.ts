import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { executeSchemaOnPostgres } from './sandbox/postgresSandbox.js';

const schema = fs.readFileSync(path.join(process.cwd(), 'target-repo/schema/postgres_pii.sql'), 'utf8');

describe('PostgreSQL schema execution', () => {
  it('runs the fixture schema on PostgreSQL and exercises retention and erasure', async () => {
    const report = await executeSchemaOnPostgres(schema);
    expect(report.engine).toMatch(/^PostgreSQL \d+/);
    expect(report.tablesCreated).toEqual(['clinical_triage_audits', 'patient_records']);
    expect(report.actualDefaultRetentionHours).toBe(720);
    expect(report.hasTenantKmsKeyColumn).toBe(false);
    expect(report.retentionPurge).toEqual({ staleRowsBefore: 1, staleRowsAfter: 0 });
    expect(report.erasureCascade).toEqual([
      expect.objectContaining({ dependentTable: 'clinical_triage_audits', dependentRowsBefore: 1, dependentRowsAfter: 0, erasureSucceeded: true }),
    ]);
  });

  it('reports a failed erasure when a foreign key restricts deletes', async () => {
    const restricted = schema.replace('ON DELETE CASCADE', 'ON DELETE RESTRICT');
    const [cascade] = (await executeSchemaOnPostgres(restricted)).erasureCascade;
    expect(cascade.erasureSucceeded).toBe(false);
    expect(cascade.error).toMatch(/foreign key/i);
  });

  it('rejects invalid PostgreSQL', async () => {
    await expect(executeSchemaOnPostgres('CREATE TABLE broken (id UUID PRIMARY KEY, x NOTATYPE);')).rejects.toThrow(/notatype/i);
  });
});
