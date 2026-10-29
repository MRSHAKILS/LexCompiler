import { PGlite } from '@electric-sql/pglite';

/** Minimal query surface shared by PGlite and node-postgres. */
interface SqlClient {
  exec(sql: string): Promise<void>;
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
  close(): Promise<void>;
}

export interface PostgresExecutionReport {
  engine: string;
  tablesCreated: string[];
  patientRecordsColumns: Array<{ name: string; type: string; notnull: boolean; defaultValue: string | null }>;
  sampleInsertedRow: Record<string, unknown>;
  hasTenantKmsKeyColumn: boolean;
  actualDefaultRetentionHours: number;
  /** Rows of a stale record removed by `DELETE … WHERE created_at < now() - retention_ttl_hours`. */
  retentionPurge: { staleRowsBefore: number; staleRowsAfter: number };
  /** Art. 17 erasure: deleting the patient must remove every dependent row. */
  erasureCascade: { dependentTable: string; dependentRowsBefore: number; dependentRowsAfter: number; erasureSucceeded: boolean; error?: string }[];
}

const SAMPLE_TEXT: Record<string, string> = {
  full_name: 'Dr. Elena Rostova',
  email: 'elena.rostova@zurich-clinic.ch',
  ssn: 'enc_kms::999-42-8810',
  diagnosis_code: 'ICD10-I21.0',
  tenant_kms_key_id: 'kms-key-eu-zurich-01',
  model_version: 'triage-v4',
};

async function openClient(): Promise<SqlClient> {
  const url = process.env.LEXCOMPILER_POSTGRES_URL;
  if (url) {
    const pg = (await import('pg')).default;
    const client = new pg.Client({ connectionString: url });
    await client.connect();
    // A throwaway schema keeps the run isolated from anything else in the database.
    const schema = `lexcompiler_sandbox_${process.pid}_${Date.now()}`;
    await client.query(`CREATE SCHEMA ${schema}; SET search_path TO ${schema}`);
    return {
      exec: async (sql) => void (await client.query(sql)),
      query: async (sql, params) => ({ rows: (await client.query(sql, params)).rows }),
      close: async () => {
        await client.query(`DROP SCHEMA ${schema} CASCADE`).catch(() => undefined);
        await client.end();
      },
    };
  }
  const db = await PGlite.create();
  return {
    exec: async (sql) => void (await db.exec(sql)),
    query: async (sql, params) => ({ rows: (await db.query(sql, params)).rows as never[] }),
    close: () => db.close(),
  };
}

function sampleValue(column: { name: string; type: string }, refs: Record<string, unknown>): unknown {
  if (column.name in refs) return refs[column.name];
  if (column.type === 'uuid') return crypto.randomUUID();
  if (/int|numeric|double|real/.test(column.type)) return column.name.includes('confidence') ? 0.78 : 1;
  if (column.type === 'bytea') return Buffer.from('sandbox-ciphertext');
  if (column.type === 'boolean') return true;
  if (column.type.includes('timestamp')) return new Date().toISOString();
  return SAMPLE_TEXT[column.name] ?? `sample-${column.name}`;
}

/** Inserts a row filling every NOT NULL column without a default (plus known sample columns). */
async function insertSample(db: SqlClient, table: string, refs: Record<string, unknown>): Promise<Record<string, unknown>> {
  const { rows: cols } = await db.query<{ name: string; type: string; notnull: boolean; has_default: boolean }>(
    `SELECT column_name AS name, data_type AS type, is_nullable = 'NO' AS notnull, column_default IS NOT NULL AS has_default
       FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position`,
    [table]
  );
  const chosen = cols.filter((c) => !c.has_default && (c.notnull || c.name in SAMPLE_TEXT || c.name in refs));
  const sql = `INSERT INTO ${table} (${chosen.map((c) => `"${c.name}"`).join(', ')}) VALUES (${chosen.map((_, i) => `$${i + 1}`).join(', ')}) RETURNING *`;
  const { rows } = await db.query(sql, chosen.map((c) => sampleValue(c, refs)));
  return rows[0];
}

/** Executes the schema on PostgreSQL (PGlite in-process, or LEXCOMPILER_POSTGRES_URL) and exercises it. */
export async function executeSchemaOnPostgres(schemaSql: string): Promise<PostgresExecutionReport> {
  const db = await openClient();
  try {
    await db.exec(schemaSql);
    const { rows: version } = await db.query<{ version: string }>('SELECT version()');
    const { rows: tables } = await db.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() ORDER BY table_name`
    );
    const { rows: cols } = await db.query<{ name: string; type: string; notnull: boolean; default_value: string | null }>(
      `SELECT column_name AS name, data_type AS type, is_nullable = 'NO' AS notnull, column_default AS default_value
         FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'patient_records' ORDER BY ordinal_position`
    );
    const sample = await insertSample(db, 'patient_records', {});
    const retentionDefault = Number(sample.retention_ttl_hours ?? 720);

    // Retention: back-date a second record past its window and run the purge statement.
    const stale = await insertSample(db, 'patient_records', {});
    await db.query(`UPDATE patient_records SET created_at = now() - (retention_ttl_hours + 1) * interval '1 hour' WHERE patient_id = $1`, [stale.patient_id]);
    const staleCount = async () =>
      Number((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM patient_records WHERE created_at < now() - retention_ttl_hours * interval '1 hour'`)).rows[0].n);
    const staleRowsBefore = await staleCount();
    await db.query(`DELETE FROM patient_records WHERE created_at < now() - retention_ttl_hours * interval '1 hour'`);
    const staleRowsAfter = await staleCount();

    // Erasure: every table with a foreign key to patient_records must lose its rows.
    const { rows: deps } = await db.query<{ child: string; column: string }>(
      `SELECT tc.table_name AS child, kcu.column_name AS column
         FROM information_schema.table_constraints tc
         JOIN information_schema.key_column_usage kcu ON kcu.constraint_name = tc.constraint_name AND kcu.table_schema = tc.table_schema
         JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name AND ccu.table_schema = tc.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = current_schema() AND ccu.table_name = 'patient_records'`
    );
    const erasureCascade: PostgresExecutionReport['erasureCascade'] = [];
    for (const dep of deps) {
      await insertSample(db, dep.child, { [dep.column]: sample.patient_id });
      const count = async () =>
        Number((await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${dep.child} WHERE "${dep.column}" = $1`, [sample.patient_id])).rows[0].n);
      const before = await count();
      let error: string | undefined;
      try {
        await db.query('DELETE FROM patient_records WHERE patient_id = $1', [sample.patient_id]);
      } catch (err) {
        error = (err as Error).message;
      }
      const after = await count();
      erasureCascade.push({ dependentTable: dep.child, dependentRowsBefore: before, dependentRowsAfter: after, erasureSucceeded: !error && after === 0, ...(error ? { error } : {}) });
    }

    const engine = version[0].version.split(' on ')[0];
    return {
      engine: `${engine} (executing schema/postgres_pii.sql${process.env.LEXCOMPILER_POSTGRES_URL ? ' on LEXCOMPILER_POSTGRES_URL' : ''})`,
      tablesCreated: tables.map((t) => t.table_name),
      patientRecordsColumns: cols.map((c) => ({ name: c.name, type: c.type, notnull: c.notnull, defaultValue: c.default_value })),
      sampleInsertedRow: Object.fromEntries(Object.entries(sample).map(([k, v]) => [k, v instanceof Date ? v.toISOString() : v])),
      hasTenantKmsKeyColumn: cols.some((c) => c.name === 'tenant_kms_key_id'),
      actualDefaultRetentionHours: retentionDefault,
      retentionPurge: { staleRowsBefore, staleRowsAfter },
      erasureCascade,
    };
  } finally {
    await db.close();
  }
}
