import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { vector } from '@electric-sql/pglite-pgvector';

export interface VectorRecord {
  id: string;
  text: string;
  embedding: number[];
}

/** Chunk vectors in PostgreSQL + pgvector with an HNSW cosine index. */
export interface VectorStore {
  readonly backend: string;
  /** Inserts or refreshes vectors; rows whose id is missing from `records` are removed. */
  sync(records: VectorRecord[]): Promise<void>;
  /** Cosine similarity (1 - cosine distance) for the nearest `k` vectors, ordered by the HNSW index. */
  search(query: number[], k: number): Promise<Map<string, number>>;
  close(): Promise<void>;
}

interface Sql {
  exec(sql: string): Promise<unknown>;
  query<T>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

const literal = (v: number[]) => `[${v.map((x) => (Number.isFinite(x) ? x : 0)).join(',')}]`;
const hash = (r: VectorRecord) => crypto.createHash('sha256').update(r.text).update(literal(r.embedding)).digest('hex');

function storeOver(db: Sql, namespace: string, dimensions: number, backend: string, close: () => Promise<void>): VectorStore {
  // One table per embedding space: vectors from different models are not comparable.
  const table = `rag_chunks_${namespace.toLowerCase().replace(/[^a-z0-9]+/g, '_')}_${dimensions}`;
  let ready: Promise<unknown> | null = null;
  const init = () =>
    (ready ??= db.exec(`
      CREATE EXTENSION IF NOT EXISTS vector;
      CREATE TABLE IF NOT EXISTS ${table} (
        chunk_id TEXT PRIMARY KEY,
        content_hash TEXT NOT NULL,
        content TEXT NOT NULL,
        embedding vector(${dimensions}) NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ${table}_hnsw ON ${table} USING hnsw (embedding vector_cosine_ops);
    `));
  return {
    backend,
    async sync(records) {
      await init();
      const { rows } = await db.query<{ chunk_id: string; content_hash: string }>(`SELECT chunk_id, content_hash FROM ${table}`);
      const existing = new Map(rows.map((r) => [r.chunk_id, r.content_hash]));
      for (const r of records) {
        if (r.embedding.length !== dimensions) throw new Error(`Vector for ${r.id} has ${r.embedding.length} dimensions, expected ${dimensions}`);
        const h = hash(r);
        if (existing.get(r.id) === h) continue;
        await db.query(
          `INSERT INTO ${table} (chunk_id, content_hash, content, embedding) VALUES ($1, $2, $3, $4)
             ON CONFLICT (chunk_id) DO UPDATE SET content_hash = EXCLUDED.content_hash, content = EXCLUDED.content, embedding = EXCLUDED.embedding`,
          [r.id, h, r.text, literal(r.embedding)]
        );
      }
      const keep = new Set(records.map((r) => r.id));
      const stale = [...existing.keys()].filter((id) => !keep.has(id));
      if (stale.length) await db.query(`DELETE FROM ${table} WHERE chunk_id = ANY($1)`, [stale]);
    },
    async search(query, k) {
      await init();
      // HNSW returns at most ef_search candidates; widen it to cover k.
      await db.exec(`SET hnsw.ef_search = ${Math.min(1000, Math.max(40, Math.floor(k)))}`);
      const { rows } = await db.query<{ chunk_id: string; similarity: number }>(
        `SELECT chunk_id, 1 - (embedding <=> $1) AS similarity FROM ${table} ORDER BY embedding <=> $1 LIMIT $2`,
        [literal(query), k]
      );
      return new Map(rows.map((r) => [r.chunk_id, Number(r.similarity)]));
    },
    close,
  };
}

/** In-process PostgreSQL (PGlite) with pgvector; persisted under `dataDir` when given. */
export async function openPgliteVectorStore(namespace: string, dimensions: number, dataDir?: string): Promise<VectorStore> {
  if (dataDir) fs.mkdirSync(path.dirname(dataDir), { recursive: true });
  const db = await PGlite.create({ ...(dataDir ? { dataDir } : {}), extensions: { vector } });
  const { rows } = await db.query<{ v: string }>(`SELECT default_version AS v FROM pg_available_extensions WHERE name = 'vector'`);
  return storeOver(db, namespace, dimensions, `pgvector ${rows[0]?.v ?? ''} on PGlite (HNSW cosine, dim=${dimensions})`.replace('  ', ' '), () => db.close());
}

/** pgvector on a PostgreSQL server (requires the `vector` extension to be installable). */
export async function openPostgresVectorStore(url: string, namespace: string, dimensions: number): Promise<VectorStore> {
  const pg = (await import('pg')).default;
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  return storeOver(
    { exec: (sql) => client.query(sql), query: async (sql, params) => ({ rows: (await client.query(sql, params)).rows }) },
    namespace,
    dimensions,
    `pgvector on PostgreSQL server (HNSW cosine, dim=${dimensions})`,
    () => client.end()
  );
}

/** PGlite supports one process per data directory: take a pid lock, or report that it is held. */
function acquireDirLock(dir: string): boolean {
  fs.mkdirSync(dir, { recursive: true });
  const lock = path.join(dir, '.lexcompiler.lock');
  try {
    const holder = Number(fs.readFileSync(lock, 'utf8'));
    if (holder && holder !== process.pid) {
      try {
        process.kill(holder, 0);
        return false; // another live process owns the directory
      } catch {
        // stale lock from a process that exited
      }
    }
  } catch {
    // no lock yet
  }
  fs.writeFileSync(lock, String(process.pid));
  process.once('exit', () => {
    try {
      if (fs.readFileSync(lock, 'utf8') === String(process.pid)) fs.rmSync(lock);
    } catch {
      // already gone
    }
  });
  return true;
}

let shared: Promise<{ open: (namespace: string, dimensions: number) => VectorStore }> | null = null;
const stores = new Map<string, VectorStore>();

/**
 * Shared store per embedding space: LEXCOMPILER_PGVECTOR_URL, else one PGlite database
 * persisted in the data directory (PGlite allows a single connection per directory).
 */
export async function getVectorStore(namespace: string, dimensions: number): Promise<VectorStore> {
  const key = `${namespace}:${dimensions}`;
  const cached = stores.get(key);
  if (cached) return cached;
  shared ??= (async () => {
    const url = process.env.LEXCOMPILER_PGVECTOR_URL;
    if (url) {
      const pg = (await import('pg')).default;
      const client = new pg.Client({ connectionString: url });
      await client.connect();
      const db: Sql = { exec: (sql) => client.query(sql), query: async (sql, params) => ({ rows: (await client.query(sql, params)).rows }) };
      return { open: (ns, dims) => storeOver(db, ns, dims, `pgvector on PostgreSQL server (HNSW cosine, dim=${dims})`, async () => undefined) };
    }
    const dataDir = path.join(path.resolve(process.env.LEXCOMPILER_DATA_DIR || path.join(process.cwd(), 'data')), 'pgvector');
    const persistent = acquireDirLock(dataDir);
    const db = await PGlite.create({ ...(persistent ? { dataDir } : {}), extensions: { vector } });
    const { rows } = await db.query<{ v: string }>(`SELECT default_version AS v FROM pg_available_extensions WHERE name = 'vector'`);
    const where = persistent ? 'persisted' : 'in-memory: data dir locked by another process';
    return { open: (ns, dims) => storeOver(db, ns, dims, `pgvector ${rows[0]?.v} on PGlite (${where}; HNSW cosine, dim=${dims})`, async () => undefined) };
  })();
  shared.catch(() => (shared = null));
  const store = (await shared).open(namespace, dimensions);
  stores.set(key, store);
  return store;
}
