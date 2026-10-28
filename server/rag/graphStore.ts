import type { KnowledgeGraphTriple } from '../../shared/types.js';

/** Entity-level knowledge graph used by Graph RAG (chunk nodes are not part of the hop count). */
export interface GraphStore {
  readonly backend: string;
  /** Replaces the graph with these entity edges. */
  load(triples: KnowledgeGraphTriple[]): Promise<void>;
  /** Shortest hop distance (≤ maxHops) from any seed to every reachable entity, keyed by lower-cased name. */
  distancesFrom(seeds: string[], maxHops: number): Promise<Map<string, number>>;
  /** Every entity name in the graph (lower-cased), used to find seeds mentioned in a query. */
  entities(): Promise<string[]>;
  close(): Promise<void>;
}

/** Entity edges of the corpus: each triple, plus `file:line` AST subjects linked to their file. */
export function entityEdges(triples: KnowledgeGraphTriple[]): Array<{ from: string; to: string; predicate: string }> {
  const edges: Array<{ from: string; to: string; predicate: string }> = [];
  for (const t of triples) {
    edges.push({ from: t.subject.toLowerCase(), to: t.object.toLowerCase(), predicate: t.predicate });
    const file = t.subject.replace(/^AST::/, '').replace(/:\d+$/, '');
    if (file !== t.subject) edges.push({ from: t.subject.toLowerCase(), to: file.toLowerCase(), predicate: 'LOCATED_IN' });
  }
  return edges;
}

export function createInMemoryGraphStore(): GraphStore {
  let adj = new Map<string, Set<string>>();
  return {
    backend: 'in-memory adjacency graph (breadth-first, 2 hops)',
    async load(triples) {
      adj = new Map();
      for (const e of entityEdges(triples)) {
        if (!adj.has(e.from)) adj.set(e.from, new Set());
        if (!adj.has(e.to)) adj.set(e.to, new Set());
        adj.get(e.from)!.add(e.to);
        adj.get(e.to)!.add(e.from);
      }
    },
    async distancesFrom(seeds, maxHops) {
      const dist = new Map<string, number>();
      let frontier = seeds.map((s) => s.toLowerCase());
      frontier.forEach((n) => dist.set(n, 0));
      for (let hop = 1; hop <= maxHops && frontier.length > 0; hop++) {
        const next: string[] = [];
        for (const n of frontier) {
          for (const m of adj.get(n) || []) {
            if (!dist.has(m)) {
              dist.set(m, hop);
              next.push(m);
            }
          }
        }
        frontier = next;
      }
      return dist;
    },
    async entities() {
      return [...adj.keys()];
    },
    async close() {},
  };
}

/** Minimal surface of `neo4j-driver` used here (lets tests substitute a fake driver). */
export interface Neo4jDriverLike {
  executeQuery(cypher: string, params?: Record<string, unknown>, config?: Record<string, unknown>): Promise<{ records: Array<{ get(key: string): unknown }> }>;
  close(): Promise<void>;
}

export const CYPHER = {
  clear: 'MATCH (n:LexEntity {graph: $graph}) DETACH DELETE n',
  load: `UNWIND $edges AS e
MERGE (a:LexEntity {graph: $graph, key: e.from})
MERGE (b:LexEntity {graph: $graph, key: e.to})
MERGE (a)-[r:LEX_REL {predicate: e.predicate}]->(b)`,
  index: 'CREATE INDEX lex_entity_key IF NOT EXISTS FOR (n:LexEntity) ON (n.graph, n.key)',
  // Shortest undirected path (0..maxHops) from any seed, as in the in-memory traversal.
  distances: (maxHops: number) => `MATCH (s:LexEntity {graph: $graph}) WHERE s.key IN $seeds
MATCH p = (s)-[:LEX_REL*0..${maxHops}]-(m:LexEntity {graph: $graph})
RETURN m.key AS key, min(length(p)) AS hops`,
  entities: 'MATCH (n:LexEntity {graph: $graph}) RETURN n.key AS key',
};

const toNumber = (v: unknown) => (typeof v === 'object' && v !== null && 'toNumber' in v ? (v as { toNumber(): number }).toNumber() : Number(v));

export function createNeo4jGraphStore(driver: Neo4jDriverLike, graph = 'lexcompiler', database?: string): GraphStore {
  const cfg = database ? { database } : {};
  return {
    backend: `Neo4j (Cypher, graph "${graph}")`,
    async load(triples) {
      await driver.executeQuery(CYPHER.index, {}, cfg);
      await driver.executeQuery(CYPHER.clear, { graph }, cfg);
      await driver.executeQuery(CYPHER.load, { graph, edges: entityEdges(triples) }, cfg);
    },
    async distancesFrom(seeds, maxHops) {
      const hops = Math.max(0, Math.min(5, Math.floor(maxHops)));
      const { records } = await driver.executeQuery(CYPHER.distances(hops), { graph, seeds: seeds.map((s) => s.toLowerCase()) }, cfg);
      const dist = new Map<string, number>(records.map((r) => [String(r.get('key')), toNumber(r.get('hops'))]));
      // Seeds that are not graph nodes still count as distance 0 (e.g. clause ids linked only to chunks).
      for (const s of seeds) if (!dist.has(s.toLowerCase())) dist.set(s.toLowerCase(), 0);
      return dist;
    },
    async entities() {
      const { records } = await driver.executeQuery(CYPHER.entities, { graph }, cfg);
      return records.map((r) => String(r.get('key')));
    },
    close: () => driver.close(),
  };
}

let shared: Promise<GraphStore> | null = null;

/** Neo4j when LEXCOMPILER_NEO4J_URL is set (bolt:// or neo4j://), otherwise the in-memory graph. */
export function getGraphStore(): Promise<GraphStore> {
  shared ??= (async () => {
    const url = process.env.LEXCOMPILER_NEO4J_URL;
    if (!url) return createInMemoryGraphStore();
    const neo4j = (await import('neo4j-driver')).default;
    const driver = neo4j.driver(url, neo4j.auth.basic(process.env.LEXCOMPILER_NEO4J_USER || 'neo4j', process.env.LEXCOMPILER_NEO4J_PASSWORD || ''));
    await driver.verifyConnectivity();
    return createNeo4jGraphStore(driver as unknown as Neo4jDriverLike, 'lexcompiler', process.env.LEXCOMPILER_NEO4J_DATABASE || undefined);
  })();
  shared.catch(() => (shared = null));
  return shared;
}
