import fs from 'node:fs';
import path from 'node:path';
import type { LegalClause } from '../shared/types.js';

const DATA_DIR = path.resolve(process.env.LEXCOMPILER_DATA_DIR || path.join(process.cwd(), 'data'));
const STATE_FILE = path.join(DATA_DIR, 'active-clauses.json');

export interface PersistedClauseState {
  clauses: LegalClause[];
  amendmentLabel: string | null;
  savedAt: string;
}

/**
 * Active clauses survive restarts and are shared with the stdio MCP server, which
 * runs in a separate process.
 */
export function loadActiveClauseState(): PersistedClauseState | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) as PersistedClauseState;
    return Array.isArray(parsed.clauses) && parsed.clauses.length > 0 ? parsed : null;
  } catch {
    return null;
  }
}

export function saveActiveClauseState(clauses: LegalClause[], amendmentLabel: string | null): void {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = `${STATE_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(
    tmp,
    JSON.stringify({ clauses, amendmentLabel, savedAt: new Date().toISOString() } satisfies PersistedClauseState),
    'utf8'
  );
  fs.renameSync(tmp, STATE_FILE);
}
