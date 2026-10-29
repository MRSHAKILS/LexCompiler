import fs from 'node:fs';
import type { LegalClause, RuleCategory } from '../../shared/types.js';

/**
 * Clauses for CLI runs: LEXCOMPILER_CLAUSES_FILE (a JSON array of
 * { rawLegalText, citation, category?, id? }) compiled with the legal compiler, or the
 * built-in illustrative clauses when unset.
 */
export async function loadClausesForCli(): Promise<LegalClause[]> {
  const { compileLegalProseToFormalPolicyAsync, getInitialClauses, inferRuleCategoryFromProse } = await import('../compiler/legalCompiler.js');
  const file = process.env.LEXCOMPILER_CLAUSES_FILE;
  if (!file) return getInitialClauses();
  const specs = JSON.parse(fs.readFileSync(file, 'utf8')) as Array<{ rawLegalText: string; citation: string; category?: RuleCategory; id?: string; title?: string }>;
  const base = getInitialClauses()[0];
  const clauses: LegalClause[] = [];
  for (const [i, spec] of specs.entries()) {
    const category = spec.category || inferRuleCategoryFromProse(spec.rawLegalText);
    const id = spec.id || `CLAUSE-${i + 1}`;
    clauses.push({
      ...base,
      id,
      category,
      citation: spec.citation,
      title: spec.title || spec.citation,
      rawLegalText: spec.rawLegalText,
      illustrative: false,
      ...(await compileLegalProseToFormalPolicyAsync(spec.rawLegalText, category, id, spec.citation)),
    });
  }
  return clauses;
}
