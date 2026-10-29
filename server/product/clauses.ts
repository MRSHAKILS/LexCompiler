import {
  FRAMEWORK_DISPLAY_NAMES,
  compileLegalProseToFormalPolicy,
  getInitialClauses,
  inferRuleCategoryFromProse,
} from '../compiler/legalCompiler.js';
import type { ComplianceFrameworkId, LegalClause, RuleCategory } from '../../shared/types.js';

export interface ClauseInput {
  text: string;
  key: string;
  title?: string;
  citation?: string;
  category?: RuleCategory;
  frameworkId?: ComplianceFrameworkId;
}

function assemble(input: ClauseInput, category: RuleCategory, compiled: Pick<LegalClause, 'deontic' | 'compiled'>): LegalClause {
  const framework: ComplianceFrameworkId =
    input.frameworkId && Object.hasOwn(FRAMEWORK_DISPLAY_NAMES, input.frameworkId) ? input.frameworkId : 'ENTERPRISE_DPA';
  return {
    id: input.key,
    frameworkId: framework,
    frameworkName: FRAMEWORK_DISPLAY_NAMES[framework],
    citation: input.citation?.trim() || input.key,
    title: input.title?.trim() || input.citation?.trim() || input.key,
    severity: 'HIGH',
    category,
    rawLegalText: input.text.trim(),
    version: '1',
    lastAmended: new Date().toISOString().slice(0, 10),
    illustrative: false,
    ...compiled,
  };
}

/** Every rule category. The Record type makes the compiler flag a category added to RuleCategory but not here. */
const CATEGORY_SET: Record<RuleCategory, true> = {
  RETENTION_AND_TENANT_KMS: true,
  ENCRYPTION_AT_REST: true,
  PII_LOGGING_BAN: true,
  RIGHT_TO_ERASURE_CASCADE: true,
  AI_HUMAN_IN_THE_LOOP: true,
  CROSS_BORDER_TRANSFER: true,
  CONSENT_LAWFUL_BASIS: true,
  BREACH_NOTIFICATION: true,
  DPIA_REQUIRED: true,
  DATA_MINIMISATION: true,
  PURPOSE_LIMITATION: true,
};
export const RULE_CATEGORIES = Object.keys(CATEGORY_SET) as RuleCategory[];
export function isRuleCategory(value: unknown): value is RuleCategory {
  return typeof value === 'string' && Object.hasOwn(CATEGORY_SET, value);
}

/**
 * Compiles legal text into a rule draft with the deterministic parser only. A model never fills
 * in a workspace's rule values here: AI drafting (product guide 5.4) proposes values separately,
 * and only values the parser confirms are shown to Legal.
 */
export async function compileClause(input: ClauseInput): Promise<LegalClause> {
  return compileClauseSync(input);
}

/** Deterministic compile, no LLM: for seeding and tests. */
export function compileClauseSync(input: ClauseInput): LegalClause {
  const category = input.category ?? inferRuleCategoryFromProse(input.text);
  return assemble(input, category, compileLegalProseToFormalPolicy(input.text, category, input.key, input.citation || input.key));
}

/** The built-in illustrative clauses, offered as templates in the rule library. */
export function libraryTemplates(): Array<Pick<LegalClause, 'id' | 'title' | 'citation' | 'category' | 'frameworkId' | 'rawLegalText'>> {
  return getInitialClauses().map((c) => ({ id: c.id, title: c.title, citation: c.citation, category: c.category, frameworkId: c.frameworkId, rawLegalText: c.rawLegalText }));
}
