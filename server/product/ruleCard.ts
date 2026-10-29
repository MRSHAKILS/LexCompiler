import crypto from 'node:crypto';
import {
  compileLegalProseWithOverrides,
  findConfidenceThresholds,
  findTemporalDurations,
  inferRuleCategoryWithEvidence,
  type RuleValueOverrides,
} from '../compiler/legalCompiler.js';
import { checkExtraction, checkParserOnly, EXTRACTION_SCHEMA, extractionPrompt, numericFieldFor, validateExtraction, type CheckedValue, type ModelExtraction } from '../ai/extraction.js';
import type { AiGateway } from '../ai/gateway.js';
import { verifyRepositoryAgainstClauses } from '../prover/z3Engine.js';
import type { ASTFindingNode, LegalClause, RuleCategory, SQLTableSchema } from '../../shared/types.js';
import { compileClauseSync, isRuleCategory } from './clauses.js';
import { asciiDigits } from './documents.js';

/**
 * The rule card (product guide, Phase 3 and 5.4): what Legal sees before approving a clause as a
 * rule. Values come from the deterministic parser. With AI on, a model may suggest a value, but it
 * is shown only when the quote is in the clause and the parser reads the same value from the
 * quote and from the whole clause (`checkExtraction`); otherwise the card asks a question.
 */

export const CATEGORY_LABELS: Record<RuleCategory, string> = {
  RETENTION_AND_TENANT_KMS: 'Retention and tenant keys',
  ENCRYPTION_AT_REST: 'Encryption at rest',
  PII_LOGGING_BAN: 'No personal data in logs',
  RIGHT_TO_ERASURE_CASCADE: 'Right to erasure',
  AI_HUMAN_IN_THE_LOOP: 'Human review of AI decisions',
  CROSS_BORDER_TRANSFER: 'Data transfers and regions',
  CONSENT_LAWFUL_BASIS: 'Consent and lawful basis',
  BREACH_NOTIFICATION: 'Breach notification',
  DPIA_REQUIRED: 'Impact assessment (DPIA)',
  DATA_MINIMISATION: 'Data minimisation',
  PURPOSE_LIMITATION: 'Purpose limitation',
};

/** The fixed questions per category (guide, Phase 3 item 3). */
const CATEGORY_QUESTIONS: Partial<Record<RuleCategory, Array<{ id: string; text: string; sets?: keyof RuleValueOverrides }>>> = {
  RETENTION_AND_TENANT_KMS: [
    { id: 'clock-start', text: 'When does the retention clock start: at upload, or when processing ends?' },
    { id: 'backups', text: 'Do backups count toward the retention period?' },
  ],
  PII_LOGGING_BAN: [{ id: 'masked-values', text: 'Are masked values (for example the last 4 digits) allowed in logs?' }],
  AI_HUMAN_IN_THE_LOOP: [{ id: 'automated-decisions', text: 'Which decisions count as automated?' }],
  CROSS_BORDER_TRANSFER: [
    { id: 'allowed-regions', text: 'Which regions are allowed? (comma-separated, for example eu-central-1, eu-west-1)', sets: 'allowedDataRegions' },
    { id: 'sub-processors', text: 'Do sub-processors count as transfers?' },
  ],
  BREACH_NOTIFICATION: [{ id: 'notify-whom', text: 'Who must be notified: the supervisory authority, the customer, or both?' }],
};

export interface Highlight {
  start: number;
  end: number;
  text: string;
  kind: 'value' | 'keyword' | 'normative';
}

export interface CardValue {
  field: keyof RuleValueOverrides;
  label: string;
  value: number | boolean | string[] | null;
  /** parser: read by our parser; model: suggested by a model and confirmed by the parser; legal: set by hand; question: needs Legal. */
  source: 'parser' | 'model' | 'legal' | 'question';
  question: string | null;
}

export interface CardQuestion {
  id: string;
  text: string;
  /** The value an answer sets, when it changes the check (allowed regions). */
  sets?: keyof RuleValueOverrides;
}

export interface AiSuggestion {
  model: string;
  promptSha256: string;
  checked: CheckedValue;
}

export interface RuleCard {
  category: RuleCategory;
  categoryLabel: string;
  /** True when the wording points to the category; false when it is a fallback Legal should check. */
  categoryFromWording: boolean;
  plainReading: string;
  highlights: Highlight[];
  values: CardValue[];
  questions: CardQuestion[];
  ai: AiSuggestion | null;
  /** Set when AI is on but no suggestion was made (the call failed or was refused). */
  aiNote: string | null;
  clause: LegalClause;
}

const VALUE_LABELS: Record<keyof RuleValueOverrides, string> = {
  maxRetentionHours: 'Delete within (hours)',
  requiresTenantIsolatedKeys: 'Tenant-isolated keys',
  minAiConfidenceThreshold: 'Human review below confidence',
  allowedDataRegions: 'Allowed regions',
  maxBreachNotificationHours: 'Report a breach within (hours)',
};

/** The values a category's check uses. */
function fieldsFor(category: RuleCategory): Array<keyof RuleValueOverrides> {
  switch (category) {
    case 'RETENTION_AND_TENANT_KMS':
      return ['maxRetentionHours', 'requiresTenantIsolatedKeys'];
    case 'AI_HUMAN_IN_THE_LOOP':
      return ['minAiConfidenceThreshold'];
    case 'CROSS_BORDER_TRANSFER':
      return ['allowedDataRegions'];
    case 'BREACH_NOTIFICATION':
      return ['maxBreachNotificationHours'];
    default:
      return [];
  }
}

function parameterValue(clause: LegalClause, field: keyof RuleValueOverrides): CardValue['value'] {
  const p = clause.deontic.extractedParameters;
  const v = p[field];
  return v === undefined ? null : (v as CardValue['value']);
}

/** Plain-language reading from a fixed template per category. */
export function plainReading(category: RuleCategory, clause: LegalClause): string {
  const p = clause.deontic.extractedParameters;
  switch (category) {
    case 'RETENTION_AND_TENANT_KMS':
      return `Personal data must be deleted within ${p.maxRetentionHours ?? '?'} hours${p.requiresTenantIsolatedKeys ? ', and stored encrypted with a key that belongs to one tenant only' : ''}.`;
    case 'ENCRYPTION_AT_REST':
      return `Columns with personal data must be encrypted at rest${p.requiredEncryptionAlgorithms?.length ? ` (${p.requiredEncryptionAlgorithms.join(', ')})` : ''}.`;
    case 'PII_LOGGING_BAN':
      return 'Personal data must not be written to logs unless it is redacted first.';
    case 'RIGHT_TO_ERASURE_CASCADE':
      return 'Deleting a person must also delete the rows that refer to them.';
    case 'AI_HUMAN_IN_THE_LOOP':
      return `A person must review automated decisions whose model confidence is below ${p.minAiConfidenceThreshold ?? '?'}.`;
    case 'CROSS_BORDER_TRANSFER':
      return p.allowedDataRegions?.length ? `Personal data may only be stored or sent in ${p.allowedDataRegions.join(', ')}.` : 'Personal data must not leave the allowed regions. Which regions are allowed?';
    case 'CONSENT_LAWFUL_BASIS':
      return 'Personal data may only be processed after a consent or lawful-basis check.';
    case 'BREACH_NOTIFICATION':
      return `A personal data breach must be reported within ${p.maxBreachNotificationHours ?? '?'} hours.`;
    case 'DPIA_REQUIRED':
      return 'High-risk processing needs a data protection impact assessment on file.';
    case 'DATA_MINIMISATION':
      return 'Collect only the personal data the service uses.';
    case 'PURPOSE_LIMITATION':
      return `Personal data may only be used for ${p.allowedProcessingPurposes?.length ? p.allowedProcessingPurposes.join(', ') : 'the stated purposes'}.`;
  }
}

const KEYWORDS: Partial<Record<RuleCategory, RegExp>> = {
  RETENTION_AND_TENANT_KMS: /tenant[- ]isolated(?:\s+(?:kms\s+)?keys?)?|tenant[- ]specific\s+keys?|per[- ]tenant\s+keys?|customer[- ]managed\s+keys?|purged?|deleted|erased|টেন্যান্ট\s*আইসোলেটেড(?:\s*কেএমএস\s*কী)?|মুছে\s*ফেলতে/giu,
  ENCRYPTION_AT_REST: /encrypt(?:ed|ion)?\s+at\s+rest|aes-?256|এনক্রিপ্ট\S*/giu,
  PII_LOGGING_BAN: /unredacted|plain\s?text|logs?|logging|redact\S*|লগ\S*/giu,
  RIGHT_TO_ERASURE_CASCADE: /erasure|cascade|forgotten/giu,
  AI_HUMAN_IN_THE_LOOP: /human\s+(?:review|oversight)|automated\s+decisions?|confidence|মানব\s*তদারকি/giu,
  CROSS_BORDER_TRANSFER: /\b(?:eu|european union|eea|third countr(?:y|ies)|us-east-\d|eu-[a-z]+-\d)\b/giu,
  BREACH_NOTIFICATION: /breach|notify|notification/giu,
};

/**
 * Matched words with offsets in the clause text. Values are found in a copy with ASCII digits,
 * which has the same length as the original, so offsets carry over to Bangla text.
 */
export function findHighlights(text: string, category: RuleCategory, normative: Array<{ start: number; end: number; text: string }> = []): Highlight[] {
  const ascii = asciiDigits(text);
  const lower = ascii.toLowerCase();
  const out: Highlight[] = [];
  const addAll = (needle: string, kind: Highlight['kind']) => {
    if (!needle) return;
    for (let i = lower.indexOf(needle); i >= 0; i = lower.indexOf(needle, i + needle.length)) out.push({ start: i, end: i + needle.length, text: text.slice(i, i + needle.length), kind });
  };
  if (lower.length === text.length) {
    const field = numericFieldFor(category);
    if (field === 'minAiConfidenceThreshold') for (const t of findConfidenceThresholds(lower)) addAll(t.text, 'value');
    else if (field) for (const d of findTemporalDurations(lower)) addAll(d.text, 'value');
    if (category === 'AI_HUMAN_IN_THE_LOOP') for (const m of lower.matchAll(/\d+(?:\.\d+)?\s*%/g)) out.push({ start: m.index!, end: m.index! + m[0].length, text: text.slice(m.index!, m.index! + m[0].length), kind: 'value' });
  }
  const kw = KEYWORDS[category];
  if (kw) for (const m of text.matchAll(kw)) out.push({ start: m.index!, end: m.index! + m[0].length, text: m[0], kind: 'keyword' });
  for (const n of normative) out.push({ ...n, kind: 'normative' });
  // Keep the longest of overlapping highlights; values win over keywords.
  const rank = { value: 0, keyword: 1, normative: 2 } as const;
  out.sort((a, b) => a.start - b.start || rank[a.kind] - rank[b.kind] || b.end - a.end);
  const kept: Highlight[] = [];
  for (const h of out) {
    const last = kept[kept.length - 1];
    if (last && h.start < last.end) continue;
    kept.push(h);
  }
  return kept;
}

export interface CardInput {
  text: string;
  key: string;
  title?: string;
  citation?: string;
  /** Legal's choice; the wording decides otherwise. */
  category?: RuleCategory;
  overrides?: RuleValueOverrides;
  normativeMatches?: Array<{ start: number; end: number; text: string }>;
  /** With a gateway and a workspace whose AI is on, the model suggests the numeric value. */
  ai?: { gateway: AiGateway; workspaceId: string };
}

/** Builds the card. Without overrides, the clause is exactly what `compileClauseSync` gives. */
export async function buildRuleCard(input: CardInput): Promise<RuleCard> {
  const fromWording = inferRuleCategoryWithEvidence(input.text);
  const category = input.category && isRuleCategory(input.category) ? input.category : (fromWording ?? 'RETENTION_AND_TENANT_KMS');
  const overrides = cleanOverrides(input.overrides ?? {});

  // Parser first; a model suggestion is checked against it.
  const parser = checkParserOnly(input.text, category);
  let ai: AiSuggestion | null = null;
  let aiNote: string | null = null;
  const field = numericFieldFor(category);
  if (input.ai && field && input.ai.gateway.settings(input.ai.workspaceId).mode !== 'off') {
    const { system, prompt } = extractionPrompt(input.text, field);
    const r = await input.ai.gateway.complete({ workspaceId: input.ai.workspaceId, task: 'drafting', system, prompt, schema: EXTRACTION_SCHEMA, validate: validateExtraction, maxTokens: 200, timeoutMs: 120_000 });
    if (r.refused) aiNote = r.refused === 'budget' ? 'The daily AI budget is used up; values come from the parser only.' : 'No model is configured for this AI mode; values come from the parser only.';
    else if (r.error) aiNote = `The model call failed (${r.error}); values come from the parser only.`;
    else {
      const promptSha256 = crypto.createHash('sha256').update(`${system}\n\n${prompt}`, 'utf8').digest('hex');
      ai = { model: r.model, promptSha256, checked: checkExtraction(input.text, category, r.ok ? (r.json as ModelExtraction) : null)! };
    }
  }

  const compiled = Object.keys(overrides).length
    ? assembleWith(input, category, overrides)
    : compileClauseSync({ text: input.text, key: input.key, title: input.title, citation: input.citation, category });

  const values: CardValue[] = fieldsFor(category).map((f) => {
    const label = VALUE_LABELS[f];
    if (overrides[f] !== undefined) return { field: f, label, value: overrides[f] as CardValue['value'], source: 'legal', question: null };
    if (f === field) {
      const checked = ai?.checked ?? parser;
      if (checked && checked.status === 'question') return { field: f, label, value: null, source: 'question', question: checked.question };
      return { field: f, label, value: checked?.value ?? parameterValue(compiled, f), source: ai?.checked.status === 'accepted' ? 'model' : 'parser', question: null };
    }
    const v = parameterValue(compiled, f);
    if (f === 'allowedDataRegions' && (!Array.isArray(v) || v.length === 0)) return { field: f, label, value: [], source: 'question', question: 'The clause names no allowed region. Which regions are allowed?' };
    return { field: f, label, value: v, source: 'parser', question: null };
  });

  const questions: CardQuestion[] = [
    ...(compiled.deontic.extractionProvenance?.reviewNotes ?? []).map((text, i) => ({ id: `review-${i + 1}`, text })),
    ...(CATEGORY_QUESTIONS[category] ?? []),
  ];
  if (!fromWording && !input.category) questions.unshift({ id: 'category', text: 'The wording names no category we check. Which category is this rule?' });

  return {
    category,
    categoryLabel: CATEGORY_LABELS[category],
    categoryFromWording: fromWording === category,
    plainReading: plainReading(category, compiled),
    highlights: findHighlights(input.text, category, input.normativeMatches),
    values,
    questions,
    ai,
    aiNote,
    clause: compiled,
  };
}

function assembleWith(input: CardInput, category: RuleCategory, overrides: RuleValueOverrides): LegalClause {
  const base = compileClauseSync({ text: input.text, key: input.key, title: input.title, citation: input.citation, category });
  return { ...base, ...compileLegalProseWithOverrides(input.text, category, input.key, input.citation || input.key, overrides) };
}

/** Keeps only valid values; anything else is dropped rather than compiled. */
export function cleanOverrides(raw: unknown): RuleValueOverrides {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const out: RuleValueOverrides = {};
  const hours = (v: unknown) => typeof v === 'number' && Number.isFinite(v) && v > 0 && v <= 24 * 365 * 100;
  if (hours(o.maxRetentionHours)) out.maxRetentionHours = o.maxRetentionHours as number;
  if (hours(o.maxBreachNotificationHours)) out.maxBreachNotificationHours = o.maxBreachNotificationHours as number;
  if (typeof o.requiresTenantIsolatedKeys === 'boolean') out.requiresTenantIsolatedKeys = o.requiresTenantIsolatedKeys;
  if (typeof o.minAiConfidenceThreshold === 'number' && o.minAiConfidenceThreshold > 0 && o.minAiConfidenceThreshold <= 1) out.minAiConfidenceThreshold = o.minAiConfidenceThreshold;
  if (Array.isArray(o.allowedDataRegions)) {
    const regions = o.allowedDataRegions.map((r) => String(r).trim().toLowerCase()).filter((r) => /^[a-z0-9-]{2,30}$/.test(r));
    if (regions.length) out.allowedDataRegions = [...new Set(regions)].slice(0, 20);
  }
  return out;
}

export interface ImpactRepo {
  repoId: string;
  repoName: string;
  scanId: string | null;
  commitSha: string | null;
  /** null when the repo has no completed scan to test against. */
  failures: number | null;
  places: Array<{ filePath: string; line: number }>;
}

/** Runs the prover with the draft clause against each repo's stored facts (the last scan of main). */
export async function impactPreview(
  clause: LegalClause,
  repos: Array<{ repoId: string; repoName: string; scan: { id: string; commitSha: string; facts: { sqlTables: unknown[]; astFindings: unknown[] } } | null }>
): Promise<ImpactRepo[]> {
  const out: ImpactRepo[] = [];
  for (const r of repos) {
    if (!r.scan) {
      out.push({ repoId: r.repoId, repoName: r.repoName, scanId: null, commitSha: null, failures: null, places: [] });
      continue;
    }
    const { proofs } = await verifyRepositoryAgainstClauses([clause], r.scan.facts.sqlTables as SQLTableSchema[], r.scan.facts.astFindings as ASTFindingNode[]);
    const places = proofs.filter((p) => p.status === 'UNSAT_VIOLATION').flatMap((p) => p.offendingLocations.map((l) => ({ filePath: l.filePath, line: l.line })));
    const unique = [...new Map(places.map((p) => [`${p.filePath}:${p.line}`, p])).values()];
    out.push({ repoId: r.repoId, repoName: r.repoName, scanId: r.scan.id, commitSha: r.scan.commitSha, failures: unique.length, places: unique });
  }
  return out;
}
