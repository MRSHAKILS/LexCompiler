import type { ClassifiedFinding } from './scanner.js';
import type { ScanSummary } from './store.js';

/**
 * failure: findings that block (new ones when there is a baseline, any unwaived one without).
 * neutral: nothing blocks, but Z3 could not decide a rule, so compliance is not proven.
 * success: every rule proven for this code, apart from waived findings.
 */
export function scanConclusion(summary: ScanSummary, hasBaseline: boolean): 'success' | 'failure' | 'neutral' {
  const blocking = hasBaseline ? summary.newCount : summary.newCount + summary.existingCount;
  if (blocking > 0) return 'failure';
  if (summary.undecidedRuleKeys.length > 0) return 'neutral';
  return 'success';
}

/** Counts findings by state, overall and per rule. */
export function summarizeFindings(findings: ClassifiedFinding[], undecidedRuleKeys: string[] = []): ScanSummary {
  const perRule = new Map<string, { ruleKey: string; newCount: number; existingCount: number; waivedCount: number }>();
  for (const f of findings) {
    const row = perRule.get(f.ruleKey) ?? { ruleKey: f.ruleKey, newCount: 0, existingCount: 0, waivedCount: 0 };
    if (f.state === 'new') row.newCount++;
    else if (f.state === 'existing') row.existingCount++;
    else row.waivedCount++;
    perRule.set(f.ruleKey, row);
  }
  const rows = [...perRule.values()].sort((a, b) => Number(a.ruleKey.slice(2)) - Number(b.ruleKey.slice(2)));
  return {
    newCount: rows.reduce((n, r) => n + r.newCount, 0),
    existingCount: rows.reduce((n, r) => n + r.existingCount, 0),
    waivedCount: rows.reduce((n, r) => n + r.waivedCount, 0),
    undecidedRuleKeys,
    perRule: rows,
  };
}
