import { describe, expect, it } from 'vitest';
import { openDatabase } from './db/index.js';
import { getInitialClauses } from './compiler/legalCompiler.js';
import { compileClauseSync } from './product/clauses.js';
import { classifyFindings, findingFingerprint, globMatch, type RawFinding } from './product/scanner.js';
import { ProductStore, rulesetSha256, type ScanSummary } from './product/store.js';
import { scanConclusion } from './product/summary.js';

const finding = (over: Partial<RawFinding>): RawFinding => ({
  ruleId: 'rule-2',
  ruleKey: 'R-2',
  ruleVersionId: 'v-2',
  fingerprint: 'fp',
  filePath: 'api/loans.py',
  startLine: 21,
  endLine: 21,
  constructType: 'Python::Call(logger.info)',
  message: 'logs PII',
  snippet: 'logger.info(x)',
  ...over,
});

describe('findings', () => {
  it('fingerprints ignore line numbers and whitespace but not the code or the file', () => {
    const a = findingFingerprint('R-2', 'api/loans.py', 'Call', 'logger.info( phone )');
    expect(findingFingerprint('R-2', 'api/loans.py', 'Call', 'logger.info(\n  phone )')).toBe(a);
    expect(findingFingerprint('R-2', 'api/other.py', 'Call', 'logger.info( phone )')).not.toBe(a);
    expect(findingFingerprint('R-1', 'api/loans.py', 'Call', 'logger.info( phone )')).not.toBe(a);
  });

  it('classifies new, existing and waived findings', () => {
    const old = finding({ fingerprint: 'old' });
    const added = finding({ fingerprint: 'added', filePath: 'api/new.py' });
    const waived = finding({ fingerprint: 'waived', filePath: 'legacy/batch.py' });
    const states = classifyFindings([old, added, waived], [old], [{ id: 'ex-1', ruleId: 'rule-2', fingerprint: null, pathGlob: 'legacy/**' }]);
    expect(states.map((f) => [f.fingerprint, f.state, f.exceptionId])).toEqual([
      ['old', 'existing', null],
      ['added', 'new', null],
      ['waived', 'waived', 'ex-1'],
    ]);
    // Without a baseline (a scan of the default branch) nothing is "new".
    expect(classifyFindings([added], null).map((f) => f.state)).toEqual(['existing']);
    // An exception for another rule does not apply.
    expect(classifyFindings([waived], [], [{ id: 'ex-2', ruleId: 'rule-9', fingerprint: 'waived', pathGlob: null }])[0].state).toBe('new');
  });

  it('matches path globs', () => {
    expect(globMatch('**', 'a/b/c.py')).toBe(true);
    expect(globMatch('services/**', 'services/ai/triage.ts')).toBe(true);
    expect(globMatch('services/*.ts', 'services/ai/triage.ts')).toBe(false);
    expect(globMatch('api/*.py', 'api/loans.py')).toBe(true);
    expect(globMatch('api/*.py', 'apixloans.py')).toBe(false);
  });
});

describe('rules in effect', () => {
  it('uses the latest approved version whose effective date has passed, and honours retirement', () => {
    const store = new ProductStore(openDatabase(':memory:'));
    const legal = store.upsertUser({ sub: 'nusrat', email: 'nusrat@example.test' });
    const ws = store.createWorkspace('FinHealth AI', legal.id);
    const text = getInitialClauses()[0].rawLegalText;
    const v1 = store.createRuleDraft({ workspaceId: ws.id, title: 'Retention', sourceText: text, clause: compileClauseSync({ text, key: 'R-1' }), createdBy: legal.id });
    expect(store.rulesInEffect(ws.id)).toEqual([]);
    store.approveRuleVersion(ws.id, v1.version.id, legal.id, { effectiveFrom: '2026-01-01T00:00:00Z' });
    const stricter = text.replace('72 hours', '24 hours');
    const v2 = store.createRuleDraft({ workspaceId: ws.id, ruleId: v1.rule.id, title: 'Retention', sourceText: stricter, clause: compileClauseSync({ text: stricter, key: 'R-1' }), createdBy: legal.id });
    expect(v2.version.version).toBe(2);
    store.approveRuleVersion(ws.id, v2.version.id, legal.id, { effectiveFrom: '2026-12-01T00:00:00Z' });

    const before = store.rulesInEffect(ws.id, '2026-06-01T00:00:00Z');
    expect(before.map((r) => [r.ruleKey, r.version, r.clause.deontic.extractedParameters.maxRetentionHours])).toEqual([['R-1', 1, 72]]);
    const after = store.rulesInEffect(ws.id, '2026-12-02T00:00:00Z');
    expect(after.map((r) => [r.ruleKey, r.version, r.clause.deontic.extractedParameters.maxRetentionHours])).toEqual([['R-1', 2, 24]]);
    expect(rulesetSha256(before)).not.toBe(rulesetSha256(after));
    // The frozen clause carries the rule key, so proofs map back to the rule.
    expect(after[0].clause.id).toBe('R-1');

    store.retireRule(ws.id, v1.rule.id, legal.id);
    expect(store.rulesInEffect(ws.id, '2099-01-01T00:00:00Z')).toEqual([]);
    expect(store.rulesInEffect(ws.id, '2026-06-01T00:00:00Z')).toHaveLength(1);
  });
});

describe('scan conclusion', () => {
  const summary = (over: Partial<ScanSummary>): ScanSummary => ({ newCount: 0, existingCount: 0, waivedCount: 0, undecidedRuleKeys: [], perRule: [], ...over });
  it('blocks a pull request only on new findings', () => {
    expect(scanConclusion(summary({ existingCount: 6 }), true)).toBe('success');
    expect(scanConclusion(summary({ newCount: 1, existingCount: 6 }), true)).toBe('failure');
  });
  it('fails a scan without a baseline on any unwaived finding and never passes an undecided rule', () => {
    expect(scanConclusion(summary({ existingCount: 1 }), false)).toBe('failure');
    expect(scanConclusion(summary({ waivedCount: 2 }), false)).toBe('success');
    expect(scanConclusion(summary({ undecidedRuleKeys: ['R-3'] }), true)).toBe('neutral');
  });
});
