import { describe, expect, it } from 'vitest';
import { compileLegalProseToFormalPolicy, extractTemporalHoursFromProse } from './compiler/legalCompiler.js';

const hours = (text: string) => extractTemporalHoursFromProse(text.toLowerCase()).hours;

describe('duration parsing', () => {
  it.each([
    ['Personal data is purged within half a day.', 12],
    ['Logs are deleted within half an hour.', 0.5],
    ['Records are purged within a fortnight.', 336],
    ['Records are purged within two fortnights.', 672],
    ['Data is erased within one and a half days.', 36],
    ['Data is erased within 1.5 days.', 36],
    ['Data is erased within a day and a half.', 36],
    ['Caches are purged within 2 and a half hours.', 2.5],
    ['Data is purged within seventy-two hours.', 72],
    ['Data is purged within 72 hours.', 72],
    ['Data is purged within one week.', 168],
    ['Data is retained for a day.', 24],
  ])('%s → %d hours', (text, expected) => {
    expect(hours(text)).toBe(expected);
  });

  it('reports no duration when the clause has none', () => {
    expect(extractTemporalHoursFromProse('data must be encrypted at rest.').hit).toBe(false);
  });

  it('compiles "half a day" into a 12-hour retention bound', () => {
    const { deontic } = compileLegalProseToFormalPolicy(
      'Personal data must be purged within half a day of collection.',
      'RETENTION_AND_TENANT_KMS',
      'R-T1',
      'Test clause'
    );
    expect(deontic.extractedParameters.maxRetentionHours).toBe(12);
  });

  it('compiles "a fortnight" into a 336-hour retention bound', () => {
    const { deontic } = compileLegalProseToFormalPolicy(
      'Session data shall be deleted within a fortnight.',
      'RETENTION_AND_TENANT_KMS',
      'R-T2',
      'Test clause'
    );
    expect(deontic.extractedParameters.maxRetentionHours).toBe(336);
  });
});
