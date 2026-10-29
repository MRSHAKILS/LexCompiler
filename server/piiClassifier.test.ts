import { describe, expect, it } from 'vitest';
import { analyzeFullRepositoryAsync } from './analyzer/astAnalyzer.js';
import { classifyPii, PII_NAME, piiValueCategory, snakeCase } from './analyzer/piiClassifier.js';
import type { TargetRepoFile } from '../shared/types.js';

const file = (path: string, language: TargetRepoFile['language'], content: string): TargetRepoFile => ({ path, language, content, description: 'pii corpus', lastModified: '' });

// Labelled corpus: every field/column/property is either personal data (true) or not (false).
// Many positives carry no PII-looking name, so only a type, schema or value signal finds them.
const CORPUS: TargetRepoFile[] = [
  file('schema/people.sql', 'sql', `CREATE TABLE people (
  id BIGSERIAL PRIMARY KEY,
  patient_id UUID NOT NULL,
  contact TEXT CHECK (contact ~* '^[^@]+@[^@]+\\.[a-z]{2,}$'),
  gov_ref VARCHAR(11) CHECK (gov_ref ~ '^\\d{3}-\\d{2}-\\d{4}$'),
  last_ip INET,
  notes TEXT,
  retention_ttl_hours INT DEFAULT 72,
  email_verified BOOLEAN DEFAULT FALSE,
  phone VARCHAR(20)
);
COMMENT ON COLUMN people.notes IS 'Free-text clinical notes; contains PHI and the diagnosis history.';
COMMENT ON COLUMN people.retention_ttl_hours IS 'How long PII retention lasts before purge.';
`),
  file('api/models.py', 'python', `from pydantic import BaseModel, EmailStr, Field

class Applicant(BaseModel):
    contact: EmailStr
    reference: str = Field(..., pattern=r"^\\d{3}-\\d{2}-\\d{4}$")
    born: str = Field(..., description="Applicant date of birth (ISO 8601)")
    card: str = Field(..., examples=["4111 1111 1111 1111"])
    full_name: str
    tenant_id: str
    status: str = "pending"
    score: float = 0.0
`),
  file('services/types.ts', 'typescript', `export interface Customer {
  customerId: string;
  /** @pii primary contact */
  handle: string;
  phone: PhoneNumber;
  mail: Email;
  diagnosisCode: string;
  createdAt: string;
  tier: 'gold' | 'silver';
}
type PhoneNumber = string & { __brand: 'phone' };
type Email = string & { __brand: 'email' };
`),
];

const LABELS: Record<string, boolean> = {
  'people.id': false, 'people.patient_id': false, 'people.contact': true, 'people.gov_ref': true, 'people.last_ip': true,
  'people.notes': true, 'people.retention_ttl_hours': false, 'people.email_verified': false, 'people.phone': true,
  'Applicant.contact': true, 'Applicant.reference': true, 'Applicant.born': true, 'Applicant.card': true, 'Applicant.full_name': true,
  'Applicant.tenant_id': false, 'Applicant.status': false, 'Applicant.score': false,
  'Customer.customerId': false, 'Customer.handle': true, 'Customer.phone': true, 'Customer.mail': true, 'Customer.diagnosisCode': true,
  'Customer.createdAt': false, 'Customer.tier': false,
};

function score(predicted: Set<string>) {
  const tp = Object.entries(LABELS).filter(([k, v]) => v && predicted.has(k)).length;
  const fp = Object.entries(LABELS).filter(([k, v]) => !v && predicted.has(k)).length;
  const fn = Object.entries(LABELS).filter(([k, v]) => v && !predicted.has(k)).length;
  return { precision: tp / Math.max(1, tp + fp), recall: tp / Math.max(1, tp + fn), fp, fn };
}

describe('PII classification beyond identifier names', () => {
  it('classifies from type, schema, and value signals', () => {
    expect(classifyPii({ name: 'contact', typeText: 'Optional[EmailStr]' })).toMatchObject({ pii: true, category: 'email', evidence: ['type'] });
    expect(classifyPii({ name: 'ref', patterns: ['^\\d{3}-\\d{2}-\\d{4}$'] })).toMatchObject({ pii: true, category: 'government_id', evidence: ['schema'] });
    expect(classifyPii({ name: 'born', description: 'Applicant date of birth' })).toMatchObject({ pii: true, category: 'dob' });
    expect(classifyPii({ name: 'x', samples: ['jane@example.org'] })).toMatchObject({ pii: true, category: 'email', evidence: ['value'] });
    expect(classifyPii({ name: 'ssn', typeText: 'str', samples: ['123-45-6789'] }).evidence).toEqual(['name', 'value']);
    // Passing mentions and identifiers are not personal data.
    expect(classifyPii({ name: 'retention_hours', description: 'How long PII retention lasts' }).pii).toBe(false);
    expect(classifyPii({ name: 'patient_id', typeText: 'UUID' }).pii).toBe(false);
    expect(classifyPii({ name: 'email_verified', typeText: 'BOOLEAN' }).pii).toBe(false);
  });

  it('recognises PII value formats, with a Luhn check for card numbers', () => {
    expect(piiValueCategory('123-45-6789')).toBe('government_id');
    expect(piiValueCategory('000-12-3456')).toBeNull();
    expect(piiValueCategory('+44 20 7946 0958')).toBe('phone');
    expect(piiValueCategory('4111 1111 1111 1111')).toBe('card_number');
    expect(piiValueCategory('4111 1111 1111 1112')).toBeNull();
    expect(piiValueCategory('DE89 3704 0044 0532 0130 00')).toBe('iban');
    expect(piiValueCategory('pending')).toBeNull();
    expect(snakeCase('diagnosisCode')).toBe('diagnosis_code');
  });

  it('finds PII across SQL, Pydantic and TypeScript with higher recall than names alone, at full precision', async () => {
    const a = await analyzeFullRepositoryAsync(CORPUS);
    const predicted = new Set<string>();
    for (const t of a.sqlTables) for (const c of t.columns) if (c.isPII) predicted.add(`${t.tableName}.${c.name}`);
    for (const f of a.astFindings.filter((x) => x.constructType === 'PII_COLLECTION_MODEL')) {
      for (const name of f.metadata.collectedPiiFields || []) predicted.add(`${f.functionName}.${name}`);
    }
    const nameOnly = new Set(Object.keys(LABELS).filter((k) => PII_NAME.test(snakeCase(k.split('.')[1]))));

    const full = score(predicted);
    const baseline = score(nameOnly);
    // Measured on this corpus: names alone find 4 of 14 positives (recall 0.29); the classifier finds all 14 with no false positives.
    expect(baseline.recall).toBeLessThan(0.5);
    expect(full.recall).toBe(1);
    expect(full.precision).toBe(1);

    const people = a.sqlTables.find((t) => t.tableName === 'people')!;
    const col = (n: string) => people.columns.find((c) => c.name === n)!;
    expect(col('contact').piiInference).toBe('SCHEMA');
    expect(col('last_ip').piiInference).toBe('TYPE');
    expect(col('notes')).toMatchObject({ piiInference: 'SCHEMA', piiClassification: 'HEALTH_PHI' });
    expect(people.unencryptedPiiColumns).toEqual(expect.arrayContaining(['contact', 'gov_ref', 'last_ip', 'notes', 'phone']));

    const applicant = a.astFindings.find((f) => f.functionName === 'Applicant')!;
    expect(applicant.metadata.piiFieldEvidence?.card).toMatchObject({ category: 'card_number', evidence: ['value'] });
    const customer = a.astFindings.find((f) => f.functionName === 'Customer')!;
    expect(customer.metadata.piiFieldEvidence?.mail.evidence).toEqual(['type']);
    expect(customer.metadata.piiFieldEvidence?.handle.evidence).toEqual(['schema']);
  });
});
