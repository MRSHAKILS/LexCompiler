/**
 * Classifies a field, column or property as personal data from every signal the analyzers
 * extract, not only its name:
 * - name:   the identifier (`ssn`, `patient_email`, …);
 * - type:   a declared type that only holds personal data (Pydantic `EmailStr`, SQL `inet`,
 *           a TypeScript `Email` / `PhoneNumber` brand, a SQL domain named after a PII field);
 * - schema: documentation and constraints (SQL `COMMENT ON COLUMN`, `CHECK` / Pydantic
 *           `pattern=` regexes for SSN, e-mail or card formats, `Field(description=…)`, JSDoc `@pii`);
 * - value:  literals assigned to it in code or fixtures that match a PII format (SSN, e-mail,
 *           E.164 phone, Luhn-valid card number, IBAN).
 * Evidence lists every signal that matched, strongest first.
 */

export type PiiEvidence = 'name' | 'type' | 'schema' | 'value';

export interface PiiSignals {
  name: string;
  /** Declared type text, e.g. `EmailStr`, `Optional[EmailStr]`, `inet`, `Email`. */
  typeText?: string;
  /** Free-text documentation: SQL column comment, Field description, JSDoc text. */
  description?: string;
  /** Validation regexes: SQL CHECK expressions, Pydantic `pattern=` / `regex=`. */
  patterns?: string[];
  /** Literal values seen for this field (defaults, fixtures, examples). */
  samples?: unknown[];
}

export interface PiiClassification {
  pii: boolean;
  /** e.g. `email`, `ssn`, `phone`, `card_number`, `iban`, `ip_address`, `health`, `name`, `dob`, `government_id`, `personal`. */
  category?: string;
  evidence: PiiEvidence[];
}

/** Identifier is PII when its last `_`-separated token(s) name a personal-data field. */
export const PII_NAME =
  /(^|_)(ssn|email|phone|dob|date_of_birth|birthdate|passport|national_id|tax_id|credit_card|card_number|full_name|diagnosis_code|diagnosis)$/i;

const NAME_CATEGORY: Array<[RegExp, string]> = [
  [/ssn|national_id|tax_id|passport/i, 'government_id'],
  [/email/i, 'email'],
  [/phone/i, 'phone'],
  [/dob|date_of_birth|birthdate/i, 'dob'],
  [/credit_card|card_number/i, 'card_number'],
  [/full_name/i, 'name'],
  [/diagnosis/i, 'health'],
];

/** Types that, by construction, only hold one kind of personal data. */
const PII_TYPES: Array<[RegExp, string]> = [
  [/\b(EmailStr|NameEmail|Email|EmailAddress)\b/, 'email'],
  [/\b(PhoneNumber|PhoneNumberStr|E164Phone)\b/, 'phone'],
  [/\b(PaymentCardNumber|CreditCardNumber|CardNumber)\b/, 'card_number'],
  [/\b(SSN|SocialSecurityNumber|NationalId|PassportNumber|TaxId)\b/, 'government_id'],
  [/\b(IBAN|Iban)\b/, 'iban'],
  [/\b(IPvAnyAddress|IPv4Address|IPv6Address|inet)\b/i, 'ip_address'],
  [/\b(DateOfBirth|BirthDate)\b/, 'dob'],
];

/** Documentation phrases that state a field holds personal data. */
const PII_DESCRIPTION: Array<[RegExp, string]> = [
  [/\bsocial security\b|\bSSN\b|\bnational (id|identification)\b|\bpassport\b|\btax (id|identification)\b/i, 'government_id'],
  [/\be-?mail address\b/i, 'email'],
  [/\bphone number\b|\bmobile number\b|\btelephone\b/i, 'phone'],
  [/\bdate of birth\b|\bbirth ?date\b/i, 'dob'],
  [/\b(credit|debit|payment) card\b|\bPAN\b/, 'card_number'],
  [/\bdiagnos(is|es)\b|\bmedical record\b|\bhealth (data|information|record)\b|\bPHI\b/i, 'health'],
  [/\bbiometric\b|\bfingerprint\b|\bgenetic\b/i, 'biometric'],
  [/\b(full|legal|first|last|given|family) name\b/i, 'name'],
  [/\bhome address\b|\bpostal address\b|\bstreet address\b/i, 'address'],
  // Only statements that the field itself holds personal data, not passing mentions ("PII retention").
  [/@pii\b|\b(contains|holds|stores|is) (pii|phi|personal data|personal information)\b|\bpersonally identifiable\b|\bsensitive personal data\b/i, 'personal'],
];

/** Regex sources (as written in CHECK / pattern=) that validate a PII format. */
const PII_PATTERN_SOURCES: Array<[RegExp, string]> = [
  // \d{3}-\d{2}-\d{4} and [0-9]{3}-[0-9]{2}-[0-9]{4} (SSN)
  [/(\\d|\[0-9\])\{3\}-?(\\d|\[0-9\])\{2\}-?(\\d|\[0-9\])\{4\}/, 'government_id'],
  // anything requiring an @ followed by a domain part (e-mail)
  [/@[^'"\s]*\\?\./, 'email'],
  // E.164: optional +, 8–15 digits
  [/\^?\\?\+[?]?(\[1-9\]|\\d)(\\d|\[0-9\])\{\d+,\d+\}/, 'phone'],
  // 13–19 digit card numbers
  [/(\\d|\[0-9\])\{1[3-6](,1[69])?\}/, 'card_number'],
];

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/** Category of a literal value that matches a PII format, or null. */
export function piiValueCategory(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const v = value.trim();
  if (/^\d{3}-\d{2}-\d{4}$/.test(v) && !/^(000|666|9\d\d)/.test(v)) return 'government_id';
  if (/^[^\s@]+@[^\s@]+\.[A-Za-z]{2,}$/.test(v)) return 'email';
  if (/^\+[1-9]\d{7,14}$/.test(v.replace(/[\s().-]/g, ''))) return 'phone';
  const digits = v.replace(/[\s-]/g, '');
  if (/^\d{13,19}$/.test(digits) && luhn(digits)) return 'card_number';
  if (/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(v.replace(/\s/g, ''))) return 'iban';
  return null;
}

function firstMatch(table: Array<[RegExp, string]>, text: string | undefined): string | null {
  if (!text) return null;
  for (const [re, cat] of table) if (re.test(text)) return cat;
  return null;
}

/** `diagnosisCode` → `diagnosis_code`, so camelCase (TypeScript) names match the snake_case rules. */
export function snakeCase(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

export function classifyPii(s: PiiSignals): PiiClassification {
  const evidence: PiiEvidence[] = [];
  let category: string | undefined;
  const hit = (e: PiiEvidence, cat: string | null) => {
    if (!cat) return;
    evidence.push(e);
    category ??= cat;
  };
  const name = snakeCase(s.name);
  if (PII_NAME.test(name)) hit('name', firstMatch(NAME_CATEGORY, name) || 'personal');
  hit('type', firstMatch(PII_TYPES, s.typeText) || (s.typeText && PII_NAME.test(s.typeText.replace(/[^A-Za-z0-9_]/g, '_')) ? firstMatch(NAME_CATEGORY, s.typeText) || 'personal' : null));
  hit('schema', firstMatch(PII_DESCRIPTION, s.description) || firstMatch(PII_PATTERN_SOURCES, (s.patterns || []).join(' ')));
  hit('value', (s.samples || []).map(piiValueCategory).find(Boolean) ?? null);
  // A `personal` description is the weakest category: prefer a specific one when another signal has it.
  if (category === 'personal') {
    const specific = [firstMatch(PII_TYPES, s.typeText), firstMatch(PII_DESCRIPTION.slice(0, -1), s.description), (s.samples || []).map(piiValueCategory).find(Boolean)].find(Boolean);
    if (specific) category = specific;
  }
  return { pii: evidence.length > 0, ...(category ? { category } : {}), evidence: [...new Set(evidence)] };
}
