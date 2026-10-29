import type { RuleCategory } from '../../shared/types.js';

export interface RegoBounds {
  maxRetentionHours: number;
  requiresTenantIsolatedKeys: boolean;
  requireEncryptionAtRest: boolean;
  forbidPlaintextLogging: boolean;
  minAiConfidenceThreshold: number;
  requireHumanOversightGate: boolean;
  requireImmutableAuditLog: boolean;
  requireCascadeErasure: boolean;
  allowedDataRegions: string[];
  requireConsentCheck: boolean;
  maxBreachNotificationHours: number;
  requireDpia: boolean;
  forbidUnusedPiiFields: boolean;
  allowedProcessingPurposes: string[];
}

export const REGO_PACKAGES: Record<RuleCategory, string> = {
  RETENTION_AND_TENANT_KMS: 'lexcompiler.dpa.retention_and_kms',
  PII_LOGGING_BAN: 'lexcompiler.hipaa.pii_logging',
  AI_HUMAN_IN_THE_LOOP: 'lexcompiler.eu_ai_act.article14',
  CROSS_BORDER_TRANSFER: 'lexcompiler.gdpr.cross_border',
  ENCRYPTION_AT_REST: 'lexcompiler.crypto.encryption_at_rest',
  RIGHT_TO_ERASURE_CASCADE: 'lexcompiler.gdpr.erasure_cascade',
  CONSENT_LAWFUL_BASIS: 'lexcompiler.gdpr.art6_lawful_basis',
  BREACH_NOTIFICATION: 'lexcompiler.gdpr.art33_breach_notification',
  DPIA_REQUIRED: 'lexcompiler.gdpr.art35_dpia',
  DATA_MINIMISATION: 'lexcompiler.gdpr.art5_minimisation',
  PURPOSE_LIMITATION: 'lexcompiler.gdpr.art5_purpose_limitation',
};

/**
 * OPA (Rego v1) policy for a compiled clause. It evaluates the analyzer's facts
 * (see buildRegoInput) and yields one `deny` message per violating construct.
 */
export function regoPolicyFor(category: RuleCategory, b: RegoBounds, citation: string): string {
  const header = `package ${REGO_PACKAGES[category]}

import rego.v1

citation := ${JSON.stringify(citation)}
`;
  switch (category) {
    case 'RETENTION_AND_TENANT_KMS':
      return `${header}
statutory_max_hours := ${b.maxRetentionHours}

requires_tenant_kms := ${b.requiresTenantIsolatedKeys}

deny contains msg if {
	some t in input.sql_tables
	t.containsPII
	not is_number(t.retentionHoursConfigured)
	msg := sprintf("VIOLATION [%s]: table '%s' stores PII without a retention period", [citation, t.tableName])
}

deny contains msg if {
	some t in input.sql_tables
	t.containsPII
	is_number(t.retentionHoursConfigured)
	t.retentionHoursConfigured > statutory_max_hours
	msg := sprintf("VIOLATION [%s]: table '%s' retains PII for %vh (limit %vh)", [citation, t.tableName, t.retentionHoursConfigured, statutory_max_hours])
}

deny contains msg if {
	requires_tenant_kms
	some t in input.sql_tables
	t.containsPII
	not t.hasTenantKeyIsolation
	msg := sprintf("VIOLATION [%s]: table '%s' lacks a tenant-isolated KMS key column", [citation, t.tableName])
}

deny contains msg if {
	requires_tenant_kms
	some e in input.endpoints
	not e.uses_tenant_isolated_kms
	msg := sprintf("VIOLATION [%s]: %s (%s:%v) persists PII without a tenant-isolated KMS envelope", [citation, e.name, e.filePath, e.line])
}

deny contains msg if {
	some c in input.caches
	c.ttl_hours > statutory_max_hours
	msg := sprintf("VIOLATION [%s]: %s keeps PII for %vh (limit %vh)", [citation, c.name, c.ttl_hours, statutory_max_hours])
}

deny contains msg if {
	requires_tenant_kms
	some c in input.caches
	c.uses_tenant_isolated_kms == false
	msg := sprintf("VIOLATION [%s]: cache %s stores PII without a tenant KMS envelope", [citation, c.name])
}
`;
    case 'ENCRYPTION_AT_REST':
      return `${header}
requires_encryption := ${b.requireEncryptionAtRest}

requires_tenant_kms := ${b.requiresTenantIsolatedKeys}

deny contains msg if {
	requires_encryption
	some t in input.sql_tables
	t.containsPII
	count(t.unencryptedPiiColumns) > 0
	msg := sprintf("VIOLATION [%s]: table '%s' stores unencrypted PII columns %v", [citation, t.tableName, t.unencryptedPiiColumns])
}

deny contains msg if {
	requires_tenant_kms
	some t in input.sql_tables
	t.containsPII
	not t.hasTenantKeyIsolation
	msg := sprintf("VIOLATION [%s]: table '%s' lacks a tenant-isolated KMS key column", [citation, t.tableName])
}
`;
    case 'RIGHT_TO_ERASURE_CASCADE':
      return `${header}
requires_cascade := ${b.requireCascadeErasure}

deny contains msg if {
	requires_cascade
	some t in input.sql_tables
	t.containsPII
	some d in t.dependentForeignKeys
	not d.onDeleteCascade
	msg := sprintf("VIOLATION [%s]: %s.%s references '%s' without ON DELETE CASCADE", [citation, d.childTable, d.childColumn, t.tableName])
}
`;
    case 'PII_LOGGING_BAN':
      return `${header}
forbid_plaintext_logging := ${b.forbidPlaintextLogging}

deny contains msg if {
	forbid_plaintext_logging
	some s in input.log_sinks
	count(s.leaked_fields) > 0
	msg := sprintf("VIOLATION [%s]: %s at %s:%v logs unredacted PII %v", [citation, s.name, s.filePath, s.line, s.leaked_fields])
}
`;
    case 'AI_HUMAN_IN_THE_LOOP':
      return `${header}
min_confidence := ${b.minAiConfidenceThreshold}

requires_human_oversight := ${b.requireHumanOversightGate}

requires_audit_log := ${b.requireImmutableAuditLog}

deny contains msg if {
	some n in input.ai_nodes
	not is_number(n.confidence_threshold)
	msg := sprintf("VIOLATION [%s]: %s has no confidence gate", [citation, n.name])
}

deny contains msg if {
	some n in input.ai_nodes
	is_number(n.confidence_threshold)
	n.confidence_threshold < min_confidence
	msg := sprintf("VIOLATION [%s]: %s auto-decides at %v (< %v)", [citation, n.name, n.confidence_threshold, min_confidence])
}

deny contains msg if {
	requires_human_oversight
	some n in input.ai_nodes
	not n.has_human_oversight_gate
	msg := sprintf("VIOLATION [%s]: %s has no human-in-the-loop gate", [citation, n.name])
}

deny contains msg if {
	requires_audit_log
	some n in input.ai_nodes
	not n.writes_audit_log
	msg := sprintf("VIOLATION [%s]: %s does not write an immutable audit log", [citation, n.name])
}
`;
    case 'CROSS_BORDER_TRANSFER':
      return `${header}
allowed_regions := ${JSON.stringify(b.allowedDataRegions)}

deny contains msg if {
	some e in input.egress_nodes
	not e.region in allowed_regions
	msg := sprintf("VIOLATION [%s]: %s transfers data to '%s' (allowed: %v)", [citation, e.name, e.region, allowed_regions])
}
`;
    case 'CONSENT_LAWFUL_BASIS':
      return `${header}
requires_consent := ${b.requireConsentCheck}

deny contains msg if {
	requires_consent
	some e in input.entrypoints
	not e.has_consent_check
	msg := sprintf("VIOLATION [%s]: %s at %s:%v processes personal data without a consent / lawful-basis check", [citation, e.name, e.filePath, e.line])
}
`;
    case 'BREACH_NOTIFICATION':
      return `${header}
max_notification_hours := ${b.maxBreachNotificationHours}

deny contains msg if {
	some p in input.breach_policies
	not is_number(p.hours)
	msg := sprintf("VIOLATION [%s]: no breach-notification deadline is configured (%s)", [citation, p.filePath])
}

deny contains msg if {
	some p in input.breach_policies
	is_number(p.hours)
	p.hours > max_notification_hours
	msg := sprintf("VIOLATION [%s]: %s notifies within %vh (limit %vh)", [citation, p.name, p.hours, max_notification_hours])
}
`;
    case 'DPIA_REQUIRED':
      return `${header}
requires_dpia := ${b.requireDpia}

dpia_on_record if {
	some d in input.dpia_records
	d.exists
}

deny contains msg if {
	requires_dpia
	some n in input.ai_nodes
	not dpia_on_record
	msg := sprintf("VIOLATION [%s]: high-risk processing in %s has no DPIA on record", [citation, n.name])
}
`;
    case 'DATA_MINIMISATION':
      return `${header}
forbid_unused_pii := ${b.forbidUnusedPiiFields}

deny contains msg if {
	forbid_unused_pii
	some m in input.models
	count(m.unused_pii_fields) > 0
	msg := sprintf("VIOLATION [%s]: %s collects PII it never uses %v", [citation, m.name, m.unused_pii_fields])
}
`;
    case 'PURPOSE_LIMITATION':
      return `${header}
allowed_purposes := ${JSON.stringify(b.allowedProcessingPurposes)}

deny contains msg if {
	some e in input.entrypoints
	not is_string(e.purpose)
	msg := sprintf("VIOLATION [%s]: %s declares no processing purpose", [citation, e.name])
}

deny contains msg if {
	count(allowed_purposes) > 0
	some e in input.entrypoints
	is_string(e.purpose)
	not e.purpose in allowed_purposes
	msg := sprintf("VIOLATION [%s]: %s processes data for '%s' (allowed: %v)", [citation, e.name, e.purpose, allowed_purposes])
}
`;
  }
}
