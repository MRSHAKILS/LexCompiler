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
}

export const REGO_PACKAGES: Record<RuleCategory, string> = {
  RETENTION_AND_TENANT_KMS: 'lexcompiler.dpa.retention_and_kms',
  PII_LOGGING_BAN: 'lexcompiler.hipaa.pii_logging',
  AI_HUMAN_IN_THE_LOOP: 'lexcompiler.eu_ai_act.article14',
  CROSS_BORDER_TRANSFER: 'lexcompiler.gdpr.cross_border',
  ENCRYPTION_AT_REST: 'lexcompiler.crypto.encryption_at_rest',
  RIGHT_TO_ERASURE_CASCADE: 'lexcompiler.gdpr.erasure_cascade',
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
  }
}
