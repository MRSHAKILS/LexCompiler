-- FinHealth AI Enterprise Platform — Core PII & PHI Relational Schema
-- Target File: schema/postgres_pii.sql

CREATE TABLE patient_records (
    patient_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    full_name VARCHAR(160) NOT NULL, -- @pii(DIRECT_IDENTIFIER) @encrypted(AES-256-GCM)
    email VARCHAR(255) NOT NULL, -- @pii(DIRECT_IDENTIFIER) @encrypted(AES-256-GCM)
    ssn VARCHAR(64) NOT NULL, -- @pii(DIRECT_IDENTIFIER) @encrypted(AES-256-GCM)
    diagnosis_code VARCHAR(64) NOT NULL, -- @pii(HEALTH_PHI) @encrypted(AES-256-GCM)
    retention_ttl_hours INT DEFAULT 720, -- @retention_hours(720) (30-Day Legacy Retention Policy)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE clinical_triage_audits (
    audit_id UUID PRIMARY KEY,
    patient_id UUID NOT NULL REFERENCES patient_records(patient_id) ON DELETE CASCADE,
    model_version VARCHAR(64) NOT NULL,
    confidence_score NUMERIC(4, 3) NOT NULL,
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
