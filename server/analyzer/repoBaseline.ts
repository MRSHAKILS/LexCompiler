import fs from 'node:fs';
import path from 'node:path';
import type { TargetRepoFile } from '../../shared/types.js';

export const TARGET_REPO_ROOT = path.resolve(process.cwd(), 'target-repo');

export const INITIAL_REPO_FILES: Record<string, { language: 'python' | 'typescript' | 'sql'; description: string; content: string }> = {
  'schema/postgres_pii.sql': {
    language: 'sql',
    description: 'PostgreSQL Relational Schema for Patient PII & Clinical Triage Audits',
    content: `-- FinHealth AI Enterprise Platform — Core PII & PHI Relational Schema
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
`,
  },
  'api/fastapi_intake.py': {
    language: 'python',
    description: 'Python FastAPI Patient PII Ingestion Endpoint & Cryptographic Envelope Handler',
    content: `# FinHealth AI — FastAPI Patient & Financial PII Intake Service
# Target File: api/fastapi_intake.py

import logging
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="FinHealth Intake Service")
logger = logging.getLogger("finhealth.intake")

# Cryptographic key isolation configuration
USING_TENANT_ISOLATED_KMS = False
ENCRYPTION_CIPHER = "AES-256-GCM-SHARED-KEY"


class PatientIntakePayload(BaseModel):
    tenant_id: str
    patient_id: str
    full_name: str
    email: str
    ssn: str
    diagnosis_code: str


def encrypt_shared_aes256(plaintext: str) -> str:
    """Encrypts field using a single global shared key (NOT tenant-isolated KMS)."""
    return f"enc_shared::{plaintext[:4]}***"


@app.post("/api/v1/patients/intake")
async def ingest_patient_pii(payload: PatientIntakePayload, x_tenant_id: str = Header(...)):
    # VIOLATION RISK: Logs plaintext SSN, email, and diagnosis_code directly to stdout sink
    logger.info(
        f"Ingesting patient record ssn={payload.ssn} email={payload.email} diagnosis={payload.diagnosis_code}"
    )

    # VIOLATION RISK: Uses shared global AES key instead of tenant-isolated KMS envelope
    encrypted_ssn = encrypt_shared_aes256(payload.ssn)
    encrypted_diagnosis = encrypt_shared_aes256(payload.diagnosis_code)

    return {
        "status": "persisted",
        "tenant_id": x_tenant_id,
        "kms_isolated": USING_TENANT_ISOLATED_KMS,
        "cipher": ENCRYPTION_CIPHER,
        "encrypted_ssn": encrypted_ssn,
        "encrypted_diagnosis": encrypted_diagnosis,
    }
`,
  },
  'workers/redis_cache_worker.py': {
    language: 'python',
    description: 'Python Redis Session Cache & Ephemeral PII Retention Purge Worker',
    content: `# FinHealth AI — Ephemeral Redis Session Cache & Retention Purge Worker
# Target File: workers/redis_cache_worker.py

import json
from typing import Dict, Any

# Legacy 30-day retention window (720 hours)
PII_CACHE_TTL_HOURS = 720
USE_TENANT_KMS_ENVELOPE = False


class RedisSessionCacheWorker:
    def __init__(self, redis_client: Any):
        self.redis = redis_client
        self.ttl_hours = PII_CACHE_TTL_HOURS
        self.tenant_isolated = USE_TENANT_KMS_ENVELOPE

    def cache_patient_session(self, tenant_id: str, patient_id: str, pii_blob: Dict[str, Any]) -> bool:
        """Caches session PII in Redis with configured TTL window."""
        cache_key = f"session:{patient_id}"
        ttl_seconds = self.ttl_hours * 3600
        serialized_payload = json.dumps(pii_blob)
        self.redis.setex(cache_key, ttl_seconds, serialized_payload)
        return True

    def enforce_retention_purge(self) -> Dict[str, Any]:
        """Scans ephemeral keys and purges records older than PII_CACHE_TTL_HOURS."""
        return {
            "configured_purge_window_hours": PII_CACHE_TTL_HOURS,
            "tenant_kms_envelope": USE_TENANT_KMS_ENVELOPE,
        }
`,
  },
  'services/ai_credit_triage.ts': {
    language: 'typescript',
    description: 'High-Risk AI Clinical & Credit Underwriting Decision Engine (EU AI Act Art. 14)',
    content: `// FinHealth AI — High-Risk Clinical & Credit Triage AI Engine
// Target File: services/ai_credit_triage.ts

export interface TriageInput {
  patientId: string;
  tenantId: string;
  diagnosisCode: string;
  requestedCreditLimit: number;
  modelConfidenceScore: number;
}

export interface TriageDecision {
  approved: boolean;
  executionMode: 'AUTONOMOUS_AI' | 'HUMAN_OVERSIGHT_REQUIRED';
  confidenceScore: number;
  auditTrailRecorded: boolean;
}

// EU AI Act Art. 14 Parameters
const MIN_CONFIDENCE_FOR_AUTO_APPROVAL = 0.68;
const ENFORCE_HUMAN_OVERSIGHT_GATE = false;
const WRITE_IMMUTABLE_AUDIT_LOG = false;

export async function evaluateClinicalAndCreditRisk(
  input: TriageInput
): Promise<TriageDecision> {
  // Executes autonomous decision even when model confidence is below 0.85 statutory threshold
  const canAutoApprove =
    input.modelConfidenceScore >= MIN_CONFIDENCE_FOR_AUTO_APPROVAL &&
    !ENFORCE_HUMAN_OVERSIGHT_GATE;

  return {
    approved: canAutoApprove,
    executionMode: canAutoApprove ? 'AUTONOMOUS_AI' : 'HUMAN_OVERSIGHT_REQUIRED',
    confidenceScore: input.modelConfidenceScore,
    auditTrailRecorded: WRITE_IMMUTABLE_AUDIT_LOG,
  };
}
`,
  },
  'services/cross_border_sync.ts': {
    language: 'typescript',
    description: 'Cross-Border Telemetry & Disaster Recovery Replication Service (GDPR Art. 44)',
    content: `// FinHealth AI — Cross-Border Analytics & Disaster Recovery Replication
// Target File: services/cross_border_sync.ts

export interface ReplicationEvent {
  tenantId: string;
  patientId: string;
  encryptedPayload: string;
}

// GDPR Chapter V (Art. 44) Data Residency Target
const REPLICA_TARGET_REGION = "us-east-1";
const ENFORCE_EU_SOVEREIGN_BOUNDARY = false;

export async function replicatePatientTelemetry(
  event: ReplicationEvent
): Promise<{ replicated: boolean; destinationRegion: string; sovereignVerified: boolean }> {
  // Replicates EU patient telemetry to non-EEA region (us-east-1)
  return {
    replicated: true,
    destinationRegion: REPLICA_TARGET_REGION,
    sovereignVerified: ENFORCE_EU_SOVEREIGN_BOUNDARY,
  };
}
`,
  },
};

export function ensureTargetRepoFilesExist(): void {
  for (const [relPath, spec] of Object.entries(INITIAL_REPO_FILES)) {
    const absPath = path.join(TARGET_REPO_ROOT, relPath);
    fs.mkdirSync(path.dirname(absPath), { recursive: true });
    if (!fs.existsSync(absPath)) {
      fs.writeFileSync(absPath, spec.content, 'utf8');
    }
  }
}

export function resetTargetRepoToBaseline(): void {
  for (const [relPath, spec] of Object.entries(INITIAL_REPO_FILES)) {
    const absPath = path.join(TARGET_REPO_ROOT, relPath);
    fs.mkdirSync(path.dirname(absPath), { recursive: true });
    fs.writeFileSync(absPath, spec.content, 'utf8');
  }
}

export function readTargetRepoFiles(): TargetRepoFile[] {
  ensureTargetRepoFilesExist();
  const result: TargetRepoFile[] = [];

  for (const [relPath, spec] of Object.entries(INITIAL_REPO_FILES)) {
    const absPath = path.join(TARGET_REPO_ROOT, relPath);
    const content = fs.readFileSync(absPath, 'utf8');
    const stat = fs.statSync(absPath);
    result.push({
      path: relPath,
      language: spec.language,
      description: spec.description,
      content,
      lastModified: stat.mtime.toISOString(),
    });
  }
  return result;
}

export function writeTargetRepoFile(relPath: string, newContent: string): void {
  const normalized = relPath.replace(/^\/+/, '');
  const absPath = path.join(TARGET_REPO_ROOT, normalized);
  fs.mkdirSync(path.dirname(absPath), { recursive: true });
  fs.writeFileSync(absPath, newContent, 'utf8');
}
