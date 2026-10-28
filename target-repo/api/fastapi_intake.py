# FinHealth AI — FastAPI Patient & Financial PII Intake Service
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
