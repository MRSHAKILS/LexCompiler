// FinHealth AI — High-Risk Clinical & Credit Triage AI Engine
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
