import { performance } from 'node:perf_hooks';
import { createTwoFilesPatch } from 'diff';
import {
  compileLegalProseToFormalPolicyAsync,
  inferRuleCategoryFromProse,
  sha256Hex,
} from '../compiler/legalCompiler.js';
import { analyzeFullRepositoryAsync } from '../analyzer/astAnalyzer.js';
import { verifyRepositoryAgainstClauses } from '../prover/z3Engine.js';
import { synthesizeRemediationPullRequest } from '../remediation/prSynthesizer.js';
import { getAttestationSigner, localSigner, registerTrustedKey, revocations, trustedKeys, verifyAttestationSignature } from './attestationSigner.js';
import { requestTimestamp, type TimestampToken } from './timestamp.js';
import type {
  ClauseVerificationProof,
  FullComplianceScanReport,
  LegalClause,
  RuleCategory,
  TargetRepoFile,
} from '../../shared/types.js';

export interface CryptographicConformityCertificate {
  certificateId: string;
  standard: 'LEXCOMPILER-SELF-ATTESTATION (not an EU AI Act Art. 43 conformity assessment or SOC 2 report)';
  issuedAt: string;
  issuer: string;
  repositoryName: string;
  commitHash: string;
  z3SolverEngine: string;
  overallVerdict: 'SAT_COMPLIANT_ATTESTED' | 'UNSAT_NON_COMPLIANT';
  complianceScorePercent: number;
  merkleAuditRoot: string;
  clauseAttestations: Array<{
    clauseId: string;
    citation: string;
    status: ClauseVerificationProof['status'];
    z3SolveTimeMs: number;
    merkleProofHash: string;
  }>;
  canonicalPayloadJson: string;
  signatureAlgorithm: 'Ed25519 (RFC 8032 PureEdDSA)' | 'ECDSA P-256 / SHA-256 (DER)';
  /** Trusted-key identifier; verification looks the key up by this id (keys survive rotation). */
  keyId: string;
  signingBackend: string;
  publicKeyPem: string;
  publicKeyFingerprintSha256: string;
  /** Signature over canonicalPayloadJson (named for the original Ed25519 format; ECDSA keys use it too). */
  ed25519SignatureHex: string;
  ed25519SignatureBase64: string;
  /** RFC 3161 timestamp over the signature, when LEXCOMPILER_TSA_URL is set. */
  timestamp?: TimestampToken;
}

export async function generateSignedConformityCertificate(
  report: FullComplianceScanReport
): Promise<CryptographicConformityCertificate> {
  const canonicalPayload = {
    certificateVersion: '2026.1',
    repositoryName: report.repositoryName,
    commitHash: report.commitHash,
    merkleAuditRoot: report.merkleAuditRoot,
    totalClausesEvaluated: report.totalClausesEvaluated,
    compliantClausesCount: report.compliantClausesCount,
    violatedClausesCount: report.violatedClausesCount,
    clauses: report.proofs.map((p) => ({
      clauseId: p.clauseId,
      citation: p.citation,
      status: p.status,
      merkleProofHash: p.cryptographicProvenance.merkleProofHash,
    })),
  };

  const canonicalPayloadJson = JSON.stringify(canonicalPayload, null, 2);
  const signer = await getAttestationSigner();
  const signatureBuffer = await signer.sign(Buffer.from(canonicalPayloadJson, 'utf8'));
  const fingerprint = sha256Hex(signer.publicKeyPem);
  const publicKeyFingerprintSha256 = fingerprint.slice(0, 32);
  const tsaUrl = process.env.LEXCOMPILER_TSA_URL;
  const timestamp = tsaUrl ? await requestTimestamp(signatureBuffer, tsaUrl) : undefined;
  const algorithmLabel = signer.algorithm === 'Ed25519' ? ('Ed25519 (RFC 8032 PureEdDSA)' as const) : ('ECDSA P-256 / SHA-256 (DER)' as const);

  return {
    certificateId: `CERT-LEX-${report.commitHash.toUpperCase()}-${Date.now().toString().slice(-4)}`,
    standard: 'LEXCOMPILER-SELF-ATTESTATION (not an EU AI Act Art. 43 conformity assessment or SOC 2 report)',
    issuedAt: new Date().toISOString(),
    issuer: `LexCompiler attestation key ${signer.keyId} (${signer.algorithm}, ${signer.backend})`,
    repositoryName: report.repositoryName,
    commitHash: report.commitHash,
    z3SolverEngine: report.z3EngineVersion,
    overallVerdict:
      report.violatedClausesCount === 0
        ? 'SAT_COMPLIANT_ATTESTED'
        : 'UNSAT_NON_COMPLIANT',
    complianceScorePercent: report.overallComplianceScore,
    merkleAuditRoot: report.merkleAuditRoot,
    clauseAttestations: report.proofs.map((p) => ({
      clauseId: p.clauseId,
      citation: p.citation,
      status: p.status,
      z3SolveTimeMs: p.z3SolveTimeMs,
      merkleProofHash: p.cryptographicProvenance.merkleProofHash,
    })),
    canonicalPayloadJson,
    signatureAlgorithm: algorithmLabel,
    keyId: signer.keyId,
    signingBackend: signer.backend,
    publicKeyPem: signer.publicKeyPem,
    publicKeyFingerprintSha256,
    ed25519SignatureHex: signatureBuffer.toString('hex'),
    ed25519SignatureBase64: signatureBuffer.toString('base64'),
    ...(timestamp ? { timestamp } : {}),
  };
}

export function verifyEd25519CertificateSignature(
  canonicalPayloadJson: string,
  signatureHex: string,
  publicKeyPem?: string,
  ids: { keyId?: string; certificateId?: string } = {}
): {
  verified: boolean;
  algorithm: string;
  payloadSha256: string;
  verificationTimestamp: string;
  reason: string;
  keyId?: string;
} {
  const base = { payloadSha256: sha256Hex(canonicalPayloadJson), verificationTimestamp: new Date().toISOString() };
  try {
    // Only keys this server has signed with are trusted; a caller-supplied key could sign anything.
    const local = localSigner();
    registerTrustedKey(local);
    const keys = trustedKeys();
    const revoked = revocations();
    if (ids.certificateId && revoked.certificates.some((c) => c.certificateId === ids.certificateId)) {
      return { ...base, verified: false, algorithm: 'n/a', reason: `REVOKED: certificate ${ids.certificateId} has been revoked.` };
    }
    if (publicKeyPem && !keys.some((k) => k.publicKeyPem.trim() === publicKeyPem.trim())) {
      return { ...base, verified: false, algorithm: 'n/a', reason: "UNTRUSTED KEY: the supplied public key is not one of this server's attestation keys (GET /api/enterprise/public-key)." };
    }
    const candidates = keys.filter((k) => (ids.keyId ? k.keyId === ids.keyId : true) && (!publicKeyPem || k.publicKeyPem.trim() === publicKeyPem.trim()));
    if (candidates.length === 0) return { ...base, verified: false, algorithm: 'n/a', reason: `UNTRUSTED KEY: unknown key id ${ids.keyId}.` };
    const sig = Buffer.from(signatureHex, 'hex');
    const data = Buffer.from(canonicalPayloadJson, 'utf8');
    const match = candidates.find((k) => {
      try {
        return verifyAttestationSignature(k.algorithm, k.publicKeyPem, data, sig);
      } catch {
        return false;
      }
    });
    if (!match) {
      return { ...base, verified: false, algorithm: candidates[0].algorithm, reason: 'INVALID: Payload or signature has been tampered with! Cryptographic verification rejected.' };
    }
    const keyRevoked = revoked.keys.find((k) => k.keyId === match.keyId);
    if (keyRevoked) return { ...base, verified: false, algorithm: match.algorithm, keyId: match.keyId, reason: `REVOKED: signing key ${match.keyId} was revoked (${keyRevoked.reason}).` };
    return { ...base, verified: true, algorithm: match.algorithm, keyId: match.keyId, reason: `VALID: ${match.algorithm} signature by trusted key ${match.keyId} matches the canonical Z3 Merkle payload.` };
  } catch (err) {
    return { ...base, verified: false, algorithm: 'n/a', reason: `INVALID: Signature format error (${String(err)})` };
  }
}

/**
 * Generates an OASIS Standard SARIF v2.1.0 report for GitHub Advanced Security / Code Scanning
 */
export function generateSarifReport(
  clauses: LegalClause[],
  proofs: ClauseVerificationProof[],
  revision: { commitHash: string; branch: string; remoteUrl?: string },
  /** Prefix that makes target-repo paths relative to the checkout SARIF is uploaded from. */
  uriPrefix = ''
): Record<string, unknown> {
  const rules = clauses.map((c) => ({
    id: c.id,
    name: c.title.replace(/[^a-zA-Z0-9]/g, ''),
    shortDescription: { text: `${c.citation}: ${c.title}` },
    fullDescription: { text: c.rawLegalText },
    helpUri: c.sourceUrl || 'https://eur-lex.europa.eu',
    defaultConfiguration: {
      level: c.severity === 'CRITICAL' ? 'error' : 'warning',
    },
    properties: {
      tags: ['compliance', 'neuro-symbolic', 'z3-smt', c.frameworkId.toLowerCase()],
      deonticFormula: c.compiled.deonticFormula,
      precision: 'very-high',
    },
  }));

  const results = proofs
    .filter((p) => p.status === 'UNSAT_VIOLATION')
    .flatMap((proof) =>
      proof.offendingLocations.map((loc) => ({
        ruleId: proof.clauseId,
        level: proof.severity === 'CRITICAL' ? 'error' : 'warning',
        message: {
          text: `[Z3 UNSAT] ${loc.explanation} | Unsat Core: [${proof.unsatCoreAssertions.join(
            ', '
          )}] | Fix: ${loc.remediationPreview}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: `${uriPrefix}${loc.filePath}`,
                uriBaseId: 'SRCROOT',
              },
              region: {
                startLine: loc.line,
                endLine: loc.endLine,
              },
            },
          },
        ],
        fingerprints: {
          merkleProofHash: proof.cryptographicProvenance.merkleProofHash,
        },
      }))
    );

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'LexCompiler Neuro-Symbolic Law-to-AST Prover',
            organization: 'JusticeSphere AI',
            semanticVersion: '2.4.0',
            informationUri: 'https://justicesphere.ai/lexcompiler',
            rules,
          },
        },
        originalUriBaseIds: { SRCROOT: { description: { text: 'Repository root' } } },
        ...(revision.remoteUrl
          ? {
              versionControlProvenance: [
                { repositoryUri: revision.remoteUrl, revisionId: revision.commitHash, branch: revision.branch },
              ],
            }
          : {}),
        results,
      },
    ],
  };
}

/**
 * Universal "Bring Your Own Code & Contract" (BYOC) Live Neuro-Symbolic Scanner.
 * Parses arbitrary user-provided contract clauses + arbitrary Python/TS/SQL code,
 * runs Microsoft Z3 formal verification, and synthesizes an instant remediated diff.
 */
function categoriesForByocScan(text: string): RuleCategory[] {
  const lower = text.toLowerCase();
  const cats = new Set<RuleCategory>();
  cats.add(inferRuleCategoryFromProse(text, 'RETENTION_AND_TENANT_KMS'));
  if (/log|redact|plaintext|unredacted/.test(lower)) cats.add('PII_LOGGING_BAN');
  if (/human|confidence|oversight|article 14/.test(lower)) cats.add('AI_HUMAN_IN_THE_LOOP');
  if (/transfer|cross-border|region|us-east|sovereign/.test(lower)) cats.add('CROSS_BORDER_TRANSFER');
  if (/erasur|forgotten|cascade|article 17/.test(lower)) cats.add('RIGHT_TO_ERASURE_CASCADE');
  if (/encrypt/.test(lower)) cats.add('ENCRYPTION_AT_REST');
  if (/retention|purge|ttl|hours|tenant|kms/.test(lower)) cats.add('RETENTION_AND_TENANT_KMS');
  return [...cats];
}

export async function executeByocCustomScan(input: {
  contractClauseText: string;
  citationLabel: string;
  language: 'python' | 'typescript' | 'sql';
  fileName: string;
  sourceCode: string;
}) {
  const t0 = performance.now();
  const citation = input.citationLabel || 'Custom Enterprise MSA §4.2';
  const categories = categoriesForByocScan(input.contractClauseText);

  const clauses: LegalClause[] = [];
  for (const category of categories) {
    const compiled = await compileLegalProseToFormalPolicyAsync(
      input.contractClauseText,
      category,
      `CLAUSE-BYOC-${category}`,
      citation
    );
    clauses.push({
      id: `CLAUSE-BYOC-${category}`,
      frameworkId: 'ENTERPRISE_DPA',
      frameworkName: 'Bring-Your-Own-Contract',
      citation,
      title: `BYOC ${category}`,
      severity: 'HIGH',
      category,
      rawLegalText: input.contractClauseText,
      version: 'v-byoc-live',
      lastAmended: new Date().toISOString().slice(0, 10),
      deontic: compiled.deontic,
      compiled: compiled.compiled,
    });
  }

  const file: TargetRepoFile = {
    path: input.fileName,
    language: input.language,
    description: 'BYOC custom scan target',
    content: input.sourceCode,
    lastModified: new Date().toISOString(),
  };
  const analysis = await analyzeFullRepositoryAsync([file]);
  const verification = await verifyRepositoryAgainstClauses(
    clauses,
    analysis.sqlTables,
    analysis.astFindings
  );

  const primary =
    clauses.find((c) => c.category === 'RETENTION_AND_TENANT_KMS') || clauses[0];
  const requiredMaxHours = primary.deontic.extractedParameters.maxRetentionHours ?? 72;
  const requiresTenantKms =
    primary.deontic.extractedParameters.requiresTenantIsolatedKeys ?? false;
  const forbidsPlaintextLog =
    clauses.some((c) => c.deontic.extractedParameters.forbidPlaintextLogging) ||
    /prohibit|never log|shall not log|unredacted|redact|mask/i.test(input.contractClauseText);

  const ttlFinding = analysis.astFindings.find(
    (f) => typeof f.metadata.retentionTtlHours === 'number'
  );
  const detectedTtlHours = ttlFinding?.metadata.retentionTtlHours ?? 720;
  const detectedTenantKms = analysis.astFindings.some(
    (f) => f.metadata.usesTenantIsolatedKms === true
  );
  const detectedPlaintextLog = analysis.astFindings.some(
    (f) => f.metadata.logsPlaintextPii === true
  );

  const violated = verification.proofs.filter((p) => p.status === 'UNSAT_VIOLATION');
  let remediatedCode = input.sourceCode;
  if (violated.length > 0) {
    const pr = await synthesizeRemediationPullRequest(clauses, [file], verification.proofs);
    remediatedCode = pr?.filePatches[0]?.patchedContent || input.sourceCode;
  }

  const z3Verdict = violated.length === 0 ? 'sat' : 'unsat';
  const solveMs = Math.max(
    0.5,
    Math.round((performance.now() - t0) * 100) / 100
  );
  const unifiedDiff = createTwoFilesPatch(
    `a/${input.fileName}`,
    `b/${input.fileName}`,
    input.sourceCode,
    remediatedCode,
    '',
    '',
    { context: 3 }
  );

  return {
    verdict: z3Verdict === 'sat' ? 'SAT_COMPLIANT' : 'UNSAT_VIOLATION',
    z3Status: z3Verdict,
    z3SolveTimeMs: solveMs,
    extractedContractRequirements: {
      requiredMaxHours,
      requiresTenantKms,
      forbidsPlaintextLog,
      deonticFormula: primary.compiled.deonticFormula,
      categories,
    },
    extractedCodeFacts: {
      detectedTtlHours,
      detectedTenantKms,
      detectedPlaintextLog,
      astFindingCount: analysis.astFindings.length,
    },
    violations: verification.proofs.flatMap((p) => p.opaRegoTriggeredDenials),
    remediatedCode,
    unifiedDiff,
    smtLib2Executed: verification.proofs.map((p) => p.smtLib2Executed).join('\n\n'),
  };
}
