import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { getInitialClauses } from './compiler/legalCompiler.js';
import {
  generateSarifReport,
  generateSignedConformityCertificate,
  verifyEd25519CertificateSignature,
} from './enterprise/enterpriseSuite.js';
import { currentWindowsAccount, getAttestationSigningKey } from './enterprise/signingKey.js';
import { merkleRoot } from './prover/z3Engine.js';
import { sha256Hex } from './util/hash.js';
import type { ClauseVerificationProof, FullComplianceScanReport } from '../shared/types.js';

const report = {
  repositoryName: 'demo',
  commitHash: 'abc123',
  merkleAuditRoot: 'root',
  totalClausesEvaluated: 0,
  compliantClausesCount: 0,
  violatedClausesCount: 0,
  overallComplianceScore: 100,
  z3EngineVersion: 'z3',
  proofs: [],
} as unknown as FullComplianceScanReport;

describe('attestation signing', () => {
  it('persists the Ed25519 key on disk with owner-only permissions', () => {
    const key = getAttestationSigningKey();
    const path = key.source.replace(/ \(created\)$/, '');
    expect(fs.existsSync(path)).toBe(true);
    if (process.platform === 'win32') {
      // Windows has no POSIX mode bits: the ACL must hold exactly one ACE, the owner's.
      const acl = execFileSync('icacls', [path], { encoding: 'utf8' });
      const aces = acl
        .slice(acl.indexOf(path) + path.length)
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => /^[^:]+:\(/.test(l));
      expect(aces).toEqual([`${currentWindowsAccount()}:(F)`]);
    } else {
      expect(fs.statSync(path).mode & 0o077).toBe(0);
    }
    expect(crypto.createPrivateKey(fs.readFileSync(path, 'utf8')).asymmetricKeyType).toBe('ed25519');
  });

  it('verifies its own signatures and detects tampering', () => {
    const cert = generateSignedConformityCertificate(report);
    expect(verifyEd25519CertificateSignature(cert.canonicalPayloadJson, cert.ed25519SignatureHex).verified).toBe(true);
    expect(
      verifyEd25519CertificateSignature(`${cert.canonicalPayloadJson} `, cert.ed25519SignatureHex).verified
    ).toBe(false);
  });

  it('rejects signatures made with a caller-supplied key', () => {
    const attacker = crypto.generateKeyPairSync('ed25519');
    const payload = '{"overallVerdict":"SAT_COMPLIANT_ATTESTED"}';
    const sig = crypto.sign(null, Buffer.from(payload), attacker.privateKey).toString('hex');
    const pem = attacker.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const result = verifyEd25519CertificateSignature(payload, sig, pem);
    expect(result.verified).toBe(false);
    expect(result.reason).toMatch(/UNTRUSTED KEY/);
  });
});

describe('Merkle root and SARIF', () => {
  it('builds a binary Merkle tree', () => {
    const [a, b, c] = ['a', 'b', 'c'].map(sha256Hex);
    expect(merkleRoot([a, b])).toBe(sha256Hex(a + b));
    expect(merkleRoot([a, b, c])).toBe(sha256Hex(sha256Hex(a + b) + sha256Hex(c + c)));
  });

  it('emits valid SARIF 2.1.0 property names and provenance only when known', () => {
    const proof = {
      clauseId: 'C1',
      severity: 'HIGH',
      status: 'UNSAT_VIOLATION',
      unsatCoreAssertions: ['x'],
      offendingLocations: [{ filePath: 'api/a.py', line: 3, endLine: 4, explanation: 'e', remediationPreview: 'r' }],
      cryptographicProvenance: { merkleProofHash: 'h' },
    } as unknown as ClauseVerificationProof;
    const sarif = generateSarifReport(getInitialClauses(), [proof], { commitHash: 'abc', branch: 'main' }, 'target-repo/') as {
      runs: Array<Record<string, unknown> & { tool: { driver: Record<string, unknown> }; results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }> }>;
    };
    const run = sarif.runs[0];
    expect(run.tool.driver.semanticVersion).toBeDefined();
    expect(run.tool.driver.SemanticVersion).toBeUndefined();
    expect(run.versionControlProvenance).toBeUndefined();
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('target-repo/api/a.py');
  });
});
