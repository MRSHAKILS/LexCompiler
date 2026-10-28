import React, { useEffect, useState } from 'react';
import {
  AlertOctagon,
  Award,
  Building2,
  CheckCircle2,
  DollarSign,
  FileCheck2,
  FileCode2,
  KeyRound,
  Lock,
  Play,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  TrendingUp,
} from 'lucide-react';
import type { FullComplianceScanReport } from '../../shared/types';

interface EnterpriseStartupSuiteProps {
  report: FullComplianceScanReport;
}

export const EnterpriseStartupSuite: React.FC<EnterpriseStartupSuiteProps> = ({ report }) => {
  // 1. BYOC (Bring Your Own Code & Contract) State
  const [byocClause, setByocClause] = useState(
    'Section 7.1 (Global Fintech & Healthcare MSA): All customer payment tokens and PII must be encrypted at rest with tenant-isolated KMS keys, strictly prohibited from plaintext logging, and purged within 48 hours.'
  );
  const [byocCitation, setByocCitation] = useState('Custom Enterprise MSA §7.1 / PCI-DSS 4.0');
  const [byocCode, setByocCode] = useState(`# Custom Enterprise Payment & PII Service (Paste any code to test)
import logging
logger = logging.getLogger("enterprise.payments")

TENANT_ISOLATED_KMS = False
RETENTION_HOURS = 360

def process_customer_payment(ssn: str, email: str, card_token: str):
    logger.info(f"Processing payment for ssn={ssn} email={email}")
    encrypted = encrypt_shared_aes256(ssn)
    return {"encrypted": encrypted, "ttl_hours": RETENTION_HOURS}
`);
  const [byocResult, setByocResult] = useState<any | null>(null);
  const [isScanningByoc, setIsScanningByoc] = useState(false);

  // 2. Ed25519 Signed Conformity Certificate State
  const [certificate, setCertificate] = useState<any | null>(null);
  const [verifyStatus, setVerifyStatus] = useState<{
    verified: boolean;
    reason: string;
    payloadSha256: string;
  } | null>(null);

  // 3. SARIF v2.1.0 Preview State
  const [sarifJson, setSarifJson] = useState<any | null>(null);

  // 4. Executive Fine Exposure ROI Calculator State
  const [annualRevenueMusd, setAnnualRevenueMusd] = useState<number>(250);

  const runByocScan = async (overrideCode?: string) => {
    setIsScanningByoc(true);
    try {
      const codeToScan = overrideCode ?? byocCode;
      if (overrideCode) setByocCode(overrideCode);
      const res = await fetch('/api/enterprise/byoc-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contractClauseText: byocClause,
          citationLabel: byocCitation,
          language: 'python',
          fileName: 'custom_payment_service.py',
          sourceCode: codeToScan,
        }),
      });
      if (res.ok) {
        setByocResult(await res.json());
      }
    } finally {
      setIsScanningByoc(false);
    }
  };

  const fetchEnterpriseArtifacts = async () => {
    const [certRes, sarifRes] = await Promise.all([
      fetch('/api/enterprise/certificate'),
      fetch('/api/enterprise/sarif'),
    ]);
    if (certRes.ok) {
      const certData = await certRes.json();
      setCertificate(certData);
      setVerifyStatus(null);
    }
    if (sarifRes.ok) {
      setSarifJson(await sarifRes.json());
    }
  };

  useEffect(() => {
    fetchEnterpriseArtifacts();
    runByocScan();
  }, [report.commitHash, report.violatedClausesCount]);

  const handleVerifySignature = async (tamperWithPayload: boolean) => {
    if (!certificate) return;
    const payloadToVerify = tamperWithPayload
      ? certificate.canonicalPayloadJson.replace(
          '"UNSAT_VIOLATION"',
          '"SAT_COMPLIANT"'
        ) + ' /* TAMPERED */'
      : certificate.canonicalPayloadJson;

    const res = await fetch('/api/enterprise/verify-signature', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        canonicalPayloadJson: payloadToVerify,
        signatureHex: certificate.ed25519SignatureHex,
        publicKeyPem: certificate.publicKeyPem,
      }),
    });
    if (res.ok) {
      setVerifyStatus(await res.json());
    }
  };

  // Calculate statutory maximum fine exposure based on active violations & annual revenue
  const gdprMaxFineMusd = Math.max(22, Math.round(annualRevenueMusd * 0.04 * 10) / 10);
  const euAiActMaxFineMusd = Math.max(38, Math.round(annualRevenueMusd * 0.07 * 10) / 10);
  const hipaaMaxFineMusd = 2.13;
  const totalStatutoryExposureMusd =
    report.violatedClausesCount > 0
      ? Math.round((gdprMaxFineMusd + euAiActMaxFineMusd + hipaaMaxFineMusd) * 10) / 10
      : 0;

  return (
    <div className="p-6 space-y-6 w-full">
      {/* Executive Commercial Value Banner */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-indigo-950/80 via-[#0C1220] to-emerald-950/50 border border-indigo-500/40 flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1.5 max-w-3xl">
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
              SERIES-A ENTERPRISE SAAS · CISO & GENERAL COUNSEL CONTROL PLANE
            </span>
            <span className="text-xs font-mono text-emerald-300">
              Ed25519 Attested · SARIF v2.1.0 · BYOC Universal Scanner
            </span>
          </div>
          <h2 className="text-lg font-bold text-white">
            Enterprise Cloud, Universal BYOC Scanner & Cryptographic Conformity Suite
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            Demonstrate LexCompiler to international CISOs, General Counsels, and VCs: scan any
            custom contract &amp; source code live, verify RFC 8032 Ed25519 cryptographic audit
            certificates, export OASIS SARIF v2.1.0 to GitHub Security, and quantify statutory fine
            exposure in real time.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-[#070A10]/90 border border-slate-800 text-right font-mono">
            <div className="text-[10px] uppercase text-slate-400">
              Active Statutory Fine Exposure
            </div>
            <div
              className={`text-xl font-bold ${
                totalStatutoryExposureMusd > 0 ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              ${totalStatutoryExposureMusd.toFixed(1)}M USD
            </div>
            <div className="text-[10px] text-slate-400">
              {totalStatutoryExposureMusd > 0
                ? 'Eliminated upon merging Auto-PR #409'
                : '0 Violations — $0.0M Fine Exposure'}
            </div>
          </div>
        </div>
      </div>

      {/* SECTION 1: Universal "Bring Your Own Code & Contract" (BYOC) Live Scanner */}
      <div className="p-5 rounded-2xl bg-[#0B101B] border border-indigo-500/40 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              1. Universal "Bring Your Own Code &amp; Contract" (BYOC) Live Z3 Studio
            </h3>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Paste any custom enterprise contract clause and any custom Python/TS/SQL code during
              a live industry demo to compile &amp; verify on the fly.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {byocResult && byocResult.verdict === 'UNSAT_VIOLATION' && (
              <button
                type="button"
                onClick={() => runByocScan(byocResult.remediatedCode)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-emerald-600 hover:bg-emerald-500 text-white cursor-pointer"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                Apply Synthesized Fix to Custom Code &amp; Re-Verify SAT
              </button>
            )}
            <button
              type="button"
              disabled={isScanningByoc}
              onClick={() => runByocScan()}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-mono font-bold bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" />
              {isScanningByoc ? 'Solving in Z3...' : 'Run Live BYOC Z3 Verification'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Custom Contract + Custom Code Inputs */}
          <div className="lg:col-span-6 space-y-3">
            <div>
              <label className="block text-[11px] font-mono text-amber-300 mb-1">
                Custom Contractual / Regulatory Clause (Edit hours, KMS rules, logging bans):
              </label>
              <textarea
                value={byocClause}
                onChange={(e) => setByocClause(e.target.value)}
                rows={3}
                className="w-full rounded-lg bg-[#06090F] border border-slate-700 p-2.5 text-xs font-legal text-slate-100"
              />
            </div>

            <div>
              <label className="block text-[11px] font-mono text-indigo-300 mb-1">
                Custom Application Source Code (`custom_payment_service.py`):
              </label>
              <textarea
                value={byocCode}
                onChange={(e) => setByocCode(e.target.value)}
                rows={9}
                className="w-full rounded-lg bg-[#06090F] border border-slate-700 p-2.5 text-xs font-mono text-slate-100 leading-relaxed"
              />
            </div>
          </div>

          {/* Live BYOC Z3 Verdict & Auto-Synthesized Diff */}
          <div className="lg:col-span-6 space-y-3">
            {byocResult && (
              <>
                <div
                  className={`p-3 rounded-xl border flex items-center justify-between ${
                    byocResult.verdict === 'SAT_COMPLIANT'
                      ? 'bg-emerald-950/35 border-emerald-500/50'
                      : 'bg-rose-950/40 border-rose-500/50'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    {byocResult.verdict === 'SAT_COMPLIANT' ? (
                      <ShieldCheck className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <ShieldAlert className="w-5 h-5 text-rose-400" />
                    )}
                    <div>
                      <div className="text-xs font-mono font-bold text-white">
                        BYOC Z3 Verdict: {byocResult.verdict} ({byocResult.z3SolveTimeMs} ms)
                      </div>
                      <div className="text-[11px] font-mono text-slate-300">
                        Required TTL ≤ {byocResult.extractedContractRequirements.requiredMaxHours}h
                        · Detected Code TTL: {byocResult.extractedCodeFacts.detectedTtlHours}h ·
                        Tenant KMS: {String(byocResult.extractedCodeFacts.detectedTenantKms)}
                      </div>
                    </div>
                  </div>
                </div>

                {byocResult.violations.length > 0 && (
                  <div className="p-2.5 rounded-lg bg-rose-950/30 border border-rose-500/30 space-y-1 text-[11px] font-mono text-rose-200">
                    {byocResult.violations.map((v: string, idx: number) => (
                      <div key={idx}>• {v}</div>
                    ))}
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  <div>
                    <div className="text-[10px] font-mono uppercase text-slate-400 mb-1">
                      Compiled SMT-LIB2 Formula:
                    </div>
                    <pre className="p-2.5 rounded-lg bg-[#05070B] border border-slate-800 text-[10.5px] font-mono text-indigo-200 overflow-x-auto max-h-48">
                      {byocResult.smtLib2Executed}
                    </pre>
                  </div>
                  <div>
                    <div className="text-[10px] font-mono uppercase text-slate-400 mb-1">
                      Auto-Synthesized Remediation Diff:
                    </div>
                    <pre className="p-2.5 rounded-lg bg-[#05070B] border border-slate-800 text-[10.5px] font-mono text-emerald-200 overflow-x-auto max-h-48">
                      {byocResult.unifiedDiff}
                    </pre>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* SECTION 2: Ed25519 Cryptographic Conformity Certificate + Executive ROI Calculator */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Ed25519 Signed Certificate & Tamper Verifier */}
        <div className="lg:col-span-7 p-5 rounded-2xl bg-[#0B101B] border border-slate-800 space-y-3.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-emerald-400" />
                2. RFC 8032 Ed25519 Cryptographically Signed Conformity Certificate
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Verifiable by external Big-4 auditors, regulators, and enterprise procurement teams
              </p>
            </div>

            {certificate && (
              <span className="px-2.5 py-1 rounded text-[10.5px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                {certificate.certificateId}
              </span>
            )}
          </div>

          {certificate && (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-[11px] font-mono">
                <div className="p-2.5 rounded bg-[#06090F] border border-slate-800">
                  <div className="text-slate-400">Standard &amp; Authority</div>
                  <div className="text-slate-100 font-semibold truncate">
                    {certificate.standard}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-[#06090F] border border-slate-800">
                  <div className="text-slate-400">Ed25519 Public Key Fingerprint</div>
                  <div className="text-emerald-300 font-semibold truncate">
                    {certificate.publicKeyFingerprintSha256}
                  </div>
                </div>
              </div>

              <div>
                <div className="text-[10px] font-mono uppercase text-slate-400 mb-1">
                  Ed25519 Digital Signature (Hex):
                </div>
                <div className="p-2 rounded bg-[#05070B] border border-slate-800 text-[10.5px] font-mono text-amber-300 break-all">
                  {certificate.ed25519SignatureHex}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => handleVerifySignature(false)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-emerald-600 hover:bg-emerald-500 text-white cursor-pointer"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Verify Ed25519 Signature (Authentic)
                </button>
                <button
                  type="button"
                  onClick={() => handleVerifySignature(true)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-rose-600/90 hover:bg-rose-500 text-white cursor-pointer"
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Simulate Audit Log Tampering (Test Rejection)
                </button>
              </div>

              {verifyStatus && (
                <div
                  className={`p-3 rounded-lg border font-mono text-xs ${
                    verifyStatus.verified
                      ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-200'
                      : 'bg-rose-950/45 border-rose-500/60 text-rose-200'
                  }`}
                >
                  <div className="font-bold">{verifyStatus.reason}</div>
                  <div className="text-[10.5px] opacity-80 mt-0.5">
                    Payload SHA-256: {verifyStatus.payloadSha256}
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Executive Statutory Fine Exposure & Deal-Velocity ROI Simulator */}
        <div className="lg:col-span-5 p-5 rounded-2xl bg-[#0B101B] border border-slate-800 space-y-4">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-amber-400" />
              3. CFO / General Counsel Regulatory Fine Exposure &amp; ROI Engine
            </h3>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Quantifies statutory fine liability &amp; enterprise sales-cycle acceleration
            </p>
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-slate-300">Enterprise Global Annual Turnover:</span>
              <span className="text-amber-300 font-bold">${annualRevenueMusd}M USD</span>
            </div>
            <input
              type="range"
              min={50}
              max={2000}
              step={50}
              value={annualRevenueMusd}
              onChange={(e) => setAnnualRevenueMusd(parseInt(e.target.value, 10))}
              className="w-full accent-indigo-500 cursor-pointer"
            />
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="p-2.5 rounded bg-[#06090F] border border-slate-800 flex justify-between">
              <span className="text-slate-300">EU AI Act Art. 99 Max Penalty (7%):</span>
              <span className="text-rose-300 font-bold">${euAiActMaxFineMusd}M USD</span>
            </div>
            <div className="p-2.5 rounded bg-[#06090F] border border-slate-800 flex justify-between">
              <span className="text-slate-300">GDPR Art. 83(5) Max Penalty (4%):</span>
              <span className="text-rose-300 font-bold">${gdprMaxFineMusd}M USD</span>
            </div>
            <div className="p-2.5 rounded bg-[#06090F] border border-slate-800 flex justify-between">
              <span className="text-slate-300">HIPAA 45 CFR §160.404 Tier 4 Cap:</span>
              <span className="text-rose-300 font-bold">${hipaaMaxFineMusd}M USD</span>
            </div>
            <div className="p-2.5 rounded bg-emerald-950/30 border border-emerald-500/30 flex justify-between">
              <span className="text-emerald-200">B2B DPA Security Review Time:</span>
              <span className="text-emerald-300 font-bold">16 Weeks → 0.2 Seconds</span>
            </div>
          </div>

          {/* SARIF v2.1.0 Preview */}
          {sarifJson && (
            <div className="pt-1">
              <div className="text-[10px] font-mono uppercase text-indigo-300 mb-1">
                4. Live OASIS SARIF v2.1.0 Report (`.github/workflows/lexcompiler-gate.yml`):
              </div>
              <pre className="p-2.5 rounded bg-[#05070B] border border-slate-800 text-[10px] font-mono text-slate-300 overflow-x-auto max-h-36">
                {JSON.stringify(sarifJson, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
