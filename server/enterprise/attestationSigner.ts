import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { getAttestationSigningKey } from './signingKey.js';

export type AttestationAlgorithm = 'Ed25519' | 'ECDSA_P256_SHA256';

/** A key that signs attestations. KMS-backed signers never expose private key material. */
export interface AttestationSigner {
  /** Stable identifier recorded in every certificate (fingerprint of the public key). */
  keyId: string;
  algorithm: AttestationAlgorithm;
  publicKeyPem: string;
  /** Human-readable backend, e.g. "Google Cloud KMS (HSM) projects/…/cryptoKeyVersions/1". */
  backend: string;
  sign(data: Buffer): Promise<Buffer>;
}

export const keyIdFor = (publicKeyPem: string) =>
  `lexc-${crypto.createHash('sha256').update(crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 24)}`;

/** Verifies a signature from any supported attestation algorithm. */
export function verifyAttestationSignature(algorithm: AttestationAlgorithm, publicKeyPem: string, data: Buffer, signature: Buffer): boolean {
  if (algorithm === 'Ed25519') return crypto.verify(null, data, publicKeyPem, signature);
  return crypto.verify('sha256', data, { key: publicKeyPem, dsaEncoding: 'der' }, signature);
}

export function localSigner(): AttestationSigner {
  const key = getAttestationSigningKey();
  return {
    keyId: keyIdFor(key.publicKeyPem),
    algorithm: 'Ed25519',
    publicKeyPem: key.publicKeyPem,
    backend: `local key file (${key.source})`,
    sign: async (data) => crypto.sign(null, data, key.privateKey),
  };
}

/** OAuth access token for Google APIs: LEXCOMPILER_GCP_ACCESS_TOKEN, else the metadata server. */
async function gcpAccessToken(fetchImpl: typeof fetch): Promise<string> {
  if (process.env.LEXCOMPILER_GCP_ACCESS_TOKEN) return process.env.LEXCOMPILER_GCP_ACCESS_TOKEN;
  const res = await fetchImpl('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', { headers: { 'Metadata-Flavor': 'Google' } });
  if (!res.ok) throw new Error(`GCP metadata token request failed (${res.status}); set LEXCOMPILER_GCP_ACCESS_TOKEN`);
  return ((await res.json()) as { access_token: string }).access_token;
}

/**
 * Google Cloud KMS asymmetric key version (EC_SIGN_ED25519 or EC_SIGN_P256_SHA256; protection
 * level SOFTWARE or HSM). Signing happens inside KMS through `:asymmetricSign`.
 */
export async function gcpKmsSigner(keyVersion: string, fetchImpl: typeof fetch = fetch): Promise<AttestationSigner> {
  const api = (process.env.LEXCOMPILER_GCP_KMS_ENDPOINT || 'https://cloudkms.googleapis.com').replace(/\/$/, '');
  const call = async (method: string, suffix: string, body?: unknown) => {
    const res = await fetchImpl(`${api}/v1/${keyVersion}${suffix}`, {
      method,
      headers: { Authorization: `Bearer ${await gcpAccessToken(fetchImpl)}`, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error(`Cloud KMS ${suffix || 'get'} failed (${res.status}): ${(await res.text()).slice(0, 200)}`);
    return (await res.json()) as Record<string, unknown>;
  };
  const pub = await call('GET', '/publicKey');
  const alg = String(pub.algorithm);
  const algorithm: AttestationAlgorithm = alg === 'EC_SIGN_ED25519' ? 'Ed25519' : alg === 'EC_SIGN_P256_SHA256' ? 'ECDSA_P256_SHA256' : (() => {
    throw new Error(`Unsupported Cloud KMS algorithm ${alg} (use EC_SIGN_ED25519 or EC_SIGN_P256_SHA256)`);
  })();
  const publicKeyPem = String(pub.pem);
  const level = pub.protectionLevel ? ` (${pub.protectionLevel})` : '';
  return {
    keyId: keyIdFor(publicKeyPem),
    algorithm,
    publicKeyPem,
    backend: `Google Cloud KMS${level} ${keyVersion}`,
    async sign(data) {
      const body = algorithm === 'Ed25519' ? { data: data.toString('base64') } : { digest: { sha256: crypto.createHash('sha256').update(data).digest('base64') } };
      const out = await call('POST', ':asymmetricSign', body);
      return Buffer.from(String(out.signature), 'base64');
    },
  };
}

/** Minimal surface of the AWS SDK KMS client (lets tests substitute a fake). */
export interface KmsClientLike {
  send(command: unknown): Promise<Record<string, unknown>>;
}

/** AWS KMS asymmetric key (key spec ECC_NIST_P256, usage SIGN_VERIFY; keys live in KMS HSMs). */
export async function awsKmsSigner(keyId: string, client?: KmsClientLike): Promise<AttestationSigner> {
  const sdk = await import('@aws-sdk/client-kms');
  const kms: KmsClientLike = client || (new sdk.KMSClient({}) as unknown as KmsClientLike);
  const pub = await kms.send(new sdk.GetPublicKeyCommand({ KeyId: keyId }));
  if (pub.KeySpec !== 'ECC_NIST_P256') throw new Error(`Unsupported AWS KMS key spec ${String(pub.KeySpec)} (use ECC_NIST_P256)`);
  const publicKeyPem = crypto.createPublicKey({ key: Buffer.from(pub.PublicKey as Uint8Array), format: 'der', type: 'spki' }).export({ type: 'spki', format: 'pem' }).toString();
  return {
    keyId: keyIdFor(publicKeyPem),
    algorithm: 'ECDSA_P256_SHA256',
    publicKeyPem,
    backend: `AWS KMS ${String(pub.KeyId || keyId)}`,
    async sign(data) {
      const out = await kms.send(new sdk.SignCommand({ KeyId: keyId, Message: data, MessageType: 'RAW', SigningAlgorithm: 'ECDSA_SHA_256' }));
      return Buffer.from(out.Signature as Uint8Array);
    },
  };
}

let signer: Promise<AttestationSigner> | null = null;

/** LEXCOMPILER_SIGNER = local (default) | gcp-kms | aws-kms. */
export function getAttestationSigner(): Promise<AttestationSigner> {
  signer ??= (async () => {
    const kind = process.env.LEXCOMPILER_SIGNER || 'local';
    const s =
      kind === 'gcp-kms'
        ? await gcpKmsSigner(required('LEXCOMPILER_GCP_KMS_KEY_VERSION'))
        : kind === 'aws-kms'
          ? await awsKmsSigner(required('LEXCOMPILER_AWS_KMS_KEY_ID'))
          : localSigner();
    registerTrustedKey(s);
    return s;
  })();
  signer.catch(() => (signer = null));
  return signer;
}

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required for LEXCOMPILER_SIGNER=${process.env.LEXCOMPILER_SIGNER}`);
  return v;
}

// --- Trusted keys (rotation) and revocation, persisted in the data directory.

export interface TrustedKey {
  keyId: string;
  algorithm: AttestationAlgorithm;
  publicKeyPem: string;
  backend: string;
  firstUsedAt: string;
}

export interface RevocationList {
  certificates: Array<{ certificateId: string; reason: string; revokedAt: string }>;
  keys: Array<{ keyId: string; reason: string; revokedAt: string }>;
}

const dataDir = () => path.resolve(process.env.LEXCOMPILER_DATA_DIR || path.join(process.cwd(), 'data'));
const readJson = <T>(file: string, fallback: T): T => {
  try {
    return JSON.parse(fs.readFileSync(path.join(dataDir(), file), 'utf8')) as T;
  } catch {
    return fallback;
  }
};
const writeJson = (file: string, data: unknown) => {
  fs.mkdirSync(dataDir(), { recursive: true });
  const target = path.join(dataDir(), file);
  fs.writeFileSync(`${target}.tmp`, JSON.stringify(data, null, 2));
  fs.renameSync(`${target}.tmp`, target);
};

export const trustedKeys = () => readJson<TrustedKey[]>('attestation-keys.json', []);

/** Every key that has signed stays trusted for verification after rotation (unless revoked). */
export function registerTrustedKey(s: AttestationSigner): void {
  const keys = trustedKeys();
  if (keys.some((k) => k.keyId === s.keyId)) return;
  writeJson('attestation-keys.json', [...keys, { keyId: s.keyId, algorithm: s.algorithm, publicKeyPem: s.publicKeyPem, backend: s.backend, firstUsedAt: new Date().toISOString() }]);
}

export const revocations = () => readJson<RevocationList>('revocations.json', { certificates: [], keys: [] });

export function revoke(entry: { certificateId?: string; keyId?: string; reason?: string }): RevocationList {
  const list = revocations();
  const revokedAt = new Date().toISOString();
  const reason = (entry.reason || 'unspecified').slice(0, 200);
  if (entry.certificateId && !list.certificates.some((c) => c.certificateId === entry.certificateId)) list.certificates.push({ certificateId: entry.certificateId, reason, revokedAt });
  if (entry.keyId && !list.keys.some((k) => k.keyId === entry.keyId)) list.keys.push({ keyId: entry.keyId, reason, revokedAt });
  if (!entry.certificateId && !entry.keyId) throw new Error('certificateId or keyId is required');
  writeJson('revocations.json', list);
  return list;
}
