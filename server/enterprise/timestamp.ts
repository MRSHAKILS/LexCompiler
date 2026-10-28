import crypto from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

pkijs.setEngine('node', new pkijs.CryptoEngine({ name: 'node', crypto: crypto.webcrypto as unknown as Crypto }));

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const TST_INFO_OID = '1.2.840.113549.1.9.16.1.4';

const toArrayBuffer = (b: Buffer) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

export interface TimestampToken {
  /** DER of the RFC 3161 TimeStampToken (CMS ContentInfo), base64. */
  tokenBase64: string;
  tsaUrl: string;
  genTime: string;
  serialNumber: string;
  policy: string;
}

/** Builds the DER TimeStampReq for SHA-256(data), with a nonce and certReq. */
export function buildTimestampRequest(data: Buffer, nonce = crypto.randomBytes(8)): ArrayBuffer {
  const req = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: SHA256_OID }),
      hashedMessage: new asn1js.OctetString({ valueHex: toArrayBuffer(crypto.createHash('sha256').update(data).digest()) }),
    }),
    nonce: new asn1js.Integer({ valueHex: toArrayBuffer(nonce) }),
    certReq: true,
  });
  return req.toSchema().toBER(false);
}

function tstInfoOf(signed: pkijs.SignedData): pkijs.TSTInfo {
  if (signed.encapContentInfo.eContentType !== TST_INFO_OID || !signed.encapContentInfo.eContent) throw new Error('not a timestamp token');
  return pkijs.TSTInfo.fromBER(signed.encapContentInfo.eContent.getValue());
}

/** Requests an RFC 3161 timestamp for `data` from a Time-Stamp Authority. */
export async function requestTimestamp(data: Buffer, tsaUrl: string, fetchImpl: typeof fetch = fetch): Promise<TimestampToken> {
  const res = await fetchImpl(tsaUrl, { method: 'POST', headers: { 'Content-Type': 'application/timestamp-query' }, body: Buffer.from(buildTimestampRequest(data)) });
  if (!res.ok) throw new Error(`TSA ${tsaUrl} returned ${res.status}`);
  const resp = pkijs.TimeStampResp.fromBER(await res.arrayBuffer());
  const status = resp.status.status;
  if (status !== 0 && status !== 1) throw new Error(`TSA rejected the request (PKIStatus ${status})`);
  if (!resp.timeStampToken) throw new Error('TSA response has no token');
  const token = Buffer.from(resp.timeStampToken.toSchema().toBER(false));
  const info = tstInfoOf(new pkijs.SignedData({ schema: resp.timeStampToken.content }));
  return {
    tokenBase64: token.toString('base64'),
    tsaUrl,
    genTime: info.genTime.toISOString(),
    serialNumber: Buffer.from(info.serialNumber.valueBlock.valueHexView).toString('hex'),
    policy: info.policy,
  };
}

/**
 * Verifies a timestamp token over `data`: the message imprint must be SHA-256(data) and the
 * CMS signature must verify with the certificate in the token (and chain to `trustedCerts`
 * when given).
 */
export async function verifyTimestamp(
  tokenBase64: string,
  data: Buffer,
  trustedCerts: pkijs.Certificate[] = []
): Promise<{ valid: boolean; genTime?: string; reason: string }> {
  try {
    const contentInfo = pkijs.ContentInfo.fromBER(toArrayBuffer(Buffer.from(tokenBase64, 'base64')));
    const signed = new pkijs.SignedData({ schema: contentInfo.content });
    const info = tstInfoOf(signed);
    const imprint = Buffer.from(info.messageImprint.hashedMessage.valueBlock.valueHexView);
    if (info.messageImprint.hashAlgorithm.algorithmId !== SHA256_OID || !imprint.equals(crypto.createHash('sha256').update(data).digest())) {
      return { valid: false, genTime: info.genTime.toISOString(), reason: 'The timestamp covers different data.' };
    }
    // asn1js decodes an OCTET STRING holding DER as nested ASN.1 and leaves valueHexView empty,
    // which pkijs reads; re-wrap the TSTInfo bytes as a primitive OCTET STRING first.
    signed.encapContentInfo.eContent = new asn1js.OctetString({ valueHex: signed.encapContentInfo.eContent!.getValue() });
    const result = await signed.verify({ signer: 0, data: toArrayBuffer(data), checkChain: trustedCerts.length > 0, trustedCerts, extendedMode: true });
    const ok = typeof result === 'boolean' ? result : result.signatureVerified === true;
    return { valid: ok, genTime: info.genTime.toISOString(), reason: ok ? 'Timestamp signature and message imprint verify.' : 'The TSA signature does not verify.' };
  } catch (err) {
    return { valid: false, reason: `Malformed or unverifiable timestamp: ${(err as Error).message}` };
  }
}
