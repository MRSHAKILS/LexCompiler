import crypto from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { describe, expect, it } from 'vitest';
import { awsKmsSigner, gcpKmsSigner, registerTrustedKey, revoke, verifyAttestationSignature, type KmsClientLike } from './enterprise/attestationSigner.js';
import { verifyEd25519CertificateSignature } from './enterprise/enterpriseSuite.js';
import { buildTimestampRequest, requestTimestamp, verifyTimestamp } from './enterprise/timestamp.js';

const toAB = (b: Buffer) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

describe('KMS-backed attestation signers', () => {
  it('Google Cloud KMS: signs through :asymmetricSign (Ed25519 and P-256)', async () => {
    for (const [alg, type] of [['EC_SIGN_ED25519', 'ed25519'], ['EC_SIGN_P256_SHA256', 'ec']] as const) {
      const pair = type === 'ed25519' ? crypto.generateKeyPairSync('ed25519') : crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const calls: Array<{ url: string; body?: Record<string, unknown> }> = [];
      const signing = Buffer.from('{"verdict":"SAT"}');
      const fakeKms = (async (url: string, init?: RequestInit) => {
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        calls.push({ url, body });
        if (url.endsWith('/publicKey')) return new Response(JSON.stringify({ pem: pair.publicKey.export({ type: 'spki', format: 'pem' }), algorithm: alg, protectionLevel: 'HSM' }));
        // KMS signs the raw data (Ed25519) or the supplied SHA-256 digest (ECDSA). Node cannot sign a
        // pre-hashed digest, so the fake checks the digest and signs the data it was computed from.
        if (type !== 'ed25519') expect(body.digest.sha256).toBe(crypto.createHash('sha256').update(signing).digest('base64'));
        const sig = type === 'ed25519' ? crypto.sign(null, Buffer.from(body.data, 'base64'), pair.privateKey) : crypto.sign('sha256', signing, { key: pair.privateKey, dsaEncoding: 'der' });
        return new Response(JSON.stringify({ signature: sig.toString('base64') }));
      }) as typeof fetch;
      process.env.LEXCOMPILER_GCP_ACCESS_TOKEN = 'test-token';
      const signer = await gcpKmsSigner('projects/p/locations/eu/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1', fakeKms);
      expect(signer.backend).toContain('(HSM)');
      const data = signing;
      const sig = await signer.sign(data);
      expect(verifyAttestationSignature(signer.algorithm, signer.publicKeyPem, data, sig)).toBe(true);
      expect(verifyAttestationSignature(signer.algorithm, signer.publicKeyPem, Buffer.from('tampered'), sig)).toBe(false);
      expect(calls.at(-1)!.url).toMatch(/cryptoKeyVersions\/1:asymmetricSign$/);
    }
  });

  it('AWS KMS: signs with ECDSA_SHA_256 and never sees a private key', async () => {
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const client: KmsClientLike = {
      async send(cmd: unknown) {
        const c = cmd as { constructor: { name: string }; input: Record<string, unknown> };
        if (c.constructor.name === 'GetPublicKeyCommand') return { KeySpec: 'ECC_NIST_P256', KeyId: 'arn:aws:kms:eu-central-1:1:key/abc', PublicKey: pair.publicKey.export({ type: 'spki', format: 'der' }) };
        expect(c.input).toMatchObject({ MessageType: 'RAW', SigningAlgorithm: 'ECDSA_SHA_256' });
        return { Signature: crypto.sign('sha256', Buffer.from(c.input.Message as Uint8Array), { key: pair.privateKey, dsaEncoding: 'der' }) };
      },
    };
    const signer = await awsKmsSigner('alias/lexcompiler', client);
    const data = Buffer.from('payload');
    expect(verifyAttestationSignature('ECDSA_P256_SHA256', signer.publicKeyPem, data, await signer.sign(data))).toBe(true);
  });

  it('keeps rotated keys trusted and honours revocation', async () => {
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const client: KmsClientLike = {
      async send(cmd: unknown) {
        const c = cmd as { constructor: { name: string }; input: Record<string, unknown> };
        if (c.constructor.name === 'GetPublicKeyCommand') return { KeySpec: 'ECC_NIST_P256', PublicKey: pair.publicKey.export({ type: 'spki', format: 'der' }) };
        return { Signature: crypto.sign('sha256', Buffer.from(c.input.Message as Uint8Array), { key: pair.privateKey, dsaEncoding: 'der' }) };
      },
    };
    const rotated = await awsKmsSigner('old-key', client);
    registerTrustedKey(rotated);
    const payload = '{"overallVerdict":"SAT_COMPLIANT_ATTESTED","n":1}';
    const sig = (await rotated.sign(Buffer.from(payload))).toString('hex');
    expect(verifyEd25519CertificateSignature(payload, sig, undefined, { keyId: rotated.keyId })).toMatchObject({ verified: true, keyId: rotated.keyId });
    revoke({ certificateId: 'CERT-1', reason: 'superseded' });
    expect(verifyEd25519CertificateSignature(payload, sig, undefined, { certificateId: 'CERT-1' }).reason).toMatch(/REVOKED: certificate/);
    revoke({ keyId: rotated.keyId, reason: 'key compromise' });
    expect(verifyEd25519CertificateSignature(payload, sig).reason).toMatch(/REVOKED: signing key/);
  });
});

/** Fake Time-Stamp Authority: a self-signed RSA certificate that signs TSTInfo in CMS. */
async function fakeTsa() {
  const subtle = crypto.webcrypto.subtle;
  const keys = (await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 1 });
  const cn = new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value: 'Test TSA' }) });
  cert.issuer.typesAndValues.push(cn);
  cert.subject.typesAndValues.push(cn);
  cert.notBefore.value = new Date(Date.now() - 60_000);
  cert.notAfter.value = new Date(Date.now() + 86_400_000);
  await cert.subjectPublicKeyInfo.importKey(keys.publicKey);
  await cert.sign(keys.privateKey, 'SHA-256');
  return async (url: string, init?: RequestInit) => {
    const body = init!.body as Buffer;
    const req = pkijs.TimeStampReq.fromBER(toAB(Buffer.from(body)));
    const tst = new pkijs.TSTInfo({
      version: 1,
      policy: '1.2.3.4.1',
      messageImprint: req.messageImprint,
      serialNumber: new asn1js.Integer({ value: 42 }),
      genTime: new Date(),
      nonce: req.nonce,
    });
    const content = tst.toSchema().toBER(false);
    const signed = new pkijs.SignedData({
      version: 3,
      encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: '1.2.840.113549.1.9.16.1.4', eContent: new asn1js.OctetString({ valueHex: content }) }),
      signerInfos: [
        new pkijs.SignerInfo({
          version: 1,
          sid: new pkijs.IssuerAndSerialNumber({ issuer: cert.issuer, serialNumber: cert.serialNumber }),
          // CMS requires signed attributes when the content is not id-data.
          signedAttrs: new pkijs.SignedAndUnsignedAttributes({
            type: 0,
            attributes: [
              new pkijs.Attribute({ type: '1.2.840.113549.1.9.3', values: [new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.9.16.1.4' })] }),
              new pkijs.Attribute({ type: '1.2.840.113549.1.9.4', values: [new asn1js.OctetString({ valueHex: toAB(crypto.createHash('sha256').update(Buffer.from(content)).digest()) })] }),
            ],
          }),
        }),
      ],
      certificates: [cert],
    });
    await signed.sign(keys.privateKey, 0, 'SHA-256');
    const resp = new pkijs.TimeStampResp({
      status: new pkijs.PKIStatusInfo({ status: 0 }),
      timeStampToken: new pkijs.ContentInfo({ contentType: '1.2.840.113549.1.7.2', content: signed.toSchema(true) }),
    });
    void url;
    return new Response(Buffer.from(resp.toSchema().toBER(false)));
  };
}

describe('RFC 3161 timestamps', () => {
  it('builds a SHA-256 request with a nonce', () => {
    const req = pkijs.TimeStampReq.fromBER(buildTimestampRequest(Buffer.from('x')));
    expect(req.messageImprint.hashAlgorithm.algorithmId).toBe('2.16.840.1.101.3.4.2.1');
    expect(req.certReq).toBe(true);
    expect(req.nonce).toBeDefined();
  });

  it('obtains and verifies a token, and rejects it for other data', async () => {
    const tsa = (await fakeTsa()) as unknown as typeof fetch;
    const signature = Buffer.from('attestation-signature');
    const token = await requestTimestamp(signature, 'https://tsa.test', tsa);
    expect(token.serialNumber).toBe('2a');
    expect(await verifyTimestamp(token.tokenBase64, signature)).toEqual(expect.objectContaining({ valid: true }));
    expect((await verifyTimestamp(token.tokenBase64, Buffer.from('other'))).reason).toMatch(/different data/);
    const tampered = Buffer.from(token.tokenBase64, 'base64');
    tampered[tampered.length - 5] ^= 0xff;
    expect((await verifyTimestamp(tampered.toString('base64'), signature)).valid).toBe(false);
  });
});
