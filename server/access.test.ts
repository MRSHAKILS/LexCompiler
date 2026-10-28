import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { INITIAL_REPO_FILES } from './analyzer/repoBaseline.js';
import { OidcProvider } from './auth/oidc.js';
import { ProjectStore } from './projects/projectStore.js';
import { createAccessRouter, createAuthenticator } from './projects/router.js';
import { createApiGuard, resolveServerSecurityConfig } from './security.js';

/** Minimal OpenID provider: discovery, JWKS, and a token endpoint that enforces PKCE. */
async function startIdp() {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  const codes = new Map<string, { challenge: string; nonce: string; sub: string; roles: string[] }>();
  const server = http.createServer((req, res) => {
    const url = new URL(req.url!, issuer);
    const json = (code: number, body: unknown) => {
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === '/.well-known/openid-configuration') {
      return json(200, { issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` });
    }
    if (url.pathname === '/jwks') return json(200, { keys: [jwk] });
    if (url.pathname === '/token' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', async () => {
        const form = new URLSearchParams(body);
        const grant = codes.get(form.get('code') || '');
        const verifier = form.get('code_verifier') || '';
        if (!grant || crypto.createHash('sha256').update(verifier).digest('base64url') !== grant.challenge) return json(400, { error: 'invalid_grant' });
        codes.delete(form.get('code')!);
        json(200, { id_token: await token(grant.sub, grant.roles, { aud: 'lexcompiler', nonce: grant.nonce }), token_type: 'Bearer' });
      });
      return;
    }
    json(404, {});
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const token = (sub: string, roles: string[] = [], extra: Record<string, unknown> = {}, key = privateKey) =>
    new SignJWT({ roles, email: `${sub}@example.test`, ...extra })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuer(issuer)
      .setSubject(sub)
      .setAudience((extra.aud as string) || 'lexcompiler')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(key);
  return { issuer, server, token, codes, otherKey: (await generateKeyPair('RS256')).privateKey };
}

let idp: Awaited<ReturnType<typeof startIdp>>;
let api: http.Server;
let base: string;
let oidc: OidcProvider;
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lexc-access-'));
const reposRoot = path.join(dataDir, 'repos');

beforeAll(async () => {
  idp = await startIdp();
  const env = { LEXCOMPILER_OIDC_ISSUER: idp.issuer, LEXCOMPILER_OIDC_CLIENT_ID: 'lexcompiler', LEXCOMPILER_DEFAULT_PROJECT_ROLE: 'viewer' };
  const config = resolveServerSecurityConfig(env);
  oidc = new OidcProvider({ issuer: idp.issuer, clientId: 'lexcompiler', redirectUri: 'http://127.0.0.1/api/auth/callback', audience: ['lexcompiler'], rolesClaim: 'roles', adminRole: 'lexcompiler-admin', scopes: 'openid', secureCookies: false });
  // A project repository: a copy of the fixture's API module.
  fs.mkdirSync(path.join(reposRoot, 'clinic', 'api'), { recursive: true });
  fs.writeFileSync(path.join(reposRoot, 'clinic', 'api', 'intake.py'), INITIAL_REPO_FILES['api/fastapi_intake.py'].content);
  const app = express();
  app.use(express.json());
  app.use('/api', createApiGuard(config, createAuthenticator(oidc, null)));
  app.use('/api', createAccessRouter(new ProjectStore(dataDir, reposRoot), oidc));
  app.get('/api/state', (_req, res) => res.json({ ok: true }));
  app.post('/api/clauses/compile', (_req, res) => res.json({ ok: true }));
  api = app.listen(0, '127.0.0.1');
  await new Promise((r) => api.once('listening', r));
  base = `http://127.0.0.1:${(api.address() as AddressInfo).port}/api`;
});

afterAll(() => {
  api?.close();
  idp?.server.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

const call = (p: string, token?: string, init: RequestInit = {}) =>
  fetch(`${base}${p}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(init.headers || {}) },
  });

describe('OIDC sign-in', () => {
  it('rejects anonymous, forged, and wrong-audience tokens', async () => {
    expect((await call('/state')).status).toBe(401);
    expect((await call('/state', await idp.token('alice', [], {}, idp.otherKey))).status).toBe(401);
    expect((await call('/state', await idp.token('alice', [], { aud: 'someone-else' }))).status).toBe(401);
    expect((await call('/state', await idp.token('alice'))).status).toBe(200);
    expect((await call('/auth/config')).status).toBe(200);
  });

  it('completes the authorization-code flow with PKCE and opens a session', async () => {
    const login = new URL(await oidc.beginLogin('/dashboard'));
    expect(login.searchParams.get('code_challenge_method')).toBe('S256');
    idp.codes.set('code-1', { challenge: login.searchParams.get('code_challenge')!, nonce: login.searchParams.get('nonce')!, sub: 'bob', roles: [] });
    const { sessionId, principal, returnTo } = await oidc.completeLogin({ code: 'code-1', state: login.searchParams.get('state')! });
    expect(principal).toMatchObject({ sub: 'bob', via: 'oidc-session', globalRole: 'member' });
    expect(returnTo).toBe('/dashboard');
    // State is single-use.
    await expect(oidc.completeLogin({ code: 'code-1', state: login.searchParams.get('state')! })).rejects.toThrow(/state/);

    const cookie = oidc.sessionCookie(sessionId).split(';')[0];
    expect(await (await call('/auth/me', undefined, { headers: { cookie } })).json()).toMatchObject({ sub: 'bob' });
    // Cookie sessions need the client header on writes (CSRF).
    expect((await call('/projects', undefined, { method: 'POST', headers: { cookie }, body: '{}' })).status).toBe(403);
  });

  it('applies the default-project role to single-repository endpoints', async () => {
    const viewer = await idp.token('carol');
    expect((await call('/state', viewer)).status).toBe(200);
    expect((await call('/clauses/compile', viewer, { method: 'POST', body: '{}' })).status).toBe(403);
    expect((await call('/clauses/compile', await idp.token('root', ['lexcompiler-admin']), { method: 'POST', body: '{}' })).status).toBe(200);
  });
});

describe('projects', () => {
  it('isolates projects by membership and enforces roles', async () => {
    const alice = await idp.token('alice');
    const dave = await idp.token('dave');
    expect((await call('/projects', alice, { method: 'POST', body: JSON.stringify({ name: 'Escape', repoPath: '../../etc' }) })).status).toBe(400);
    const created = await (await call('/projects', alice, { method: 'POST', body: JSON.stringify({ name: 'Clinic', repoPath: 'clinic' }) })).json();
    expect(created.members).toEqual([{ sub: 'alice', role: 'owner' }]);
    const id = created.id;

    expect((await (await call('/projects', dave)).json()).map((p: { id: string }) => p.id)).not.toContain(id);
    expect((await call(`/projects/${id}/clauses`, dave)).status).toBe(403);

    expect((await call(`/projects/${id}/members`, alice, { method: 'PUT', body: JSON.stringify({ members: [{ sub: 'alice', role: 'owner' }, { sub: 'dave', role: 'viewer' }] }) })).status).toBe(200);
    expect((await call(`/projects/${id}/clauses`, dave)).status).toBe(200);
    expect((await call(`/projects/${id}/clauses`, dave, { method: 'POST', body: JSON.stringify({ rawLegalText: 'Processing requires consent.' }) })).status).toBe(403);
    // Owners cannot remove the last owner.
    expect((await call(`/projects/${id}/members`, alice, { method: 'PUT', body: JSON.stringify({ members: [{ sub: 'dave', role: 'viewer' }] }) })).status).toBe(400);

    const clause = await (await call(`/projects/${id}/clauses`, alice, { method: 'POST', body: JSON.stringify({ rawLegalText: 'Personal data shall be processed only with consent or another lawful basis.', clauseId: 'CONSENT-1' }) })).json();
    expect(clause.category).toBe('CONSENT_LAWFUL_BASIS');

    const scan = await (await call(`/projects/${id}/scan`, dave, { method: 'POST' })).json();
    expect(scan.filesScanned).toBe(1);
    expect(scan.clauses.find((c: { clauseId: string }) => c.clauseId === 'CONSENT-1').status).toBe('UNSAT_VIOLATION');
    const scans = await (await call(`/projects/${id}/scans`, dave)).json();
    expect(scans[0]).toMatchObject({ scanId: scan.scanId, by: 'dave' });
  });
});
