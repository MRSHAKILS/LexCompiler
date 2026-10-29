import express from 'express';
import type { Request, Response } from 'express';
import { analyzeFullRepositoryAsync } from '../analyzer/astAnalyzer.js';
import { readRepositoryFilesAt, readTargetRepoFiles } from '../analyzer/repoBaseline.js';
import { OidcProvider, type Principal } from '../auth/oidc.js';
import { compileLegalProseToFormalPolicyAsync, getInitialClauses, inferRuleCategoryFromProse } from '../compiler/legalCompiler.js';
import { verifyRepositoryAgainstClauses } from '../prover/z3Engine.js';
import { tokensMatch, type Authenticator } from '../security.js';
import type { LegalClause } from '../../shared/types.js';
import { roleAtLeast, type ProjectRole, type ProjectStore } from './projectStore.js';

/** Bearer API token (admin), OIDC bearer JWT, or OIDC session cookie. */
export function createAuthenticator(oidc: OidcProvider, apiToken: string | null): Authenticator {
  return async (req) => {
    const auth = req.headers.authorization || '';
    const bearer = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    if (bearer && apiToken && tokensMatch(apiToken, bearer)) return { sub: 'api-token', globalRole: 'admin', via: 'api-token' };
    if (bearer) return oidc.principalFromBearer(bearer);
    return oidc.principalFromSession(OidcProvider.sessionIdFromCookies(req.headers.cookie));
  };
}

const principalOf = (res: Response) => res.locals.principal as Principal;
const pid = (req: Request) => String(req.params.projectId);

/** Sign-in endpoints and the multi-project API (members, clauses, scans). */
export function createAccessRouter(store: ProjectStore, oidc: OidcProvider | null) {
  const r = express.Router();

  r.get('/auth/config', (_req, res) => {
    res.json({ oidcEnabled: Boolean(oidc), issuer: oidc?.config.issuer ?? null, loginUrl: oidc ? '/api/auth/login' : null });
  });
  if (oidc) {
    r.get('/auth/login', async (req, res) => {
      try {
        res.redirect(302, await oidc.beginLogin(String(req.query.returnTo || '/')));
      } catch (err) {
        res.status(502).json({ error: (err as Error).message });
      }
    });
    r.get('/auth/callback', async (req, res) => {
      try {
        const { sessionId, returnTo } = await oidc.completeLogin({ code: req.query.code as string, state: req.query.state as string, error: req.query.error as string });
        res.setHeader('Set-Cookie', oidc.sessionCookie(sessionId));
        res.redirect(302, returnTo);
      } catch (err) {
        res.status(401).json({ error: `Sign-in failed: ${(err as Error).message}` });
      }
    });
    r.post('/auth/logout', (req, res) => {
      oidc.endSession(OidcProvider.sessionIdFromCookies(req.headers.cookie));
      res.setHeader('Set-Cookie', oidc.clearedCookie());
      res.json({ signedOut: true });
    });
  }
  r.get('/auth/me', (_req, res) => res.json(principalOf(res) ?? null));

  const roleFor = (req: Request, res: Response): ProjectRole | null => {
    const p = store.get(pid(req));
    if (!p) return null;
    const who = principalOf(res);
    return who.globalRole === 'admin' ? 'owner' : store.roleOf(p, who.sub);
  };
  const need = (min: ProjectRole) => (req: Request, res: Response, next: express.NextFunction) => {
    if (!store.get(pid(req))) return void res.status(404).json({ error: 'project not found' });
    if (!roleAtLeast(roleFor(req, res), min)) return void res.status(403).json({ error: `requires the ${min} role on this project` });
    next();
  };

  r.get('/projects', (_req, res) => {
    const who = principalOf(res);
    const visible = store.list().filter((p) => who.globalRole === 'admin' || store.roleOf(p, who.sub));
    res.json(visible.map((p) => ({ ...p, myRole: who.globalRole === 'admin' ? 'owner' : store.roleOf(p, who.sub) })));
  });

  r.post('/projects', (req, res) => {
    try {
      const p = store.create({ name: String(req.body?.name || ''), repoPath: String(req.body?.repoPath || ''), owner: principalOf(res).sub });
      store.saveClauses(p.id, getInitialClauses());
      res.status(201).json(p);
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });

  r.get('/projects/:projectId', need('viewer'), (req, res) => res.json({ ...store.get(pid(req)), myRole: roleFor(req, res) }));

  r.delete('/projects/:projectId', need('owner'), (req, res) => {
    store.delete(pid(req));
    res.json({ deleted: pid(req) });
  });

  r.put('/projects/:projectId/members', need('owner'), (req, res) => {
    const members = req.body?.members;
    if (!Array.isArray(members) || !members.every((m) => typeof m?.sub === 'string' && ['viewer', 'editor', 'owner'].includes(m?.role))) {
      return void res.status(400).json({ error: 'members must be [{ sub, role: viewer|editor|owner }]' });
    }
    try {
      res.json(store.update(pid(req), (p) => (p.members = members.map((m: { sub: string; role: ProjectRole }) => ({ sub: m.sub, role: m.role })))));
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });

  r.get('/projects/:projectId/clauses', need('viewer'), (req, res) => res.json(store.clauses(pid(req)) ?? getInitialClauses()));

  r.post('/projects/:projectId/clauses', need('editor'), async (req, res) => {
    const text = String(req.body?.rawLegalText || '').trim();
    if (!text) return void res.status(400).json({ error: 'rawLegalText is required' });
    const category = req.body?.category || inferRuleCategoryFromProse(text);
    const id = String(req.body?.clauseId || `CLAUSE-${Date.now().toString(36).toUpperCase()}`);
    const citation = String(req.body?.citation || id);
    const compiled = await compileLegalProseToFormalPolicyAsync(text, category, id, citation);
    const base = getInitialClauses()[0];
    const clause: LegalClause = { ...base, id, category, citation, title: String(req.body?.title || citation), rawLegalText: text, illustrative: false, version: '1', lastAmended: new Date().toISOString().slice(0, 10), ...compiled };
    const clauses = (store.clauses(pid(req)) ?? getInitialClauses()).filter((c) => c.id !== id);
    store.saveClauses(pid(req), [...clauses, clause]);
    res.status(201).json(clause);
  });

  r.delete('/projects/:projectId/clauses/:clauseId', need('editor'), (req, res) => {
    const clauses = store.clauses(pid(req)) ?? getInitialClauses();
    store.saveClauses(pid(req), clauses.filter((c) => c.id !== String(req.params.clauseId)));
    res.json({ deleted: String(req.params.clauseId) });
  });

  r.post('/projects/:projectId/scan', need('viewer'), async (req, res) => {
    try {
      const project = store.get(pid(req))!;
      const clauses = store.clauses(project.id) ?? getInitialClauses();
      // The default project always follows LEXCOMPILER_TARGET_REPO.
      const files = project.id === 'default' ? readTargetRepoFiles() : readRepositoryFilesAt(project.repoPath);
      const a = await analyzeFullRepositoryAsync(files);
      const v = await verifyRepositoryAgainstClauses(clauses, a.sqlTables, a.astFindings);
      const record = {
        scanId: `SCAN-${Date.now().toString(36).toUpperCase()}`,
        at: new Date().toISOString(),
        by: principalOf(res).sub,
        filesScanned: files.length,
        merkleAuditRoot: v.merkleAuditRoot,
        clauses: v.proofs.map((p) => ({ clauseId: p.clauseId, citation: p.citation, status: p.status, violations: p.offendingLocations.length })),
      };
      store.appendScan(project.id, record);
      res.json({ ...record, proofs: v.proofs });
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  });

  r.get('/projects/:projectId/scans', need('viewer'), (req, res) => res.json(store.scans(pid(req))));

  return r;
}
