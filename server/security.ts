import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

/**
 * Header every LexCompiler API client must send. Browsers cannot attach a custom
 * header to a cross-origin request without a CORS preflight, which the origin
 * allowlist rejects, so this blocks drive-by requests from other web pages
 * (including `<img>`/form GETs that carry no Origin header).
 */
export const CLIENT_HEADER = 'x-lexcompiler-client';

const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3001',
  'http://127.0.0.1:3001',
];

export interface ServerSecurityConfig {
  host: string;
  port: number;
  apiToken: string | null;
  allowedOrigins: string[];
  allowedHosts: string[];
  runtimeSandboxEnabled: boolean;
}

function splitList(value: string | undefined): string[] {
  return (value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function isLoopbackHostname(hostname: string): boolean {
  return LOOPBACK_HOSTNAMES.has(hostname.toLowerCase());
}

export function resolveServerSecurityConfig(env: NodeJS.ProcessEnv = process.env): ServerSecurityConfig {
  const port = env.PORT ? parseInt(env.PORT, 10) : 3001;
  const extraOrigins = splitList(env.LEXCOMPILER_ALLOWED_ORIGINS);
  return {
    host: env.HOST || '127.0.0.1',
    port,
    apiToken: env.LEXCOMPILER_API_TOKEN?.trim() || null,
    allowedOrigins: extraOrigins.length > 0 ? extraOrigins : DEFAULT_ALLOWED_ORIGINS,
    allowedHosts: splitList(env.LEXCOMPILER_ALLOWED_HOSTS).map((h) => h.toLowerCase()),
    runtimeSandboxEnabled: env.LEXCOMPILER_ENABLE_RUNTIME_SANDBOX === '1',
  };
}

/**
 * Refuses to expose the API beyond loopback without a token: every endpoint can
 * rewrite target-repo files and trigger Git commits.
 */
export function assertSafeBindConfig(config: ServerSecurityConfig): void {
  if (!isLoopbackHostname(config.host) && !config.apiToken) {
    throw new Error(
      `Refusing to listen on non-loopback host "${config.host}" without LEXCOMPILER_API_TOKEN. ` +
        'Set LEXCOMPILER_API_TOKEN, or bind to 127.0.0.1.'
    );
  }
}

function hostnameFromHostHeader(hostHeader: string | undefined): string {
  if (!hostHeader) return '';
  if (hostHeader.startsWith('[')) {
    return hostHeader.slice(0, hostHeader.indexOf(']') + 1).toLowerCase();
  }
  return hostHeader.split(':')[0].toLowerCase();
}

function tokensMatch(expected: string, provided: string): boolean {
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(provided, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function isOriginAllowed(config: ServerSecurityConfig, origin: string | undefined): boolean {
  return !origin || config.allowedOrigins.includes(origin);
}

/**
 * Guards every `/api` route except `/api/health`:
 * - Origin, when present, must be in the allowlist.
 * - With LEXCOMPILER_API_TOKEN set, `Authorization: Bearer <token>` is required.
 * - Without a token, the Host header must be loopback (or allowlisted) to defeat
 *   DNS rebinding, and the client header must be present.
 */
export function createApiGuard(config: ServerSecurityConfig) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.path === '/health' || req.method === 'OPTIONS') {
      next();
      return;
    }

    const origin = req.headers.origin;
    if (!isOriginAllowed(config, origin)) {
      res.status(403).json({ error: `Origin "${origin}" is not allowed (LEXCOMPILER_ALLOWED_ORIGINS).` });
      return;
    }

    if (config.apiToken) {
      const auth = req.headers.authorization || '';
      const provided = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length).trim() : '';
      if (!provided || !tokensMatch(config.apiToken, provided)) {
        res.status(401).json({ error: 'Missing or invalid API token.', authRequired: true });
        return;
      }
      next();
      return;
    }

    const hostname = hostnameFromHostHeader(req.headers.host);
    if (!isLoopbackHostname(hostname) && !config.allowedHosts.includes(hostname)) {
      res.status(403).json({ error: `Host "${hostname}" is not allowed (LEXCOMPILER_ALLOWED_HOSTS).` });
      return;
    }

    if (!req.headers[CLIENT_HEADER]) {
      res.status(403).json({ error: `Missing required "${CLIENT_HEADER}" request header.` });
      return;
    }

    next();
  };
}
