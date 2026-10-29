import fs from 'node:fs';
import path from 'node:path';
import { dataDir } from '../db/index.js';

/** A registered GitHub App. The private key and secrets never leave the server. */
export interface GitHubAppCredentials {
  appId: string;
  slug: string | null;
  name: string | null;
  htmlUrl: string | null;
  privateKeyPem: string;
  webhookSecret: string;
  /** OAuth client credentials, used to confirm who installed the app. */
  clientId: string | null;
  clientSecret: string | null;
  source: 'env' | 'file';
}

function credentialsFile(env: NodeJS.ProcessEnv = process.env): string {
  return path.resolve(env.LEXCOMPILER_GITHUB_APP_FILE || path.join(dataDir(), 'github-app.json'));
}

/**
 * Environment variables win (production). Otherwise data/github-app.json, which the manifest
 * flow at /github/register writes. Returns null when no app is registered.
 */
export function loadGitHubAppCredentials(env: NodeJS.ProcessEnv = process.env): GitHubAppCredentials | null {
  const appId = env.LEXCOMPILER_GITHUB_APP_ID?.trim();
  if (appId) {
    const keyPath = env.LEXCOMPILER_GITHUB_APP_PRIVATE_KEY_PATH?.trim();
    const privateKeyPem = env.LEXCOMPILER_GITHUB_APP_PRIVATE_KEY?.replace(/\\n/g, '\n') || (keyPath ? fs.readFileSync(keyPath, 'utf8') : '');
    const webhookSecret = env.LEXCOMPILER_GITHUB_WEBHOOK_SECRET?.trim() || '';
    if (!privateKeyPem || !webhookSecret) {
      throw new Error('LEXCOMPILER_GITHUB_APP_ID is set, but the private key or LEXCOMPILER_GITHUB_WEBHOOK_SECRET is missing');
    }
    return {
      appId,
      slug: env.LEXCOMPILER_GITHUB_APP_SLUG?.trim() || null,
      name: null,
      htmlUrl: null,
      privateKeyPem,
      webhookSecret,
      clientId: env.LEXCOMPILER_GITHUB_CLIENT_ID?.trim() || null,
      clientSecret: env.LEXCOMPILER_GITHUB_CLIENT_SECRET?.trim() || null,
      source: 'env',
    };
  }
  const file = credentialsFile(env);
  if (!fs.existsSync(file)) return null;
  const c = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<GitHubAppCredentials>;
  if (!c.appId || !c.privateKeyPem || !c.webhookSecret) throw new Error(`${file} is missing appId, privateKeyPem or webhookSecret`);
  return {
    appId: String(c.appId),
    slug: c.slug ?? null,
    name: c.name ?? null,
    htmlUrl: c.htmlUrl ?? null,
    privateKeyPem: c.privateKeyPem,
    webhookSecret: c.webhookSecret,
    clientId: c.clientId ?? null,
    clientSecret: c.clientSecret ?? null,
    source: 'file',
  };
}

/** Saves credentials from the manifest flow, readable only by the server's user (mode 0600). */
export function saveGitHubAppCredentials(credentials: Omit<GitHubAppCredentials, 'source'>, env: NodeJS.ProcessEnv = process.env): string {
  const file = credentialsFile(env);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(credentials, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmp, file);
  fs.chmodSync(file, 0o600);
  return file;
}
