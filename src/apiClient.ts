/**
 * Adds the LexCompiler client header (and the API token, when the server requires
 * one) to every same-origin `/api` request made through `window.fetch`.
 */
const CLIENT_HEADER = 'X-LexCompiler-Client';
const TOKEN_STORAGE_KEY = 'lexcompiler.apiToken';

function readToken(): string | null {
  try {
    return window.sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

function storeToken(token: string): void {
  try {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
  } catch {
    // Storage unavailable: the token lasts for this request only.
  }
}

function isApiRequest(input: RequestInfo | URL): boolean {
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  const url = new URL(raw, window.location.origin);
  return url.origin === window.location.origin && url.pathname.startsWith('/api/');
}

function withAuthHeaders(init: RequestInit | undefined, token: string | null): RequestInit {
  const headers = new Headers(init?.headers);
  // Same-origin requests carry the OIDC session cookie.
  init = { credentials: 'same-origin', ...init };
  headers.set(CLIENT_HEADER, 'web');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return { ...init, headers };
}

export function installApiClient(): void {
  const nativeFetch = window.fetch.bind(window);
  let tokenPrompt: Promise<string | null> | null = null;

  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    if (!isApiRequest(input)) {
      return nativeFetch(input, init);
    }
    const res = await nativeFetch(input, withAuthHeaders(init, readToken()));
    if (res.status !== 401) {
      return res;
    }

    // OIDC sign-in: the server names its login endpoint; the session cookie does the rest.
    const body = (await res.clone().json().catch(() => null)) as { loginUrl?: string } | null;
    if (body?.loginUrl) {
      const returnTo = `${window.location.pathname}${window.location.search}`;
      window.location.assign(`${body.loginUrl}?returnTo=${encodeURIComponent(returnTo)}`);
      return res;
    }

    // Server requires LEXCOMPILER_API_TOKEN: ask once, then retry.
    tokenPrompt ??= Promise.resolve(
      window.prompt('This LexCompiler server requires an API token (LEXCOMPILER_API_TOKEN):')
    ).finally(() => {
      tokenPrompt = null;
    });
    const token = (await tokenPrompt)?.trim();
    if (!token) {
      return res;
    }
    storeToken(token);
    return nativeFetch(input, withAuthHeaders(init, token));
  };
}
