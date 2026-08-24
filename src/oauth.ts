/**
 * The Google side of connecting a mailbox.
 *
 * Three things happen here: build a consent URL, trade the code Google sends
 * back for a refresh token, and turn that refresh token into a short-lived
 * access token whenever a request needs one.
 *
 * Two protections are not optional even on loopback, and both exist because the
 * callback is an unauthenticated HTTP endpoint on this machine that any web page
 * the user visits can cause their browser to request.
 *
 *   `state`  — a nonce minted at `/connect` and required at `/callback`. Without
 *              it, a page could redirect the browser to
 *              `127.0.0.1:8789/callback?code=<attacker's code>` and this service
 *              would dutifully connect the attacker's mailbox, after which every
 *              draft the runtime writes lands somewhere else. Authorization code
 *              injection, and it is cheap to prevent.
 *
 *   PKCE     — a per-attempt verifier, so a code intercepted in transit is
 *              useless without it. Google recommends it for installed apps for
 *              the good reason that a desktop client's secret is not a secret:
 *              it ships with the application, and ours sits in a `.env`.
 *
 * Pending attempts live in memory. A restart between `/connect` and `/callback`
 * loses the attempt and the user connects again, which is the right trade for
 * not persisting a second secret to disk.
 */

import { createHash, randomBytes } from 'node:crypto';
import { config, redirectUri, scopes } from './config.js';
import { readTokens } from './tokens.js';

const AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const REVOKE_ENDPOINT = 'https://oauth2.googleapis.com/revoke';

const TOKEN_TIMEOUT_MS = 15_000;

/** How long a started consent may sit before it is abandoned. */
const PENDING_TTL_MS = 10 * 60 * 1000;

/**
 * Refresh a little before expiry rather than on it, so a token that is valid
 * when checked is not expired by the time Gmail reads it.
 */
const EXPIRY_SKEW_MS = 60_000;

const base64url = (input: Buffer): string =>
  input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

type Pending = { verifier: string; createdAt: number };

const pending = new Map<string, Pending>();

const sweepPending = (): void => {
  const now = Date.now();

  for (const [state, attempt] of pending) {
    if (now - attempt.createdAt > PENDING_TTL_MS) pending.delete(state);
  }
};

/** Builds the consent URL and remembers the attempt it belongs to. */
export const startAuthorization = (): { url: string; state: string } => {
  sweepPending();

  const state = base64url(randomBytes(24));
  const verifier = base64url(randomBytes(48));
  const challenge = base64url(createHash('sha256').update(verifier).digest());

  pending.set(state, { verifier, createdAt: Date.now() });

  const parameters = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: redirectUri(),
    response_type: 'code',
    scope: scopes().join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    // Without `offline` Google returns no refresh token, and without a forced
    // consent it returns one only on the very first authorization — so a second
    // connect after clearing the token file would silently produce a session
    // that dies in an hour and cannot be renewed.
    access_type: 'offline',
    prompt: 'consent'
  });

  return { url: `${AUTH_ENDPOINT}?${parameters.toString()}`, state };
};

export type ExchangeResult =
  | { status: 'ok'; refreshToken: string; accessToken: string; scope: string }
  | { status: 'failed'; detail: string };

type TokenResponse = {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
};

const postToken = async (body: URLSearchParams): Promise<TokenResponse | undefined> => {
  try {
    const response = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS)
    });

    return (await response.json()) as TokenResponse;
  } catch {
    return undefined;
  }
};

/** Trades the authorization code for tokens, consuming the pending attempt. */
export const exchangeCode = async (
  code: string,
  state: string
): Promise<ExchangeResult> => {
  sweepPending();

  const attempt = pending.get(state);

  if (!attempt) {
    return {
      status: 'failed',
      detail:
        'This callback did not match a consent this service started, or it arrived more than ten minutes late. Start again at /connect.'
    };
  }

  // Single use, whatever happens next: a verifier that survives a failed
  // exchange is a verifier available for a second attempt with another code.
  pending.delete(state);

  const payload = await postToken(
    new URLSearchParams({
      code,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      redirect_uri: redirectUri(),
      grant_type: 'authorization_code',
      code_verifier: attempt.verifier
    })
  );

  if (!payload) {
    return { status: 'failed', detail: 'Google did not answer the token request.' };
  }

  if (payload.error || !payload.access_token) {
    return {
      status: 'failed',
      detail: payload.error_description ?? payload.error ?? 'Google refused the code.'
    };
  }

  if (!payload.refresh_token) {
    return {
      status: 'failed',
      detail:
        'Google returned no refresh token. This happens when consent was already granted to this client; remove the app under your Google account permissions and connect again.'
    };
  }

  return {
    status: 'ok',
    refreshToken: payload.refresh_token,
    accessToken: payload.access_token,
    scope: payload.scope ?? scopes().join(' ')
  };
};

let cached: { token: string; expiresAt: number } | undefined;

/** Discards the cached access token — after a revoke, or a 401 from Gmail. */
export const forgetAccessToken = (): void => {
  cached = undefined;
};

export type AccessTokenResult =
  | { status: 'ok'; token: string }
  | { status: 'not_connected'; detail: string }
  | { status: 'failed'; detail: string };

/**
 * The access token for the connected mailbox, refreshed when it has run out.
 *
 * Every Gmail call goes through this rather than holding a token of its own, so
 * there is one place that knows whether the connection is still good.
 */
export const accessToken = async (): Promise<AccessTokenResult> => {
  if (cached && cached.expiresAt - EXPIRY_SKEW_MS > Date.now()) {
    return { status: 'ok', token: cached.token };
  }

  const stored = await readTokens();

  if (!stored) {
    return {
      status: 'not_connected',
      detail: 'No mailbox is connected. Open /connect in a browser.'
    };
  }

  const payload = await postToken(
    new URLSearchParams({
      refresh_token: stored.refresh_token,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      grant_type: 'refresh_token'
    })
  );

  if (!payload) {
    return { status: 'failed', detail: 'Google did not answer the refresh request.' };
  }

  if (payload.error || !payload.access_token) {
    // `invalid_grant` is the one worth naming: the refresh token was revoked,
    // the password changed, or it went unused for six months. Reconnecting is
    // the only remedy, and saying so beats a generic upstream failure.
    const reason =
      payload.error === 'invalid_grant'
        ? 'The stored authorization is no longer valid — it was revoked, or it expired through disuse. Connect again at /connect.'
        : (payload.error_description ?? payload.error ?? 'Google refused the refresh.');

    return { status: 'failed', detail: reason };
  }

  cached = {
    token: payload.access_token,
    expiresAt: Date.now() + (payload.expires_in ?? 3600) * 1000
  };

  return { status: 'ok', token: cached.token };
};

/** Best-effort revoke at Google. The local token is deleted regardless. */
export const revoke = async (refreshToken: string): Promise<void> => {
  forgetAccessToken();

  await fetch(REVOKE_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: refreshToken }),
    signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS)
  }).catch(() => undefined);
};
