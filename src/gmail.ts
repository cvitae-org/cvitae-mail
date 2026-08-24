/**
 * The Gmail REST calls, over plain `fetch`.
 *
 * `googleapis` would do this too, at the cost of a very large dependency and a
 * generated client, for four endpoints whose entire contract is "POST some JSON
 * with a bearer token". The runtime already talks to cvitae-scrapper this way,
 * so this is the house pattern rather than a preference.
 *
 * Every call routes through `authorized`, which is where the access token is
 * obtained and where a 401 is turned into "reconnect" rather than an opaque
 * upstream error. Nothing else in this service holds a token.
 */

import { accessToken, forgetAccessToken } from './oauth.js';

const API = 'https://gmail.googleapis.com/gmail/v1/users/me';

const TIMEOUT_MS = 20_000;

export type GmailOutcome<T> =
  | { status: 'ok'; data: T }
  | { status: 'not_connected'; detail: string }
  | { status: 'failed'; reason: string; detail: string };

type RequestOptions = {
  path: string;
  method?: 'GET' | 'POST';
  body?: unknown;
};

const authorized = async <T>({
  path,
  method = 'GET',
  body
}: RequestOptions): Promise<GmailOutcome<T>> => {
  const token = await accessToken();

  if (token.status === 'not_connected') {
    return { status: 'not_connected', detail: token.detail };
  }

  if (token.status === 'failed') {
    return { status: 'failed', reason: 'auth_failed', detail: token.detail };
  }

  let response: Response;

  try {
    response = await fetch(`${API}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token.token}`,
        ...(body ? { 'Content-Type': 'application/json' } : {})
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(TIMEOUT_MS)
    });
  } catch (error) {
    const detail =
      error instanceof Error && error.name === 'TimeoutError'
        ? `Gmail did not answer within ${TIMEOUT_MS / 1000}s.`
        : 'Gmail could not be reached.';

    return { status: 'failed', reason: 'unreachable', detail };
  }

  if (response.ok) {
    return { status: 'ok', data: (await response.json()) as T };
  }

  const detail = await response.text().catch(() => '');

  if (response.status === 401) {
    // The cached token is stale or the grant is gone. Dropping the cache means
    // the next call refreshes rather than repeating this with the same token.
    forgetAccessToken();

    return {
      status: 'not_connected',
      detail: 'Gmail rejected the credentials. Connect again at /connect.'
    };
  }

  if (response.status === 403) {
    return {
      status: 'failed',
      reason: 'forbidden',
      // Nearly always a scope that was not granted — reading with
      // MAIL_ALLOW_READ switched off at consent time is the common one, and the
      // fix is to reconnect rather than to retry.
      detail:
        'Gmail refused the request, usually because the connected token lacks the scope for it. Reconnect after changing MAIL_ALLOW_READ.'
    };
  }

  if (response.status === 429) {
    return {
      status: 'failed',
      reason: 'rate_limited',
      detail: 'Gmail is rate limiting this account. Try again shortly.'
    };
  }

  return {
    status: 'failed',
    reason: 'upstream_error',
    detail: `Gmail answered HTTP ${response.status}. ${detail.slice(0, 300)}`
  };
};

export const profile = async (): Promise<GmailOutcome<{ emailAddress: string }>> =>
  authorized<{ emailAddress: string }>({ path: '/profile' });

/** Creates a draft. The message is not sent, and no delivery is attempted. */
export const createDraft = async (
  raw: string
): Promise<GmailOutcome<{ id: string; message: { id: string; threadId: string } }>> =>
  authorized({
    path: '/drafts',
    method: 'POST',
    body: { message: { raw } }
  });

/** Sends immediately. Only reachable when MAIL_ALLOW_SEND is on. */
export const sendMessage = async (
  raw: string
): Promise<GmailOutcome<{ id: string; threadId: string }>> =>
  authorized({
    path: '/messages/send',
    method: 'POST',
    body: { raw }
  });

export type MailHeaderSummary = {
  id: string;
  thread_id: string;
  from: string;
  subject: string;
  date: string;
  snippet: string;
};

type ListResponse = { messages?: { id: string; threadId: string }[] };

type MessageResponse = {
  id: string;
  threadId: string;
  snippet?: string;
  payload?: { headers?: { name: string; value: string }[] };
};

const header = (message: MessageResponse, name: string): string =>
  message.payload?.headers?.find(
    (entry) => entry.name.toLowerCase() === name.toLowerCase()
  )?.value ?? '';

/**
 * Searches the mailbox and returns headers only.
 *
 * Headers rather than bodies, and that is a deliberate ceiling rather than an
 * unfinished feature. This is the one surface a model is meant to reach, and a
 * message body is text an arbitrary stranger wrote and sent to the user — the
 * most directly attacker-controlled input anywhere in this system. Returning
 * "who wrote, about what, when" answers the question worth asking of a mailbox
 * here ("has anyone replied about my applications?") while keeping the amount of
 * hostile prose entering a model's context to a subject line and a snippet.
 *
 * Reading a full thread is a reasonable thing to want next. It should be its own
 * endpoint, taking an id the *user* chose from these results.
 *
 * One `get` per hit, so the cost is linear in `limit`; the cap keeps that honest.
 */
export const search = async (
  query: string,
  limit: number
): Promise<GmailOutcome<MailHeaderSummary[]>> => {
  const parameters = new URLSearchParams({
    q: query,
    maxResults: String(limit)
  });

  const listed = await authorized<ListResponse>({
    path: `/messages?${parameters.toString()}`
  });

  if (listed.status !== 'ok') return listed;

  const ids = listed.data.messages ?? [];

  if (ids.length === 0) return { status: 'ok', data: [] };

  const details = await Promise.all(
    ids.map((entry) =>
      authorized<MessageResponse>({
        path: `/messages/${entry.id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`
      })
    )
  );

  const summaries: MailHeaderSummary[] = [];

  for (const detail of details) {
    // One message failing to load is not worth failing the search over; the
    // others still answer the question.
    if (detail.status !== 'ok') continue;

    summaries.push({
      id: detail.data.id,
      thread_id: detail.data.threadId,
      from: header(detail.data, 'From'),
      subject: header(detail.data, 'Subject'),
      date: header(detail.data, 'Date'),
      snippet: detail.data.snippet ?? ''
    });
  }

  return { status: 'ok', data: summaries };
};
