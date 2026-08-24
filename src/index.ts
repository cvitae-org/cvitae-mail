/**
 * cvitae-mail — the mailbox, as a separate process.
 *
 * It exists so that the credential which can read and send a person's email
 * never sits in the same process as their CV, their offer history and their
 * model provider keys. That is the whole architectural argument, and it is
 * bounded honestly: this does not stop a compromised runtime from *calling*
 * `/draft`, it stops one from *holding the token*. Those are different wins, and
 * only the second is on offer here.
 *
 * The surface is split by who is trusted to decide, not by what it touches:
 *
 *   /connect, /callback, /disconnect  the user, in a browser
 *   /draft, /send                     the runtime, on behalf of a user who has
 *                                     confirmed a recipient in cvitae's UI
 *   /search                           safe to reach from a model tool loop
 *
 * The line that matters runs between the last two. `/search` returns text
 * strangers wrote; `/draft` and `/send` are an outbound channel. A model holding
 * both, alongside a CV, is the complete exfiltration triangle — untrusted input,
 * private data, somewhere to put it. Keep the drafting path out of every tool
 * set and the triangle has no third side.
 *
 * Answers carry their outcome in the body, always: `{ status: 'ok', data }` or
 * `{ status: '<reason>', detail }`. The runtime decides on `status` rather than
 * on the HTTP code, for the reason cvitae-scrapper settled — a 403 here means
 * "Google refused a scope", not "this service is broken", and a client reading
 * status codes would fall back or retry on exactly the wrong ones.
 */

// First, and before anything below reads `process.env`.
import './env.js';

import Fastify from 'fastify';
import { z } from 'zod';
import { config, isConfigured, isRecipientAllowed, redirectUri, scopes } from './config.js';
import { createDraft, profile, search, sendMessage, type GmailOutcome } from './gmail.js';
import { compose, MAX_RAW_BYTES } from './mime.js';
import { exchangeCode, forgetAccessToken, revoke, startAuthorization } from './oauth.js';
import { clearTokens, readTokens, writeTokens } from './tokens.js';

/**
 * Room for a CV attached to an application. Base64 inflates by a third and the
 * whole MIME message is base64'd again for Gmail, so the JSON envelope has to be
 * comfortably above `MAX_RAW_BYTES`; `mime.ts` enforces the meaningful ceiling.
 */
const BODY_LIMIT_BYTES = 12 * 1024 * 1024;

const server = Fastify({
  logger: { level: process.env.LOG_LEVEL ?? 'info' },
  bodyLimit: BODY_LIMIT_BYTES
});

/** No display names, no commas, no newlines. A header value, not a phrase. */
const emailAddress = z
  .string()
  .trim()
  .min(3)
  .max(254)
  .regex(/^[^\s<>,;@]+@[^\s<>,;@]+\.[^\s<>,;@]+$/, 'Not a bare email address.');

const attachmentSchema = z.object({
  filename: z.string().min(1).max(255),
  content_type: z.string().min(1).max(255).default('application/octet-stream'),
  content_base64: z.string().min(1)
});

const messageSchema = z.object({
  to: z.array(emailAddress).min(1).max(10),
  cc: z.array(emailAddress).max(10).optional(),
  bcc: z.array(emailAddress).max(10).optional(),
  subject: z.string().max(500).default(''),
  text: z.string().max(200_000),
  html: z.string().max(400_000).optional(),
  from_name: z.string().max(200).optional(),
  reply_to: emailAddress.optional(),
  attachments: z.array(attachmentSchema).max(5).optional()
});

const searchSchema = z.object({
  // Gmail's own search syntax, passed through. It reads the user's mailbox and
  // nothing else, so there is no query here that widens what the token can see.
  q: z.string().min(1).max(500),
  limit: z.coerce.number().int().min(1).max(25).default(10)
});

type Reason =
  | 'not_configured'
  | 'not_connected'
  | 'not_allowed'
  | 'invalid_request'
  | 'too_large'
  | 'rate_limited'
  | 'forbidden'
  | 'unreachable'
  | 'auth_failed'
  | 'upstream_error';

const refuse = (reason: Reason, detail: string) => ({ status: reason, detail });

server.get('/health', async () => {
  if (!isConfigured()) {
    return {
      status: 'not_configured',
      detail:
        'GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET are not set. See the README for creating the OAuth client.',
      allow_send: config.allowSend,
      allow_read: config.allowRead
    };
  }

  const stored = await readTokens();

  return {
    status: 'ok',
    connected: Boolean(stored),
    email: stored?.email ?? null,
    connected_at: stored?.connected_at ?? null,
    scopes: stored?.scope?.split(' ') ?? scopes(),
    allow_send: config.allowSend,
    allow_read: config.allowRead,
    redirect_uri: redirectUri()
  };
});

server.get('/connect', async (_request, reply) => {
  if (!isConfigured()) {
    return reply.status(500).send(
      refuse(
        'not_configured',
        'GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET are not set.'
      )
    );
  }

  const { url } = startAuthorization();

  return reply.redirect(url, 302);
});

const page = (title: string, body: string): string =>
  `<!doctype html><meta charset="utf-8"><title>${title}</title>` +
  `<body style="font:16px/1.5 system-ui;margin:4rem auto;max-width:34rem;padding:0 1rem">` +
  `<h1 style="font-size:1.25rem">${title}</h1><p>${body}</p></body>`;

server.get('/callback', async (request, reply) => {
  const query = request.query as Record<string, string | undefined>;

  reply.type('text/html');

  if (query.error) {
    return reply
      .status(400)
      .send(page('Not connected', `Google returned: ${query.error}`));
  }

  if (!query.code || !query.state) {
    return reply
      .status(400)
      .send(page('Not connected', 'The callback carried no authorization code.'));
  }

  const exchanged = await exchangeCode(query.code, query.state);

  if (exchanged.status === 'failed') {
    request.log.warn(exchanged.detail);
    return reply.status(400).send(page('Not connected', exchanged.detail));
  }

  // Written before the profile lookup, because the profile call needs a stored
  // refresh token to authorize with. The address is filled in immediately after.
  await writeTokens({
    refresh_token: exchanged.refreshToken,
    email: '',
    scope: exchanged.scope,
    connected_at: new Date().toISOString()
  });

  forgetAccessToken();

  const who = await profile();
  const address = who.status === 'ok' ? who.data.emailAddress : '';

  if (address) {
    await writeTokens({
      refresh_token: exchanged.refreshToken,
      email: address,
      scope: exchanged.scope,
      connected_at: new Date().toISOString()
    });
  }

  request.log.info(`Connected ${address || 'a mailbox'}.`);

  return reply.send(
    page(
      'Connected',
      `cvitae-mail is now connected to <strong>${address || 'your mailbox'}</strong>. You can close this tab.`
    )
  );
});

server.post('/disconnect', async () => {
  const stored = await readTokens();

  if (stored) await revoke(stored.refresh_token);

  await clearTokens();
  forgetAccessToken();

  return { status: 'ok', data: { disconnected: true } };
});

/**
 * Builds the message, checks the recipients, and hands it to Gmail.
 *
 * Shared by `/draft` and `/send` because the two differ in exactly one call —
 * and keeping the validation, the allow-list and the size ceiling in one place
 * is what stops the send path from quietly acquiring weaker checks than the
 * draft path it was copied from.
 */
const prepare = async (body: unknown) => {
  const parsed = messageSchema.safeParse(body);

  if (!parsed.success) {
    return {
      error: refuse(
        'invalid_request',
        parsed.error.issues
          .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
          .join('; ')
      )
    } as const;
  }

  const recipients = [
    ...parsed.data.to,
    ...(parsed.data.cc ?? []),
    ...(parsed.data.bcc ?? [])
  ];

  const blocked = recipients.filter((entry) => !isRecipientAllowed(entry));

  if (blocked.length > 0) {
    return {
      error: refuse(
        'not_allowed',
        `MAIL_ALLOWED_RECIPIENTS does not permit: ${blocked.join(', ')}.`
      )
    } as const;
  }

  const stored = await readTokens();

  if (!stored) {
    return {
      error: refuse('not_connected', 'No mailbox is connected. Open /connect in a browser.')
    } as const;
  }

  const built = compose({
    ...parsed.data,
    from_address: stored.email || 'me'
  });

  if (built.status === 'too_large') {
    return {
      error: refuse(
        'too_large',
        `The message is ${Math.round(built.bytes / 1024)}KB; the limit is ${MAX_RAW_BYTES / 1024 / 1024}MB.`
      )
    } as const;
  }

  return { raw: built.raw, to: parsed.data.to } as const;
};

/**
 * Maps a Gmail outcome onto the body-carried contract.
 *
 * Generic over the payload so `/draft` and `/send` share it: a draft answers
 * with its own id alongside the message's, a send with only the message's.
 */
const settle = <T>(outcome: GmailOutcome<T>) =>
  outcome.status === 'ok'
    ? { status: 'ok' as const, data: outcome.data }
    : outcome.status === 'not_connected'
      ? refuse('not_connected', outcome.detail)
      : refuse(outcome.reason as Reason, outcome.detail);

server.post('/draft', async (request, reply) => {
  const prepared = await prepare(request.body);

  if ('error' in prepared) return reply.status(400).send(prepared.error);

  const outcome = await createDraft(prepared.raw);

  if (outcome.status === 'ok') {
    request.log.info(`Drafted a message to ${prepared.to.join(', ')}.`);
  }

  return reply.status(outcome.status === 'ok' ? 200 : 502).send(settle(outcome));
});

server.post('/send', async (request, reply) => {
  if (!config.allowSend) {
    return reply.status(403).send(
      refuse(
        'not_allowed',
        'Sending is switched off. Set MAIL_ALLOW_SEND=true to enable it, or use /draft and press Send in Gmail.'
      )
    );
  }

  const prepared = await prepare(request.body);

  if ('error' in prepared) return reply.status(400).send(prepared.error);

  const outcome = await sendMessage(prepared.raw);

  if (outcome.status === 'ok') {
    request.log.info(`Sent a message to ${prepared.to.join(', ')}.`);
  }

  return reply.status(outcome.status === 'ok' ? 200 : 502).send(settle(outcome));
});

server.get('/search', async (request, reply) => {
  if (!config.allowRead) {
    return reply
      .status(403)
      .send(refuse('not_allowed', 'Reading is switched off. Set MAIL_ALLOW_READ=true.'));
  }

  const parsed = searchSchema.safeParse(request.query);

  if (!parsed.success) {
    return reply
      .status(400)
      .send(refuse('invalid_request', 'A non-empty `q` is required.'));
  }

  const outcome = await search(parsed.data.q, parsed.data.limit);

  if (outcome.status === 'ok') {
    return reply.send({ status: 'ok', data: { results: outcome.data } });
  }

  return reply
    .status(502)
    .send(
      outcome.status === 'not_connected'
        ? refuse('not_connected', outcome.detail)
        : refuse(outcome.reason as Reason, outcome.detail)
    );
});

const start = async () => {
  try {
    await server.listen({ port: config.port, host: config.host });

    server.log.info(`cvitae-mail state lives in ${config.home}`);
    server.log.info(
      `Sending is ${config.allowSend ? 'ENABLED' : 'off — /draft only'}; reading is ${config.allowRead ? 'enabled' : 'off'}.`
    );

    if (!isConfigured()) {
      server.log.warn(
        'No OAuth client configured. /health will say so and nothing else will work until GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET are set.'
      );
    }
  } catch (error) {
    server.log.error(error);
    process.exit(1);
  }
};

void start();
