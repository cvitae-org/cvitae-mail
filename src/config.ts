/**
 * Everything this service reads from the environment, resolved once.
 *
 * Two of these settings are the whole security posture, so they are worth
 * reading before anything else.
 *
 * `MAIL_ALLOW_SEND` is **off by default**, and that is the difference between a
 * service that can embarrass you and one that cannot. With it off, the only
 * outbound operation is `POST /draft`: the message lands in Gmail's Drafts
 * folder and a human presses Send. Nothing this service does — no bug, no
 * malformed model output, no prompt injected into a scraped job offer — can put
 * a message in front of another person. That property is worth more than the
 * one click it costs.
 *
 * The honest caveat: Google has no scope that grants "create drafts but never
 * send". `gmail.compose` is the narrowest scope that can write a draft and it
 * carries the ability to send. So the guarantee above is enforced by this
 * service not exposing a send path, not by the token itself. A stolen token can
 * still send. That is an argument for keeping the token here rather than in the
 * runtime, which is most of why this process exists.
 *
 * `MAIL_ALLOWED_RECIPIENTS` is a development guard, not a production control.
 * Job applications go to arbitrary recruiters, so an allow-list cannot survive
 * real use — but while wiring this up it is the difference between a mistake you
 * find in your own inbox and one you find in someone else's.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';

/** Read scopes are requested only when reading is switched on. */
const SCOPE_COMPOSE = 'https://www.googleapis.com/auth/gmail.compose';
const SCOPE_READONLY = 'https://www.googleapis.com/auth/gmail.readonly';

const flag = (raw: string | undefined, fallback: boolean): boolean => {
  if (raw === undefined || raw.trim() === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.trim().toLowerCase());
};

const port = (raw: string | undefined, fallback: number): number => {
  if (raw === undefined) return fallback;

  const parsed = Number(raw);

  // `Number('')` is 0 and `Number('8789x')` is NaN. Binding to port 0 would
  // pick a random free port, which for a service whose whole OAuth flow depends
  // on a fixed redirect URI is worse than refusing the value outright.
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65_535) {
    console.warn(`PORT is "${raw}", which is not a usable port. Using ${fallback}.`);
    return fallback;
  }

  return parsed;
};

const list = (raw: string | undefined): string[] =>
  (raw ?? '')
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);

export const config = {
  port: port(process.env.PORT, 8789),

  /**
   * Loopback, and not configurable to anything else.
   *
   * The runtime at least has a reason to offer `HOST`: it can sit behind
   * something. This holds a live mailbox credential and has no authentication,
   * so there is no configuration of it that is safe to expose. A service that
   * cannot be misconfigured this way does not need a warning in its README.
   */
  host: '127.0.0.1',

  /**
   * Separate from the runtime's `~/.cvitae` on purpose. Two processes holding
   * two different secrets in one directory makes the isolation harder to
   * describe and easier to lose to a stray `chmod -R`.
   */
  home: process.env.MAIL_HOME ?? join(homedir(), '.cvitae-mail'),

  clientId: process.env.GMAIL_CLIENT_ID ?? '',
  clientSecret: process.env.GMAIL_CLIENT_SECRET ?? '',

  allowSend: flag(process.env.MAIL_ALLOW_SEND, false),
  allowRead: flag(process.env.MAIL_ALLOW_READ, true),

  allowedRecipients: list(process.env.MAIL_ALLOWED_RECIPIENTS)
} as const;

export const tokenPath = (): string => join(config.home, 'tokens.json');

/**
 * The redirect Google sends the browser back to.
 *
 * It has to match what is registered on the OAuth client exactly, which is why
 * `host` is fixed and `port` is warned about rather than coerced. Create the
 * client as an **installed / desktop** application: Google allows loopback
 * redirects for that type, and refuses them for a web application.
 */
export const redirectUri = (): string =>
  `http://127.0.0.1:${config.port}/callback`;

/**
 * Only what is switched on is asked for.
 *
 * `gmail.readonly` grants the entire mailbox — there is no scope for "read only
 * the messages matching this query" — so a deployment that only ever drafts
 * should set `MAIL_ALLOW_READ=false` and hold a token that cannot read mail at
 * all. Changing this later requires reconnecting, since scopes are fixed at
 * consent.
 */
export const scopes = (): string[] =>
  config.allowRead ? [SCOPE_COMPOSE, SCOPE_READONLY] : [SCOPE_COMPOSE];

export const isConfigured = (): boolean =>
  config.clientId.length > 0 && config.clientSecret.length > 0;

/**
 * Whether a recipient is permitted, given the development allow-list.
 *
 * An empty list means no restriction, which is the shape real use takes. An
 * entry starting with `@` matches a whole domain.
 */
export const isRecipientAllowed = (address: string): boolean => {
  if (config.allowedRecipients.length === 0) return true;

  const lower = address.trim().toLowerCase();

  return config.allowedRecipients.some((entry) =>
    entry.startsWith('@') ? lower.endsWith(entry) : lower === entry
  );
};
