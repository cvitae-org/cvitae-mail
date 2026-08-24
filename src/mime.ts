/**
 * Assembles an RFC 5322 message and encodes it the way Gmail wants it.
 *
 * The part to read before changing anything is `headerValue`. Header fields are
 * separated by CRLF, so a value carrying one stops being a value and becomes
 * the start of another field — a subject of `Offer\r\nBcc: someone@else` is a
 * blind copy the sender never wrote. That is the classic email header injection,
 * and it matters more here than in most places that quote it, because in this
 * system **the subject line is written by a language model reading text scraped
 * off a job board.** Untrusted input reaching a header is the normal case, not
 * the edge one. Stripping CR and LF is the whole defence and it belongs at the
 * single point every header goes through.
 *
 * Encoding is deliberately dull: base64 for every body part, `=?UTF-8?B?…?=`
 * for any header that is not plain ASCII. Quoted-printable would be smaller and
 * more readable down the wire, and it has line-length and soft-break rules that
 * are easy to get subtly wrong. Nobody reads the wire format of a job
 * application.
 */

import { randomBytes } from 'node:crypto';

export type Attachment = {
  filename: string;
  content_type: string;
  /** Base64, with or without a `data:…;base64,` prefix. */
  content_base64: string;
};

export type Message = {
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  text: string;
  html?: string;
  /** `Display Name <address>` is built from this and the connected address. */
  from_name?: string;
  from_address: string;
  reply_to?: string;
  attachments?: Attachment[];
};

/**
 * Gmail's JSON upload — the one that takes `raw` in the request body — tops out
 * around 5MB. Larger messages need the resumable upload endpoint, which is a
 * different protocol for a case a job application does not have. Refusing here
 * with a size gives a better error than a 400 from Google that does not.
 */
export const MAX_RAW_BYTES = 5 * 1024 * 1024;

const isAscii = (value: string): boolean => /^[\x20-\x7E]*$/.test(value);

/** The single choke point for anything that becomes a header. */
const headerValue = (value: string): string => {
  const flattened = value.replace(/[\r\n]+/g, ' ').trim();

  return isAscii(flattened)
    ? flattened
    : `=?UTF-8?B?${Buffer.from(flattened, 'utf8').toString('base64')}?=`;
};

/**
 * An address as it appears in a header.
 *
 * The address itself is never encoded — an encoded-word inside an addr-spec is
 * not a valid address — so it is only stripped of anything structural. A display
 * name may be encoded, and is quoted when it is not.
 */
const address = (spec: string, name?: string): string => {
  const clean = spec.replace(/[\r\n<>,;]/g, '').trim();

  if (!name) return clean;

  const encoded = headerValue(name);

  return encoded.startsWith('=?')
    ? `${encoded} <${clean}>`
    : `"${encoded.replace(/"/g, '')}" <${clean}>`;
};

const base64Lines = (input: Buffer): string =>
  // RFC 2045 caps an encoded line at 76 characters. Gmail is forgiving about
  // this; other agents in the delivery path are less so.
  (input.toString('base64').match(/.{1,76}/g) ?? []).join('\r\n');

const boundary = (): string => `----=_cvitae_${randomBytes(12).toString('hex')}`;

const textPart = (contentType: string, body: string): string =>
  [
    `Content-Type: ${contentType}; charset="UTF-8"`,
    'Content-Transfer-Encoding: base64',
    '',
    base64Lines(Buffer.from(body, 'utf8'))
  ].join('\r\n');

/**
 * A filename, safe to sit inside a quoted header parameter.
 *
 * `headerValue` alone is not enough here, and a test caught the difference. It
 * strips CR and LF, so nothing can start a new header — but the result lands
 * inside `filename="…"` on Content-Disposition, where a quote closes the
 * parameter, a backslash escapes the next character, and a semicolon begins
 * another parameter. None of those belong in a name, and the name arrives from
 * the same untrusted direction as everything else in this module.
 *
 * Capped as well, because a header line has a practical length limit and a
 * 4KB filename is a bug on the caller's side worth containing rather than
 * forwarding.
 */
const attachmentFilename = (raw: string): string => {
  const printable = [...raw]
    .filter((character) => {
      const code = character.codePointAt(0) ?? 0;
      return code > 0x1f && code !== 0x7f;
    })
    .join('');

  const stripped = printable.replace(/["\\;]/g, ' ').trim().slice(0, 200);

  return headerValue(stripped) || 'attachment';
};

/** A media type, reduced to the one token it is allowed to be. */
const mediaType = (raw: string): string => {
  const match = /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+/.exec(raw.trim());

  return match ? match[0] : 'application/octet-stream';
};

const attachmentPart = (attachment: Attachment): string => {
  // `readAsDataURL` in a browser produces the prefixed form, and cvitae is a
  // browser application, so accepting it costs one regex and saves every caller
  // from remembering to strip it.
  const payload = attachment.content_base64.replace(/^data:[^;]*;base64,/, '');
  const bytes = Buffer.from(payload, 'base64');

  return [
    `Content-Type: ${mediaType(attachment.content_type)}`,
    'Content-Transfer-Encoding: base64',
    `Content-Disposition: attachment; filename="${attachmentFilename(attachment.filename)}"`,
    '',
    base64Lines(bytes)
  ].join('\r\n');
};

/** Wraps parts in a multipart of the given subtype. */
const multipart = (subtype: string, parts: string[]): string => {
  const mark = boundary();

  return [
    `Content-Type: multipart/${subtype}; boundary="${mark}"`,
    '',
    ...parts.map((part) => `--${mark}\r\n${part}`),
    `--${mark}--`,
    ''
  ].join('\r\n');
};

export type ComposeResult =
  | { status: 'ok'; raw: string; bytes: number }
  | { status: 'too_large'; bytes: number };

/**
 * Builds the message and returns it base64url-encoded, which is the only form
 * the Gmail REST API accepts for `raw`.
 */
export const compose = (message: Message): ComposeResult => {
  const attachments = message.attachments ?? [];

  const body = message.html
    ? multipart('alternative', [
        textPart('text/plain', message.text),
        textPart('text/html', message.html)
      ])
    : textPart('text/plain', message.text);

  const content =
    attachments.length > 0
      ? multipart('mixed', [body, ...attachments.map(attachmentPart)])
      : body;

  const headers = [
    `From: ${address(message.from_address, message.from_name)}`,
    `To: ${message.to.map((entry) => address(entry)).join(', ')}`,
    ...(message.cc?.length ? [`Cc: ${message.cc.map((e) => address(e)).join(', ')}`] : []),
    // Bcc is a header the sender's own server strips before delivery; Gmail
    // does exactly that, and it is how the API expects blind copies to arrive.
    ...(message.bcc?.length ? [`Bcc: ${message.bcc.map((e) => address(e)).join(', ')}`] : []),
    ...(message.reply_to ? [`Reply-To: ${address(message.reply_to)}`] : []),
    `Subject: ${headerValue(message.subject)}`,
    `Date: ${new Date().toUTCString()}`,
    'MIME-Version: 1.0'
  ];

  // The multipart helper emits its own Content-Type as the first line, so the
  // headers and the content join directly; a single-part body carries its
  // Content-Type the same way. Either way one blank line separates the header
  // block from what follows.
  const raw = `${headers.join('\r\n')}\r\n${content}`;
  const buffer = Buffer.from(raw, 'utf8');

  if (buffer.byteLength > MAX_RAW_BYTES) {
    return { status: 'too_large', bytes: buffer.byteLength };
  }

  return {
    status: 'ok',
    raw: buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, ''),
    bytes: buffer.byteLength
  };
};
