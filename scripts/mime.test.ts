/**
 * The composer, which is the part of this service worth testing without a
 * mailbox: pure, deterministic, and the place a mistake is a security bug
 * rather than a broken feature.
 *
 * The first group is the one to keep green. In this system the subject line is
 * written by a small model reading text scraped off a job board, so a header
 * carrying attacker-chosen content is the normal case rather than the edge one.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compose, type Message } from '../src/mime.js';

const base: Omit<Message, 'subject'> = {
  to: ['recruiter@example.com'],
  text: 'Hello.',
  from_address: 'me@example.com'
};

/** Gmail takes base64url; this reads it back as the message it encodes. */
const decode = (raw: string): string =>
  Buffer.from(raw.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');

const composed = (message: Message): string => {
  const result = compose(message);
  assert.equal(result.status, 'ok', 'compose refused a message it should have built');
  return decode((result as { raw: string }).raw);
};

const headers = (text: string): string[] =>
  text.split('\r\n\r\n')[0]?.split('\r\n') ?? [];

test('a CRLF in the subject cannot introduce a header', () => {
  const text = composed({
    ...base,
    subject: 'Application\r\nBcc: attacker@evil.com\r\nX-Evil: yes'
  });

  assert.ok(!headers(text).some((line) => line.startsWith('Bcc:')));
  assert.ok(!headers(text).some((line) => line.startsWith('X-Evil:')));

  // Flattened rather than dropped: the user still sees what the model wrote,
  // which is how a bad subject gets noticed instead of silently truncated.
  assert.ok(
    text.includes('Subject: Application Bcc: attacker@evil.com X-Evil: yes')
  );
});

test('a hostile attachment filename cannot escape its parameter', () => {
  const text = composed({
    ...base,
    subject: 'x',
    attachments: [
      {
        // Three escapes in one name: a CRLF to start a header, a quote to close
        // the parameter, and a semicolon to begin another one.
        filename: 'cv.pdf\r\nContent-Type: text/html";\tx="y',
        content_type: 'application/pdf',
        content_base64: Buffer.from('%PDF-1.4').toString('base64')
      }
    ]
  });

  // Structural, not a substring search: the flattened text may legitimately
  // appear inside the quoted filename. What must not exist is a *line* that
  // parses as a header, or a second parameter on Content-Disposition.
  const lines = text.split('\r\n');

  assert.ok(!lines.includes('Content-Type: text/html'));

  const disposition = lines.find((line) => line.startsWith('Content-Disposition:'));

  assert.ok(disposition);
  assert.equal(disposition.split(';').length, 2, disposition);
  assert.equal(disposition.match(/"/g)?.length, 2, disposition);
});

test('a bogus content type is reduced to one media type token', () => {
  const text = composed({
    ...base,
    subject: 'x',
    attachments: [
      {
        filename: 'cv.pdf',
        content_type: 'application/pdf; boundary="x"\r\nX-Evil: yes',
        content_base64: Buffer.from('%PDF-1.4').toString('base64')
      }
    ]
  });

  const lines = text.split('\r\n');

  assert.ok(!lines.includes('X-Evil: yes'));
  assert.ok(lines.includes('Content-Type: application/pdf'));
});

test('a display name cannot break out of the From header', () => {
  const text = composed({
    ...base,
    subject: 'x',
    from_name: 'Jan\r\nBcc: attacker@evil.com'
  });

  assert.ok(!headers(text).some((line) => line.startsWith('Bcc:')));
  assert.equal(headers(text).filter((line) => line.startsWith('From:')).length, 1);
});

test('exactly one To header is emitted for several recipients', () => {
  const text = composed({
    ...base,
    to: ['one@example.com', 'two@example.com'],
    subject: 'x'
  });

  const to = headers(text).filter((line) => line.startsWith('To:'));

  assert.equal(to.length, 1);
  assert.ok(to[0]?.includes('one@example.com'));
  assert.ok(to[0]?.includes('two@example.com'));
});

test('a non-ASCII subject is encoded and decodes back unchanged', () => {
  const subject = 'Zgłoszenie — Starszy Programista';
  const text = composed({ ...base, subject });

  const line = headers(text).find((entry) => entry.startsWith('Subject:')) ?? '';

  assert.match(line, /^Subject: =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/);

  const encoded = line.replace(/^Subject: =\?UTF-8\?B\?/, '').replace(/\?=$/, '');

  assert.equal(Buffer.from(encoded, 'base64').toString('utf8'), subject);
});

test('an attachment is carried, prefix stripped, bytes intact', () => {
  const pdf = Buffer.from('%PDF-1.4 pretend cv');

  const text = composed({
    ...base,
    subject: 'Application',
    html: '<p>Hello.</p>',
    attachments: [
      {
        filename: 'cv.pdf',
        content_type: 'application/pdf',
        // What readAsDataURL produces, since cvitae is a browser application.
        content_base64: `data:application/pdf;base64,${pdf.toString('base64')}`
      }
    ]
  });

  assert.match(text, /Content-Type: multipart\/mixed/);
  assert.match(text, /Content-Type: multipart\/alternative/);
  assert.match(text, /filename="cv\.pdf"/);
  assert.ok(text.includes(pdf.toString('base64')));
});

test('raw is base64url, which is the only form Gmail accepts', () => {
  const result = compose({ ...base, subject: 'x' });

  assert.equal(result.status, 'ok');
  assert.doesNotMatch((result as { raw: string }).raw, /[+/=]/);
});

test('an oversized message is refused rather than truncated', () => {
  const result = compose({
    ...base,
    subject: 'big',
    attachments: [
      {
        filename: 'big.bin',
        content_type: 'application/octet-stream',
        content_base64: Buffer.alloc(6 * 1024 * 1024).toString('base64')
      }
    ]
  });

  assert.equal(result.status, 'too_large');
});
