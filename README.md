# cvitae-mail

The mailbox, in a process of its own.

[cvitae-agent-runtime](../cvitae-agent-runtime) drafts job applications; this
delivers them. It is a sibling in the same sense cvitae-scrapper is one: a
separate service on loopback, optional, and written to be absent. If it is not
running, `MAIL_URL` is unset, or no mailbox is connected, the runtime reports
that and carries on.

## Why it is not just a module in the runtime

Because of what the credential is. An API key can be rotated after a leak and
the damage is a bill. A mailbox token is read access to everything the user has
ever been sent and the ability to write as them, and by the time it is rotated
someone has already read the inbox. Keeping it in a process that holds neither
the CV nor the model provider keys means a leak in one is not a leak in both.

Being exact about the size of that win: **this does not stop a compromised
runtime from calling `/draft`.** It stops one from holding the token. Those are
different things and only the second is on offer here.

## The split that actually matters

Not between the two processes — between who is trusted to decide.

| Endpoint | Decided by |
| --- | --- |
| `/connect`, `/callback`, `/disconnect` | the user, in a browser |
| `/draft`, `/send` | the runtime, for a recipient the user confirmed in cvitae's UI |
| `/search` | safe to reach from a model tool loop |

The line runs between the last two rows. `/search` returns text strangers wrote
and sent; `/draft` is an outbound channel. A model holding both, next to a CV,
is the complete exfiltration triangle — untrusted input, private data, somewhere
to put it — and job offers scraped off public boards already put attacker-
controlled prose into this system's model context. Keep the drafting path out of
every tool set and the triangle has no third side.

This is why `analyze_offer`'s extracted `how_to_apply` address must reach the UI
as *a suggestion the user clicks*, never as a recipient the runtime uses on its
own. A model that read the offer chose that address.

## Drafts, not sends

`MAIL_ALLOW_SEND` is off by default. With it off the only outbound operation is
`POST /draft`: the message appears in Gmail's Drafts folder and a human presses
Send. Nothing this service does can put a message in front of another person.

That property is worth the one click, and it is worth more here than in most
places, because the subject line and body were written by a small model reading
scraped text.

**The honest caveat.** Google has no scope granting "create drafts but never
send". `gmail.compose` is the narrowest that can write a draft and it carries the
ability to send. So the guarantee is enforced by this service not exposing a send
path, not by the token. A stolen token can still send — which is the argument for
keeping it here rather than in the runtime.

## Quick start

```bash
pnpm install
```

```bash
cp .env.example .env
```

Create an OAuth client at
[console.cloud.google.com/apis/credentials](https://console.cloud.google.com/apis/credentials),
in a project with the **Gmail API** enabled. Application type must be **Desktop
app** — Google permits loopback redirects for that type and refuses them for a
web application. Put the id and secret in `.env`.

```bash
pnpm dev
```

Then open `http://127.0.0.1:8789/connect` in a browser and grant consent. The
refresh token lands in `~/.cvitae-mail/tokens.json` at `0600`, and
`GET /health` will name the connected address.

Google will warn that the app is unverified. That is expected for a desktop
client used by its own author; add yourself as a test user on the consent screen.

## Endpoints

Loopback-bound, no authentication. It holds a live mailbox credential, so `HOST`
is fixed at `127.0.0.1` and is deliberately not configurable.

| Method | Path | Does |
| --- | --- | --- |
| GET | `/health` | configured, connected, which address, which scopes |
| GET | `/connect` | redirects to Google's consent screen |
| GET | `/callback` | receives the code; stores the refresh token |
| POST | `/disconnect` | revokes at Google and deletes the local token |
| POST | `/draft` | composes and creates a Gmail draft |
| POST | `/send` | sends immediately; 403 unless `MAIL_ALLOW_SEND=true` |
| GET | `/search?q=&limit=` | Gmail search, **headers only** |

### The outcome contract

Every answer carries its outcome in the body, never only in the status code:

```jsonc
{ "status": "ok", "data": { "id": "r-8837…" } }
{ "status": "not_connected", "detail": "No mailbox is connected…" }
```

The runtime decides on `status`. This is the lesson cvitae-scrapper already paid
for: a `403` here means "Google refused a scope", not "this service is broken",
and a client reading HTTP codes would fall back or retry on exactly the wrong
ones. The reasons are `not_configured`, `not_connected`, `not_allowed`,
`invalid_request`, `too_large`, `rate_limited`, `forbidden`, `unreachable`,
`auth_failed` and `upstream_error`.

### Drafting

```jsonc
{
  "to": ["recruiter@example.com"],
  "subject": "Application — Senior Frontend Engineer",
  "text": "…",
  "from_name": "Jan Kowalski",
  "attachments": [
    { "filename": "cv.pdf", "content_type": "application/pdf", "content_base64": "JVBERi0…" }
  ]
}
```

A `data:…;base64,` prefix is accepted, since that is what `readAsDataURL`
produces and cvitae is a browser application.

Message ceiling is 5MB after encoding. Gmail's JSON upload — the one taking
`raw` in the body — tops out around there; larger needs the resumable endpoint,
which is a different protocol for a case a job application does not have.

### Searching

```
GET /search?q=subject:application newer_than:14d&limit=10
```

Returns `id`, `thread_id`, `from`, `subject`, `date` and `snippet`. **Headers
only, and that is a ceiling rather than an unfinished feature.** This is the one
surface meant to be model-reachable, and a message body is text an arbitrary
stranger wrote — the most directly attacker-controlled input anywhere in this
system. Headers answer the question worth asking of a mailbox here ("has anyone
replied about my applications?") while keeping hostile prose out of model
context.

Reading a full thread is a reasonable next thing to want. It should be its own
endpoint, taking an id the *user* picked from these results.

## Security notes worth keeping

**Header injection.** A subject carrying a CRLF stops being a value and becomes
the start of another header — `Offer\r\nBcc: someone@else` is a blind copy the
sender never wrote. Here the subject line is written by a model reading scraped
text, so untrusted input reaching a header is the normal case. `mime.ts` strips
CR and LF at the single point every header goes through; keep it that way.

**Authorization code injection.** `/callback` is an unauthenticated endpoint any
web page can make the browser request. Without the `state` nonce, a page could
redirect to `127.0.0.1:8789/callback?code=<attacker's code>` and connect the
attacker's mailbox — after which every draft the runtime writes lands somewhere
else. PKCE is there for the same class of reason: a desktop client's secret ships
with the application and is not one.

**Token file.** `0700` on the directory, `0600` on the file, both set explicitly
rather than left to the umask, which on a shared machine would otherwise produce
a world-readable mailbox credential. Writes are temp-file-plus-rename with a UUID
in the temp name, so two concurrent writes cannot collide.

## Tests

```bash
pnpm test
```

Nine checks over `mime.ts`, which is the part worth testing without a mailbox:
pure, deterministic, and the place where a mistake is a security bug rather than
a broken feature. They cover header injection through the subject, the display
name, the attachment filename and the content type, plus encoding, attachments
and the size ceiling.

The filename case earned its keep immediately — it found that flattening CRLF
stopped a header being introduced but still let a quote and a semicolon sit
inside the `Content-Disposition` parameter. `attachmentFilename` exists because
of that test.

## Wired up

cvitae reaches this through cvitae-agent-runtime rather than directly — a
browser cannot open a loopback port, and the app has no business knowing which
one this is. The chain is:

```
cvitae  ──POST /api/mail/draft──▶  runtime ──POST /mail/draft──▶  cvitae-mail ──▶ Gmail
```

Neither hop exposes a send route. This service still can, behind
`MAIL_ALLOW_SEND`, but nothing upstream calls it.

## Status

Every path that does not require Google has been exercised: the service starts,
`/health` reports `not_configured`, `/draft` refuses with `not_connected`,
`/send` refuses with `not_allowed` while sending is off, `/search` rejects an
empty query, and the runtime's client maps each of those onto `failed` while
treating an absent service as `unavailable`. The nine composer tests pass.

**Verified against a live mailbox.** The OAuth client was created, consent
granted, and the whole path exercised end to end: the code exchange stored a
refresh token, `/search` returned real headers, and `/draft` created a real
Gmail draft carrying a PDF — confirmed by Gmail's own
`in:drafts has:attachment filename:cv.pdf`. `/send` refused, as it should while
`MAIL_ALLOW_SEND` is off.

What is still unexercised is the token *refresh* under real expiry: the access
token lives about an hour, and every call so far has been inside one window. The
first call an hour after connecting is the one that proves `invalid_grant`
handling, and nothing has waited that long yet.
