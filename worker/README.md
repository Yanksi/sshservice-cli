# cscs-key-proxy (Cloudflare Worker)

A Cloudflare Worker that brokers CSCS-signed SSH keys for one or more users
without storing standing CSCS credentials. Each user POSTs their CSCS
credentials encrypted with a bearer token of their choosing; the Worker
keeps only opaque ciphertext in KV. On `GET /credential`, the Worker
decrypts with the supplied token, fetches a fresh cert from CSCS if the
cached one is older than 23h, re-encrypts, and returns the plaintext key+cert.

This solves CSCS's 5-keys-per-account quota (one issued cert across all your
machines, regardless of count) and lets you and your colleagues share the
same Worker without sharing CSCS credentials with each other.

## Security model — what this does and does not give you

**Threats this defends against:**

- A KV dump alone reveals nothing actionable. Each blob is AES-GCM-256
  encrypted; the key is `HKDF(salt=PEPPER, ikm=token)` and the KV index
  is `HMAC(PEPPER, "user:" + token)` — without both `WORKER_PEPPER` and a
  valid bearer token, an attacker can't even tell which blob belongs to
  whom.
- The Worker has no standing access to anyone's CSCS account. It can
  only act on behalf of a token holder, and only while a request is in
  flight.
- Multi-tenant by construction: each token is its own isolated record.
  A leaked token compromises exactly one CSCS account, not everyone's.

**Threats this does NOT defend against:**

- The Worker briefly handles plaintext credentials in memory while
  refreshing from CSCS (it has to, to compute the TOTP and call the
  sshservice). An attacker who can modify the Worker code can exfiltrate
  plaintext at that moment. **Trust in the Worker operator (whoever
  controls the Cloudflare account) is required.**
- A leaked bearer token gives full access to that user's CSCS account
  for as long as the token is valid. Treat tokens like passwords.
- Cloudflare has full visibility into request bodies. Don't deploy this
  to a Cloudflare account you don't trust.
- This is **encrypted-at-rest**, not zero-knowledge in the strict
  cryptographic sense (the Worker sees plaintext during the refresh
  step). The README intentionally avoids the "zero-knowledge" label for
  that reason.

If those tradeoffs aren't acceptable, run `cscs-keygen.py` directly on
each device instead — at the cost of the 5-key quota.

## What gets deployed

- **One Worker** with three HTTP endpoints (POST/GET/DELETE). No cron.
- **One KV namespace** holding per-user `AES-GCM(record)` blobs.
- **One Worker secret** — `WORKER_PEPPER`, 32 bytes of randomness in hex,
  generated once and never rotated. Rotating it makes every existing
  encrypted blob unrecoverable.

## HTTP API

All `/account` and `/credential` routes require
`Authorization: Bearer <token>` where `<token>` is the per-user secret
chosen by the caller. Tokens have no server-side enrolment step — the
first `POST /account` with a given token implicitly creates the
account.

| Method   | Path           | Body                                         | Behaviour                                                                                                |
|----------|----------------|----------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `GET`    | `/`            | —                                            | liveness; no auth.                                                                                       |
| `POST`   | `/account`     | `{ "username", "password", "otp_secret" }`   | Encrypts the body and stores it under `HMAC(PEPPER, "user:"+token)`. Overwrites any prior record.        |
| `DELETE` | `/account`     | —                                            | Deletes the KV record for this token. 204 even if no record existed (idempotent).                        |
| `GET`    | `/credential`  | —                                            | Returns `{ key, cert, generated_at }`. If the cached cert is older than 23h, the Worker refreshes it.    |

`POST /account` request body:

```json
{
  "username":   "lshuhao",
  "password":   "...",
  "otp_secret": "JBSWY3DPEHPK3PXP"   // base32 TOTP seed, NOT a 6-digit code
}
```

`GET /credential` response:

```json
{
  "key":          "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "cert":         "ssh-ed25519-cert-v01@openssh.com AAAA... lshuhao",
  "generated_at": 1746559200000
}
```

Errors are JSON of the form `{ "error": "..." }` with conventional
status codes (`400` malformed body, `401` missing/invalid token, `502`
upstream CSCS error, `500` Worker misconfigured).

## Deploying

The button in the top-level [README](../README.md) targets the
auto-generated `worker` branch (a flat-layout mirror of this directory;
see [.github/workflows/mirror-worker-branch.yml](../.github/workflows/mirror-worker-branch.yml)).
The Cloudflare deploy UI works most reliably with `wrangler.toml` at
the repository root.

### 1. Click the button

Cloudflare will fork the repo, install the Cloudflare GitHub App if
needed, provision the KV namespace declared in `wrangler.toml`
(rewriting the all-zeros placeholder id), build, and deploy.

### 2. Set the `WORKER_PEPPER` secret

The button does not prompt for secrets. Set it manually:

1. **Cloudflare dashboard** → **Workers & Pages** → click the Worker.
2. **Settings** → **Variables and Secrets** → **Add variable**, type
   **Secret**.
3. Name: `WORKER_PEPPER`. Value: 32 bytes of randomness in hex —
   generate locally with `openssl rand -hex 32` and paste.

Until this is set, every authenticated route returns 500 with a clear
message. After it's set, the Worker is ready to accept registrations.

### 3. Hand out the URL to users

Each user generates their own bearer token (e.g. `openssl rand -hex 32`),
keeps it secret, and registers their own CSCS credentials. They never
need to share their token with you, the Worker operator, or each other.

A user's first call:

```bash
TOKEN="<their token>"
curl -X POST -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"username":"<cscs-user>","password":"<cscs-pwd>","otp_secret":"<base32-seed>"}' \
     https://cscs-key-proxy.<sub>.workers.dev/account
```

Then any time after that:

```bash
curl -H "Authorization: Bearer $TOKEN" \
     https://cscs-key-proxy.<sub>.workers.dev/credential
# → { "key": "...", "cert": "...", "generated_at": ... }
```

## Deploy manually (no button)

```bash
cd worker
npm install
npx wrangler kv namespace create CERT_STORE     # paste the printed id into wrangler.toml
npx wrangler secret put WORKER_PEPPER           # paste `openssl rand -hex 32`
npx wrangler deploy
```

## Operations

**Rotating `WORKER_PEPPER`:** don't. It rederives every account's
encryption key and KV index, so a rotation invalidates every existing
record. If you really need to rotate, all users must re-`POST /account`.

**Removing a user:** the user themselves can `DELETE /account` with their
own token. There is no admin override (by design — the Worker operator
should not be able to enumerate or delete user records).

**Logs:** Cloudflare Worker logs (Workers & Pages → your Worker →
Logs) show only path/method/status by default. Bodies and headers
aren't logged. Avoid adding `console.log` of request bodies in this
codebase.
