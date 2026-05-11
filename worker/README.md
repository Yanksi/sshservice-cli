# cscs-keystore (Cloudflare Worker)

A Cloudflare Worker that acts as a zero-knowledge, TTL-bounded keyring
backend. Clients PUT raw bytes (which they encrypted client-side with a
key the Worker never sees), the Worker stores them in KV under an
HMAC-obfuscated index with the requested TTL, and GET returns them
as-is until KV evicts them at expiry. The Worker doesn't know what's in
the blobs, doesn't know which CSCS account a blob belongs to, and
doesn't talk to CSCS at all — that's all the client's job.

This is the storage backend for `cscs-keygen.py`'s "remote" mode, where
one user runs the refresh on a privileged box (which has their CSCS
password and TOTP seed locally) and the resulting signed key is shared
across their other machines via this Worker so they don't burn the
5-keys-per-account quota.

## Security model

**Defended against:**

- A KV dump alone reveals nothing actionable. Each value is opaque
  ciphertext supplied by the client; the KV index is
  `HMAC(WORKER_PEPPER, token + ":" + name)`, so without both the pepper
  and a valid bearer token an attacker can't even tell which blob
  belongs to whom.
- The Worker has no encryption key. A compromised Worker operator —
  including someone with full Cloudflare dashboard access — cannot
  decrypt user data without obtaining a user's passphrase out-of-band.
- The Worker has no standing CSCS credentials, and never sees CSCS
  credentials or TOTP seeds in any form (encrypted or otherwise) at the
  protocol level. CSCS auth happens entirely on the client.
- Multi-tenant by construction: each bearer token is its own isolated
  namespace. A leaked token compromises overwrite/delete access on one
  user's records — never decryption, never anyone else.

**NOT defended against:**

- A leaked bearer token + leaked passphrase together let an attacker
  read, overwrite, and delete that user's records. Treat both as
  passwords.
- A bearer token alone (no passphrase) lets an attacker delete or
  overwrite a user's blobs — i.e. denial-of-service against that user's
  cache, forcing them to re-refresh from CSCS. They still can't read
  the existing blobs.
- Cloudflare retains visibility into request bodies in transit. The
  bodies are ciphertext, so this is uninteresting unless you don't
  trust your own client's crypto, but it's worth knowing.

## What gets deployed

- **One Worker** with three authenticated routes (PUT/GET/DELETE) and a
  health endpoint. No cron triggers.
- **One KV namespace** holding opaque client-supplied ciphertext blobs.
  Each entry carries a Cloudflare-enforced TTL — expired entries are
  physically removed by KV, so a `GET` on an expired item returns 404
  by construction.
- **One Worker secret** — `WORKER_PEPPER`, 32 bytes of randomness in
  hex. Used only as the HMAC key for index derivation; the Worker does
  not use it for encryption. Rotating it orphans every existing record
  (the KV index changes), so treat it as generate-once.

## HTTP API

All `/item/*` routes require `Authorization: Bearer <token>` where the
token is whatever the client wants — usually derived client-side from
the user's passphrase. There is no enrolment step; the first PUT for a
given token implicitly creates that user's namespace.

| Method   | Path             | Body          | Behaviour                                                                                                  |
|----------|------------------|---------------|------------------------------------------------------------------------------------------------------------|
| `GET`    | `/`              | —             | Liveness; no auth.                                                                                         |
| `PUT`    | `/item/<name>`   | raw bytes     | Stores body verbatim under `HMAC(PEPPER, token + ":" + name)`. Optional `?ttl=<seconds>` (default 86400, min 60, max 7776000). Returns `204` with `X-Expires-At: <ms>`. |
| `GET`    | `/item/<name>`   | —             | Returns the stored bytes with `Content-Type: application/octet-stream` and `X-Expires-At: <ms>`. Returns `404` if the name is missing or KV has already evicted it for expiry. |
| `DELETE` | `/item/<name>`   | —             | Deletes the record. `204` even if no record existed (idempotent).                                          |

**Rate-limit semantics on PUT:** the Worker rejects a second PUT to the
same `(token, name)` within ~60 seconds with `429` and a `Retry-After`
header. This coordinates racing refreshers: if two clients both see a
404 on GET and both fetch a fresh secret from upstream, the slower one
hits `429` on PUT instead of overwriting the winner, and can re-`GET`
to pick up the value that just landed. (The 60 s floor comes from
Cloudflare KV's minimum `expirationTtl`.)

**Status code contract for clients:**

- `200` on GET → here's your data.
- `404` on GET → refresh it.
- `429` on PUT → another writer already stored this name; re-GET, don't
  loop back to upstream a second time.
- `401` → missing/empty Bearer token.
- `400`/`413` → malformed request (bad `ttl`, empty body, body over 64 KiB).
- `500` → Worker is missing `WORKER_PEPPER`.

Limits: name ≤ 256 bytes (after URL-decoding); body ≤ 64 KiB.

## Deploying

The button in the top-level [README](../README.md) targets the
auto-generated `worker` branch (a flat-layout mirror of this directory;
see [.github/workflows/mirror-worker-branch.yml](../.github/workflows/mirror-worker-branch.yml)).
The Cloudflare deploy UI works most reliably with `wrangler.toml` at
the repository root.

### 1. Click the button

Cloudflare forks the repo, installs the Cloudflare GitHub App if
needed, provisions the KV namespace declared in `wrangler.toml`
(rewriting the all-zeros placeholder id), builds, and deploys.

### 2. Set the `WORKER_PEPPER` secret

The button does not prompt for secrets. Set it manually:

1. **Cloudflare dashboard** → **Workers & Pages** → click the Worker.
2. **Settings** → **Variables and Secrets** → **Add variable**, type
   **Secret**.
3. Name: `WORKER_PEPPER`. Value: 32 bytes of randomness in hex —
   generate locally with `openssl rand -hex 32` and paste.

Until this is set, every authenticated route returns `500` with a
clear message.

### 3. Hand out the URL to users

Each user generates their own passphrase (e.g. `openssl rand -hex 32`)
on first run of `cscs-keygen.py`, which derives both a bearer token
and an AES-GCM encryption key from it via HKDF. They keep the
passphrase secret and use the same one on every device that should
share the cached signed key. They never share their passphrase with
you (the Worker operator) or each other.

See the top-level README for the client-side flow.

## Deploy manually (no button)

```bash
cd worker
npm install
npx wrangler kv namespace create ITEM_STORE   # paste the printed id into wrangler.toml
npx wrangler secret put WORKER_PEPPER         # paste `openssl rand -hex 32`
npx wrangler deploy
```

## Operations

**Rotating `WORKER_PEPPER`:** don't. It rederives every KV index, so a
rotation makes every existing record unreachable (the data isn't
decryptable by the Worker anyway, but it becomes unreachable by name).
If you really need to rotate, all clients will start with an empty
namespace and re-push on their next refresh.

**Removing a user's data:** the user themselves DELETEs whatever
items they want. There is no admin override.

**Logs:** Cloudflare Worker logs (Workers & Pages → your Worker →
Logs) show only path/method/status by default. Bodies and headers
aren't logged. Avoid adding `console.log` of request bodies in this
codebase.
