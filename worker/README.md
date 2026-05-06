# cscs-key-proxy (Cloudflare Worker)

A tiny Cloudflare Worker that holds your CSCS credentials, refreshes the
short-lived SSH key+cert from the CSCS sshservice on a cron schedule, and
serves the latest cert to authorised client devices over HTTPS.

This exists to work around CSCS's 5-keys-per-account quota: instead of every
device/cluster running `cscs-keygen.py` and burning a slot, only the Worker
talks to CSCS, and every device fetches the same cert from the Worker.

## Security tradeoff (read this)

The Worker stores your **CSCS username + password + TOTP seed** as Worker
secrets. That is a meaningful escalation from running `cscs-keygen.py`
locally:

- **Local:** an attacker who steals the cert has 24h of access.
- **Worker:** an attacker who compromises the Worker (Cloudflare account
  takeover, leaked secrets, malicious dependency) has *persistent* CSCS access
  until you rotate the password and TOTP seed.

The upside is one issued cert across all your devices, well under the quota.
Deploy this only if you're comfortable with that tradeoff. Cloudflare secrets
are encrypted at rest and not visible in logs, but they are exfiltrable by
anyone with write access to the Worker code.

## What gets deployed

- **One Worker** with two HTTP endpoints and a cron trigger.
- **One KV namespace** holding the latest `{ key, cert, generated_at }` JSON.
- **Four Worker secrets**: `CSCS_USERNAME`, `CSCS_PASSWORD`, `CSCS_OTP_SECRET`,
  `FETCH_TOKEN`.

The cron fires every 12h (`0 */12 * * *`). CSCS certs are valid for 24h.

## HTTP API

All non-`/` routes require `Authorization: Bearer <FETCH_TOKEN>`.

| Method | Path       | Description                                         |
|--------|------------|-----------------------------------------------------|
| `GET`  | `/`        | Liveness check; no auth.                            |
| `GET`  | `/cert`    | Returns the current cert as JSON.                   |
| `POST` | `/refresh` | Force a fresh fetch from CSCS. Rate-limited to 1/min. |

`GET /cert` response shape:

```json
{
  "key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "cert": "ssh-ed25519-cert-v01@openssh.com AAAA... lshuhao",
  "generated_at": 1746559200000
}
```

## Deploy via the button (recommended)

Click **Deploy to Cloudflare Workers** in the top-level [README](../README.md).
The Cloudflare UI will:

1. Fork the repo into your account.
2. Provision the KV namespace defined in `wrangler.toml`.
3. Prompt you for the four secrets above.
4. Deploy the Worker and start the cron.

You can then `POST /refresh` once to populate the KV before the first cron
fires.

## Deploy manually

```bash
cd worker
npm install
npx wrangler kv namespace create CERT_STORE     # paste the printed id into wrangler.toml
npx wrangler secret put CSCS_USERNAME
npx wrangler secret put CSCS_PASSWORD
npx wrangler secret put CSCS_OTP_SECRET         # base32 seed, NOT a 6-digit code
npx wrangler secret put FETCH_TOKEN             # generate one, e.g. `openssl rand -hex 32`
npx wrangler deploy
```

Then trigger the first refresh:

```bash
curl -X POST -H "Authorization: Bearer $FETCH_TOKEN" \
  https://cscs-key-proxy.<your-subdomain>.workers.dev/refresh
```

## Rotating tokens

`FETCH_TOKEN` rotation: `wrangler secret put FETCH_TOKEN`, then update each
client's keyring entry (or `~/.config/cscs-keygen/proxy_token` fallback).

CSCS password / TOTP rotation: re-run `wrangler secret put CSCS_PASSWORD` /
`CSCS_OTP_SECRET`. The next cron tick (or a `POST /refresh`) picks up the new
values.
