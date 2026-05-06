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
- **Four Worker secrets** that you set after deploy: `CSCS_USERNAME`,
  `CSCS_PASSWORD`, `CSCS_OTP_SECRET`, `FETCH_TOKEN`.

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

The button is in the top-level [README](../README.md). It targets the
auto-generated `worker` branch, which is a flat-layout mirror of this
directory (see [.github/workflows/mirror-worker-branch.yml](../.github/workflows/mirror-worker-branch.yml))
because Cloudflare's deploy UI works most reliably with `wrangler.toml` at
the repository root.

The walkthrough below is one-time setup; afterwards every push to `main`
that touches `worker/` redeploys automatically through Cloudflare Workers
Builds.

### 1. Click the button

The Cloudflare UI will:

- Authenticate you with Cloudflare (and prompt to install the Cloudflare
  GitHub App if it isn't already).
- Fork the repo into your account.
- Provision the KV namespace declared in `wrangler.toml`. The placeholder
  `id = "0000…"` value is rewritten with the real id during deploy.
- Build and deploy the Worker, register the cron.

### 2. Set the secrets manually

The button **does not prompt for secrets** — it only ever prompts for
plaintext `[vars]` declared in `wrangler.toml`, which secrets are not. Set
them in the dashboard right after deploy:

1. **Cloudflare dashboard** → **Workers & Pages** → click your Worker.
2. **Settings** → **Variables and Secrets** → **Add variable**.
3. For each row below, set the **Type** to **Secret** and click Save:

   | Name                | Value                                                                |
   |---------------------|----------------------------------------------------------------------|
   | `CSCS_USERNAME`     | Your CSCS username                                                   |
   | `CSCS_PASSWORD`     | Your CSCS password                                                   |
   | `CSCS_OTP_SECRET`   | Your TOTP **seed** (base32). Not a 6-digit code.                     |
   | `FETCH_TOKEN`       | A random bearer token; e.g. `openssl rand -hex 32`. Save a copy — clients need it. |

Until all four are present, the cron will error on every tick with a
clear log line in the Worker's "Logs" tab.

### 3. Trigger the first refresh

The next cron is up to 12 hours away, so kick off a refresh manually so
clients have something to fetch immediately:

```bash
curl -X POST -H "Authorization: Bearer <FETCH_TOKEN>" \
  https://cscs-key-proxy.<your-subdomain>.workers.dev/refresh
```

A `200` with `{ "key": "...", "cert": "...", "generated_at": ... }` means
the whole pipeline (CSCS auth, TOTP generation, KV write) is healthy.
Anything else: open the Worker's Logs tab in the dashboard and read the
error.

### 4. Point clients at the Worker

In each device's `credential.json`:

```json
{
  "mode": "proxy",
  "proxy": {
    "url": "https://cscs-key-proxy.<your-subdomain>.workers.dev",
    "token": "<FETCH_TOKEN>"
  }
}
```

The token is moved into the OS keyring (or
`~/.config/cscs-keygen/proxy_token` chmod-600 fallback) on the first
`python cscs-keygen.py --once` and stripped from the file.

## Deploy manually (no button)

If you'd rather skip the button and run wrangler yourself:

```bash
cd worker
npm install
npx wrangler kv namespace create CERT_STORE     # paste the printed id into wrangler.toml
npx wrangler secret put CSCS_USERNAME
npx wrangler secret put CSCS_PASSWORD
npx wrangler secret put CSCS_OTP_SECRET         # base32 seed, NOT a 6-digit code
npx wrangler secret put FETCH_TOKEN             # e.g. `openssl rand -hex 32`
npx wrangler deploy
```

Then trigger the first refresh as in step 3 above.

## Rotating secrets

`FETCH_TOKEN` rotation: dashboard (or `wrangler secret put FETCH_TOKEN`),
then update each client's keyring entry (or
`~/.config/cscs-keygen/proxy_token` fallback).

CSCS password / TOTP rotation: re-run `wrangler secret put CSCS_PASSWORD`
/ `CSCS_OTP_SECRET`. The next cron tick (or a `POST /refresh`) picks up
the new values.
