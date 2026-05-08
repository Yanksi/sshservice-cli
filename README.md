# mfa-cscs-access

A small toolkit for fetching CSCS-signed SSH keys without having to type your
MFA code by hand each time.

Each user in `credential.json` has an `endpoint`:

- `"cscs"` (or absent) — talk directly to the CSCS sshservice. Simple, but
  every device counts toward CSCS's 5-key per-account quota.
- A proxy URL (e.g. `https://cscs-key-proxy.<sub>.workers.dev`) — register
  with a Cloudflare Worker on first run, then fetch from there. One issued
  cert across all your devices, so you stay under quota with many machines
  and clusters. Multiple users / colleagues can share the same Worker
  without sharing CSCS credentials.

`endpoint` can also live at the top level as a default for all listed users;
per-user `endpoint` overrides it. See
[credential_sample.json](credential_sample.json) for the file shape.

## Setup

```sh
git clone git@github.com:Yanksi/sshservice-cli.git
cd sshservice-cli
pip install -r requirements.txt
python cscs-keygen.py
```

Or with `uv`, which reads the inline PEP 723 metadata at the top of the
script:

```sh
uv run cscs-keygen.py
```

For Windows scheduling, see [autotask.ps1](autotask.ps1).

## How the first run works

For each user, on first run, the script needs the user's CSCS password and
TOTP seed (the base32 secret, **not** a 6-digit code). You can either let
the script prompt interactively, or pre-seed `credential.json` with the
fields filled in — the script reads them once, takes the action below, and
strips them from the file.

| Endpoint        | What happens to the password / OTP seed                                                                |
|-----------------|--------------------------------------------------------------------------------------------------------|
| `cscs`          | Stored in the OS keyring (`cscs-keygen` service). Subsequent runs read them from there.                |
| Proxy URL       | A random 256-bit bearer token is generated. The script POSTs the credentials encrypted-at-rest to the Worker, then keeps **only the token** locally (in keyring, or `~/.config/cscs-keygen/token-<...>` if no keyring backend). The local password / OTP entries are wiped — they live only on the Worker from then on. The generated token is printed once at the end of the registration so you can copy it to other devices. |

After the first run, `credential.json` contains only `username`, `endpoint`,
and (optionally) `key_name` for each user. No secrets remain on disk.

### Sharing a proxy account across devices

The first device a user registers from prints something like:

```
======================================================================
[lshuhao] Registered new proxy account on https://cscs-key-proxy.<sub>.workers.dev
[lshuhao] Proxy token (save this to use the SAME account on other devices):

    AbC...64-char-url-safe-string

[lshuhao] On another device, add it under this user's entry in credential.json:
[lshuhao]   { "username": "lshuhao", "endpoint": "https://...", "token": "<paste>" }
======================================================================
```

On the second (and subsequent) devices, put that token in `credential.json`
under the matching user entry as `"token": "..."`. The script imports it
into the keyring on first run and strips it from the file — no password /
OTP prompt, no extra `POST /account` call.

If you lose the token, just delete the user's row on the Worker (`DELETE
/account` from any device that still has the token) and re-register from
any device — a fresh token gets generated.

## Proxy mode (one-time Worker deploy)

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Yanksi/sshservice-cli/tree/worker)

The deploy URL targets the `worker` branch, which is auto-mirrored from
`worker/` on `main` by [.github/workflows/mirror-worker-branch.yml](.github/workflows/mirror-worker-branch.yml).

**Read [worker/README.md](worker/README.md) before clicking** — it covers the
security model (encrypted at rest, but the Worker briefly handles plaintext
during refresh), the one secret you set manually after deploy
(`WORKER_PEPPER`), and the HTTP API.

Once the Worker is live, set `endpoint` to the Worker URL in
`credential.json` (top-level default, or per-user) and run
`python cscs-keygen.py --once` on each device. The first run on each device
will prompt for the password / OTP seed (or read them from
`credential.json`), register the account on the Worker, and stash the
auto-generated bearer token locally.

For a `.bashrc` snippet that refreshes the cert at every shell start —
fast in proxy mode (a single ~10–40 ms HTTP roundtrip to the worker, which
serves its own ~23h cache) and a no-op for direct users whose local cert
is still valid:

```bash
if [ -x "$HOME/sshservice-cli/cscs-keygen.py" ]; then
    uv run "$HOME/sshservice-cli/cscs-keygen.py" --once >/dev/null 2>&1 &
fi
```

In proxy mode the script always hits the worker — the local mtime gate
is intentionally bypassed so the local cert can never go stale relative
to what the worker has, regardless of when the script last ran.

## Re-registering / rotating tokens

To rotate a token (or fully reset a user's proxy state), run:

```sh
python cscs-keygen.py --delete-account <username>
```

This DELETEs the user's record on the Worker and clears the local token
(keyring + fallback file). The next normal run will re-register from
scratch — put the password / OTP seed back in `credential.json`, or let
the script prompt for them, and a fresh token gets generated.

For ad-hoc cleanup without the script (e.g. starting over on a single
device), deleting the keyring entry (`cscs-keygen_proxy` service,
account `<username>::<endpoint>`) or the fallback file under
`~/.config/cscs-keygen/` is enough — the next run treats that as
"register a new account" and overwrites the prior server-side record.

If you revoked the cert in the CSCS dashboard and want a fresh one
right away (without waiting up to 23h for the Worker's cache to expire):

```sh
python cscs-keygen.py --once --force
```

This propagates as `?force=1` to `GET /credential`, so the Worker
ignores its cache and hits CSCS directly. The Worker rate-limits forced
refreshes to 1/min per token to prevent loops or accidental hammering.
