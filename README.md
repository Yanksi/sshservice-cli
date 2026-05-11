# mfa-cscs-access

A small toolkit for fetching CSCS-signed SSH keys without having to type your
MFA code by hand each time.

Each user in `credential.json` has an `endpoint`:

- `"cscs"` (or absent) — talk directly to the CSCS sshservice. Simple, but
  every device counts toward CSCS's 5-key per-account quota.
- A remote-keystore URL (e.g. `https://cscs-key-proxy.<sub>.workers.dev`) —
  share one CSCS-signed key across many machines via a zero-knowledge
  Cloudflare Worker. The Worker is a generic encrypted-blob TTL store —
  it never sees plaintext credentials or keys. Each device that holds the
  user's passphrase can read the cached key, and any device with the
  passphrase can refresh from CSCS when the cached key expires. Multiple
  users / colleagues can share the same Worker without sharing
  passphrases with each other.

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

| Endpoint            | What happens to the password / OTP seed                                                                |
|---------------------|--------------------------------------------------------------------------------------------------------|
| `cscs`              | Stored in the OS keyring (`cscs-keygen` service). Subsequent runs read them from there.                |
| Remote-keystore URL | A random 256-bit passphrase is generated locally. The script HKDFs it into a bearer token (server auth) and an AES-GCM-256 key (client-side encryption), then pushes `{username, password, otp_secret}` to the Worker as ciphertext under `cscs/<user>/creds` with a 90-day TTL. The passphrase is stashed locally (in keyring, or `~/.config/cscs-keygen/passphrase-<...>` if no keyring backend). The local password / OTP keyring entries are wiped — they live only on the remote keystore from then on. The passphrase is printed once at the end of registration so you can copy it to other devices. |

After the first run, `credential.json` contains only `username`, `endpoint`,
and (optionally) `key_name` for each user. No secrets remain on disk.

### Sharing a remote-keystore account across devices

The first device a user registers from prints something like:

```
======================================================================
[lshuhao] Generated a new remote-keyring passphrase for https://cscs-key-proxy.<sub>.workers.dev
[lshuhao] Copy this to any OTHER device that should share the same cached key:

    AbC...43-char-url-safe-string

[lshuhao] On another device, add it under this user's entry in credential.json:
[lshuhao]   { "username": "lshuhao", "endpoint": "https://...", "passphrase": "<paste>" }
======================================================================
```

On the second (and subsequent) devices, put that passphrase in
`credential.json` under the matching user entry as `"passphrase": "..."`.
The script imports it into the local keyring on first run and strips it
from the file — no password / OTP prompt; the CSCS credentials sit
encrypted on the remote keystore and the second device decrypts them
locally when it needs to refresh.

If you lose the passphrase, just run `python cscs-keygen.py
--delete-account <username>` from any device that still has it (this
DELETEs `cscs/<user>/creds` and `cscs/<user>/key` from the Worker and
clears the local passphrase). Then re-register from any device — a
fresh passphrase gets generated.

## Remote-keystore mode (one-time Worker deploy)

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Yanksi/sshservice-cli/tree/worker)

The deploy URL targets the `worker` branch, which is auto-mirrored from
`worker/` on `main` by [.github/workflows/mirror-worker-branch.yml](.github/workflows/mirror-worker-branch.yml).

**Read [worker/README.md](worker/README.md) before clicking** — it covers
the zero-knowledge model (client-side AES-GCM-256, the Worker never sees
plaintext), the one secret you set manually after deploy
(`WORKER_PEPPER`, used only as an HMAC key for KV-index obfuscation),
and the HTTP API.

Once the Worker is live, set `endpoint` to the Worker URL in
`credential.json` (top-level default, or per-user) and run
`python cscs-keygen.py --once` on each device. The first run on each
device will either prompt for the password / OTP seed (pushed to the
remote keystore, encrypted) or read an existing passphrase you copied
from another device.

For a `.bashrc` snippet that refreshes the cert at every shell start —
typically a single ~10–40 ms round-trip when the cached key on the
remote keystore is still valid, transparently refreshing from CSCS only
when the Worker returns 404 for an expired/missing cached key:

```bash
if [ -x "$HOME/sshservice-cli/cscs-keygen.py" ]; then
    uv run "$HOME/sshservice-cli/cscs-keygen.py" --once >/dev/null 2>&1 &
fi
```

In remote-keystore mode the script always asks the Worker for the
current cached key — the local mtime gate is bypassed because the
Worker enforces expiry via KV's `expirationTtl`, so a 200 from the
Worker is by definition a still-valid cert.

## Re-registering / rotating credentials

To rotate the passphrase (or fully reset a user's remote state), run:

```sh
python cscs-keygen.py --delete-account <username>
```

This DELETEs both `cscs/<user>/creds` and `cscs/<user>/key` on the
Worker and clears the local passphrase (keyring + fallback file). The
next normal run will generate a fresh passphrase, prompt for the CSCS
password / OTP seed (or read them from `credential.json`), and re-push.

For ad-hoc cleanup without the script (e.g. starting over on a single
device), deleting the keyring entry (`cscs-keygen_remote` service,
account `<username>::<endpoint>`) or the fallback file under
`~/.config/cscs-keygen/` is enough — the next run treats that as a
fresh registration and overwrites the prior remote records.

If you revoked the cert in the CSCS dashboard and want a fresh one
right away (without waiting up to 23h for the Worker's cached key to
expire):

```sh
python cscs-keygen.py --once --force
```

This bypasses the cached-key check on the client side, fetches the CSCS
credentials from the remote keystore, calls CSCS for a fresh cert, and
pushes the result. If two devices both `--force` within the Worker's
60-second PUT rate-limit window, the slower one is told to re-GET (HTTP
429) instead of overwriting the winner, so the 5-key quota is preserved.
