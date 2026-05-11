# mfa-cscs-access

A small toolkit for fetching CSCS-signed SSH keys without retyping your
MFA code each time. Cache lives in a TTL-aware keyring — either the
local OS keyring or a Cloudflare Worker you deploy yourself for
cross-device sharing.

## How it works

`cscs-keygen.py` is a thin CLI over two modules:

- **`ttl_keyring`** — a TTL-aware abstraction with two backends:
  - `"local"`: wraps the OS keyring with client-side expiry.
  - `"remote"`: talks to a Cloudflare Worker (see [worker/](worker/))
    that stores client-encrypted blobs with a TTL.
- **`cscs_client`** — the CSCS-specific glue. Given a `TTLKeyring`,
  `ensure_key(username)` reads the cached signed key and writes it to
  `~/.ssh`. CSCS itself is contacted **only** when the cached key is
  missing or expired — every other run is a single keyring read plus
  two file writes.

Each user in `credential.json` picks the backend via an `endpoint`:

- `"cscs"` (or absent) — talk to CSCS directly, cache in the OS keyring
  of the current device. Every device counts toward CSCS's 5-key
  per-account quota.
- A Worker URL — talk to CSCS through your own deployed Worker. One
  CSCS-signed key can be shared across many devices that hold the
  user's passphrase; the quota is consumed once per refresh cycle, not
  once per device.

Nothing sensitive lives in `credential.json`. Passwords, TOTP seeds,
remote passphrases, and deployment access secrets all live in the OS
keyring.

## Setup

```sh
git clone git@github.com:Yanksi/sshservice-cli.git
cd sshservice-cli
pip install -r requirements.txt
python cscs-keygen.py
```

Or with `uv`, which reads the inline PEP 723 metadata at the top of the
script (no `pip install` step):

```sh
uv run cscs-keygen.py
```

The first run will prompt for a username if `credential.json` doesn't
exist, then proceed with first-time setup for whichever backend the
endpoint points to.

For Windows scheduling, see [autotask.ps1](autotask.ps1).

## `credential.json`

Holds only routing information — no secrets, ever:

```json
{
    "endpoint": "https://cscs-key-proxy.<sub>.workers.dev",
    "users": [
        {"username": "alice"},
        {"username": "bob", "key_name": "cscs-bob-custom"}
    ]
}
```

- Top-level `endpoint` is the default for every user. Optional;
  defaults to `"cscs"` (direct mode).
- Per-user `endpoint` overrides the default. Optional.
- `key_name` overrides the default `cscs-key-<username>` for the
  on-disk file in `~/.ssh`. Optional.

See [credential_sample.json](credential_sample.json) for a full example.

## First run — direct mode (`endpoint: "cscs"`)

The script prompts for your CSCS password and base32 TOTP seed (the
TOTP **seed**, not a 6-digit code). They go straight into the OS
keyring under `ttl_keyring.local`, and the script then calls CSCS and
writes `~/.ssh/cscs-key-<username>` + `~/.ssh/cscs-key-<username>-cert.pub`.

Subsequent runs read the cached key from the OS keyring and write it
back out to `~/.ssh`. CSCS is only contacted again once the cache
entry expires (~23 hours), at which point the stored credentials are
used to mint a fresh cert.

## First run — remote-keystore mode (Worker URL endpoint)

### Step 1: deploy the Worker (once per group of devices)

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Yanksi/sshservice-cli/tree/worker)

The deploy URL targets the `worker` branch, auto-mirrored from
`worker/` on `main` by
[.github/workflows/mirror-worker-branch.yml](.github/workflows/mirror-worker-branch.yml).

**Read [worker/README.md](worker/README.md) before clicking.** It
covers the zero-knowledge model (client-side AES-GCM-256, the Worker
never sees plaintext), the one required secret you set manually after
deploy (`WORKER_PEPPER`), the optional bot-deflector secret
(`WORKER_ACCESS_SECRET`), and the HTTP API.

### Step 2: first device — generate a passphrase

Put the Worker URL into `credential.json` and run:

```sh
python cscs-keygen.py
```

The script prints:

```
First-time remote-keystore setup for https://cscs-key-proxy.<sub>.workers.dev.
  [g] Generate a fresh passphrase (this is your first device).
  [p] Paste an existing passphrase (another device already registered).
Choose [g/p]:
```

Pick **g**. The script announces the freshly generated passphrase:

```
======================================================================
[alice] Generated a new remote-keystore passphrase for https://cscs-key-proxy.<sub>.workers.dev.
[alice] Copy this to any OTHER device that should share the same cached key:

    AbC...43-char-url-safe-string

[alice] On another device, run cscs-keygen.py and choose 'paste existing'
[alice] when prompted. The passphrase is stored only in the OS keyring,
[alice] never on disk.
======================================================================
```

**Copy the passphrase to a safe place** before continuing — it never
appears on screen again. The script then prompts for your CSCS
password and TOTP seed; those get pushed to the Worker as ciphertext
(under `cscs/<user>/creds`, 90-day TTL) and stay only there. The
script writes `~/.ssh/cscs-key-<username>` + cert and exits.

If the Worker has `WORKER_ACCESS_SECRET` set, the script will prompt
once for that separately and cache it in the OS keyring.

### Step 3: subsequent devices — paste the passphrase

On a new device with the same Worker URL in `credential.json`:

```sh
python cscs-keygen.py
```

```
Choose [g/p]: p
Paste passphrase: <paste>
```

That's it — the script derives the bearer token + AES key from the
passphrase, GETs the existing credentials and signed key from the
Worker, decrypts them locally, and writes the key out to `~/.ssh`. No
CSCS round-trip on this device; no password / OTP prompt.

## Rotation and recovery

### Rotate the passphrase or fully reset a user

```sh
python cscs-keygen.py --delete-account <username>
```

For a remote-endpoint user this DELETEs `cscs/<user>/creds` and
`cscs/<user>/key` on the Worker and clears the locally-cached remote
config. The next normal run will treat it as first-time setup. For a
direct-endpoint user it just wipes the local OS-keyring entries.

### Force a fresh fetch from CSCS

If you revoked the cert in the CSCS dashboard and don't want to wait
up to ~23 h for the cached key to expire:

```sh
python cscs-keygen.py --force
```

In remote mode, if two devices both `--force` within the Worker's
60-second PUT rate-limit window, the slower one gets HTTP 429 and
re-GETs the winner's blob — so the 5-key CSCS quota is preserved.

### Recover from a lost passphrase

You can't. The Worker only stores ciphertext that nobody but a
passphrase-holder can decrypt; that's the whole zero-knowledge point.
Run `--delete-account` from any device that still has the passphrase,
then re-register. If no device has it, delete the Worker's KV namespace
(or wait out the TTL) and re-register from scratch.

## Drop-in cert refresh from `.bashrc`

```bash
if [ -x "$HOME/sshservice-cli/cscs-keygen.py" ]; then
    uv run "$HOME/sshservice-cli/cscs-keygen.py" >/dev/null 2>&1 &
fi
```

In remote-keystore mode the typical refresh is a single ~10–40 ms
round-trip — the Worker holds the signed key, the client decrypts and
writes it. CSCS is contacted only when the Worker returns 404 for an
expired or missing cached key.
