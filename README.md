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
| Proxy URL       | A random bearer token is generated. The script POSTs the credentials encrypted-at-rest to the Worker, then keeps **only the token** locally (in keyring, or `~/.config/cscs-keygen/token-<...>` if no keyring backend). The local password / OTP entries are wiped — they live only on the Worker from then on. |

After the first run, `credential.json` contains only `username`, `endpoint`,
and (optionally) `key_name` for each user. No secrets remain on disk.

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

For a `.bashrc` snippet that refreshes the cert in the background only when
it's about to expire:

```bash
if [ -x "$HOME/sshservice-cli/cscs-keygen.py" ]; then
    python "$HOME/sshservice-cli/cscs-keygen.py" --once >/dev/null 2>&1 &
fi
```

## Re-registering / rotating tokens

If you delete the keyring entry (`cscs-keygen_proxy` service, account
`<username>::<endpoint>`) or the fallback file under
`~/.config/cscs-keygen/`, the next run treats it as a fresh registration:
prompts for password / OTP, generates a new token, calls `POST /account`
(which overwrites the prior record on the Worker), and stores the new
token. No re-deploy needed.

To remove an account from the Worker, the device that holds the token can
DELETE it (see [worker/README.md](worker/README.md#http-api)).
