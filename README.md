# mfa-cscs-access

A small toolkit for fetching CSCS-signed SSH keys without having to type your
MFA code by hand each time.

There are two ways to use it:

- **Direct mode** — each device runs `cscs-keygen.py` against the CSCS
  sshservice. Simple, but every device counts toward CSCS's 5-key per-account
  quota.
- **Proxy mode** — a Cloudflare Worker holds your CSCS credentials, refreshes
  the cert on a 12-hour cron, and serves it to your devices. One issued cert
  across all your machines, so you stay under quota even with many devices and
  clusters.

## Direct mode (default)

```sh
git clone git@github.com:eth-cscs/sshservice-cli.git
cd sshservice-cli
pip install virtualenv          # if you don't already have it
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
python cscs-keygen.py
```

Or use the shell script:

```sh
bash cscs-keygen.sh
```

The first run prompts for username/password/OTP and stores the secrets in your
OS keyring. See [credential_sample.json](credential_sample.json) for the
multi-user file format (direct mode); see
[credential_sample_proxy.json](credential_sample_proxy.json) for the proxy-mode
shape.

## Proxy mode

Deploy the Worker once, then point every device's `credential.json` at it.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Yanksi/sshservice-cli/tree/worker)

> The deploy URL targets the `worker` branch, which is auto-mirrored from
> `worker/` on `main` by [.github/workflows/mirror-worker-branch.yml](.github/workflows/mirror-worker-branch.yml).

**Read [worker/README.md](worker/README.md) before clicking** — it covers the
security tradeoff (the Worker holds your password + TOTP seed), the
post-deploy steps the button does *not* cover (you set the four secrets
manually in the dashboard), the HTTP API, and rotation procedures.

Once the Worker is live, point each device at it via `credential.json`:

```json
{
    "mode": "proxy",
    "proxy": {
        "url": "https://cscs-key-proxy.<your-subdomain>.workers.dev",
        "token": "<paste FETCH_TOKEN here, will be moved to keyring on first run>"
    }
}
```

Then run:

```sh
python cscs-keygen.py --once
```

The token is moved to the OS keyring (`cscs-keygen_proxy` service) on the
first run and stripped from the file. On clusters without a keyring backend
(e.g. headless CSCS login nodes), it falls back to a `chmod 600` file at
`~/.config/cscs-keygen/proxy_token`.

For a `.bashrc` snippet that refreshes the cert in the background only when
it's about to expire:

```bash
if [ -x "$HOME/sshservice-cli/cscs-keygen.py" ]; then
    python "$HOME/sshservice-cli/cscs-keygen.py" --once >/dev/null 2>&1 &
fi
```
