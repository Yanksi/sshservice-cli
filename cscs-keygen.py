# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "progress==1.6",
#     "psutil",
#     "pyotp",
#     "requests==2.25.1",
#     "keyring",
# ]
# ///

# This script sets the environment properly so that a user can access CSCS
# login nodes via ssh.

#    Copyright (C) 2023, ETH Zuerich, Switzerland
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 3 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    AUTHORS Massimo Benini

import getpass
import requests
import os
import secrets
import sys
import time
import json
import pyotp
from pathlib import Path
import psutil
import argparse
import keyring
# from progress.bar import IncrementalBar

#Variables:
api_get_keys = 'https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key'
service_id = 'cscs-keygen'
proxy_service_id = 'cscs-keygen_proxy'
ssh_folder = Path(os.path.expanduser("~")) / '.ssh'
priv_key_name = 'cscs-key'
proxy_token_fallback_dir = Path(os.path.expanduser("~")) / '.config' / 'cscs-keygen'

# Sentinel value used in the `endpoint` field to mean "talk to CSCS directly".
# Anything else is treated as a proxy URL.
DIRECT_ENDPOINT = 'cscs'

#Methods:
def load_config(fname):
    """Load the credentials file. Returns (default_endpoint, users, legacy).

    Supports two file shapes:
      - legacy single-user:  {"username": "...", "endpoint": "...", "password": "...", "otp_secret": "..."}
      - multi-user:          {"endpoint": "...", "users": [{"username": "...", "endpoint": "...", ...}, ...]}

    `endpoint` is "cscs" (or absent → defaults to "cscs") for direct-to-CSCS
    auth, or a proxy URL like "https://cscs-key-proxy.<sub>.workers.dev".
    """
    data = {}
    if fname is not None and fname.exists():
        print("Reading credentials from file: " + str(fname))
        try:
            with open(fname, 'r') as f:
                data = json.load(f)
        except Exception:
            pass

    if not isinstance(data, dict):
        data = {}

    default_endpoint = data.get('endpoint', DIRECT_ENDPOINT) or DIRECT_ENDPOINT

    if isinstance(data.get('users'), list):
        users, legacy = list(data['users']), False
    else:
        # Legacy single-user file: top-level fields belong to one user entry.
        legacy_entry = {
            k: v for k, v in data.items()
            if k in ('username', 'password', 'otp_secret', 'key_name', 'endpoint')
        }
        users, legacy = [legacy_entry], True

    return default_endpoint, users, legacy

def resolve_endpoint(user_entry, default_endpoint):
    """Per-user `endpoint` overrides the top-level default."""
    return user_entry.get('endpoint') or default_endpoint or DIRECT_ENDPOINT

def is_proxy_endpoint(endpoint):
    return endpoint and endpoint != DIRECT_ENDPOINT

def save_config_file(fname, default_endpoint, users, legacy):
    """Persist non-secret config back to disk. Secrets live only in the keyring
    (or the chmod-600 fallback file when keyring is unavailable)."""
    if not fname:
        return
    cleaned_users = []
    for u in users:
        if not u.get('username'):
            continue
        entry = {'username': u['username']}
        if 'key_name' in u:
            entry['key_name'] = u['key_name']
        # Preserve per-user endpoint only when it differs from the top-level default.
        ep = u.get('endpoint')
        if ep and ep != default_endpoint:
            entry['endpoint'] = ep
        cleaned_users.append(entry)

    if legacy and len(cleaned_users) == 1:
        # Legacy single-user shape: flatten endpoint to top level if non-default.
        out = {'username': cleaned_users[0]['username']}
        if 'key_name' in cleaned_users[0]:
            out['key_name'] = cleaned_users[0]['key_name']
        ep = users[0].get('endpoint') or default_endpoint
        if ep and ep != DIRECT_ENDPOINT:
            out['endpoint'] = ep
    else:
        out = {}
        if default_endpoint and default_endpoint != DIRECT_ENDPOINT:
            out['endpoint'] = default_endpoint
        out['users'] = cleaned_users

    try:
        with open(fname, 'w') as f:
            json.dump(out, f, indent=4)
    except Exception as e:
        print(f"Warning: Could not save credentials file: {e}")

def resolve_key_name(user_entry, legacy):
    """Default key name: `cscs-key` for legacy single-user, `cscs-key-<username>` otherwise."""
    if user_entry.get('key_name'):
        return user_entry['key_name']
    if legacy:
        return priv_key_name
    return f"{priv_key_name}-{user_entry['username']}"

def get_user_credentials(user_entry):
    """Resolve (user, pwd, otp) for a single user entry, prompting as needed.
    Returns (user, pwd, otp, had_file_secret) where the last flag indicates a
    password/otp_secret was migrated out of the on-disk file into the keyring."""
    user = user_entry.get('username')
    if not user:
        user = input("Username: ").strip()
        user_entry['username'] = user

    pwd = keyring.get_password(service_id, user)
    had_file_secret = False
    if not pwd:
        if 'password' in user_entry:
            pwd = user_entry.pop('password')
            keyring.set_password(service_id, user, pwd)
            print(f"[{user}] Migrated password to keyring.")
            had_file_secret = True
        else:
            pwd = getpass.getpass(f"[{user}] Password: ")
            keyring.set_password(service_id, user, pwd)

    otp_secret = keyring.get_password(service_id + "_otp", user)
    otp = None

    if otp_secret:
        otp = pyotp.TOTP(otp_secret).now()
    else:
        if 'otp_secret' in user_entry:
            otp_secret = user_entry.pop('otp_secret')
            keyring.set_password(service_id + "_otp", user, otp_secret)
            otp = pyotp.TOTP(otp_secret).now()
            print(f"[{user}] Migrated OTP secret to keyring.")
            had_file_secret = True
        else:
            while not otp:
                inp = getpass.getpass(f"[{user}] Enter OTP (6-digit code) or OTP Secret to store: ")
                clean_inp = inp.strip()
                if len(clean_inp) == 6 and clean_inp.isdigit():
                    otp = clean_inp
                elif clean_inp:
                    try:
                        otp = pyotp.TOTP(clean_inp).now()
                        keyring.set_password(service_id + "_otp", user, clean_inp)
                        print(f"[{user}] OTP Secret stored in keyring.")
                    except:
                        print("Invalid input. Please enter a valid 6-digit OTP code or a valid OTP Secret.")
                else:
                    print("Input cannot be empty.")

    return user, pwd, otp, had_file_secret

def _keyring_set(service, account, secret):
    """Try to store in OS keyring; return True on success, False if backend unavailable."""
    try:
        keyring.set_password(service, account, secret)
        return True
    except Exception as e:
        print(f"Keyring unavailable ({e}); falling back to {proxy_token_fallback_dir}.")
        return False

def _keyring_get(service, account):
    """Try to read from OS keyring; return None on missing entry or backend failure."""
    try:
        return keyring.get_password(service, account)
    except Exception:
        return None

def _keyring_delete(service, account):
    """Best-effort delete from keyring. Silent on missing entries or backend failure."""
    try:
        keyring.delete_password(service, account)
    except Exception:
        pass

def _proxy_token_path(account):
    """Per-account file path for the keyring fallback."""
    # Use a stable, filesystem-safe filename derived from the account label.
    safe = ''.join(c if c.isalnum() or c in '-._' else '_' for c in account)
    return proxy_token_fallback_dir / f'token-{safe}'

def _file_token_read(account):
    fp = _proxy_token_path(account)
    if not fp.exists():
        return None
    try:
        return fp.read_text().strip() or None
    except Exception:
        return None

def _file_token_write(account, token):
    fp = _proxy_token_path(account)
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(token)
    try:
        os.chmod(fp, 0o600)
    except Exception:
        pass

def _file_token_delete(account):
    fp = _proxy_token_path(account)
    try:
        fp.unlink(missing_ok=True)
    except Exception:
        pass

def _store_proxy_token(account, token):
    """Save token to keyring; fall back to chmod-600 file if keyring is unavailable."""
    if _keyring_set(proxy_service_id, account, token):
        print(f"Stored proxy token in keyring (account={account}).")
    else:
        _file_token_write(account, token)
        print(f"Stored proxy token at {_proxy_token_path(account)} (chmod 600).")

def _read_proxy_token(account):
    """Look up the proxy token by account label. Returns None if not present."""
    t = _keyring_get(proxy_service_id, account)
    if t:
        return t
    return _file_token_read(account)

def proxy_account_label(username, endpoint):
    """Stable label for keyring + fallback file lookups."""
    return f"{username}::{endpoint}"

def register_proxy_account(endpoint, token, username, password, otp_secret):
    """POST /account to the proxy worker. Stores encrypted CSCS credentials there."""
    url = endpoint.rstrip('/') + '/account'
    print(f"[{username}] Registering account on proxy {url}")
    try:
        resp = requests.post(
            url,
            headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
            data=json.dumps({'username': username, 'password': password, 'otp_secret': otp_secret}),
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        sys.exit(f"Error: proxy registration failed: {e}")
    if not resp.ok:
        try:
            err = resp.json().get('error', resp.text)
        except Exception:
            err = resp.text
        sys.exit(f"Error: proxy returned HTTP {resp.status_code}: {err}")

def fetch_keys_from_proxy(endpoint, token):
    """GET /credential from the proxy worker. Returns (public_cert, private_key, generated_at_ms).

    generated_at_ms is when the worker fetched the cert from CSCS, used to anchor
    local mtime to the CSCS-side creation time instead of this fetch time."""
    url = endpoint.rstrip('/') + '/credential'
    print(f"Fetching keys from proxy {url}")
    try:
        resp = requests.get(url, headers={'Authorization': f'Bearer {token}'}, timeout=30)
    except requests.exceptions.RequestException as e:
        sys.exit(f"Error: proxy fetch failed: {e}")
    if resp.status_code == 401:
        sys.exit(
            "Error: proxy rejected token. The local token may be stale; delete the keyring entry "
            f"`{proxy_service_id}` for this user and re-run to re-register."
        )
    if not resp.ok:
        try:
            err = resp.json().get('error', resp.text)
        except Exception:
            err = resp.text
        sys.exit(f"Error: proxy returned HTTP {resp.status_code}: {err}")
    body = resp.json()
    if not body.get('cert') or not body.get('key'):
        sys.exit("Error: proxy returned no cert/key.")
    generated_at = body.get('generated_at')
    if not isinstance(generated_at, (int, float)):
        generated_at = None
    return body['cert'], body['key'], generated_at

def ensure_proxy_account(user_entry, endpoint):
    """Ensure the worker has an account for this user. Returns (token, file_dirty).

    If a token already exists locally for (username, endpoint), returns it.
    Otherwise gathers password + OTP secret (file → migrate-and-prompt fallback),
    generates a fresh token, registers with the worker, stores the token, and
    erases any locally-cached password/OTP keyring entries for this user since
    they now live encrypted on the worker."""
    username = user_entry['username']
    account = proxy_account_label(username, endpoint)
    file_dirty = False

    existing = _read_proxy_token(account)
    if existing:
        return existing, file_dirty

    # No local token for this (user, endpoint) — register a new account.
    print(f"[{username}] No proxy token cached locally for {endpoint}; registering a new account.")

    # Resolve password.
    if 'password' in user_entry:
        password = user_entry.pop('password')
        file_dirty = True
    else:
        password = keyring.get_password(service_id, username)
        if not password:
            password = getpass.getpass(f"[{username}] CSCS password: ")

    # Resolve OTP secret. Must be a TOTP seed (base32), not a 6-digit code,
    # because the worker generates fresh codes on every refresh.
    if 'otp_secret' in user_entry:
        otp_secret = user_entry.pop('otp_secret')
        file_dirty = True
    else:
        otp_secret = keyring.get_password(service_id + "_otp", username)
        if not otp_secret:
            while True:
                inp = getpass.getpass(
                    f"[{username}] CSCS TOTP secret (base32 seed, NOT a 6-digit code): "
                ).strip()
                if not inp:
                    print("Input cannot be empty.")
                    continue
                try:
                    pyotp.TOTP(inp).now()
                except Exception:
                    print("That doesn't look like a valid base32 TOTP seed. Try again.")
                    continue
                otp_secret = inp
                break

    # Validate the OTP secret one last time, regardless of source.
    try:
        pyotp.TOTP(otp_secret).now()
    except Exception as e:
        sys.exit(f"Error: stored OTP secret is not valid base32: {e}")

    token = secrets.token_urlsafe(32)
    register_proxy_account(endpoint, token, username, password, otp_secret)
    _store_proxy_token(account, token)

    # Wipe locally-cached CSCS secrets for this user — they only live on the worker now.
    _keyring_delete(service_id, username)
    _keyring_delete(service_id + "_otp", username)

    return token, file_dirty

def get_keys(username, password, otp):
    print(f"[{username}] Fetching keys from CSCS...")
    headers = {'Content-Type': 'application/json', 'Accept':'application/json'}
    data = {
        "username": username,
        "password": password,
        "otp": otp
    }
    try:
        resp = requests.post(api_get_keys, data=json.dumps(data), headers=headers, verify=True)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        try:
            d_payload = e.response.json()
        except:
            raise SystemExit(e)
        if "payload" in d_payload and "message" in d_payload["payload"]:
            print("Error: "+d_payload["payload"]["message"])
        raise SystemExit(e)
    else:
        public_key = resp.json()['public']
        if not public_key:
            sys.exit("Error: Unable to fetch public key.")
        private_key = resp.json()['private']
        if not private_key:
            sys.exit("Error: Unable to fetch private key.")
        return public_key, private_key

def save_keys(public, private, key_name, generated_at_ms=None):
    if not public or not private:
        sys.exit("Error: invalid keys.")
    priv_path = ssh_folder / key_name
    pub_path = ssh_folder / f"{key_name}-cert.pub"
    try:
        with open(pub_path, 'w') as file:
            file.write(public)
    except IOError as er:
        sys.exit(f'Error: writing public key failed: {er}')
    try:
        with open(priv_path, 'w') as file:
            file.write(private)
    except IOError as er:
        sys.exit(f'Error: writing private key failed: {er}')
    try:
        os.chmod(pub_path, 0o644)
    except Exception as ex:
        sys.exit(f'Error: cannot change permissions of the public key: {ex}')
    try:
        os.chmod(priv_path, 0o600)
    except Exception as ex:
        sys.exit(f'Error: cannot change permissions of the private key: {ex}')
    # Anchor mtime to the CSCS-side creation time so key_invalid_after()
    # measures against when the cert was signed, not when we fetched it.
    if generated_at_ms is not None:
        ts = generated_at_ms / 1000.0
        try:
            os.utime(pub_path, (ts, ts))
            os.utime(priv_path, (ts, ts))
        except Exception as ex:
            print(f"Warning: could not set mtime from generated_at: {ex}")

def key_invalid_after(priv_key_f):
    curr_time = int(time.time())
    if not priv_key_f.exists():
        return 0
    modified_time = int(os.path.getmtime(priv_key_f))
    return max(86400 - (curr_time - modified_time), 0) # number of seconds left for the key to expire

def main(credentials_file=None, once=False, force=False):
    credential_folder = Path(__file__).parent
    # check if a file called pid exists in the same folder as the script
    # if it does, then the script is already running
    if not once: # if the script is running only once, then there is no need to check for other instances
        pid_file = credential_folder / 'pid'
        if pid_file.exists():
            # kill the previous process
            with open(pid_file, 'r') as f:
                pid = int(f.read())
                if psutil.pid_exists(pid):
                    ps = psutil.Process(pid)
                    # check if the process is actually a the previous process
                    cmdline = ps.cmdline()
                    if len(cmdline) == 2 and 'python' in cmdline[0] and 'cscs-keygen.py' in cmdline[1]:
                        print("The script is already running. Terminating the previous process...")
                        ps.terminate()

        # write the current process id to the pid file
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))

    default_endpoint, users, legacy = load_config(credentials_file)
    if not users:
        users = [{}]

    # Resolve any missing usernames up-front so key file paths are known.
    file_dirty = False
    for user_entry in users:
        if not user_entry.get('username'):
            user_entry['username'] = input("Username: ").strip()
            file_dirty = True
    if file_dirty:
        save_config_file(credentials_file, default_endpoint, users, legacy)

    while True:
        min_time_left = min(
            key_invalid_after(ssh_folder / resolve_key_name(u, legacy))
            for u in users
        )
        if min_time_left > 0 and not force:
            print("The key is still valid for " + str(min_time_left) + " seconds.")
            if once:
                break
            time.sleep(min_time_left + 10) # sleep for 10 seconds more than the time left

        had_any_file_secret = False
        for user_entry in users:
            key_name = resolve_key_name(user_entry, legacy)
            time_left = key_invalid_after(ssh_folder / key_name)
            if time_left > 0 and not force:
                continue

            endpoint = resolve_endpoint(user_entry, default_endpoint)
            username = user_entry['username']

            if is_proxy_endpoint(endpoint):
                token, dirty = ensure_proxy_account(user_entry, endpoint)
                had_any_file_secret = had_any_file_secret or dirty
                public, private, generated_at = fetch_keys_from_proxy(endpoint, token)
                save_keys(public, private, key_name, generated_at)
                print(f"[{username}] Keys saved to {ssh_folder / key_name}")
            else:
                user, pwd, otp, had_file_secret = get_user_credentials(user_entry)
                had_any_file_secret = had_any_file_secret or had_file_secret
                public, private = get_keys(user, pwd, otp)
                save_keys(public, private, key_name)
                print(f"[{user}] Keys saved to {ssh_folder / key_name}")

        if had_any_file_secret:
            print("Cleaning up secrets from file...")
            save_config_file(credentials_file, default_endpoint, users, legacy)

        if once or force:
            break
        # Otherwise loop: the next iteration's validity-check sleep handles cadence.

#     message = """

# Usage:

# 1. Add the key to the SSH agent"""+substrg+"""
# ssh-add -t 1d ~/.ssh/cscs-key

# 2. Connect to the login node using CSCS keys:
# ssh -A your_usernamen@<CSCS-LOGIN-NODE>

# Note - if the key is not added to the SSH agent as mentioned in the step-1 above then use the command:
# ssh -i ~/.ssh/cscs-key <CSCS-LOGIN-NODE>

# """
#     print(message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate CSCS keys')
    parser.add_argument('--once', action='store_true', help='Run the script only once')
    parser.add_argument('--force', action='store_true', help='Force the script to run even if the key is still valid')
    parser.add_argument('--credentials', type=str, help='Path to the credentials file', default=Path(__file__).parent / 'credential.json')
    args = parser.parse_args()
    exit(main(args.credentials, args.once, args.force))
