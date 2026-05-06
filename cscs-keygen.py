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
proxy_token_fallback = Path(os.path.expanduser("~")) / '.config' / 'cscs-keygen' / 'proxy_token'

#Methods:
def load_config(fname):
    """Load the credentials file. Returns (mode, proxy, users, legacy).

    Supports three file shapes:
      - legacy single-user:  {"username": "...", "password": "...", "otp_secret": "..."}
      - multi-user direct:   {"users": [{"username": "...", ...}, ...]}
      - proxy fetcher:       {"mode": "proxy", "proxy": {"url": "...", "token": "..."}}
    """
    data = {}
    if fname is not None and fname.exists():
        print("Reading credentials from file: " + str(fname))
        try:
            with open(fname, 'r') as f:
                data = json.load(f)
        except Exception:
            pass

    mode = data.get('mode', 'direct') if isinstance(data, dict) else 'direct'
    proxy = data.get('proxy') if isinstance(data, dict) else None
    if not isinstance(proxy, dict):
        proxy = {}

    if isinstance(data, dict) and isinstance(data.get('users'), list):
        users, legacy = list(data['users']), False
    else:
        # Legacy / empty file: treat as a single-user entry
        legacy_entry = {
            k: v for k, v in (data.items() if isinstance(data, dict) else [])
            if k in ('username', 'password', 'otp_secret', 'key_name')
        }
        users, legacy = [legacy_entry], True

    return mode, proxy, users, legacy

def save_config_file(fname, mode, proxy, users, legacy):
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
        cleaned_users.append(entry)

    if mode == 'proxy':
        out = {'mode': 'proxy'}
        if proxy.get('url'):
            out['proxy'] = {'url': proxy['url']}
            if proxy.get('key_name'):
                out['proxy']['key_name'] = proxy['key_name']
    elif legacy and len(cleaned_users) == 1:
        out = cleaned_users[0]
    else:
        out = {'users': cleaned_users}

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
        print(f"Keyring unavailable ({e}); falling back to {proxy_token_fallback}.")
        return False

def _keyring_get(service, account):
    """Try to read from OS keyring; return None on missing entry or backend failure."""
    try:
        return keyring.get_password(service, account)
    except Exception:
        return None

def _file_token_read():
    if not proxy_token_fallback.exists():
        return None
    try:
        return proxy_token_fallback.read_text().strip() or None
    except Exception:
        return None

def _file_token_write(token):
    proxy_token_fallback.parent.mkdir(parents=True, exist_ok=True)
    proxy_token_fallback.write_text(token)
    try:
        os.chmod(proxy_token_fallback, 0o600)
    except Exception:
        pass

def get_proxy_token(proxy):
    """Resolve the proxy fetch token. Prefers keyring; falls back to a chmod-600
    file at ~/.config/cscs-keygen/proxy_token. On first run, migrates a token
    found in the config file into whichever store is available, then signals
    the caller to strip it from the config."""
    url = proxy.get('url')
    if not url:
        sys.exit("Error: proxy mode requires `proxy.url` in the credentials file.")

    account = url  # one token per proxy URL

    token = _keyring_get(proxy_service_id, account)
    if token:
        return token, False

    token = _file_token_read()
    if token:
        return token, False

    # Migration path: token still sitting in the config file from initial setup.
    if proxy.get('token'):
        token = proxy.pop('token')
        if _keyring_set(proxy_service_id, account, token):
            print("Migrated proxy token to keyring.")
        else:
            _file_token_write(token)
            print(f"Stored proxy token at {proxy_token_fallback} (chmod 600).")
        return token, True

    # Last resort: prompt.
    token = getpass.getpass("Proxy fetch token: ").strip()
    if not token:
        sys.exit("Error: proxy token is required.")
    if _keyring_set(proxy_service_id, account, token):
        print("Stored proxy token in keyring.")
    else:
        _file_token_write(token)
        print(f"Stored proxy token at {proxy_token_fallback} (chmod 600).")
    return token, False

def fetch_keys_from_proxy(proxy_url, token):
    """GET /cert from the proxy worker. Returns (public_cert, private_key)."""
    url = proxy_url.rstrip('/') + '/cert'
    print(f"Fetching keys from proxy {url}")
    try:
        resp = requests.get(url, headers={'Authorization': f'Bearer {token}'}, timeout=15)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit(f"Error: proxy fetch failed: {e}")
    body = resp.json()
    if not body.get('cert') or not body.get('key'):
        sys.exit("Error: proxy returned no cert/key (worker may not have populated yet — try POST /refresh).")
    return body['cert'], body['key']

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

def save_keys(public, private, key_name):
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

    mode, proxy, users, legacy = load_config(credentials_file)

    if mode == 'proxy':
        key_name = proxy.get('key_name') or priv_key_name
        while True:
            time_left = key_invalid_after(ssh_folder / key_name)
            if time_left > 0 and not force:
                print(f"The key is still valid for {time_left} seconds.")
                if once:
                    break
                time.sleep(time_left + 10)
                continue

            token, migrated = get_proxy_token(proxy)
            public, private = fetch_keys_from_proxy(proxy['url'], token)
            save_keys(public, private, key_name)
            print(f"Keys saved to {ssh_folder / key_name}")

            if migrated:
                print("Cleaning up token from file...")
                save_config_file(credentials_file, mode, proxy, users, legacy)

            if once or force:
                break
        return

    # mode == 'direct'
    if not users:
        users = [{}]

    # Resolve any missing usernames up-front so key file paths are known.
    file_dirty = False
    for user_entry in users:
        if not user_entry.get('username'):
            user_entry['username'] = input("Username: ").strip()
            file_dirty = True
    if file_dirty:
        save_config_file(credentials_file, mode, proxy, users, legacy)

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
            user, pwd, otp, had_file_secret = get_user_credentials(user_entry)
            had_any_file_secret = had_any_file_secret or had_file_secret
            public, private = get_keys(user, pwd, otp)
            save_keys(public, private, key_name)
            print(f"[{user}] Keys saved to {ssh_folder / key_name}")

        if had_any_file_secret:
            print("Cleaning up secrets from file...")
            save_config_file(credentials_file, mode, proxy, users, legacy)

        if force:
            break

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
