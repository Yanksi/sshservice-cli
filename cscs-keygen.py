# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "progress==1.6",
#     "psutil",
#     "pyotp",
#     "requests==2.25.1",
#     "keyring",
#     "cryptography>=42",
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
import remote_keyring
# from progress.bar import IncrementalBar

#Variables:
api_get_keys = 'https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key'
service_id = 'cscs-keygen'
# Service id for the local OS-keyring entry that holds the per-(user,endpoint)
# passphrase. The passphrase is the one secret the user types/copies between
# devices; the `remote_keyring` module HKDFs it into a bearer token and an
# AES-GCM key locally.
remote_service_id = 'cscs-keygen_remote'
# Service id for the OS-keyring entry that holds the per-endpoint
# deployment access secret (the WORKER_ACCESS_SECRET bot-deflector).
# Shared across all users of a given endpoint, so the keyring `account`
# is the endpoint URL itself rather than a (user, endpoint) tuple.
remote_access_service_id = 'cscs-keygen_remote_access'
ssh_folder = Path(os.path.expanduser("~")) / '.ssh'
priv_key_name = 'cscs-key'
passphrase_fallback_dir = Path(os.path.expanduser("~")) / '.config' / 'cscs-keygen'

# TTLs on the remote keyring side. CSCS-signed certs are valid 24h, so we
# expire the cached key just under that and let the client refresh. The
# login credentials live much longer — they only change when CSCS forces
# a password / TOTP reset, which is rare.
KEY_TTL_SECONDS = 23 * 60 * 60
CREDS_TTL_SECONDS = 90 * 24 * 60 * 60

# Sentinel value used in the `endpoint` field to mean "talk to CSCS directly".
# Anything else is treated as a remote-keystore URL.
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

def is_remote_endpoint(endpoint):
    return endpoint and endpoint != DIRECT_ENDPOINT


# Old alias kept for callers that haven't been renamed yet.
is_proxy_endpoint = is_remote_endpoint

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
        print(f"Keyring unavailable ({e}); falling back to {passphrase_fallback_dir}.")
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

def _passphrase_path(account):
    """Per-account file path for the keyring fallback."""
    # Use a stable, filesystem-safe filename derived from the account label.
    safe = ''.join(c if c.isalnum() or c in '-._' else '_' for c in account)
    return passphrase_fallback_dir / f'passphrase-{safe}'

def _file_passphrase_read(account):
    fp = _passphrase_path(account)
    if not fp.exists():
        return None
    try:
        return fp.read_text().strip() or None
    except Exception:
        return None

def _file_passphrase_write(account, passphrase):
    fp = _passphrase_path(account)
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(passphrase)
    try:
        os.chmod(fp, 0o600)
    except Exception:
        pass

def _file_passphrase_delete(account):
    fp = _passphrase_path(account)
    try:
        fp.unlink(missing_ok=True)
    except Exception:
        pass

def _store_passphrase(account, passphrase):
    """Save passphrase to keyring; fall back to chmod-600 file if keyring is unavailable."""
    if _keyring_set(remote_service_id, account, passphrase):
        print(f"Stored remote keyring passphrase in OS keyring (account={account}).")
    else:
        _file_passphrase_write(account, passphrase)
        print(f"Stored remote keyring passphrase at {_passphrase_path(account)} (chmod 600).")

def _read_passphrase(account):
    """Look up the passphrase by account label. Returns None if not present."""
    t = _keyring_get(remote_service_id, account)
    if t:
        return t
    return _file_passphrase_read(account)

def remote_account_label(username, endpoint):
    """Stable label for keyring + fallback file lookups."""
    return f"{username}::{endpoint}"

# ---------- deployment access secret (WORKER_ACCESS_SECRET) ----------
# Per-endpoint, shared across all users of that endpoint. Cached locally
# so each device only needs to be prompted once. The Worker decides
# whether it's required at all (operator sets / unsets the secret on
# the Worker side); the client only learns about it via a 403 →
# AccessDenied at runtime.

def _safe_endpoint(endpoint):
    return ''.join(c if c.isalnum() or c in '-._' else '_' for c in endpoint)

def _access_path(endpoint):
    return passphrase_fallback_dir / f'access-{_safe_endpoint(endpoint)}'

def _file_access_read(endpoint):
    fp = _access_path(endpoint)
    if not fp.exists():
        return None
    try:
        return fp.read_text().strip() or None
    except Exception:
        return None

def _file_access_write(endpoint, secret):
    fp = _access_path(endpoint)
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(secret)
    try:
        os.chmod(fp, 0o600)
    except Exception:
        pass

def _file_access_delete(endpoint):
    fp = _access_path(endpoint)
    try:
        fp.unlink(missing_ok=True)
    except Exception:
        pass

def _read_access_secret(endpoint):
    """OS keyring → file fallback. Returns None if neither holds a value
    (which is also the steady state for Workers that have no
    WORKER_ACCESS_SECRET configured)."""
    s = _keyring_get(remote_access_service_id, endpoint)
    if s:
        return s
    return _file_access_read(endpoint)

def _store_access_secret(endpoint, secret):
    if _keyring_set(remote_access_service_id, endpoint, secret):
        print(f"Stored Worker access secret in OS keyring (endpoint={endpoint}).")
    else:
        _file_access_write(endpoint, secret)
        print(f"Stored Worker access secret at {_access_path(endpoint)} (chmod 600).")

def _clear_access_secret(endpoint):
    _keyring_delete(remote_access_service_id, endpoint)
    _file_access_delete(endpoint)

def _prompt_access_secret(endpoint):
    print()
    print(f"The Worker at {endpoint} requires a deployment access secret (X-Access-Secret).")
    print("Get this value from whoever runs the Worker.")
    while True:
        s = getpass.getpass(f"Access secret for {endpoint}: ").strip()
        if s:
            return s
        print("Input cannot be empty.")

def with_access_retry(endpoint, passphrase, fn):
    """Call `fn(store)` once with the locally-cached access secret. On
    AccessDenied (HTTP 403), clear the cache, prompt the operator-shared
    secret from the user, rebuild the store, and try `fn` exactly once
    more. The new secret is cached only on a successful retry, so a
    typo doesn't poison the local cache.

    Use this around every entry point that does real work against the
    remote keystore (the main refresh loop, the `--delete-account`
    flow), not around every individual store call — one prompt per
    invocation, not per HTTP request."""
    cached = _read_access_secret(endpoint)
    store = remote_keyring.RemoteSecretStore(endpoint, passphrase, access_secret=cached)
    try:
        return fn(store)
    except remote_keyring.AccessDenied:
        if cached:
            print(f"Cached access secret for {endpoint} was rejected by the Worker (403).")
        # else: nothing was cached — first run on a Worker that has
        # WORKER_ACCESS_SECRET set. Either way, ask the user.
        _clear_access_secret(endpoint)

    new_secret = _prompt_access_secret(endpoint)
    store = remote_keyring.RemoteSecretStore(endpoint, passphrase, access_secret=new_secret)
    result = fn(store)
    _store_access_secret(endpoint, new_secret)
    return result

def _remote_key_name(username):
    """Remote-keyring item name for the cached signed key/cert blob."""
    return f"cscs/{username}/key"

def _remote_creds_name(username):
    """Remote-keyring item name for the encrypted CSCS login credentials."""
    return f"cscs/{username}/creds"

def _prompt_cscs_password(username):
    return getpass.getpass(f"[{username}] CSCS password: ")

def _prompt_otp_secret(username):
    """Prompt until the user supplies a valid base32 TOTP seed."""
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
        return inp

def ensure_remote_passphrase(user_entry, endpoint):
    """Resolve (or freshly generate) the per-(user, endpoint) remote-keyring
    passphrase. Returns (passphrase, file_dirty).

    Resolution order:
      1. Cached locally in the OS keyring (or chmod-600 fallback file).
      2. Provided in the credential file under `passphrase` — adopted into
         local storage and stripped from the file.
      3. (Legacy) provided in the credential file under `token` — adopted as
         the passphrase. Old multi-device setups copied a `token` between
         devices; we accept it under the new name so users don't have to
         hand-edit every credential.json.
      4. Generate a fresh 256-bit random passphrase, print it once so the
         user can copy it to their other devices, and store it locally.
    """
    username = user_entry['username']
    account = remote_account_label(username, endpoint)
    file_dirty = False

    existing = _read_passphrase(account)
    if existing:
        # Defensive cleanup: strip anything secret-shaped from the file now
        # that the passphrase lives in the local keyring/fallback.
        leftover = [k for k in ('password', 'otp_secret', 'token', 'passphrase') if k in user_entry]
        if leftover:
            for k in leftover:
                user_entry.pop(k, None)
            file_dirty = True
        return existing, file_dirty

    # Path 2 / 3: passphrase supplied in the file (copied from another device).
    supplied = user_entry.pop('passphrase', None) or user_entry.pop('token', None)
    if supplied:
        file_dirty = True
        _store_passphrase(account, supplied)
        print(f"[{username}] Adopted remote-keyring passphrase from credential file.")
        return supplied, file_dirty

    # Path 4: brand new account on this device — generate and announce.
    print(f"[{username}] No remote-keyring passphrase cached locally for {endpoint}; generating a fresh one.")
    passphrase = secrets.token_urlsafe(32)
    _store_passphrase(account, passphrase)

    border = "=" * 70
    print()
    print(border)
    print(f"[{username}] Generated a new remote-keyring passphrase for {endpoint}.")
    print(f"[{username}] Copy this to any OTHER device that should share the same cached key:")
    print()
    print(f"    {passphrase}")
    print()
    print(f"[{username}] On another device, add it under this user's entry in credential.json:")
    print(f'[{username}]   {{ "username": "{username}", "endpoint": "{endpoint}", "passphrase": "<paste>" }}')
    print(f"[{username}] The passphrase moves to the local keyring on first run and is stripped from the file.")
    print(border)
    print()
    return passphrase, file_dirty

def remote_ensure_creds(store, user_entry):
    """Make sure CSCS login credentials exist on the remote keyring for this
    user, prompting + uploading them if absent. Returns (password, otp_secret,
    file_dirty).

    Sources, in order:
      1. The remote keyring (decrypted client-side).
      2. The credential file (password / otp_secret keys), then promoted to
         the remote keyring with a long TTL and stripped from the file.
      3. The local direct-mode OS-keyring entries.
      4. Interactive prompt.
    """
    username = user_entry['username']
    file_dirty = False

    item = store.get_json(_remote_creds_name(username))
    if isinstance(item, dict) and item.get('password') and item.get('otp_secret'):
        return item['password'], item['otp_secret'], file_dirty

    # Need to seed the remote keyring with creds. Gather them locally.
    if 'password' in user_entry:
        password = user_entry.pop('password')
        file_dirty = True
    else:
        password = keyring.get_password(service_id, username)
        if not password:
            password = _prompt_cscs_password(username)

    if 'otp_secret' in user_entry:
        otp_secret = user_entry.pop('otp_secret')
        file_dirty = True
    else:
        otp_secret = keyring.get_password(service_id + "_otp", username)
        if not otp_secret:
            otp_secret = _prompt_otp_secret(username)

    # Validate the OTP secret before storing, regardless of source — a bad
    # secret here will fail every subsequent refresh, so fail fast.
    try:
        pyotp.TOTP(otp_secret).now()
    except Exception as e:
        sys.exit(f"Error: stored OTP secret is not valid base32: {e}")

    print(f"[{username}] Storing CSCS credentials on remote keyring (encrypted client-side).")
    try:
        store.set_json(
            _remote_creds_name(username),
            {'password': password, 'otp_secret': otp_secret},
            ttl=CREDS_TTL_SECONDS,
        )
    except remote_keyring.WriteRateLimited:
        # Highly unusual on the creds path (this only runs at first setup
        # or after creds expiry), but treat it as harmless: another device
        # just pushed the same thing.
        print(f"[{username}] Remote creds were updated by another device concurrently; using what's there.")
    except remote_keyring.RemoteStoreError as e:
        sys.exit(f"Error: failed to push CSCS credentials to remote keyring: {e}")

    # Wipe locally-cached CSCS secrets for this user — they only live on the
    # remote keyring now.
    _keyring_delete(service_id, username)
    _keyring_delete(service_id + "_otp", username)

    return password, otp_secret, file_dirty

def remote_get_or_refresh(store, user_entry, force=False):
    """Resolve a usable signed key for `user_entry`, refreshing from CSCS if
    necessary. Returns (public_cert, private_key, generated_at_ms, file_dirty).

    Flow:
      1. If not `force`, GET cscs/<user>/key from the remote keyring. On hit,
         return the cached blob.
      2. On miss (404, KV has evicted for expiry), fetch CSCS login creds
         (from the remote keyring or, on first run, locally) and call CSCS
         to mint a fresh key.
      3. PUT the new key back to the remote keyring with KEY_TTL_SECONDS.
         If another refresher beat us to the punch (HTTP 429 from the
         Worker), re-GET to pick up the value they just wrote instead of
         hammering CSCS again.
    """
    username = user_entry['username']
    key_item_name = _remote_key_name(username)

    if not force:
        cached = store.get_json(key_item_name)
        if isinstance(cached, dict) and cached.get('public') and cached.get('private'):
            print(f"[{username}] Using cached signed key from remote keyring.")
            return (
                cached['public'],
                cached['private'],
                cached.get('generated_at'),
                False,
            )

    # Refresh path.
    password, otp_secret, file_dirty = remote_ensure_creds(store, user_entry)
    otp = pyotp.TOTP(otp_secret).now()
    public, private = get_keys(username, password, otp)
    generated_at_ms = int(time.time() * 1000)

    try:
        store.set_json(
            key_item_name,
            {'public': public, 'private': private, 'generated_at': generated_at_ms},
            ttl=KEY_TTL_SECONDS,
        )
        print(f"[{username}] Pushed fresh signed key to remote keyring (TTL {KEY_TTL_SECONDS}s).")
    except remote_keyring.WriteRateLimited:
        # Another device just pushed; trust their write over ours rather
        # than burning a second slot in the CSCS 5-key quota.
        print(f"[{username}] Another device just pushed a fresh key; using theirs.")
        cached = store.get_json(key_item_name)
        if isinstance(cached, dict) and cached.get('public') and cached.get('private'):
            return (
                cached['public'],
                cached['private'],
                cached.get('generated_at'),
                file_dirty,
            )
        # Race lost but the winner's blob already vanished or won't decrypt:
        # fall through with our own freshly-minted pair.
    except remote_keyring.RemoteStoreError as e:
        # Non-rate-limit errors are unusual — log but still use our local
        # copy, since the user already has a working cert.
        print(f"[{username}] Warning: failed to push key to remote keyring: {e}")

    return public, private, generated_at_ms, file_dirty

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

def do_delete_account(credentials_file, target_username):
    """Tear down the remote-keyring entries for `target_username` and clear the
    locally-cached passphrase. After this, the next normal run will generate
    a fresh passphrase, prompt for CSCS credentials, and push them anew."""
    default_endpoint, users, legacy = load_config(credentials_file)
    matched = [u for u in users if u.get('username') == target_username]
    if not matched:
        sys.exit(f"Error: no user `{target_username}` in {credentials_file}.")

    for user_entry in matched:
        endpoint = resolve_endpoint(user_entry, default_endpoint)
        if not is_remote_endpoint(endpoint):
            print(f"[{target_username}] endpoint is `{endpoint}`, not a remote-keystore URL — nothing to delete.")
            continue

        account = remote_account_label(target_username, endpoint)
        passphrase = _read_passphrase(account)
        if passphrase:
            def _delete_both(store):
                for name in (_remote_key_name(target_username), _remote_creds_name(target_username)):
                    try:
                        store.delete(name)
                        print(f"[{target_username}] Deleted remote item `{name}`.")
                    except remote_keyring.RemoteStoreError as e:
                        print(f"[{target_username}] Warning: failed to delete `{name}`: {e}")
            try:
                with_access_retry(endpoint, passphrase, _delete_both)
            except remote_keyring.RemoteStoreError as e:
                print(f"[{target_username}] Warning: could not contact remote keystore at {endpoint}: {e}")
        else:
            print(f"[{target_username}] No local passphrase for {endpoint}; skipping server-side DELETE.")

        # Always wipe local passphrase storage, even if the server response was iffy:
        # the user asked us to forget this credential locally.
        _keyring_delete(remote_service_id, account)
        _file_passphrase_delete(account)
        print(f"[{target_username}] Local passphrase cleared.")

def main(credentials_file=None, once=False, force=False, delete_account=None):
    if delete_account:
        do_delete_account(credentials_file, delete_account)
        return

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
        had_any_file_secret = False
        for user_entry in users:
            endpoint = resolve_endpoint(user_entry, default_endpoint)
            username = user_entry['username']
            key_name = resolve_key_name(user_entry, legacy)

            if is_remote_endpoint(endpoint):
                # Remote-keyring users skip the local mtime gate: the
                # server enforces the cached key's TTL (its GET returns
                # 404 once expired), so we ask for the current key on
                # every invocation. If it's still valid we get it back
                # in one round-trip; if it isn't, we transparently
                # refresh from CSCS and push the new one. This makes
                # `cscs-keygen.py --once` from .bashrc trivial.
                passphrase, dirty1 = ensure_remote_passphrase(user_entry, endpoint)
                public, private, generated_at, dirty2 = with_access_retry(
                    endpoint,
                    passphrase,
                    lambda store: remote_get_or_refresh(store, user_entry, force=force),
                )
                had_any_file_secret = had_any_file_secret or dirty1 or dirty2
                save_keys(public, private, key_name, generated_at)
                print(f"[{username}] Keys saved to {ssh_folder / key_name}")
            else:
                # Direct users: respect the local mtime so we don't burn
                # the 5-key quota on unnecessary re-fetches.
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
            save_config_file(credentials_file, default_endpoint, users, legacy)

        # Always report the resulting min validity so autotask.ps1 can parse
        # it to schedule the next wake-up — including after a fresh fetch,
        # which the previous flow skipped past in --once mode.
        min_time_left = min(
            key_invalid_after(ssh_folder / resolve_key_name(u, legacy))
            for u in users
        )
        print(f"The key is still valid for {min_time_left} seconds.")

        if once or force:
            break
        # Daemon mode: wait until the soonest local expiry, then loop.
        time.sleep(min_time_left + 10)

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
    parser.add_argument('--delete-account', metavar='USERNAME', type=str,
                        help='Tear down the remote-keyring entries (CSCS credentials and cached key) '
                             'for USERNAME, clear the locally cached passphrase, then exit. The next '
                             'normal run will generate a fresh passphrase and re-prompt for CSCS credentials.')
    args = parser.parse_args()
    exit(main(args.credentials, args.once, args.force, args.delete_account))
