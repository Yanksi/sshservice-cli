# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pyotp",
#     "requests==2.25.1",
#     "keyring",
#     "cryptography>=42",
# ]
# ///

# This script sets the environment properly so that a user can access CSCS
# login nodes via ssh.
#
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

"""Thin CLI over cscs_client + ttl_keyring.

The cache lives in a TTLKeyring (OS keyring for ``"cscs"`` endpoints, a
Cloudflare Worker for URL endpoints). CSCS is contacted only when the
cache misses — every run otherwise just copies the cached signed key
out to ``~/.ssh``. Nothing sensitive lives in the credentials file:
passwords, TOTP seeds, remote-keystore passphrases, and deployment
access secrets all live in the OS keyring.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Callable, Optional

import pyotp

import cscs_client
import ttl_keyring


DIRECT_ENDPOINT = "cscs"
SSH_FOLDER = Path(os.path.expanduser("~")) / ".ssh"
DEFAULT_KEY_NAME = "cscs-key"


# ---------- credentials file IO ----------

def load_config(fname: Optional[Path]):
    """Return ``(default_endpoint, users)``.

    The credentials file holds only non-secret routing information:

    .. code-block:: json

        {
            "endpoint": "https://cscs-key-proxy.<sub>.workers.dev",
            "users": [
                {"username": "alice"},
                {"username": "bob", "key_name": "cscs-bob", "endpoint": "cscs"}
            ]
        }

    Top-level ``endpoint`` is the default; per-user ``endpoint``
    overrides it. Both are optional (default is ``"cscs"``).
    """
    data = {}
    if fname is not None and fname.exists():
        print(f"Reading credentials from file: {fname}")
        try:
            with open(fname, "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"Warning: could not read {fname}: {e}")
            data = {}

    if not isinstance(data, dict):
        data = {}

    default_endpoint = data.get("endpoint", DIRECT_ENDPOINT) or DIRECT_ENDPOINT
    users = list(data["users"]) if isinstance(data.get("users"), list) else []
    return default_endpoint, users


def save_config_file(fname: Optional[Path], default_endpoint: str, users: list) -> None:
    if not fname:
        return
    cleaned = []
    for u in users:
        if not u.get("username"):
            continue
        entry = {"username": u["username"]}
        if u.get("key_name"):
            entry["key_name"] = u["key_name"]
        ep = u.get("endpoint")
        if ep and ep != default_endpoint:
            entry["endpoint"] = ep
        cleaned.append(entry)

    out: dict = {}
    if default_endpoint and default_endpoint != DIRECT_ENDPOINT:
        out["endpoint"] = default_endpoint
    out["users"] = cleaned

    try:
        with open(fname, "w") as f:
            json.dump(out, f, indent=4)
    except OSError as e:
        print(f"Warning: could not save credentials file: {e}")


def resolve_endpoint(user_entry: dict, default_endpoint: str) -> str:
    return user_entry.get("endpoint") or default_endpoint or DIRECT_ENDPOINT


def is_remote_endpoint(endpoint: str) -> bool:
    return bool(endpoint) and endpoint != DIRECT_ENDPOINT


def resolve_key_name(user_entry: dict) -> str:
    return user_entry.get("key_name") or f"{DEFAULT_KEY_NAME}-{user_entry['username']}"


# ---------- interactive prompts ----------

def prompt_username() -> str:
    return input("Username: ").strip()


def prompt_cscs_password(username: str) -> str:
    return getpass.getpass(f"[{username}] CSCS password: ")


def prompt_otp_secret(username: str) -> str:
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


def prompt_access_secret(endpoint: str) -> str:
    print()
    print(f"The Worker at {endpoint} requires a deployment access secret (X-Access-Secret).")
    print("Get this value from whoever runs the Worker.")
    while True:
        s = getpass.getpass(f"Access secret for {endpoint}: ").strip()
        if s:
            return s
        print("Input cannot be empty.")


def prompt_remote_setup(endpoint: str, username: str) -> str:
    """First-time setup for the remote backend on this device. Either
    generate a fresh passphrase (announce it so the user can copy it to
    other devices) or accept a pasted one (from another device that
    already registered)."""
    print()
    print(f"First-time remote-keystore setup for {endpoint}.")
    print("  [g] Generate a fresh passphrase (this is your first device).")
    print("  [p] Paste an existing passphrase (another device already registered).")
    while True:
        choice = input("Choose [g/p]: ").strip().lower()
        if choice in ("g", "generate"):
            passphrase = secrets.token_urlsafe(32)
            _announce_passphrase(username, endpoint, passphrase)
            return passphrase
        if choice in ("p", "paste"):
            while True:
                inp = getpass.getpass("Paste passphrase: ").strip()
                if inp:
                    return inp
                print("Input cannot be empty.")
        print("Please type 'g' or 'p'.")


def _announce_passphrase(username: str, endpoint: str, passphrase: str) -> None:
    border = "=" * 70
    print()
    print(border)
    print(f"[{username}] Generated a new remote-keystore passphrase for {endpoint}.")
    print(f"[{username}] Copy this to any OTHER device that should share the same cached key:")
    print()
    print(f"    {passphrase}")
    print()
    print(f"[{username}] On another device, run cscs-keygen.py and choose 'paste existing'")
    print(f"[{username}] when prompted. The passphrase is stored only in the OS keyring,")
    print(f"[{username}] never on disk.")
    print(border)
    print()


# ---------- remote-config bootstrap ----------

def ensure_remote_config(endpoint: str, username: str) -> None:
    """Make sure ``ttl_keyring`` has a remote config pointing at
    ``endpoint``.

    Maintains "one passphrase per device": once a passphrase is on this
    machine, it gets reused across every remote endpoint this device
    talks to. The access secret IS per-endpoint, so it's reset to
    ``None`` when the endpoint changes and re-prompted lazily on the
    next 403.
    """
    cfg = ttl_keyring.get_remote_config()
    if cfg is not None and cfg.get("endpoint") == endpoint:
        return

    if cfg is not None:
        # Same passphrase, new endpoint, fresh (unknown) access secret.
        ttl_keyring.configure_remote(endpoint, cfg["passphrase"], access_secret=None)
        return

    passphrase = prompt_remote_setup(endpoint, username)
    ttl_keyring.configure_remote(endpoint, passphrase, access_secret=None)


def with_access_retry(endpoint: str, op: Callable[[], object]):
    """Run ``op`` once. On AccessDenied, prompt for a new deployment
    access secret, update the saved config, and retry exactly once."""
    try:
        return op()
    except ttl_keyring.AccessDenied:
        print(f"Cached access secret for {endpoint} was rejected by the Worker (403).")
    new_secret = prompt_access_secret(endpoint)
    cfg = ttl_keyring.get_remote_config()
    if cfg is None:
        sys.exit("Internal error: remote config disappeared between calls.")
    ttl_keyring.configure_remote(cfg["endpoint"], cfg["passphrase"], access_secret=new_secret)
    return op()


# ---------- per-user processing ----------

def process_user(user_entry: dict, default_endpoint: str, *, force: bool) -> None:
    """Resolve one user's key and write it to ~/.ssh."""
    username = user_entry["username"]
    key_name = resolve_key_name(user_entry)
    endpoint = resolve_endpoint(user_entry, default_endpoint)

    if is_remote_endpoint(endpoint):
        ensure_remote_config(endpoint, username)

        def run():
            kr = ttl_keyring.TTLKeyring("remote")
            client = cscs_client.CscsClient(kr, ssh_folder=SSH_FOLDER)
            return _ensure_key_with_cred_prompt(client, username, key_name, force=force)

        with_access_retry(endpoint, run)
    else:
        kr = ttl_keyring.TTLKeyring("local")
        client = cscs_client.CscsClient(kr, ssh_folder=SSH_FOLDER)
        _ensure_key_with_cred_prompt(client, username, key_name, force=force)

    print(f"[{username}] Keys saved to {SSH_FOLDER / key_name}")


def _ensure_key_with_cred_prompt(
    client: cscs_client.CscsClient,
    username: str,
    key_name: str,
    *,
    force: bool,
) -> cscs_client.KeyMaterial:
    """Wrapper around ``ensure_key`` that prompts for CSCS credentials on
    the two interactive failure modes (missing creds, CSCS rejected creds)."""
    try:
        return client.ensure_key(username, key_name=key_name, force=force)
    except cscs_client.CredentialsNotConfigured:
        pwd = prompt_cscs_password(username)
        otp_seed = prompt_otp_secret(username)
        client.store_credentials(username, pwd, otp_seed)
        return client.ensure_key(username, key_name=key_name, force=force)
    except cscs_client.CscsAuthError as e:
        print(f"[{username}] CSCS rejected stored credentials ({e}). Re-prompting.")
        client.clear_credentials(username)
        pwd = prompt_cscs_password(username)
        otp_seed = prompt_otp_secret(username)
        client.store_credentials(username, pwd, otp_seed)
        return client.ensure_key(username, key_name=key_name, force=force)


# ---------- --delete-account ----------

def do_delete_account(credentials_file: Optional[Path], target_username: str) -> None:
    default_endpoint, users = load_config(credentials_file)
    matched = [u for u in users if u.get("username") == target_username]
    if not matched:
        sys.exit(f"Error: no user `{target_username}` in {credentials_file}.")

    for user_entry in matched:
        endpoint = resolve_endpoint(user_entry, default_endpoint)
        if is_remote_endpoint(endpoint):
            cfg = ttl_keyring.get_remote_config()
            if cfg is None:
                print(f"[{target_username}] No remote config on this device — nothing to delete remotely.")
                continue
            if cfg.get("endpoint") != endpoint:
                ttl_keyring.configure_remote(endpoint, cfg["passphrase"], access_secret=None)

            def delete():
                kr = ttl_keyring.TTLKeyring("remote")
                cscs_client.CscsClient(kr).delete_user(target_username)
                print(f"[{target_username}] Deleted remote keystore entries.")

            try:
                with_access_retry(endpoint, delete)
            except ttl_keyring.TTLKeyringError as e:
                print(f"[{target_username}] Warning: could not contact remote: {e}")
            ttl_keyring.clear_remote_config()
            print(f"[{target_username}] Local remote-config cleared.")
        else:
            kr = ttl_keyring.TTLKeyring("local")
            cscs_client.CscsClient(kr).delete_user(target_username)
            print(f"[{target_username}] Local keyring entries cleared.")


# ---------- main ----------

def main(credentials_file: Optional[Path], force: bool, delete_account: Optional[str]) -> None:
    if delete_account:
        do_delete_account(credentials_file, delete_account)
        return

    default_endpoint, users = load_config(credentials_file)
    if not users:
        users = [{"username": prompt_username()}]
        save_config_file(credentials_file, default_endpoint, users)
    elif any(not u.get("username") for u in users):
        for u in users:
            if not u.get("username"):
                u["username"] = prompt_username()
        save_config_file(credentials_file, default_endpoint, users)

    for user_entry in users:
        process_user(user_entry, default_endpoint, force=force)

    # Report soonest expiry across the on-disk files so external
    # schedulers (autotask.ps1, cron) can decide when to re-run.
    min_time_left = min(
        cscs_client.key_seconds_remaining(SSH_FOLDER / resolve_key_name(u))
        for u in users
    )
    print(f"The key is still valid for {min_time_left} seconds.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate CSCS keys")
    parser.add_argument("--force", action="store_true",
                        help="Force a fresh fetch from CSCS even if the cached key is still valid")
    parser.add_argument("--credentials", type=str,
                        default=Path(__file__).parent / "credential.json",
                        help="Path to the credentials file")
    parser.add_argument("--delete-account", metavar="USERNAME", type=str,
                        help="Tear down the cached CSCS credentials and key for USERNAME, "
                             "then exit. For remote users this also clears the locally-cached "
                             "remote config (passphrase + access secret).")
    args = parser.parse_args()
    creds = Path(args.credentials) if args.credentials else None
    exit(main(creds, args.force, args.delete_account))
