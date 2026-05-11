"""CSCS signed-key client over a TTLKeyring.

Encapsulates the "fetch a 24-hour signed key from CSCS, cache it
somewhere with a TTL, and copy it into ~/.ssh" loop. The backing store
is a :class:`ttl_keyring.TTLKeyring`, which lets the caller choose
between an OS-keyring local cache and a Cloudflare Worker remote cache
without this module knowing or caring which is in use.

Layout in the keyring:

  - ``cscs/<username>/key``   — most recent signed key, with
    ``KEY_TTL_SECONDS`` (just under the cert's 24 h validity).
  - ``cscs/<username>/creds`` — CSCS login credentials (password and
    base32 TOTP seed), with ``CREDS_TTL_SECONDS``.

The public entry point is :meth:`CscsClient.ensure_key`. It always
writes a key pair to ``~/.ssh``; it only calls CSCS when no usable
cached key exists. If credentials are missing it raises
:class:`CredentialsNotConfigured` — this module never prompts the user.
Driving the prompt loop is the caller's job.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import pyotp
import requests

import ttl_keyring


CSCS_KEYS_URL = "https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key"

# CSCS signs each key for 24 h. We expire the cache just under that so a
# refresh fires while the existing cert is still usable.
KEY_TTL_SECONDS = 23 * 60 * 60

# Credentials only change on password / TOTP reset. Keep them around so
# unattended refreshes don't get derailed by a long pause between runs.
CREDS_TTL_SECONDS = 90 * 24 * 60 * 60

# How long a signed key from CSCS is actually valid for, regardless of
# our cache TTL. Used by :func:`key_seconds_remaining` to answer "is
# the file on disk still good?" for callers that schedule re-runs.
CSCS_KEY_LIFETIME_SECONDS = 24 * 60 * 60


# ---------- errors ----------


class CscsClientError(Exception):
    """Base class for cscs_client errors."""


class CredentialsNotConfigured(CscsClientError):
    """The TTLKeyring has no CSCS credentials for the requested user.

    The caller should prompt for password + base32 TOTP seed, validate
    them, call :meth:`CscsClient.store_credentials`, and retry."""


class CscsAuthError(CscsClientError):
    """CSCS rejected the stored credentials (401/403). The caller likely
    needs to re-prompt and re-store."""


# ---------- data ----------


@dataclass
class KeyMaterial:
    public_cert: str
    private_key: str
    # Wall-clock time (ms since epoch) the cert was signed. Used to
    # anchor the on-disk mtime so external schedulers can check freshness
    # by stat()ing the file rather than asking us.
    generated_at_ms: int


# ---------- client ----------


def _key_item(username: str) -> str:
    return f"cscs/{username}/key"


def _creds_item(username: str) -> str:
    return f"cscs/{username}/creds"


class CscsClient:
    """Talks to CSCS using credentials in a TTLKeyring.

    Stateless apart from the TTLKeyring reference — safe to construct
    per-call or once per process.
    """

    def __init__(
        self,
        keyring: ttl_keyring.TTLKeyring,
        ssh_folder: Optional[Path] = None,
        *,
        request_timeout: float = 30.0,
    ):
        self._kr = keyring
        self._ssh = ssh_folder or Path(os.path.expanduser("~")) / ".ssh"
        self._timeout = request_timeout

    # ---------- credentials ----------

    def has_credentials(self, username: str) -> bool:
        item = self._kr.get_json(_creds_item(username))
        return (
            isinstance(item, dict)
            and bool(item.get("password"))
            and bool(item.get("otp_secret"))
        )

    def store_credentials(
        self, username: str, password: str, otp_secret: str
    ) -> None:
        """Validate ``otp_secret`` (base32 TOTP seed) and push the pair
        to the keyring with ``CREDS_TTL_SECONDS``.

        Raises :class:`ValueError` for an obviously invalid seed — fail
        fast here, not 12 hours later on the next unattended refresh.
        """
        if not password:
            raise ValueError("password must not be empty")
        try:
            pyotp.TOTP(otp_secret).now()
        except Exception as e:
            raise ValueError(
                f"OTP secret is not a valid base32 seed: {e}"
            ) from e
        self._kr.set_json(
            _creds_item(username),
            {"password": password, "otp_secret": otp_secret},
            ttl=CREDS_TTL_SECONDS,
        )

    def clear_credentials(self, username: str) -> None:
        self._kr.delete(_creds_item(username))

    # ---------- key fetch + write ----------

    def ensure_key(
        self,
        username: str,
        key_name: Optional[str] = None,
        *,
        force: bool = False,
    ) -> KeyMaterial:
        """Resolve a usable signed key for ``username`` and write it to
        ``~/.ssh``.

        The contract — and the thing that distinguishes the cached
        backend model from "always hit CSCS":

          1. Read ``cscs/<user>/key`` from the keyring. If present (and
             not ``force``), write it to ``~/.ssh`` and return — no
             network call.
          2. Otherwise: load credentials from the keyring (raise
             :class:`CredentialsNotConfigured` if missing), call CSCS,
             push the resulting key back to the keyring, write to
             ``~/.ssh``.

        ``key_name`` defaults to ``cscs-key-<username>``. The matching
        certificate is written next to it as ``<key_name>-cert.pub``.
        """
        if key_name is None:
            key_name = f"cscs-key-{username}"

        if not force:
            cached = self._kr.get_json(_key_item(username))
            if (
                isinstance(cached, dict)
                and cached.get("public")
                and cached.get("private")
            ):
                km = KeyMaterial(
                    public_cert=cached["public"],
                    private_key=cached["private"],
                    generated_at_ms=int(cached.get("generated_at") or 0),
                )
                self._write_to_ssh(km, key_name)
                return km

        # Cache miss (or forced refresh) — need credentials.
        creds = self._kr.get_json(_creds_item(username))
        if (
            not isinstance(creds, dict)
            or not creds.get("password")
            or not creds.get("otp_secret")
        ):
            raise CredentialsNotConfigured(
                f"no CSCS credentials in keyring for user {username!r}; "
                f"call store_credentials() first"
            )

        otp = pyotp.TOTP(creds["otp_secret"]).now()
        public, private = self._fetch_from_cscs(username, creds["password"], otp)
        generated_at_ms = int(time.time() * 1000)

        try:
            self._kr.set_json(
                _key_item(username),
                {
                    "public": public,
                    "private": private,
                    "generated_at": generated_at_ms,
                },
                ttl=KEY_TTL_SECONDS,
            )
        except ttl_keyring.WriteRateLimited:
            # Concurrent refresh from another device beat us. Their blob
            # is fresher in terms of "what other consumers will see", so
            # prefer it over ours — and avoid burning a second slot of
            # the 5-key CSCS quota on a retry.
            winner = self._kr.get_json(_key_item(username))
            if (
                isinstance(winner, dict)
                and winner.get("public")
                and winner.get("private")
            ):
                km = KeyMaterial(
                    public_cert=winner["public"],
                    private_key=winner["private"],
                    generated_at_ms=int(
                        winner.get("generated_at") or generated_at_ms
                    ),
                )
                self._write_to_ssh(km, key_name)
                return km
            # Lost the race AND can't read the winner's value — fall
            # through with our own freshly-minted pair.

        km = KeyMaterial(
            public_cert=public,
            private_key=private,
            generated_at_ms=generated_at_ms,
        )
        self._write_to_ssh(km, key_name)
        return km

    def delete_user(self, username: str) -> None:
        """Wipe the cached key and credentials for ``username``."""
        self._kr.delete(_key_item(username))
        self._kr.delete(_creds_item(username))

    # ---------- internals ----------

    def _fetch_from_cscs(
        self, username: str, password: str, otp: str
    ) -> Tuple[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = json.dumps(
            {"username": username, "password": password, "otp": otp}
        )
        try:
            resp = requests.post(
                CSCS_KEYS_URL,
                data=body,
                headers=headers,
                verify=True,
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            msg = self._extract_cscs_error(e) or str(e)
            status = None
            if e.response is not None:
                status = e.response.status_code
            if status in (401, 403):
                raise CscsAuthError(msg) from e
            raise CscsClientError(f"CSCS request failed: {msg}") from e

        data = resp.json()
        public = data.get("public")
        private = data.get("private")
        if not public or not private:
            raise CscsClientError("CSCS response was missing key material")
        return public, private

    @staticmethod
    def _extract_cscs_error(exc: requests.exceptions.RequestException) -> str:
        if exc.response is None:
            return ""
        try:
            payload = exc.response.json()
        except Exception:
            return ""
        if (
            isinstance(payload, dict)
            and isinstance(payload.get("payload"), dict)
            and payload["payload"].get("message")
        ):
            return str(payload["payload"]["message"])
        return ""

    def _write_to_ssh(self, km: KeyMaterial, key_name: str) -> None:
        self._ssh.mkdir(parents=True, exist_ok=True)
        priv_path = self._ssh / key_name
        pub_path = self._ssh / f"{key_name}-cert.pub"
        pub_path.write_text(km.public_cert)
        priv_path.write_text(km.private_key)
        try:
            os.chmod(pub_path, 0o644)
            os.chmod(priv_path, 0o600)
        except Exception:
            # chmod is meaningless / unsupported on some Windows layouts.
            pass
        if km.generated_at_ms:
            # Anchor mtime to the CSCS sign time so external schedulers
            # can reason about freshness by stat()ing the file.
            ts = km.generated_at_ms / 1000.0
            try:
                os.utime(pub_path, (ts, ts))
                os.utime(priv_path, (ts, ts))
            except Exception:
                pass


# ---------- helpers callers tend to need ----------


def key_seconds_remaining(priv_key_path: Path) -> int:
    """How many seconds is the on-disk key still valid for?

    Returns 0 if the file is missing or already past
    :data:`CSCS_KEY_LIFETIME_SECONDS`. Useful for daemon-mode schedulers
    that want to sleep until the soonest expiry across multiple users.
    """
    if not priv_key_path.exists():
        return 0
    age = int(time.time()) - int(os.path.getmtime(priv_key_path))
    return max(CSCS_KEY_LIFETIME_SECONDS - age, 0)
