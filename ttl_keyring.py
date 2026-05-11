"""TTL-aware keyring abstraction with explicit backend selection.

The standard `keyring` library has no notion of expiry — stored secrets
sit forever until something deletes them. This module layers a uniform
``get / set(ttl=...) / delete`` API on top of two pluggable backends:

  - ``backend="local"`` — wraps the OS keyring (``keyring.get_password``
    et al.). TTL is enforced client-side: values are stored as
    ``{"v": <base64-of-bytes>, "exp": <unix_ms>}`` JSON strings, and
    ``get`` returns ``None`` (and silently evicts the entry) once the
    expiry has passed.
  - ``backend="remote"`` — talks to a deployment of the cscs-keystore
    Cloudflare Worker via the existing :mod:`remote_keyring`. TTL is
    enforced server-side by Cloudflare KV's own ``expirationTtl``.

There is exactly one remote config slot at a time, held as a single JSON
blob in the OS keyring under
``(ttl_keyring.remote, config)``. Call
:func:`configure_remote` once to populate it; subsequent
``TTLKeyring(backend="remote")`` invocations pick the config up
automatically. This keeps the chain of trust honest — the OS keyring
protects the passphrase that protects the remote.

Typical use::

    # one-time setup (e.g. an enrolment subcommand of the calling tool)
    ttl_keyring.configure_remote(endpoint, passphrase, access_secret=None)

    # at runtime
    kr = ttl_keyring.TTLKeyring(backend="remote")  # or "local"
    kr.set_json("cscs/lshuhao/key", {"public": ..., "private": ...}, ttl=82800)
    cached = kr.get_json("cscs/lshuhao/key")     # None if missing/expired
    kr.delete("cscs/lshuhao/key")
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Optional

import keyring as _keyring
from keyring.errors import KeyringError as _KeyringError

import remote_keyring as _remote_keyring


# Where the remote-backend config blob lives in the OS keyring. Only one
# slot exists by design — switching remotes means overwriting it.
_REMOTE_CONFIG_SERVICE = "ttl_keyring.remote"
_REMOTE_CONFIG_ACCOUNT = "config"

# OS-keyring service used to namespace local-backend items. Keeping a
# dedicated service prevents collisions with anything the host
# application stores directly via `keyring.set_password`.
_LOCAL_SERVICE = "ttl_keyring.local"

# File fallback root, used on hosts where `keyring` has no usable backend
# (headless Linux, cluster login nodes — anything where Secret Service /
# Keychain / Credential Manager isn't available and the library falls
# through to its `fail` backend). The fallback files mirror the
# (service, account) layout one-to-one with chmod 0600.
_FALLBACK_ROOT = Path(os.path.expanduser("~")) / ".config" / "ttl-keyring"


# ---------- low-level (service, account) -> str storage ----------
# `keyring` raises NoKeyringError (a subclass of KeyringError) when no
# native backend is available. We catch the base class so any backend
# init failure routes us to the file fallback — getting *some* secret
# storage is better than failing the whole tool on a cluster node.


def _safe(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in s)


def _fallback_path(service: str, account: str) -> Path:
    return _FALLBACK_ROOT / _safe(service) / _safe(account)


def _kv_set(service: str, account: str, value: str) -> None:
    try:
        _keyring.set_password(service, account, value)
        return
    except _KeyringError:
        pass
    p = _fallback_path(service, account)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(value)
    try:
        os.chmod(p, 0o600)
    except OSError:
        # Windows / restricted filesystem — POSIX chmod is meaningless
        # there. NTFS ACLs would be the analogous mechanism, but the
        # native keyring path is taken on Windows anyway, so we only
        # hit this branch on Unix where chmod always works.
        pass


def _kv_get(service: str, account: str) -> Optional[str]:
    try:
        v = _keyring.get_password(service, account)
        if v is not None:
            return v
    except _KeyringError:
        pass
    p = _fallback_path(service, account)
    if not p.exists():
        return None
    try:
        return p.read_text() or None
    except OSError:
        return None


def _kv_delete(service: str, account: str) -> None:
    try:
        _keyring.delete_password(service, account)
    except Exception:
        # `delete_password` raises on missing entries on some backends
        # AND on backends that don't exist — both are non-fatal here
        # since the post-condition ("no entry") still holds.
        pass
    p = _fallback_path(service, account)
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass


# ---------- typed errors ----------


class TTLKeyringError(Exception):
    """Base class for all errors surfaced through this module."""


class NotConfiguredError(TTLKeyringError):
    """``backend="remote"`` was selected but :func:`configure_remote`
    has not been called (or the saved blob is corrupt)."""


class WriteRateLimited(TTLKeyringError):
    """A concurrent writer just stored this name on the remote backend.
    Callers should re-``get`` rather than retrying the upstream fetch."""


class AccessDenied(TTLKeyringError):
    """The remote Worker rejected the deployment access secret
    (``X-Access-Secret``). Callers should re-prompt the operator-shared
    secret, call :func:`configure_remote` again with the new value, and
    rebuild the :class:`TTLKeyring`."""


# ---------- remote config (single global slot) ----------


def configure_remote(
    endpoint: str,
    passphrase: str,
    access_secret: Optional[str] = None,
) -> None:
    """Write the remote-backend config to the OS keyring.

    Overwrites any existing config — there is exactly one slot. Pass
    ``access_secret=None`` for Workers that don't require the
    ``WORKER_ACCESS_SECRET`` gate; pass the hex value for those that do.
    """
    if not endpoint:
        raise ValueError("endpoint is required")
    if not passphrase:
        raise ValueError("passphrase is required")
    blob = json.dumps(
        {
            "endpoint": endpoint,
            "passphrase": passphrase,
            "access_secret": access_secret,
        },
        separators=(",", ":"),
    )
    _kv_set(_REMOTE_CONFIG_SERVICE, _REMOTE_CONFIG_ACCOUNT, blob)


def get_remote_config() -> Optional[dict]:
    """Return ``{"endpoint", "passphrase", "access_secret"}`` if present,
    else ``None``."""
    raw = _kv_get(_REMOTE_CONFIG_SERVICE, _REMOTE_CONFIG_ACCOUNT)
    if not raw:
        return None
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(cfg, dict):
        return None
    if not cfg.get("endpoint") or not cfg.get("passphrase"):
        return None
    cfg.setdefault("access_secret", None)
    return cfg


def clear_remote_config() -> None:
    """Drop the saved remote config. Idempotent — safe to call when no
    config is set."""
    _kv_delete(_REMOTE_CONFIG_SERVICE, _REMOTE_CONFIG_ACCOUNT)


# ---------- backends ----------


class _Backend:
    name: str

    def get(self, name: str) -> Optional[bytes]:
        raise NotImplementedError

    def set(self, name: str, value: bytes, ttl: int) -> None:
        raise NotImplementedError

    def delete(self, name: str) -> None:
        raise NotImplementedError


class _LocalBackend(_Backend):
    """OS keyring + client-side TTL.

    Entries are stored as compact JSON ``{"v": <b64>, "exp": <unix_ms>}``.
    On read, expired entries are deleted and reported as missing — so
    callers see the same "None on miss/expired" shape as the remote
    backend.
    """

    name = "local"

    def get(self, name: str) -> Optional[bytes]:
        raw = _kv_get(_LOCAL_SERVICE, name)
        if not raw:
            return None
        try:
            obj = json.loads(raw)
            v_b64 = obj["v"]
            exp_ms = int(obj["exp"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            # Corrupt entry — treat as missing and clean up so the next
            # write isn't fighting an unparseable blob.
            self.delete(name)
            return None
        if _now_ms() >= exp_ms:
            self.delete(name)
            return None
        try:
            return base64.b64decode(v_b64.encode("ascii"))
        except Exception:
            self.delete(name)
            return None

    def set(self, name: str, value: bytes, ttl: int) -> None:
        blob = json.dumps(
            {
                "v": base64.b64encode(value).decode("ascii"),
                "exp": _now_ms() + ttl * 1000,
            },
            separators=(",", ":"),
        )
        _kv_set(_LOCAL_SERVICE, name, blob)

    def delete(self, name: str) -> None:
        _kv_delete(_LOCAL_SERVICE, name)


class _RemoteBackend(_Backend):
    """Thin adapter over :class:`remote_keyring.RemoteSecretStore`."""

    name = "remote"

    def __init__(self, cfg: dict):
        self._store = _remote_keyring.RemoteSecretStore(
            cfg["endpoint"],
            cfg["passphrase"],
            access_secret=cfg.get("access_secret"),
        )

    def get(self, name: str) -> Optional[bytes]:
        try:
            item = self._store.get(name)
        except _remote_keyring.AccessDenied as e:
            raise AccessDenied(str(e)) from e
        except _remote_keyring.RemoteStoreError as e:
            raise TTLKeyringError(str(e)) from e
        return item.data if item is not None else None

    def set(self, name: str, value: bytes, ttl: int) -> None:
        try:
            self._store.set(name, value, ttl=ttl)
        except _remote_keyring.WriteRateLimited as e:
            raise WriteRateLimited(str(e)) from e
        except _remote_keyring.AccessDenied as e:
            raise AccessDenied(str(e)) from e
        except _remote_keyring.RemoteStoreError as e:
            raise TTLKeyringError(str(e)) from e

    def delete(self, name: str) -> None:
        try:
            self._store.delete(name)
        except _remote_keyring.AccessDenied as e:
            raise AccessDenied(str(e)) from e
        except _remote_keyring.RemoteStoreError as e:
            raise TTLKeyringError(str(e)) from e


# ---------- public class ----------


class TTLKeyring:
    """Uniform TTL-aware keyring over one of two backends.

    ``backend`` must be exactly ``"local"`` or ``"remote"``; no automatic
    selection is performed. For ``"remote"``, :func:`configure_remote`
    must have been called previously — otherwise :class:`NotConfiguredError`
    is raised at construction time.
    """

    def __init__(self, backend: str):
        if backend == "local":
            self._impl: _Backend = _LocalBackend()
        elif backend == "remote":
            cfg = get_remote_config()
            if cfg is None:
                raise NotConfiguredError(
                    "remote backend selected but no config saved; "
                    "call ttl_keyring.configure_remote(endpoint, passphrase, "
                    "access_secret=...) first"
                )
            self._impl = _RemoteBackend(cfg)
        else:
            raise ValueError(
                f"unknown backend {backend!r}; expected 'local' or 'remote'"
            )

    @property
    def backend(self) -> str:
        return self._impl.name

    def get(self, name: str) -> Optional[bytes]:
        """Return the raw bytes stored under ``name``, or ``None`` if
        the entry is missing or has expired."""
        _check_name(name)
        return self._impl.get(name)

    def set(self, name: str, value: bytes, ttl: int) -> None:
        """Store ``value`` under ``name`` with a ``ttl``-second lifetime."""
        _check_name(name)
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("value must be bytes")
        if not isinstance(ttl, int) or ttl <= 0:
            raise ValueError("ttl must be a positive integer (seconds)")
        self._impl.set(name, bytes(value), ttl)

    def delete(self, name: str) -> None:
        """Remove the entry. Idempotent — silent on missing entries."""
        _check_name(name)
        self._impl.delete(name)

    def get_json(self, name: str) -> Optional[object]:
        """Convenience wrapper: decode UTF-8 JSON. Returns ``None`` for
        missing/expired entries; raises :class:`TTLKeyringError` if the
        stored bytes aren't valid JSON."""
        data = self.get(name)
        if data is None:
            return None
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise TTLKeyringError(f"item {name!r} is not valid JSON: {e}") from e

    def set_json(self, name: str, value: object, ttl: int) -> None:
        """Convenience wrapper for :meth:`set` with JSON encoding."""
        self.set(name, json.dumps(value, separators=(",", ":")).encode("utf-8"), ttl)


# ---------- internals ----------


def _now_ms() -> int:
    return int(time.time() * 1000)


def _check_name(name: str) -> None:
    if not isinstance(name, str) or not name:
        raise ValueError("name must be a non-empty string")
