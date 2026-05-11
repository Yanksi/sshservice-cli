"""Cloud-backed encrypted keyring with per-item TTL.

Talks to a deployment of the Cloudflare Worker in ./worker/ (which is a
zero-knowledge, TTL-bounded blob store) and layers AES-GCM-256
encryption and HMAC-derived bearer auth on top. The Worker only ever
sees opaque ciphertext; it can't decrypt anything even with full
operator access.

Public API:
  RemoteSecretStore(endpoint, passphrase)
    .set(name, value: bytes, ttl: int | None = None) -> None
    .get(name) -> Item | None      # None if 404 (missing/expired)
    .delete(name) -> None

Optionally also (when the `keyring` package is importable):
  RemoteKeyring(store)              # keyring.backend.KeyringBackend adapter

A single user-supplied passphrase is HKDF'd into two independent
subkeys: one used as the bearer token to the Worker (so the Worker can
authenticate the client without learning anything decryptable) and one
used as the AES-GCM key (so a stolen bearer token alone cannot decrypt
existing blobs). The encryption AAD is the item name, so the Worker
also cannot swap blobs between names without breaking the tag.
"""

from __future__ import annotations

import base64
import hmac
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from hashlib import sha256
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Stable across reinstalls — derivation must be reproducible so the same
# passphrase yields the same keys on every device.
_HKDF_SALT = b"cscs-remote-keyring/v1"
_HKDF_INFO_AUTH = b"auth-token"
_HKDF_INFO_ENC = b"enc-key"


class RemoteStoreError(Exception):
    """The Worker rejected a request, or the network call failed."""


class WriteRateLimited(RemoteStoreError):
    """A racing PUT to the same name happened within the Worker's
    rate-limit window. Callers should re-GET rather than retrying the
    upstream refresh."""


@dataclass
class Item:
    data: bytes
    expires_at_ms: Optional[int] = None  # server-reported absolute expiry


def _derive_keys(passphrase: str) -> Tuple[str, bytes]:
    """Return (bearer_token, aes_key) derived from a single passphrase."""
    ikm = passphrase.encode("utf-8")
    auth = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO_AUTH,
    ).derive(ikm)
    enc = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO_ENC,
    ).derive(ikm)
    # Encode the bearer token as urlsafe base64 (no padding) for a clean
    # ASCII header value.
    bearer = base64.urlsafe_b64encode(auth).decode("ascii").rstrip("=")
    return bearer, enc


class RemoteSecretStore:
    """Client for the cscs-keystore Worker.

    Threading: instances are safe to share across threads — urllib opens
    a fresh socket per request and the AES key is read-only after
    construction.
    """

    def __init__(self, endpoint: str, passphrase: str, *, timeout: float = 30.0):
        if not endpoint:
            raise ValueError("endpoint required")
        if not passphrase:
            raise ValueError("passphrase required")
        self._endpoint = endpoint.rstrip("/")
        self._bearer, self._enc_key = _derive_keys(passphrase)
        self._timeout = timeout

    # The fingerprint identifies which passphrase was used WITHOUT
    # revealing it — useful for local "is this the same passphrase I
    # already have stored?" checks across devices.
    @property
    def fingerprint(self) -> str:
        return sha256(self._bearer.encode("ascii")).hexdigest()[:16]

    # ---------- crypto ----------

    def _encrypt(self, plaintext: bytes, name: str) -> bytes:
        iv = secrets.token_bytes(12)
        ct = AESGCM(self._enc_key).encrypt(iv, plaintext, name.encode("utf-8"))
        return iv + ct

    def _decrypt(self, blob: bytes, name: str) -> Optional[bytes]:
        if len(blob) < 12 + 16:  # 12-byte IV + at least the 16-byte tag
            return None
        iv, ct = blob[:12], blob[12:]
        try:
            return AESGCM(self._enc_key).decrypt(iv, ct, name.encode("utf-8"))
        except Exception:
            # Wrong passphrase, tampered blob, or server returned junk.
            return None

    # ---------- HTTP ----------

    def _url(self, name: str) -> str:
        if not name:
            raise ValueError("name required")
        # Allow `/` in names (e.g. "cscs/lshuhao/key") since the Worker
        # treats the entire path tail as the name. Encode everything
        # else.
        return f"{self._endpoint}/item/{urllib.parse.quote(name, safe='/')}"

    def _request(
        self, method: str, url: str, body: Optional[bytes] = None
    ) -> Tuple[int, bytes, dict]:
        headers = {"Authorization": f"Bearer {self._bearer}"}
        if body is not None:
            headers["Content-Type"] = "application/octet-stream"
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.status, resp.read(), {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as e:
            body_bytes = e.read() if e.fp is not None else b""
            hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
            return e.code, body_bytes, hdrs
        except urllib.error.URLError as e:
            raise RemoteStoreError(f"{method} {url}: {e.reason}") from e

    @staticmethod
    def _err_text(body: bytes) -> str:
        try:
            j = json.loads(body)
            if isinstance(j, dict) and "error" in j:
                return str(j["error"])
        except Exception:
            pass
        return body[:200].decode("utf-8", "replace") if body else ""

    # ---------- public API ----------

    def set(self, name: str, value: bytes, ttl: Optional[int] = None) -> None:
        """Encrypt and store `value` under `name`.

        `ttl`, if given, is the absolute lifetime in seconds (60 .. 7776000).
        Omitting it uses the Worker's default (24h).

        Raises WriteRateLimited if a recent PUT to the same name has
        already happened within the Worker's coordination window —
        callers refreshing concurrently should treat this as "someone
        else just stored a value; re-GET instead of retrying upstream."
        """
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("value must be bytes")
        blob = self._encrypt(bytes(value), name)
        url = self._url(name)
        if ttl is not None:
            url += "?" + urllib.parse.urlencode({"ttl": int(ttl)})
        status, body, _ = self._request("PUT", url, blob)
        if status == 204:
            return
        if status == 429:
            raise WriteRateLimited(self._err_text(body))
        raise RemoteStoreError(f"PUT {url}: HTTP {status}: {self._err_text(body)}")

    def get(self, name: str) -> Optional[Item]:
        """Fetch and decrypt `name`. Returns None if the Worker returned
        404 (missing or already-expired) or if decryption fails.

        A decryption failure on a successful 200 strongly indicates the
        wrong passphrase: the value is intact on the server, you just
        can't read it locally. Callers that want to distinguish "no
        such item" from "wrong passphrase" should check `.fingerprint`
        out-of-band or expose the failure to the user.
        """
        url = self._url(name)
        status, body, headers = self._request("GET", url)
        if status == 404:
            return None
        if status != 200:
            raise RemoteStoreError(
                f"GET {url}: HTTP {status}: {self._err_text(body)}"
            )
        plain = self._decrypt(body, name)
        if plain is None:
            return None
        exp = headers.get("x-expires-at")
        expires_at_ms: Optional[int] = None
        if exp:
            try:
                expires_at_ms = int(exp)
            except ValueError:
                pass
        return Item(data=plain, expires_at_ms=expires_at_ms)

    def delete(self, name: str) -> None:
        url = self._url(name)
        status, body, _ = self._request("DELETE", url)
        if status in (200, 204):
            return
        raise RemoteStoreError(
            f"DELETE {url}: HTTP {status}: {self._err_text(body)}"
        )

    # Convenience wrappers for the very common "store/fetch a UTF-8
    # string or a JSON-encodable dict" cases.

    def set_json(self, name: str, value: object, ttl: Optional[int] = None) -> None:
        self.set(name, json.dumps(value, separators=(",", ":")).encode("utf-8"), ttl=ttl)

    def get_json(self, name: str) -> Optional[object]:
        item = self.get(name)
        if item is None:
            return None
        try:
            return json.loads(item.data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise RemoteStoreError(f"item {name!r} is not valid JSON: {e}") from e


# ---------- optional keyring backend adapter ----------
#
# Lets callers drop a RemoteSecretStore into anything that consumes a
# keyring.backend.KeyringBackend. The TTL extension is only on the
# native API — through this adapter, items inherit the Worker's
# default TTL.

try:
    from keyring.backend import KeyringBackend as _KeyringBackend
    from keyring.errors import PasswordDeleteError as _PasswordDeleteError

    class RemoteKeyring(_KeyringBackend):
        """keyring.backend.KeyringBackend adapter over RemoteSecretStore."""

        # Opt-in only — never auto-picked by keyring's priority sort.
        priority = 0.5  # type: ignore[assignment]

        def __init__(self, store: RemoteSecretStore):
            self._store = store

        @staticmethod
        def _name(service: str, username: str) -> str:
            return (
                "keyring/"
                + urllib.parse.quote(service, safe="")
                + "/"
                + urllib.parse.quote(username, safe="")
            )

        def get_password(self, service: str, username: str) -> Optional[str]:
            item = self._store.get(self._name(service, username))
            return item.data.decode("utf-8") if item is not None else None

        def set_password(self, service: str, username: str, password: str) -> None:
            self._store.set(self._name(service, username), password.encode("utf-8"))

        def delete_password(self, service: str, username: str) -> None:
            try:
                self._store.delete(self._name(service, username))
            except RemoteStoreError as e:
                raise _PasswordDeleteError(str(e)) from e

except ImportError:  # keyring optional — only the adapter is gated
    pass


# Cheap constant-time-ish compare for fingerprints (string equality
# already short-circuits, but be explicit about intent).
def fingerprints_match(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))
