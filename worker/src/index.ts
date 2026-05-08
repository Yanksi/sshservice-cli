// Cloudflare Worker — per-user encrypted CSCS key proxy. (api: v2.1; force=1)
//
// Each user POSTs their CSCS credentials encrypted with a token of their
// choosing; the Worker stores only opaque ciphertext in KV. On GET, the
// Worker decrypts with the supplied token, refreshes the CSCS-signed cert
// if the cached one is stale, re-encrypts, and returns the plaintext
// key+cert. The Worker holds no standing CSCS credentials and cannot
// enumerate users without the WORKER_PEPPER secret.
//
// See ../README.md for the security model and the threats this does and
// does not defend against.

export interface Env {
  CERT_STORE: KVNamespace;
  WORKER_PEPPER: string; // 32+ bytes, hex
}

interface AccountRecord {
  username: string;
  password: string;
  otp_secret: string;
  cached_cert?: {
    key: string;
    cert: string;
    generated_at: number;
  };
}

const CSCS_API = "https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key";
const CACHE_LIFETIME_MS = 23 * 60 * 60 * 1000; // refresh anything older than 23h

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- helpers: hex / base64 ----------

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("invalid hex length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function bytesToB64(b: Uint8Array): string {
  let s = "";
  for (const byte of b) s += String.fromCharCode(byte);
  return btoa(s);
}

function b64ToBytes(s: string): Uint8Array {
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

// ---------- TOTP (RFC 6238, SHA-1 / 30s / 6 digits) ----------

function base32Decode(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = input.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  const bytes: number[] = [];
  let buf = 0;
  let bits = 0;
  for (const ch of cleaned) {
    const v = alphabet.indexOf(ch);
    if (v < 0) throw new Error(`invalid base32 char: ${ch}`);
    buf = (buf << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buf >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

async function generateTOTP(secretBase32: string, now = Date.now()): Promise<string> {
  const counter = Math.floor(now / 1000 / 30);
  const counterBytes = new ArrayBuffer(8);
  new DataView(counterBytes).setBigUint64(0, BigInt(counter));

  const keyData = base32Decode(secretBase32);
  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, counterBytes);
  const sig = new Uint8Array(sigBuf);
  const offset = sig[sig.length - 1] & 0x0f;
  const code =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return (code % 1_000_000).toString().padStart(6, "0");
}

// ---------- per-token derivation ----------

async function kvKeyForToken(token: string, env: Env): Promise<string> {
  // KV key = HMAC-SHA256(PEPPER, "user:" + token), hex.
  const pepper = hexToBytes(env.WORKER_PEPPER);
  const key = await crypto.subtle.importKey(
    "raw",
    pepper,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode("user:" + token));
  return bytesToHex(new Uint8Array(sig));
}

async function deriveCryptKey(token: string, env: Env): Promise<CryptoKey> {
  // HKDF(salt=PEPPER, ikm=token, info="aes-gcm-account") → AES-GCM 256.
  const salt = hexToBytes(env.WORKER_PEPPER);
  const ikm = await crypto.subtle.importKey(
    "raw",
    enc.encode(token),
    "HKDF",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", salt, info: enc.encode("aes-gcm-account"), hash: "SHA-256" },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptRecord(record: AccountRecord, token: string, env: Env): Promise<string> {
  const key = await deriveCryptKey(token, env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = enc.encode(JSON.stringify(record));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data));
  // Stored format: base64(iv || ciphertext+tag).
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return bytesToB64(out);
}

async function decryptRecord(blob: string, token: string, env: Env): Promise<AccountRecord | null> {
  try {
    const key = await deriveCryptKey(token, env);
    const bytes = b64ToBytes(blob);
    const iv = bytes.slice(0, 12);
    const ct = bytes.slice(12);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return JSON.parse(dec.decode(new Uint8Array(pt)));
  } catch {
    return null; // wrong token / tampered ciphertext / missing
  }
}

// ---------- CSCS API ----------

async function fetchKeysFromCSCS(record: AccountRecord): Promise<{ key: string; cert: string }> {
  const otp = await generateTOTP(record.otp_secret);
  const resp = await fetch(CSCS_API, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify({
      username: record.username,
      password: record.password,
      otp,
    }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`CSCS API ${resp.status}: ${text.slice(0, 500)}`);
  }
  const body = (await resp.json()) as { public?: string; private?: string };
  if (!body.public || !body.private) throw new Error("CSCS API returned empty key/cert");
  return { key: body.private, cert: body.public };
}

// ---------- request helpers ----------

function tokenFromRequest(req: Request): string | null {
  const header = req.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/.exec(header);
  if (!m) return null;
  const t = m[1].trim();
  return t.length > 0 ? t : null;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ---------- handlers ----------

async function handlePostAccount(req: Request, env: Env, token: string): Promise<Response> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: "invalid JSON body" }, 400);
  }
  if (
    typeof body !== "object" || body === null ||
    typeof (body as any).username !== "string" ||
    typeof (body as any).password !== "string" ||
    typeof (body as any).otp_secret !== "string"
  ) {
    return jsonResponse({ error: "body must be { username, password, otp_secret }" }, 400);
  }
  const record: AccountRecord = {
    username: (body as any).username,
    password: (body as any).password,
    otp_secret: (body as any).otp_secret,
    // no cached_cert yet
  };
  const blob = await encryptRecord(record, token, env);
  await env.CERT_STORE.put(await kvKeyForToken(token, env), blob);
  return jsonResponse({ stored: true }, 201);
}

async function handleDeleteAccount(env: Env, token: string): Promise<Response> {
  await env.CERT_STORE.delete(await kvKeyForToken(token, env));
  return new Response(null, { status: 204 });
}

async function handleGetCredential(env: Env, token: string, force: boolean): Promise<Response> {
  const kvKey = await kvKeyForToken(token, env);
  const blob = await env.CERT_STORE.get(kvKey);
  if (!blob) return jsonResponse({ error: "no account for this token" }, 401);

  const record = await decryptRecord(blob, token, env);
  if (!record) return jsonResponse({ error: "decryption failed (wrong token)" }, 401);

  const now = Date.now();
  const cached = record.cached_cert;
  if (!force && cached && now - cached.generated_at < CACHE_LIFETIME_MS) {
    return jsonResponse(cached);
  }

  // Force path: per-token rate-limit so a repeated force=1 can't hammer CSCS.
  // Normal stale-refresh path skips the lock since at most one expiry happens
  // per ~23h per token anyway.
  if (force) {
    const lockKey = kvKey + ":force-lock";
    if (await env.CERT_STORE.get(lockKey)) {
      return jsonResponse(
        { error: "force-refresh rate-limited; try again in up to 60s" },
        429,
      );
    }
    await env.CERT_STORE.put(lockKey, "1", { expirationTtl: 60 });
  }

  // Stale or forced — refresh from CSCS.
  let fresh: { key: string; cert: string };
  try {
    fresh = await fetchKeysFromCSCS(record);
  } catch (e) {
    return jsonResponse(
      { error: String(e instanceof Error ? e.message : e) },
      502,
    );
  }

  record.cached_cert = { key: fresh.key, cert: fresh.cert, generated_at: now };
  const newBlob = await encryptRecord(record, token, env);
  await env.CERT_STORE.put(kvKey, newBlob);

  return jsonResponse(record.cached_cert);
}

// ---------- entrypoint ----------

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/" && req.method === "GET") {
      return new Response("cscs-key-proxy: OK\n", { headers: { "Content-Type": "text/plain" } });
    }

    if (!env.WORKER_PEPPER) {
      return jsonResponse(
        { error: "Worker is not configured: WORKER_PEPPER secret is missing" },
        500,
      );
    }

    const token = tokenFromRequest(req);
    if (!token) return jsonResponse({ error: "missing Bearer token" }, 401);

    if (url.pathname === "/account" && req.method === "POST") {
      return handlePostAccount(req, env, token);
    }
    if (url.pathname === "/account" && req.method === "DELETE") {
      return handleDeleteAccount(env, token);
    }
    if (url.pathname === "/credential" && req.method === "GET") {
      const f = url.searchParams.get("force");
      const force = f === "1" || f === "true";
      return handleGetCredential(env, token, force);
    }

    return jsonResponse({ error: "not found" }, 404);
  },
};
