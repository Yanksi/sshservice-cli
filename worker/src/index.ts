// Cloudflare Worker — opaque, TTL-bounded blob store. (api: v3.0)
//
// The Worker is a zero-knowledge keyring backend: clients PUT raw bytes
// (encrypted client-side with a key the Worker never sees), the Worker
// stores them in KV under an HMAC-obfuscated key with the requested TTL,
// and GET returns them as-is until KV evicts them at expiry.
//
// Routes:
//   GET    /                 health, no auth
//   PUT    /item/<name>      store opaque body; ?ttl=<sec> (default 24h)
//   GET    /item/<name>      200 with body + X-Expires-At header, or 404
//   DELETE /item/<name>      idempotent
//
// Auth: Authorization: Bearer <token>. KV key = HMAC(PEPPER, token+":"+name).
// The token is opaque to the Worker (no enrolment step); first PUT for a
// given (token, name) creates the record. A leaked token grants only
// overwrite/delete capability on that user's records — never the ability
// to decrypt, since the Worker doesn't hold the encryption key.
//
// PUT is rate-limited per (token, name) to ~1/min; over-the-limit writes
// get 429 so a racing refresher knows another writer just stored this
// name and can re-GET instead of hitting upstream again. GET is not
// rate-limited by the Worker itself; consumers can poll freely.
//
// See ../README.md for the security model.

export interface Env {
  ITEM_STORE: KVNamespace;
  WORKER_PEPPER: string; // 32+ bytes, hex
}

const DEFAULT_TTL_SEC = 24 * 60 * 60;
const MIN_TTL_SEC = 60; // KV minimum
const MAX_TTL_SEC = 90 * 24 * 60 * 60;
const PUT_RATE_LIMIT_SEC = 60; // matches KV's expirationTtl minimum
const MAX_NAME_LEN = 256;
const MAX_BODY_BYTES = 64 * 1024;

const enc = new TextEncoder();

// ---------- helpers ----------

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

async function kvKeyFor(pepperHex: string, token: string, name: string): Promise<string> {
  // KV key = HMAC-SHA256(PEPPER, token + ":" + name), hex.
  // Pepper makes the index unforgeable without server cooperation, so a
  // raw KV dump can't be cross-referenced against guessed tokens.
  const pepper = hexToBytes(pepperHex);
  const key = await crypto.subtle.importKey(
    "raw",
    pepper,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(token + ":" + name));
  return bytesToHex(new Uint8Array(sig));
}

function tokenFromRequest(req: Request): string | null {
  const h = req.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/.exec(h);
  if (!m) return null;
  const t = m[1].trim();
  return t.length > 0 ? t : null;
}

function nameFromPath(pathname: string): string | null {
  if (!pathname.startsWith("/item/")) return null;
  const raw = pathname.slice("/item/".length);
  if (!raw) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null;
  }
  if (decoded.length === 0 || decoded.length > MAX_NAME_LEN) return null;
  return decoded;
}

function parseTtl(url: URL): number | "invalid" {
  const raw = url.searchParams.get("ttl");
  if (raw === null) return DEFAULT_TTL_SEC;
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n)) return "invalid";
  if (n < MIN_TTL_SEC || n > MAX_TTL_SEC) return "invalid";
  return n;
}

function jsonError(error: string, status: number, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { "Content-Type": "application/json", ...(extraHeaders ?? {}) },
  });
}

// ---------- handlers ----------

async function handleGet(env: Env, token: string, name: string): Promise<Response> {
  const k = await kvKeyFor(env.WORKER_PEPPER, token, name);
  const result = await env.ITEM_STORE.getWithMetadata<{ expires_at?: number }>(k, "arrayBuffer");
  // KV auto-deletes records past expirationTtl, so an expired item
  // appears as missing — exactly the 404 semantics the client wants.
  if (result.value === null) {
    return jsonError("not found or expired", 404);
  }
  const headers: Record<string, string> = {
    "Content-Type": "application/octet-stream",
    "Cache-Control": "no-store",
  };
  const exp = result.metadata?.expires_at;
  if (typeof exp === "number") {
    headers["X-Expires-At"] = String(exp);
  }
  return new Response(result.value, { status: 200, headers });
}

async function handlePut(req: Request, env: Env, token: string, name: string, url: URL): Promise<Response> {
  const ttl = parseTtl(url);
  if (ttl === "invalid") {
    return jsonError(
      `ttl must be an integer in [${MIN_TTL_SEC}, ${MAX_TTL_SEC}] seconds`,
      400,
    );
  }
  const body = await req.arrayBuffer();
  if (body.byteLength === 0) {
    return jsonError("empty body", 400);
  }
  if (body.byteLength > MAX_BODY_BYTES) {
    return jsonError(`body exceeds ${MAX_BODY_BYTES} bytes`, 413);
  }

  const k = await kvKeyFor(env.WORKER_PEPPER, token, name);
  const lockKey = k + ":put-lock";

  // Coordinate concurrent refreshers: if another writer stored this
  // name within the last PUT_RATE_LIMIT_SEC, refuse with 429 so the
  // racing client can re-GET the value the winner just wrote instead
  // of hitting the upstream a second time.
  if (await env.ITEM_STORE.get(lockKey)) {
    return jsonError(
      `another writer just stored this name; re-GET instead of retrying`,
      429,
      { "Retry-After": String(PUT_RATE_LIMIT_SEC) },
    );
  }
  // Best-effort lock — KV is eventually consistent so a near-simultaneous
  // PUT may slip past, but that just degrades to a harmless overwrite.
  await env.ITEM_STORE.put(lockKey, "1", { expirationTtl: PUT_RATE_LIMIT_SEC });

  const expires_at = Date.now() + ttl * 1000;
  await env.ITEM_STORE.put(k, body, {
    expirationTtl: ttl,
    metadata: { expires_at },
  });

  return new Response(null, {
    status: 204,
    headers: { "X-Expires-At": String(expires_at) },
  });
}

async function handleDelete(env: Env, token: string, name: string): Promise<Response> {
  const k = await kvKeyFor(env.WORKER_PEPPER, token, name);
  await env.ITEM_STORE.delete(k);
  return new Response(null, { status: 204 });
}

// ---------- entrypoint ----------

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/" && req.method === "GET") {
      return new Response("cscs-key-proxy: OK\n", {
        headers: { "Content-Type": "text/plain" },
      });
    }

    if (!env.WORKER_PEPPER) {
      return jsonError("Worker is not configured: WORKER_PEPPER secret is missing", 500);
    }

    const token = tokenFromRequest(req);
    if (!token) return jsonError("missing Bearer token", 401);

    const name = nameFromPath(url.pathname);
    if (name === null) return jsonError("not found", 404);

    switch (req.method) {
      case "GET":
        return handleGet(env, token, name);
      case "PUT":
        return handlePut(req, env, token, name, url);
      case "DELETE":
        return handleDelete(env, token, name);
      default:
        return jsonError("method not allowed", 405);
    }
  },
};
