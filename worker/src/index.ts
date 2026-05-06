// Cloudflare Worker that fetches CSCS-signed SSH key+cert on a schedule and
// serves them to authorised clients. See ../README.md for deployment notes.

export interface Env {
  CERT_STORE: KVNamespace;
  CSCS_USERNAME: string;
  CSCS_PASSWORD: string;
  CSCS_OTP_SECRET: string;
  FETCH_TOKEN: string;
}

interface StoredCert {
  key: string;
  cert: string;
  generated_at: number;
}

const CSCS_API = "https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key";
const KV_KEY = "current";
const REFRESH_LOCK_KEY = "refresh:lock";

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

// ---------- CSCS API ----------

async function fetchKeysFromCSCS(env: Env): Promise<StoredCert> {
  const otp = await generateTOTP(env.CSCS_OTP_SECRET);
  const resp = await fetch(CSCS_API, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify({
      username: env.CSCS_USERNAME,
      password: env.CSCS_PASSWORD,
      otp,
    }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`CSCS API ${resp.status}: ${text.slice(0, 500)}`);
  }
  const body = (await resp.json()) as { public?: string; private?: string };
  if (!body.public || !body.private) {
    throw new Error("CSCS API returned empty key/cert");
  }
  return { key: body.private, cert: body.public, generated_at: Date.now() };
}

async function refreshAndStore(env: Env): Promise<StoredCert> {
  const stored = await fetchKeysFromCSCS(env);
  await env.CERT_STORE.put(KV_KEY, JSON.stringify(stored));
  return stored;
}

// ---------- Auth ----------

function constantTimeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function checkAuth(req: Request, env: Env): boolean {
  const header = req.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/.exec(header);
  if (!m) return false;
  return constantTimeEq(m[1].trim(), env.FETCH_TOKEN);
}

// ---------- HTTP handler ----------

async function handleGet(env: Env): Promise<Response> {
  const raw = await env.CERT_STORE.get(KV_KEY);
  if (!raw) {
    return new Response(
      JSON.stringify({ error: "no cert stored yet — POST /refresh or wait for cron" }),
      { status: 404, headers: { "Content-Type": "application/json" } }
    );
  }
  return new Response(raw, { headers: { "Content-Type": "application/json" } });
}

async function handleRefresh(env: Env): Promise<Response> {
  // Crude rate-limit: KV-backed lock with 60s TTL.
  const locked = await env.CERT_STORE.get(REFRESH_LOCK_KEY);
  if (locked) {
    return new Response(
      JSON.stringify({ error: "refresh rate-limited; try again in <60s" }),
      { status: 429, headers: { "Content-Type": "application/json" } }
    );
  }
  await env.CERT_STORE.put(REFRESH_LOCK_KEY, "1", { expirationTtl: 60 });

  try {
    const stored = await refreshAndStore(env);
    return new Response(JSON.stringify(stored), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(
      JSON.stringify({ error: String(e instanceof Error ? e.message : e) }),
      { status: 502, headers: { "Content-Type": "application/json" } }
    );
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/" && req.method === "GET") {
      return new Response("cscs-key-proxy: OK\n", { headers: { "Content-Type": "text/plain" } });
    }

    if (!checkAuth(req, env)) {
      return new Response("unauthorized\n", { status: 401 });
    }

    if (url.pathname === "/cert" && req.method === "GET") return handleGet(env);
    if (url.pathname === "/refresh" && req.method === "POST") return handleRefresh(env);

    return new Response("not found\n", { status: 404 });
  },

  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(refreshAndStore(env).then(() => undefined));
  },
};
