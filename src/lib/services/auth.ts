// Session token signing/verification for Clarity365's single-operator login gate.
// Uses Web Crypto (globalThis.crypto.subtle) exclusively so this module works
// identically in the Node.js API routes and in the Edge-runtime middleware.
// Password hashing/verification lives in ./crypto.ts (Node-only, never runs in middleware).

const encoder = new TextEncoder();

export const SESSION_COOKIE_NAME = "clarity365_session";
export const SESSION_TTL_SECONDS = 60 * 60 * 12; // 12 hours

interface SessionPayload {
  iat: number;
  exp: number;
}

function getSessionSecret(): string {
  const secret = process.env.CLARITY365_SESSION_SECRET;
  if (!secret) {
    throw new Error("CLARITY365_SESSION_SECRET is not set.");
  }
  return secret;
}

function bufferToBase64Url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

async function hmacSign(data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(getSessionSecret()),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return bufferToBase64Url(signature);
}

export async function createSessionToken(): Promise<string> {
  const now = Date.now();
  const payload: SessionPayload = { iat: now, exp: now + SESSION_TTL_SECONDS * 1000 };
  const payloadB64 = btoa(JSON.stringify(payload));
  const signature = await hmacSign(payloadB64);
  return `${payloadB64}.${signature}`;
}

export async function verifySessionToken(token: string | undefined | null): Promise<boolean> {
  if (!token) return false;
  const [payloadB64, signature] = token.split(".");
  if (!payloadB64 || !signature) return false;

  try {
    const expectedSignature = await hmacSign(payloadB64);
    if (!timingSafeEqualStr(signature, expectedSignature)) return false;
    const payload: SessionPayload = JSON.parse(atob(payloadB64));
    return typeof payload.exp === "number" && Date.now() < payload.exp;
  } catch {
    return false;
  }
}
