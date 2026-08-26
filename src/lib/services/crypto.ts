import crypto from "crypto";

// AES-256-GCM at-rest encryption for tenant client secrets.
// Storage format: "enc:v1:<iv-hex>:<authTag-hex>:<ciphertext-hex>"
const ENC_PREFIX = "enc:v1:";
const ALGORITHM = "aes-256-gcm";
const KEY_SALT = "clarity365-secret-store";

function getKey(): Buffer {
  const passphrase = process.env.CLARITY365_ENCRYPTION_KEY;
  if (!passphrase) {
    throw new Error(
      "CLARITY365_ENCRYPTION_KEY is not set. Add it to .env.local before storing tenant credentials."
    );
  }
  return crypto.scryptSync(passphrase, KEY_SALT, 32);
}

export function isEncrypted(value: string | undefined | null): value is string {
  return typeof value === "string" && value.startsWith(ENC_PREFIX);
}

export function encryptSecret(plainText: string): string {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plainText, "utf-8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${ENC_PREFIX}${iv.toString("hex")}:${authTag.toString("hex")}:${ciphertext.toString("hex")}`;
}

export function decryptSecret(encoded: string): string {
  if (!isEncrypted(encoded)) {
    throw new Error("Value is not in the expected encrypted format.");
  }
  const [, , ivHex, tagHex, dataHex] = encoded.split(":");
  const key = getKey();
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(tagHex, "hex");
  const ciphertext = Buffer.from(dataHex, "hex");
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf-8");
}

// Mask shown to API/UI consumers in place of a real secret value. Never send the
// decrypted (or encrypted) value to a client - this is a write-only field.
export const SECRET_MASK = "••••••••";

// Operator password hashing (scrypt, salted per-password). Storage format:
// "scrypt:v1:<salt-hex>:<hash-hex>". Deliberately slow/memory-hard, unlike the
// plain SHA-256 used for session-token signing - this is for a real password.
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt:v1:${salt.toString("hex")}:${hash.toString("hex")}`;
}

export function verifyPasswordHash(password: string, stored: string): boolean {
  const parts = stored.split(":");
  if (parts.length !== 4 || parts[0] !== "scrypt" || parts[1] !== "v1") return false;
  try {
    const salt = Buffer.from(parts[2], "hex");
    const expected = Buffer.from(parts[3], "hex");
    const actual = crypto.scryptSync(password, salt, 64);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}
