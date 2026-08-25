import { describe, it, expect, beforeAll } from "vitest";

// getKey() reads this at call time (not import time), so it just needs to be
// set before any encrypt/decrypt/hash call runs.
beforeAll(() => {
  process.env.CLARITY365_ENCRYPTION_KEY = "test-only-encryption-key-do-not-use-in-prod";
});

import { encryptSecret, decryptSecret, isEncrypted, hashPassword, verifyPasswordHash } from "./crypto";

describe("encryptSecret / decryptSecret", () => {
  it("round-trips a plaintext value", () => {
    const plaintext = "super-secret-client-secret-value";
    const encrypted = encryptSecret(plaintext);
    expect(decryptSecret(encrypted)).toBe(plaintext);
  });

  it("produces a different ciphertext each time (random IV) but both still decrypt correctly", () => {
    const plaintext = "same-input-twice";
    const a = encryptSecret(plaintext);
    const b = encryptSecret(plaintext);
    expect(a).not.toBe(b);
    expect(decryptSecret(a)).toBe(plaintext);
    expect(decryptSecret(b)).toBe(plaintext);
  });

  it("round-trips an empty string", () => {
    const encrypted = encryptSecret("");
    expect(decryptSecret(encrypted)).toBe("");
  });

  it("throws when decrypting a value that isn't in the enc:v1: format", () => {
    expect(() => decryptSecret("plain-text-not-encrypted")).toThrow();
  });

  it("throws when the auth tag has been tampered with", () => {
    const encrypted = encryptSecret("tamper-test");
    const parts = encrypted.split(":");
    // parts: ["enc", "v1", iv, authTag, ciphertext] — corrupt the auth tag.
    parts[3] = parts[3].replace(/./, (c) => (c === "0" ? "1" : "0"));
    const tampered = parts.join(":");
    expect(() => decryptSecret(tampered)).toThrow();
  });
});

describe("isEncrypted", () => {
  it("returns true for a value produced by encryptSecret", () => {
    expect(isEncrypted(encryptSecret("hello"))).toBe(true);
  });

  it("returns false for plaintext, undefined, and null", () => {
    expect(isEncrypted("plain-text")).toBe(false);
    expect(isEncrypted(undefined)).toBe(false);
    expect(isEncrypted(null)).toBe(false);
  });
});

describe("hashPassword / verifyPasswordHash", () => {
  it("verifies the correct password against its own hash", () => {
    const hash = hashPassword("correct-horse-battery-staple");
    expect(verifyPasswordHash("correct-horse-battery-staple", hash)).toBe(true);
  });

  it("rejects an incorrect password", () => {
    const hash = hashPassword("correct-horse-battery-staple");
    expect(verifyPasswordHash("wrong-password", hash)).toBe(false);
  });

  it("produces a different hash each time (random salt) but both still verify", () => {
    const a = hashPassword("same-password");
    const b = hashPassword("same-password");
    expect(a).not.toBe(b);
    expect(verifyPasswordHash("same-password", a)).toBe(true);
    expect(verifyPasswordHash("same-password", b)).toBe(true);
  });

  it("returns false (not throw) for a malformed stored hash", () => {
    expect(verifyPasswordHash("anything", "not-a-valid-hash")).toBe(false);
    expect(verifyPasswordHash("anything", "scrypt:v2:deadbeef:deadbeef")).toBe(false);
    expect(verifyPasswordHash("anything", "")).toBe(false);
  });
});
