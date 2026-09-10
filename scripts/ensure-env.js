#!/usr/bin/env node

/**
 * Ensures .env.local exists and has CLARITY365_SESSION_SECRET / CLARITY365_ENCRYPTION_KEY
 * populated before Next.js boots. Runs as a pre-hook on dev/build/start so a fresh clone
 * works immediately instead of failing first-run password setup with
 * "CLARITY365_SESSION_SECRET is not set." (see ai-context-vault/Optimization/Optimization Plan.md).
 *
 * Only fills in blank values - a secret a user already set (here, or via a real
 * environment variable, which always takes precedence over .env.local) is never touched.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const envPath = path.join(__dirname, "..", ".env.local");
const examplePath = path.join(__dirname, "..", ".env.example");

const REQUIRED_SECRETS = ["CLARITY365_SESSION_SECRET", "CLARITY365_ENCRYPTION_KEY"];

let contents = fs.existsSync(envPath)
  ? fs.readFileSync(envPath, "utf-8")
  : fs.existsSync(examplePath)
  ? fs.readFileSync(examplePath, "utf-8")
  : REQUIRED_SECRETS.map((k) => `${k}=`).join("\n") + "\n";

let changed = false;
const generatedKeys = [];

for (const key of REQUIRED_SECRETS) {
  // Real environment variables (Docker/host/CI) always win over .env.local, so if one is
  // already set there's nothing to generate or persist for that key.
  if (process.env[key]) continue;

  const re = new RegExp(`^${key}=(.*)$`, "m");
  const match = contents.match(re);
  const existingValue = match?.[1]?.trim();
  if (existingValue) continue;

  const generated = crypto.randomBytes(32).toString("hex");
  changed = true;
  generatedKeys.push(key);

  if (match) {
    contents = contents.replace(re, `${key}=${generated}`);
  } else {
    contents += `${contents.length > 0 && !contents.endsWith("\n") ? "\n" : ""}${key}=${generated}\n`;
  }
}

if (changed) {
  fs.writeFileSync(envPath, contents);
  console.log(
    `[Clarity365] Generated ${generatedKeys.join(" and ")} in .env.local (first run). ` +
      `Back these up to a password manager - CLARITY365_ENCRYPTION_KEY can't be rotated once tenants are added.`
  );
}
