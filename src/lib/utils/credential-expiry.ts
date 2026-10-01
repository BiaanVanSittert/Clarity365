import { SecretExpiry, TenantCredentials } from "../types";

// When does the client secret Clarity365 uses for a tenant expire? When it
// does, every module for that tenant stops (Exchange too, now that it runs on
// the same secret), so the header, the fleet table and the Permissions check
// warn 30 days ahead.
//
// The sync already reads the tenant's app registrations; this finds
// Clarity365's own app in that list and picks out the secret in use.

export const SECRET_EXPIRY_WARNING_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

// rawApp: Clarity365's own application object from GET /applications
// (passwordCredentials carry `hint`, the secret's first three characters, and
// `endDateTime`). If the hint identifies exactly one unexpired secret, that
// expiry is exact; otherwise the soonest unexpired one is the safe answer.
export function resolveOwnAppSecretExpiry(rawApp: any, clientSecret: string | undefined, now: Date = new Date()): SecretExpiry | undefined {
  const secrets: { hint?: string; end: number }[] = (Array.isArray(rawApp?.passwordCredentials) ? rawApp.passwordCredentials : [])
    .map((c: any) => ({ hint: typeof c?.hint === "string" ? c.hint : undefined, end: Date.parse(c?.endDateTime) }))
    .filter((c: { end: number }) => !Number.isNaN(c.end));
  const live = secrets.filter((c) => c.end > now.getTime());
  if (live.length === 0) return undefined;

  const hint = clientSecret ? clientSecret.slice(0, 3) : undefined;
  const matching = hint ? live.filter((c) => c.hint === hint) : [];
  const exact = matching.length === 1;
  const candidates = matching.length > 0 ? matching : live;
  const soonest = Math.min(...candidates.map((c) => c.end));
  return { expiresAt: new Date(soonest).toISOString(), exact, checkedAt: now.toISOString() };
}

export interface SecretExpiryStatus {
  state: "ok" | "expiring" | "expired";
  daysLeft: number;
  expiresAt: string;
  // Short text for a badge, e.g. "Secret expires in 12 days".
  label: string;
  // One sentence for a tooltip.
  detail: string;
}

// Undefined when the expiry isn't known (never synced, demo tenant, or the
// app can't read its own registration).
export function getSecretExpiryStatus(credentials: Pick<TenantCredentials, "secretExpiry"> | undefined, now: Date = new Date()): SecretExpiryStatus | undefined {
  const expiry = credentials?.secretExpiry;
  if (!expiry?.expiresAt) return undefined;
  const end = Date.parse(expiry.expiresAt);
  if (Number.isNaN(end)) return undefined;
  const daysLeft = Math.floor((end - now.getTime()) / DAY_MS);
  const date = expiry.expiresAt.slice(0, 10);
  const which = expiry.exact ? "The client secret Clarity365 uses" : "The app registration's soonest-expiring client secret";
  if (end <= now.getTime()) {
    return { state: "expired", daysLeft, expiresAt: expiry.expiresAt, label: "Secret expired", detail: `${which} expired on ${date}. Create a new one in Entra and update it under Edit credentials.` };
  }
  if (daysLeft < SECRET_EXPIRY_WARNING_DAYS) {
    const label = daysLeft === 0 ? "Secret expires today" : `Secret expires in ${daysLeft} day${daysLeft === 1 ? "" : "s"}`;
    return { state: "expiring", daysLeft, expiresAt: expiry.expiresAt, label, detail: `${which} expires on ${date}. Create a new one in Entra and update it under Edit credentials before then.` };
  }
  return { state: "ok", daysLeft, expiresAt: expiry.expiresAt, label: `Secret valid until ${date}`, detail: `${which} expires on ${date}.` };
}
