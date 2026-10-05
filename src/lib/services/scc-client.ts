import { AlertPolicyInventory, Tenant } from "../types";
import { graphFetch } from "./graph-fetch";
import { mapAlertPolicy } from "./alert-policy-mapper";

// Security & Compliance PowerShell over REST, as the app registration itself
// (no sign-in). Read-only: this file only ever invokes Get-ProtectionAlert.
//
// Proven live 2026-10-02 (ai-context-vault/Optimization/Recommendations
// Plan.md): the tenant's client secret gets a token for this resource that
// carries Exchange.ManageAsApp and the app's Entra role - the same setup
// Exchange app-only access needs, nothing extra.
//
// Routing is the awkward part, and it is observed behaviour, not documented:
//  1. The global host can't serve a tenant directly ("Could not find the
//     organization container"). POSTed with an X-AnchorMailbox for the
//     tenant's INITIAL (onmicrosoft.com) domain, it answers 302 to
//     "<region>.admin.protection.outlook.com:446" - a backend that isn't
//     reachable from outside.
//  2. The same region on the public host works:
//     "<region>.ps.compliance.protection.outlook.com".
// If Microsoft changes this, fetchAlertPolicyInventory returns
// unavailable: "error" with the reason - never an empty "no alert policies".

const SCC_HOST = "ps.compliance.protection.outlook.com";
const SCC_SCOPE = `https://${SCC_HOST}/.default`;
const SYSTEM_MAILBOX = "SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}";
const TOKEN_SAFETY_MARGIN_MS = 5 * 60_000;

interface SccCacheGlobal {
  clarity365SccTokens?: Map<string, { token: string; expiresAt: number }>;
  clarity365SccRegions?: Map<string, string>;
}
const g = globalThis as unknown as SccCacheGlobal;
if (!g.clarity365SccTokens) g.clarity365SccTokens = new Map();
if (!g.clarity365SccRegions) g.clarity365SccRegions = new Map();
const tokenCache = g.clarity365SccTokens;
const regionCache = g.clarity365SccRegions;

export function resetSccCachesForTests(): void {
  tokenCache.clear();
  regionCache.clear();
}

type Outcome<T> = { value: T } | { unavailable: "notSetUp" | "error"; detail: string };

const NOT_SET_UP =
  "Exchange app access isn't set up for this tenant: the app registration needs Exchange.ManageAsApp and a role such as Global Reader (see the Permissions check).";

function decodeRoles(token: string): string[] {
  try {
    const claims = JSON.parse(Buffer.from(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    return Array.isArray(claims.roles) ? claims.roles : [];
  } catch {
    return [];
  }
}

async function getSccToken(credentials: Tenant["credentials"]): Promise<Outcome<string>> {
  if (!credentials.tenantId || !credentials.clientId || !credentials.clientSecret) return { unavailable: "notSetUp", detail: NOT_SET_UP };
  const key = `${credentials.tenantId}:${credentials.clientId}`;
  const cached = tokenCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return { value: cached.token };

  const res = await graphFetch(
    `https://login.microsoftonline.com/${encodeURIComponent(credentials.tenantId)}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: credentials.clientId, client_secret: credentials.clientSecret, grant_type: "client_credentials", scope: SCC_SCOPE }),
    },
    { timeoutMs: 15_000, maxRetries: 1 }
  );
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) {
    return { unavailable: "error", detail: String(data.error_description || data.error || `Token request failed (${res.status})`).split("\r\n")[0] };
  }
  // Without the permission Microsoft still issues a token, just with no roles in it.
  if (!decodeRoles(data.access_token).includes("Exchange.ManageAsApp")) return { unavailable: "notSetUp", detail: NOT_SET_UP };
  const expiresIn = typeof data.expires_in === "number" ? data.expires_in : 3600;
  tokenCache.set(key, { token: data.access_token, expiresAt: Date.now() + expiresIn * 1000 - TOKEN_SAFETY_MARGIN_MS });
  return { value: data.access_token };
}

function invokeUrl(host: string, tenantId: string): string {
  return `https://${host}/adminapi/beta/${encodeURIComponent(tenantId)}/InvokeCommand`;
}

async function postCmdlet(url: string, token: string, cmdlet: string, extraHeaders: Record<string, string> = {}): Promise<Response> {
  return graphFetch(
    url,
    {
      method: "POST",
      // The redirect target isn't reachable; it is read for its region, never followed.
      redirect: "manual",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", "Accept-Encoding": "identity", ...extraHeaders },
      body: JSON.stringify({ CmdletInput: { CmdletName: cmdlet, Parameters: {} } }),
    },
    { timeoutMs: 60_000, maxRetries: 1 }
  );
}

async function getInitialDomain(graphHeaders: HeadersInit): Promise<string | undefined> {
  const res = await graphFetch("https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains", { headers: graphHeaders }, { maxRetries: 1 });
  if (!res.ok) return undefined;
  const data = await res.json().catch(() => ({}));
  const domains: any[] = data?.value?.[0]?.verifiedDomains || [];
  return domains.find((d) => d?.isInitial)?.name;
}

// "zaf01b" from "https://zaf01b.admin.protection.outlook.com:446/..."
export function regionFromRedirect(location: string | null): string | undefined {
  if (!location) return undefined;
  try {
    const first = new URL(location).hostname.split(".")[0];
    return /^[a-z0-9]{3,12}$/i.test(first) ? first.toLowerCase() : undefined;
  } catch {
    return undefined;
  }
}

async function resolveRegionalHost(tenantId: string, token: string, graphHeaders: HeadersInit): Promise<Outcome<string>> {
  const cached = regionCache.get(tenantId);
  if (cached) return { value: cached };
  const initialDomain = await getInitialDomain(graphHeaders);
  if (!initialDomain) return { unavailable: "error", detail: "Couldn't read the tenant's initial onmicrosoft.com domain, which is needed to find its Microsoft region." };
  const res = await postCmdlet(invokeUrl(SCC_HOST, tenantId), token, "Get-ProtectionAlert", { "X-AnchorMailbox": `UPN:${SYSTEM_MAILBOX}@${initialDomain}` });
  const region = res.status >= 300 && res.status < 400 ? regionFromRedirect(res.headers.get("location")) : undefined;
  if (!region) return { unavailable: "error", detail: `Microsoft didn't say which region serves this tenant's alert policies (HTTP ${res.status}).` };
  const host = `${region}.${SCC_HOST}`;
  regionCache.set(tenantId, host);
  return { value: host };
}

// Reads the tenant's alert policies. Never throws; a failure comes back as
// `unavailable` so the checks say "couldn't be read" rather than "none".
export async function fetchAlertPolicyInventory(tenant: Tenant, graphHeaders: HeadersInit): Promise<AlertPolicyInventory> {
  const checkedAt = new Date().toISOString();
  const fail = (o: { unavailable: "notSetUp" | "error"; detail: string }): AlertPolicyInventory => ({ policies: [], unavailable: o.unavailable, detail: o.detail, checkedAt });
  try {
    const token = await getSccToken(tenant.credentials);
    if (!("value" in token)) return fail(token);
    const tenantId = tenant.credentials.tenantId!;
    const host = await resolveRegionalHost(tenantId, token.value, graphHeaders);
    if (!("value" in host)) return fail(host);

    const res = await postCmdlet(invokeUrl(host.value, tenantId), token.value, "Get-ProtectionAlert");
    if (res.status === 401 || res.status === 403) return fail({ unavailable: "notSetUp", detail: NOT_SET_UP });
    let data: any;
    try {
      data = await res.json();
    } catch {
      data = undefined;
    }
    if (!res.ok || !Array.isArray(data?.value)) {
      // A stale region is the likeliest cause; look it up again next time.
      regionCache.delete(tenantId);
      return fail({ unavailable: "error", detail: String(data?.error?.message || `Get-ProtectionAlert failed (HTTP ${res.status}).`).slice(0, 300) });
    }
    return { policies: data.value.map(mapAlertPolicy), checkedAt };
  } catch (err: any) {
    return fail({ unavailable: "error", detail: err?.message || "Couldn't reach Microsoft's Security & Compliance service." });
  }
}
