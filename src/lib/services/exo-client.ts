import jwt from "jsonwebtoken";
import { Tenant, MdoThreatPolicy, TablEntry } from "../types";
import { graphFetch } from "./graph-fetch";
import { mapMdoPolicy, mapTablEntry, TablListType } from "./mdo-mapper";

// Exchange Online / Defender for Office 365 policy data (anti-phish, anti-spam,
// Safe Links, Safe Attachments) isn't exposed via standard Microsoft Graph —
// it's Exchange admin surface, reachable only through Exchange Online
// PowerShell or Security & Compliance PowerShell. The modern EXO V3 module
// actually talks to a REST endpoint under the hood
// (outlook.office365.com/adminapi/beta/{tenantId}/InvokeCommand) rather than
// classic WinRM remoting, so this is reachable with a plain authenticated
// HTTPS POST — no PowerShell runtime/shelling required. The catch: this
// endpoint only accepts certificate-based OAuth (a signed JWT client
// assertion); Microsoft does not support the client-secret flow used
// everywhere else in this app for Exchange admin APIs.

interface CachedExoToken {
  token: string;
  expiresAt: number;
}

interface ExoTokenCacheGlobal {
  clarity365ExoTokenCache?: Map<string, CachedExoToken>;
}

const EXO_TOKEN_SAFETY_MARGIN_MS = 5 * 60_000;
const exoTokenCacheGlobal = globalThis as unknown as ExoTokenCacheGlobal;
if (!exoTokenCacheGlobal.clarity365ExoTokenCache) {
  exoTokenCacheGlobal.clarity365ExoTokenCache = new Map<string, CachedExoToken>();
}
const exoTokenCache = exoTokenCacheGlobal.clarity365ExoTokenCache;

// Azure AD's client-assertion JWT header needs the cert's SHA-1 thumbprint
// (as usually copy-pasted from the "Certificates & secrets" blade, hex)
// base64url-encoded as the x5t claim, so it can match the assertion's
// signature to the public cert uploaded to the app registration.
function hexThumbprintToBase64Url(thumbprint: string): string {
  const hex = thumbprint.replace(/[^0-9a-fA-F]/g, "");
  return Buffer.from(hex, "hex").toString("base64url");
}

export async function getExoAccessToken(credentials: Tenant["credentials"]): Promise<{ token?: string; error?: string }> {
  if (!credentials.tenantId || !credentials.clientId || !credentials.certificateThumbprint || !credentials.certificatePrivateKeyPem) {
    return { error: "Missing Tenant ID, Client ID, certificate thumbprint, or private key for Exchange Online authentication." };
  }

  const cacheKey = `exo:${credentials.tenantId}:${credentials.clientId}`;
  const cached = exoTokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return { token: cached.token };
  }

  const tokenEndpoint = `https://login.microsoftonline.com/${encodeURIComponent(credentials.tenantId)}/oauth2/v2.0/token`;

  let assertion: string;
  try {
    const now = Math.floor(Date.now() / 1000);
    assertion = jwt.sign(
      {
        iss: credentials.clientId,
        sub: credentials.clientId,
        aud: tokenEndpoint,
        jti: crypto.randomUUID(),
        nbf: now,
        exp: now + 600, // short-lived — this assertion is single-use, not a session token
      },
      credentials.certificatePrivateKeyPem,
      { algorithm: "RS256", header: { alg: "RS256", x5t: hexThumbprintToBase64Url(credentials.certificateThumbprint) } }
    );
  } catch (err: any) {
    return { error: `Failed to sign the Exchange Online certificate assertion: ${err.message || "invalid private key"}` };
  }

  const body = new URLSearchParams();
  body.append("client_id", credentials.clientId);
  body.append("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
  body.append("client_assertion", assertion);
  body.append("scope", "https://outlook.office365.com/.default");
  body.append("grant_type", "client_credentials");

  try {
    const res = await graphFetch(
      tokenEndpoint,
      { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body },
      { timeoutMs: 10_000 }
    );
    const data = await res.json();
    if (!res.ok || !data.access_token) {
      return { error: data.error_description || data.error || `Exchange Online authentication failed with status ${res.status}` };
    }

    const expiresInSeconds = typeof data.expires_in === "number" ? data.expires_in : 3600;
    exoTokenCache.set(cacheKey, {
      token: data.access_token,
      expiresAt: Date.now() + expiresInSeconds * 1000 - EXO_TOKEN_SAFETY_MARGIN_MS,
    });
    return { token: data.access_token };
  } catch (err: any) {
    return { error: err.message || "Failed to reach Microsoft Entra ID token endpoint." };
  }
}

// Runs one Exchange Online cmdlet via the InvokeCommand REST surface.
// Response shape mirrors Graph's list convention closely enough that we
// normalize the same way (an array directly, or a `.value` array) — worth
// confirming the exact shape against a live tenant, since this endpoint's
// JSON contract isn't as consistently documented as Graph's.
export async function invokeExoCommand(
  tenant: Tenant,
  cmdletName: string,
  parameters: Record<string, any> = {}
): Promise<{ items: any[]; error?: string }> {
  const { token, error } = await getExoAccessToken(tenant.credentials);
  if (error || !token) return { items: [], error };

  try {
    const res = await graphFetch(
      `https://outlook.office365.com/adminapi/beta/${encodeURIComponent(tenant.credentials.tenantId)}/InvokeCommand`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ CmdletInput: { CmdletName: cmdletName, Parameters: parameters } }),
      },
      { timeoutMs: 30_000 }
    );
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return { items: [], error: data?.error?.message || `${cmdletName} failed with status ${res.status}` };
    }
    const items = Array.isArray(data) ? data : Array.isArray(data.value) ? data.value : [];
    return { items };
  } catch (err: any) {
    return { items: [], error: err.message || `Network error while invoking ${cmdletName}.` };
  }
}

const POLICY_CMDLETS: { cmdlet: string; policyType: MdoThreatPolicy["policyType"] }[] = [
  { cmdlet: "Get-HostedContentFilterPolicy", policyType: "AntiSpamInbound" },
  { cmdlet: "Get-HostedOutboundSpamFilterPolicy", policyType: "AntiSpamOutbound" },
  { cmdlet: "Get-AntiPhishPolicy", policyType: "AntiPhishing" },
  { cmdlet: "Get-MalwareFilterPolicy", policyType: "AntiMalware" },
  { cmdlet: "Get-SafeLinksPolicy", policyType: "SafeLinks" },
  { cmdlet: "Get-SafeAttachmentPolicy", policyType: "SafeAttachments" },
];

export interface ExoConnectivityResult {
  connected: boolean;
  error?: string;
  testedAt: string;
}

// Lightweight connectivity check for the Permissions modal — confirms the
// certificate assertion is accepted and the app's service principal can run
// at least one read-only Exchange Online cmdlet, without pulling all six
// policy types.
export async function testExoConnectivity(tenant: Tenant): Promise<ExoConnectivityResult> {
  const testedAt = new Date().toISOString();
  if (!tenant.credentials.certificateThumbprint || !tenant.credentials.certificatePrivateKeyPem) {
    return { connected: false, error: "No Exchange Online certificate configured for this tenant.", testedAt };
  }
  const result = await invokeExoCommand(tenant, "Get-OrganizationConfig");
  return { connected: !result.error, error: result.error, testedAt };
}

const TABL_LIST_TYPES: TablListType[] = ["Sender", "Url", "FileHash"];

export async function fetchMdoPoliciesAndTabl(
  tenant: Tenant
): Promise<{ policies: MdoThreatPolicy[]; tabl: TablEntry[]; errors: string[] }> {
  const errors: string[] = [];
  const policies: MdoThreatPolicy[] = [];

  for (const { cmdlet, policyType } of POLICY_CMDLETS) {
    const result = await invokeExoCommand(tenant, cmdlet);
    if (result.error) {
      errors.push(`${cmdlet}: ${result.error}`);
      continue;
    }
    result.items.forEach((raw) => policies.push(mapMdoPolicy(raw, policyType)));
  }

  const tabl: TablEntry[] = [];
  for (const listType of TABL_LIST_TYPES) {
    const result = await invokeExoCommand(tenant, "Get-TenantAllowBlockListItems", { ListType: listType });
    if (result.error) {
      errors.push(`Get-TenantAllowBlockListItems (${listType}): ${result.error}`);
      continue;
    }
    result.items.forEach((raw) => tabl.push(mapTablEntry(raw, listType)));
  }

  return { policies, tabl, errors };
}
