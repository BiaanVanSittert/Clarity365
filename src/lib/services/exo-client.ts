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
// HTTPS POST — no PowerShell runtime/shelling required.
//
// Auth: Exchange admin APIs don't accept the client-secret flow used
// everywhere else in this app. Rather than requiring a certificate (an
// earlier version of this file did), this uses a delegated OAuth device-code
// flow against Microsoft's own first-party "Microsoft Exchange REST API
// Based PowerShell" multi-tenant public client — the exact same client ID
// the real Connect-ExchangeOnline cmdlet uses for interactive sign-in. That
// means zero custom app-registration configuration: no certificate, no
// Exchange.ManageAsApp permission, nothing to add to the tenant's own app
// registration. An admin with Global Reader/Security Reader/Exchange admin
// rights does a one-time interactive sign-in (enter a short code at a
// Microsoft URL); Clarity365 stores the resulting refresh token (encrypted,
// like clientSecret) and silently refreshes access tokens going forward.
const EXO_POWERSHELL_CLIENT_ID = "fb78d390-0c51-40cd-8e17-fdbfab77341b";
const EXO_SCOPE = "https://outlook.office365.com/.default offline_access";

// Called whenever a refresh-token grant rotates the token (which happens on
// every use — these are single-use/rotating public-client refresh tokens).
// exo-client.ts has no database access (avoiding a circular import with
// tenant-store.ts), so persistence is delegated to the caller via this
// callback, threaded through every layer up to tenant-store.ts.
export type ExoRefreshRotatedCallback = (newRefreshToken: string) => void;

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

function tokenEndpoint(azureTenantId: string): string {
  return `https://login.microsoftonline.com/${encodeURIComponent(azureTenantId)}/oauth2/v2.0/token`;
}

export async function getExoAccessToken(
  credentials: Tenant["credentials"],
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<{ token?: string; error?: string }> {
  if (!credentials.tenantId || !credentials.exoRefreshToken) {
    return { error: "Exchange Online isn't connected for this tenant yet — use the Permissions check to connect." };
  }

  const cacheKey = `exo:${credentials.tenantId}`;
  const cached = exoTokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return { token: cached.token };
  }

  const body = new URLSearchParams();
  body.append("client_id", EXO_POWERSHELL_CLIENT_ID);
  body.append("grant_type", "refresh_token");
  body.append("refresh_token", credentials.exoRefreshToken);
  body.append("scope", EXO_SCOPE);

  try {
    const res = await graphFetch(
      tokenEndpoint(credentials.tenantId),
      { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body },
      { timeoutMs: 10_000 }
    );
    const data = await res.json();
    if (!res.ok || !data.access_token) {
      return {
        error:
          data.error_description ||
          "Exchange Online authentication failed — the connection may have been revoked; try reconnecting in the Permissions check.",
      };
    }

    const expiresInSeconds = typeof data.expires_in === "number" ? data.expires_in : 3600;
    exoTokenCache.set(cacheKey, {
      token: data.access_token,
      expiresAt: Date.now() + expiresInSeconds * 1000 - EXO_TOKEN_SAFETY_MARGIN_MS,
    });

    // Public-client refresh tokens rotate on every use — the old one becomes
    // invalid the moment a new one is issued, so this MUST be persisted every
    // time or the connection silently breaks after the very next sync.
    if (data.refresh_token && data.refresh_token !== credentials.exoRefreshToken) {
      onRefreshRotated?.(data.refresh_token);
    }

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
  parameters: Record<string, any> = {},
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<{ items: any[]; error?: string }> {
  const { token, error } = await getExoAccessToken(tenant.credentials, onRefreshRotated);
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

const TABL_LIST_TYPES: TablListType[] = ["Sender", "Url", "FileHash"];

export async function fetchMdoPoliciesAndTabl(
  tenant: Tenant,
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<{ policies: MdoThreatPolicy[]; tabl: TablEntry[]; errors: string[] }> {
  const errors: string[] = [];
  const policies: MdoThreatPolicy[] = [];

  for (const { cmdlet, policyType } of POLICY_CMDLETS) {
    const result = await invokeExoCommand(tenant, cmdlet, {}, onRefreshRotated);
    if (result.error) {
      errors.push(`${cmdlet}: ${result.error}`);
      continue;
    }
    result.items.forEach((raw) => policies.push(mapMdoPolicy(raw, policyType)));
  }

  const tabl: TablEntry[] = [];
  for (const listType of TABL_LIST_TYPES) {
    const result = await invokeExoCommand(tenant, "Get-TenantAllowBlockListItems", { ListType: listType }, onRefreshRotated);
    if (result.error) {
      errors.push(`Get-TenantAllowBlockListItems (${listType}): ${result.error}`);
      continue;
    }
    result.items.forEach((raw) => tabl.push(mapTablEntry(raw, listType)));
  }

  return { policies, tabl, errors };
}

// Real, live writes to the Tenant Allow/Block List — gated by
// tenant.credentials.exoWriteEnabled at the tenant-store layer (see
// addTablEntry/removeTablEntry there), never called unconditionally just
// because a read-only EXO connection exists. Cmdlet parameter names below
// follow the documented New-/Remove-TenantAllowBlockListItems shape as of
// this writing — worth confirming against a live tenant during testing,
// matching the same honesty-about-untested-assumptions pattern already used
// for the read-side mapping in mdo-mapper.ts.
export async function addTenantAllowBlockListItem(
  tenant: Tenant,
  params: { listType: TablListType; action: "Allow" | "Block"; value: string; notes?: string; expirationDate?: string },
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<{ success: boolean; error?: string }> {
  const parameters: Record<string, any> = {
    ListType: params.listType,
    Entries: [params.value],
  };
  if (params.expirationDate) {
    parameters.ExpirationDate = params.expirationDate;
  } else {
    parameters.NoExpiration = true;
  }
  parameters[params.action] = true;
  if (params.notes) parameters.Notes = params.notes;

  const result = await invokeExoCommand(tenant, "New-TenantAllowBlockListItems", parameters, onRefreshRotated);
  return result.error ? { success: false, error: result.error } : { success: true };
}

export async function removeTenantAllowBlockListItem(
  tenant: Tenant,
  params: { listType: TablListType; identity: string },
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<{ success: boolean; error?: string }> {
  const result = await invokeExoCommand(
    tenant,
    "Remove-TenantAllowBlockListItems",
    { ListType: params.listType, Ids: [params.identity] },
    onRefreshRotated
  );
  return result.error ? { success: false, error: result.error } : { success: true };
}

// Runs a single Set-*Policy remediation cmdlet for one MDO baseline gap (see
// mdo-baseline-definitions.ts's MdoRemediationAction) — a thin wrapper over
// invokeExoCommand, same shape/gating as the TABL write functions above.
export async function applyMdoRemediation(
  tenant: Tenant,
  cmdlet: string,
  parameters: Record<string, any>,
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<{ success: boolean; error?: string }> {
  const result = await invokeExoCommand(tenant, cmdlet, parameters, onRefreshRotated);
  return result.error ? { success: false, error: result.error } : { success: true };
}

export interface ExoConnectivityResult {
  connected: boolean;
  error?: string;
  testedAt: string;
}

// Lightweight connectivity check for the Permissions modal — confirms the
// stored refresh token is still valid and can run at least one read-only
// Exchange Online cmdlet, without pulling all six policy types.
export async function testExoConnectivity(
  tenant: Tenant,
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<ExoConnectivityResult> {
  const testedAt = new Date().toISOString();
  if (!tenant.credentials.exoRefreshToken) {
    return { connected: false, error: "Exchange Online isn't connected for this tenant yet.", testedAt };
  }
  const result = await invokeExoCommand(tenant, "Get-OrganizationConfig", {}, onRefreshRotated);
  return { connected: !result.error, error: result.error, testedAt };
}

// ---- Device-code sign-in flow ---------------------------------------------
// Two-step interactive flow the Permissions modal drives: start() returns a
// short code + verification URL for the admin to open in any browser; poll()
// is called repeatedly (per the returned `interval`) until the admin
// completes sign-in, the code expires, or they decline.

export interface DeviceCodeStart {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresIn: number;
  interval: number;
  message: string;
}

export async function startExoDeviceCodeFlow(azureTenantId: string): Promise<{ result?: DeviceCodeStart; error?: string }> {
  try {
    const body = new URLSearchParams();
    body.append("client_id", EXO_POWERSHELL_CLIENT_ID);
    body.append("scope", EXO_SCOPE);
    const res = await graphFetch(
      `https://login.microsoftonline.com/${encodeURIComponent(azureTenantId)}/oauth2/v2.0/devicecode`,
      { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body },
      { timeoutMs: 10_000 }
    );
    const data = await res.json();
    if (!res.ok) {
      return { error: data.error_description || "Failed to start Exchange Online sign-in." };
    }
    return {
      result: {
        deviceCode: data.device_code,
        userCode: data.user_code,
        verificationUri: data.verification_uri,
        expiresIn: data.expires_in,
        interval: data.interval,
        message: data.message,
      },
    };
  } catch (err: any) {
    return { error: err.message || "Failed to reach Microsoft Entra ID." };
  }
}

export type DeviceCodePollStatus = "pending" | "success" | "error" | "expired" | "declined";

export async function pollExoDeviceCodeFlow(
  azureTenantId: string,
  deviceCode: string
): Promise<{ status: DeviceCodePollStatus; refreshToken?: string; error?: string }> {
  try {
    const body = new URLSearchParams();
    body.append("client_id", EXO_POWERSHELL_CLIENT_ID);
    body.append("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
    body.append("device_code", deviceCode);
    const res = await graphFetch(
      tokenEndpoint(azureTenantId),
      { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body },
      { timeoutMs: 10_000, retryOnNetworkError: false }
    );
    const data = await res.json().catch(() => ({}));

    if (res.ok && data.refresh_token) {
      return { status: "success", refreshToken: data.refresh_token };
    }
    if (data.error === "authorization_pending" || data.error === "slow_down") {
      return { status: "pending" };
    }
    if (data.error === "expired_token") {
      return { status: "expired", error: "The sign-in code expired before it was used." };
    }
    if (data.error === "authorization_declined") {
      return { status: "declined", error: "Sign-in was declined." };
    }
    return { status: "error", error: data.error_description || "Exchange Online sign-in failed." };
  } catch (err: any) {
    return { status: "error", error: err.message || "Network error while checking sign-in status." };
  }
}
