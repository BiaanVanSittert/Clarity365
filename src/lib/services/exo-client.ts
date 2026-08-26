import { Tenant, MdoThreatPolicy, TablEntry, MailboxItem, EmailForwardingRule, MailflowTransportRule, DomainAuthCheck, MailflowConnector } from "../types";
import { graphFetch } from "./graph-fetch";
import { mapMdoPolicy, mapTablEntry, TablListType } from "./mdo-mapper";
import {
  mapMailboxItem,
  mapMailboxStatistics,
  mapFullAccessDelegations,
  mapSendAsDelegations,
  mapSendOnBehalfDelegations,
  mapMailboxAutoForward,
  mapInboxRule,
  mapTransportRule,
  mapMailflowTransportRule,
  mapAcceptedDomain,
  mapDkimStatus,
  mapConnector,
  mapRemoteDomainAutoForwardBlocked,
  mapExternalSenderTagEnabled,
} from "./mailflow-mapper";

// Exchange Online / Defender for Office 365 policy data (anti-phish, anti-spam,
// Safe Links, Safe Attachments) isn't exposed via standard Microsoft Graph -
// it's Exchange admin surface, reachable only through Exchange Online
// PowerShell or Security & Compliance PowerShell. The modern EXO V3 module
// actually talks to a REST endpoint under the hood
// (outlook.office365.com/adminapi/beta/{tenantId}/InvokeCommand) rather than
// classic WinRM remoting, so this is reachable with a plain authenticated
// HTTPS POST - no PowerShell runtime/shelling required.
//
// Auth: Exchange admin APIs don't accept the client-secret flow used
// everywhere else in this app. Rather than requiring a certificate (an
// earlier version of this file did), this uses a delegated OAuth device-code
// flow against Microsoft's own first-party "Microsoft Exchange REST API
// Based PowerShell" multi-tenant public client - the exact same client ID
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
// every use - these are single-use/rotating public-client refresh tokens).
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
    return { error: "Exchange Online isn't connected for this tenant yet - use the Permissions check to connect." };
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
          "Exchange Online authentication failed - the connection may have been revoked; try reconnecting in the Permissions check.",
      };
    }

    const expiresInSeconds = typeof data.expires_in === "number" ? data.expires_in : 3600;
    exoTokenCache.set(cacheKey, {
      token: data.access_token,
      expiresAt: Date.now() + expiresInSeconds * 1000 - EXO_TOKEN_SAFETY_MARGIN_MS,
    });

    // Public-client refresh tokens rotate on every use - the old one becomes
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
// normalize the same way (an array directly, or a `.value` array) - worth
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
): Promise<{ policies: MdoThreatPolicy[]; tabl: TablEntry[]; policyErrors: string[]; tablErrors: string[] }> {
  const policyErrors: string[] = [];
  const policies: MdoThreatPolicy[] = [];

  for (const { cmdlet, policyType } of POLICY_CMDLETS) {
    const result = await invokeExoCommand(tenant, cmdlet, {}, onRefreshRotated);
    if (result.error) {
      policyErrors.push(`${cmdlet}: ${result.error}`);
      continue;
    }
    result.items.forEach((raw) => policies.push(mapMdoPolicy(raw, policyType)));
  }

  // Kept as a distinct array from policyErrors above (rather than one shared
  // list) so callers can label a Get-TenantAllowBlockListItems failure as an
  // "MDO TABL" problem instead of an "MDO Policies" one - the two surfaces
  // fail independently and the UI shows them in different tabs.
  const tablErrors: string[] = [];
  const tabl: TablEntry[] = [];
  for (const listType of TABL_LIST_TYPES) {
    const result = await invokeExoCommand(tenant, "Get-TenantAllowBlockListItems", { ListType: listType }, onRefreshRotated);
    if (result.error) {
      tablErrors.push(`Get-TenantAllowBlockListItems (${listType}): ${result.error}`);
      continue;
    }
    result.items.forEach((raw) => tabl.push(mapTablEntry(raw, listType)));
  }

  return { policies, tabl, policyErrors, tablErrors };
}

// Real, live writes to the Tenant Allow/Block List - gated by
// tenant.credentials.exoWriteEnabled at the tenant-store layer (see
// addTablEntry/removeTablEntry there), never called unconditionally just
// because a read-only EXO connection exists. Cmdlet parameter names below
// follow the documented New-/Remove-TenantAllowBlockListItems shape as of
// this writing - worth confirming against a live tenant during testing,
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
// mdo-baseline-definitions.ts's MdoRemediationAction) - a thin wrapper over
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

// ---- Mailbox delegation & email forwarding (Module 6/7 live data) --------
//
// Unlike the MDO policy fetch above, Exchange has no bulk "get every
// mailbox's permissions/rules" cmdlet - each mailbox needs its own
// Get-MailboxStatistics/Get-MailboxPermission/Get-RecipientPermission/
// Get-InboxRule round trip, so this is N+1 network calls rather than a
// single paginated fetch like the Graph endpoints elsewhere in this app.
// The per-mailbox calls run concurrently (Promise.all) to keep wall-clock
// time down, and the mailbox count itself is capped so one sync can't run
// unboundedly long on a very large tenant - mailboxes beyond the cap simply
// aren't scanned this cycle (surfaced as a sync note, not a hard error)
// rather than silently showing "no delegations found".
const MAX_MAILBOXES_FOR_MAILFLOW_SCAN = 250;

export interface MailflowFetchResult {
  mailboxes: MailboxItem[];
  emailForwarding: EmailForwardingRule[];
  transportRules: MailflowTransportRule[];
  connectors: MailflowConnector[];
  remoteDomainAutoForwardBlocked: boolean | null;
  externalSenderTagEnabled: boolean | null;
  mailboxAuditingEnabled: boolean | null;
  errors: string[];
}

export async function fetchMailflowData(
  tenant: Tenant,
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<MailflowFetchResult> {
  const errors: string[] = [];
  const tenantDomain = tenant.defaultDomainName;

  const mailboxResult = await invokeExoCommand(
    tenant,
    "Get-Mailbox",
    { ResultSize: MAX_MAILBOXES_FOR_MAILFLOW_SCAN },
    onRefreshRotated
  );
  if (mailboxResult.error) {
    errors.push(`Get-Mailbox: ${mailboxResult.error}`);
    return {
      mailboxes: [],
      emailForwarding: [],
      transportRules: [],
      connectors: [],
      remoteDomainAutoForwardBlocked: null,
      externalSenderTagEnabled: null,
      mailboxAuditingEnabled: null,
      errors,
    };
  }
  if (mailboxResult.items.length === MAX_MAILBOXES_FOR_MAILFLOW_SCAN) {
    errors.push(
      `Mailbox scan capped at the first ${MAX_MAILBOXES_FOR_MAILFLOW_SCAN} mailboxes for sync performance - this tenant may have more.`
    );
  }

  const mailboxes: MailboxItem[] = [];
  const emailForwarding: EmailForwardingRule[] = [];

  for (const raw of mailboxResult.items) {
    const mailbox = mapMailboxItem(raw);

    const [statsResult, fullAccessResult, sendAsResult, inboxRulesResult] = await Promise.all([
      invokeExoCommand(tenant, "Get-MailboxStatistics", { Identity: mailbox.userPrincipalName }, onRefreshRotated),
      invokeExoCommand(tenant, "Get-MailboxPermission", { Identity: mailbox.userPrincipalName }, onRefreshRotated),
      invokeExoCommand(tenant, "Get-RecipientPermission", { Identity: mailbox.userPrincipalName }, onRefreshRotated),
      invokeExoCommand(tenant, "Get-InboxRule", { Mailbox: mailbox.userPrincipalName, IncludeHidden: true }, onRefreshRotated),
    ]);

    if (statsResult.error) {
      errors.push(`Get-MailboxStatistics (${mailbox.userPrincipalName}): ${statsResult.error}`);
    } else {
      const stats = mapMailboxStatistics(statsResult.items[0]);
      mailbox.totalItemSizeMB = stats.totalItemSizeMB;
      mailbox.itemCount = stats.itemCount;
    }

    if (fullAccessResult.error) errors.push(`Get-MailboxPermission (${mailbox.userPrincipalName}): ${fullAccessResult.error}`);
    if (sendAsResult.error) errors.push(`Get-RecipientPermission (${mailbox.userPrincipalName}): ${sendAsResult.error}`);
    mailbox.delegations = [
      ...(fullAccessResult.error ? [] : mapFullAccessDelegations(fullAccessResult.items)),
      ...(sendAsResult.error ? [] : mapSendAsDelegations(sendAsResult.items)),
      ...mapSendOnBehalfDelegations(raw.GrantSendOnBehalfTo),
    ];

    const autoForward = mapMailboxAutoForward(raw, tenantDomain);
    if (autoForward) emailForwarding.push(autoForward);

    if (inboxRulesResult.error) {
      errors.push(`Get-InboxRule (${mailbox.userPrincipalName}): ${inboxRulesResult.error}`);
    } else {
      inboxRulesResult.items.forEach((ruleRaw) => {
        const rule = mapInboxRule(ruleRaw, mailbox.userPrincipalName, tenantDomain);
        if (rule) emailForwarding.push(rule);
      });
    }

    mailboxes.push(mailbox);
  }

  const transportRules: MailflowTransportRule[] = [];
  const transportRuleResult = await invokeExoCommand(tenant, "Get-TransportRule", {}, onRefreshRotated);
  if (transportRuleResult.error) {
    errors.push(`Get-TransportRule: ${transportRuleResult.error}`);
  } else {
    transportRuleResult.items.forEach((raw) => {
      const forwardingRule = mapTransportRule(raw, tenantDomain);
      if (forwardingRule) emailForwarding.push(forwardingRule);
      // Every transport rule (not just the forwarding-shaped subset above)
      // gets scored against the Mail Flow Rules baseline (MF01-03) - a rule
      // can be flagged there (e.g. an SCL override) without ever appearing
      // in Email Forwarding Audit at all.
      transportRules.push(mapMailflowTransportRule(raw, tenantDomain));
    });
  }

  const connectors: MailflowConnector[] = [];
  const [inboundResult, outboundResult] = await Promise.all([
    invokeExoCommand(tenant, "Get-InboundConnector", {}, onRefreshRotated),
    invokeExoCommand(tenant, "Get-OutboundConnector", {}, onRefreshRotated),
  ]);
  if (inboundResult.error) errors.push(`Get-InboundConnector: ${inboundResult.error}`);
  else inboundResult.items.forEach((raw) => connectors.push(mapConnector(raw, "Inbound")));
  if (outboundResult.error) errors.push(`Get-OutboundConnector: ${outboundResult.error}`);
  else outboundResult.items.forEach((raw) => connectors.push(mapConnector(raw, "Outbound")));

  // Get-OrganizationConfig, Get-RemoteDomain (Default), and
  // Get-ExternalInOutlook all normally return a single object rather than a
  // list - worth confirming these still land in items[0] via
  // invokeExoCommand's array/`.value` normalization against a live tenant,
  // same caveat as every other not-yet-verified EXO field assumption here.
  let mailboxAuditingEnabled: boolean | null = null;
  const orgConfigResult = await invokeExoCommand(tenant, "Get-OrganizationConfig", {}, onRefreshRotated);
  if (orgConfigResult.error) {
    errors.push(`Get-OrganizationConfig: ${orgConfigResult.error}`);
  } else if (orgConfigResult.items[0]) {
    mailboxAuditingEnabled = orgConfigResult.items[0].AuditDisabled === false;
  }

  let remoteDomainAutoForwardBlocked: boolean | null = null;
  const remoteDomainResult = await invokeExoCommand(tenant, "Get-RemoteDomain", { Identity: "Default" }, onRefreshRotated);
  if (remoteDomainResult.error) {
    errors.push(`Get-RemoteDomain: ${remoteDomainResult.error}`);
  } else if (remoteDomainResult.items[0]) {
    remoteDomainAutoForwardBlocked = mapRemoteDomainAutoForwardBlocked(remoteDomainResult.items[0]);
  }

  let externalSenderTagEnabled: boolean | null = null;
  const externalTagResult = await invokeExoCommand(tenant, "Get-ExternalInOutlook", {}, onRefreshRotated);
  if (externalTagResult.error) {
    errors.push(`Get-ExternalInOutlook: ${externalTagResult.error}`);
  } else if (externalTagResult.items[0]) {
    externalSenderTagEnabled = mapExternalSenderTagEnabled(externalTagResult.items[0]);
  }

  return {
    mailboxes,
    emailForwarding,
    transportRules,
    connectors,
    remoteDomainAutoForwardBlocked,
    externalSenderTagEnabled,
    mailboxAuditingEnabled,
    errors,
  };
}

export type DelegationAccessRight = "FullAccess" | "SendAs" | "SendOnBehalf";

export async function removeMailboxDelegation(
  tenant: Tenant,
  params: {
    mailboxUpn: string;
    principalUpn: string;
    accessRight: DelegationAccessRight;
    // Required (and used) only for SendOnBehalf - see comment below.
    remainingSendOnBehalf?: string[];
  },
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<{ success: boolean; error?: string }> {
  let result;
  if (params.accessRight === "FullAccess") {
    result = await invokeExoCommand(
      tenant,
      "Remove-MailboxPermission",
      { Identity: params.mailboxUpn, User: params.principalUpn, AccessRights: ["FullAccess"], Confirm: false },
      onRefreshRotated
    );
  } else if (params.accessRight === "SendAs") {
    result = await invokeExoCommand(
      tenant,
      "Remove-RecipientPermission",
      { Identity: params.mailboxUpn, Trustee: params.principalUpn, AccessRights: ["SendAs"], Confirm: false },
      onRefreshRotated
    );
  } else {
    // GrantSendOnBehalfTo is a multi-valued mailbox property with no
    // dedicated Remove- cmdlet (PowerShell's interactive `@{remove=...}`
    // hash syntax for updating multi-valued properties has no equivalent in
    // a plain JSON RPC parameter payload) - revoking one entry means
    // replacing the whole list with everyone except the principal being
    // removed, which the caller computes from the already-synced snapshot.
    result = await invokeExoCommand(
      tenant,
      "Set-Mailbox",
      { Identity: params.mailboxUpn, GrantSendOnBehalfTo: params.remainingSendOnBehalf || [] },
      onRefreshRotated
    );
  }
  return result.error ? { success: false, error: result.error } : { success: true };
}

export async function disableForwardingRule(
  tenant: Tenant,
  rule: { scope: EmailForwardingRule["scope"]; name: string; mailboxOwner?: string },
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<{ success: boolean; error?: string }> {
  let result;
  if (rule.scope === "transport_rule") {
    result = await invokeExoCommand(tenant, "Disable-TransportRule", { Identity: rule.name, Confirm: false }, onRefreshRotated);
  } else if (rule.scope === "inbox_rule") {
    if (!rule.mailboxOwner) return { success: false, error: "Missing mailbox owner for inbox rule." };
    result = await invokeExoCommand(
      tenant,
      "Disable-InboxRule",
      { Mailbox: rule.mailboxOwner, Identity: rule.name, Confirm: false },
      onRefreshRotated
    );
  } else {
    if (!rule.mailboxOwner) return { success: false, error: "Missing mailbox owner for auto-forward rule." };
    result = await invokeExoCommand(
      tenant,
      "Set-Mailbox",
      { Identity: rule.mailboxOwner, ForwardingSmtpAddress: null, ForwardingAddress: null },
      onRefreshRotated
    );
  }
  return result.error ? { success: false, error: result.error } : { success: true };
}

export async function setMailboxAuditingEnabled(
  tenant: Tenant,
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<{ success: boolean; error?: string }> {
  const result = await invokeExoCommand(tenant, "Set-OrganizationConfig", { AuditDisabled: false }, onRefreshRotated);
  return result.error ? { success: false, error: result.error } : { success: true };
}

// ---- Domain Authentication (SPF/DKIM/DMARC) - Module: DKIM half ----------
//
// DKIM is Exchange Online config, reached the same way as everything else in
// this file. SPF/DMARC are plain public DNS TXT lookups (see
// domain-dns-checker.ts) - a different mechanism entirely, orchestrated by
// the caller (graph-client.ts) rather than living in this file, which is
// scoped to "things that need the EXO device-code credential."
export async function fetchAcceptedDomainsAndDkim(
  tenant: Tenant,
  onRefreshRotated?: ExoRefreshRotatedCallback
): Promise<{
  domains: { domain: string; isDefaultDomain: boolean }[];
  dkimByDomain: Map<string, DomainAuthCheck>;
  errors: string[];
}> {
  const errors: string[] = [];

  const domainsResult = await invokeExoCommand(tenant, "Get-AcceptedDomain", {}, onRefreshRotated);
  if (domainsResult.error) {
    errors.push(`Get-AcceptedDomain: ${domainsResult.error}`);
    return { domains: [], dkimByDomain: new Map(), errors };
  }
  const domains = domainsResult.items.map(mapAcceptedDomain).filter((d) => d.domain);

  const dkimByDomain = new Map<string, DomainAuthCheck>();
  const dkimResult = await invokeExoCommand(tenant, "Get-DkimSigningConfig", {}, onRefreshRotated);
  if (dkimResult.error) {
    errors.push(`Get-DkimSigningConfig: ${dkimResult.error}`);
  } else {
    dkimResult.items.forEach((raw) => {
      const domain = (raw.Domain || "").toLowerCase();
      if (domain) dkimByDomain.set(domain, mapDkimStatus(raw));
    });
  }

  return { domains, dkimByDomain, errors };
}

export interface ExoConnectivityResult {
  connected: boolean;
  error?: string;
  testedAt: string;
}

// Lightweight connectivity check for the Permissions modal - confirms the
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
