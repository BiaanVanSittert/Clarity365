import { Tenant, TenantSecuritySnapshot, CAPolicyRule, UserMfaProfile, TenantAccountSummary, SignInEvent, SignInStatus, SignInCoverage, SecretExpiry, AlertPolicyInventory, SyncHealth, IntuneDevice, TenantSecureScore, MdoThreatPolicy, TablEntry, MdoThreatAlert, MailboxItem, EmailForwardingRule, MailflowTransportRule, DomainAuthStatus, MailflowConnector, TenantGroup, SharePointTenantPolicy, AppRegistrationItem, TenantCapability, TenantLicenseSku, SecurityIncidentItem, AsrRuleMode, AsrRuleState, AsrRuleActivitySummary, AsrDetectionEvent, MdeConnectorSettings, AtpOnboardingDeviceState, DefenderAvPolicySettings, IntuneAssignmentTarget, AsrDetectionTimeRange, EdrPolicySettings, BitLockerPolicySettings, DeviceComplianceReason, CaNamedLocation, CaSessionControls, TenantIdentitySettings, ExchangeSecuritySettings, PrivilegedRoleAssignments, OAuthConsentGrantSummary } from "../types";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { classifyPolicyBaselineCode, computeBaselineCoveragePercent } from "./ca-baseline-matcher";
import { fetchAllPages } from "./graph-pagination";
import { createBlankSnapshot } from "../data/default-snapshot";
import { classifyUserAuthMethods } from "./mfa-classifier";
import { mapManagedDeviceToIntuneDevice, mapMdeConnectorSettings, mapAtpOnboardingDeviceState, applyRealEdrOnboardingStates, mapDeviceComplianceSettingStateRow, applyDeviceComplianceReasons } from "./intune-mapper";
import { mapSecureScoreControl, buildSecureScoreHistory, computeScoreDelta, extractIndustryBenchmark } from "./secure-score-mapper";
import { buildCompanyBrandingControl } from "./company-branding-analyzer";
import { fetchMdoPoliciesAndTabl, fetchMailflowData, fetchAcceptedDomainsAndDkim, fetchExchangeSecuritySettings, getExoAppOnlyAccess } from "./exo-client";
import { getExchangeAccess } from "../utils/exchange-access";
import { mapSharePointSecuritySettings, mapPimAssignments, mapRoleAssignmentsFallback, buildAdminRoleMapsFromRoleAssignments, aggregateOAuthGrants, ServicePrincipalInfo } from "./security-posture-mapper";
import { mapMdoAlert } from "./mdo-alert-mapper";
import { checkSpfRecord, checkDmarcRecord } from "./domain-dns-checker";
import {
  mapGroup,
  mapGroupExpirationPolicyEnabled,
  mapGroupSelfServiceCreationRestricted,
  mapGroupNamingPolicyEnabled,
} from "./groups-mapper";
import { mapSharePointSite, mapTenantSharingSettings } from "./sharepoint-mapper";
import { mapAppRegistration } from "./app-registration-mapper";
import { mapSubscribedSkusToCapabilities } from "./capabilities-mapper";
import { SNAPSHOT_SYNC_SCHEMA_VERSION } from "../utils/sync-schema-version";
import { mapCaPolicyExtendedFields, mapCaBetaSessionExtras, applyCaBetaSessionExtras, mapNamedLocation, mapTenantIdentitySettings } from "./ca-environment-mapper";
import { mapSecurityIncident, synthesizeIncidentsFromMdoAlerts } from "./incident-mapper";
import { graphFetch } from "./graph-fetch";
import { ASR_RULE_DEFINITIONS } from "../data/asr-rule-definitions";
import { buildActivitySummaries, synthesizeMockActivity } from "./asr-detection-mapper";
import {
  AsrConfigSignal,
  LEGACY_ASR_PROPERTY_TO_RULE_ID,
  buildAsrSlugMap,
  mapAsrSettingDefinitionIdsToSignals,
  mapNamedPropertyValuesToSignals,
  mergeAsrRuleStates,
} from "./asr-configuration-mapper";
import { applyLicenseAwareStatus, PERMISSION_LICENSE_REQUIREMENT } from "./permission-license-check";
import { GRAPH_PERMISSIONS, isPermissionGrantedByRoles } from "../data/graph-permissions";
import { resolveSyncErrors } from "../utils/sync-permission-errors";
import { SIGN_IN_WINDOW_DAYS, computeSignInCoverage } from "../utils/sign-in-coverage";
import { mapSignInAuthentication } from "../utils/sign-in-authentication";
import { resolveOwnAppSecretExpiry } from "../utils/credential-expiry";
import { fetchAlertPolicyInventory } from "./scc-client";
import { UNCONFIRMED_ADMIN_ROLE_LABEL } from "../utils/directory-role-templates";



// No bulk "every group's owners/members" Graph endpoint exists - capped for
// the same reason the mailflow mailbox scan is capped (see exo-client.ts).
const MAX_GROUPS_FOR_MEMBER_SCAN = 250;
// No bulk "every site's storage quota" Graph endpoint exists either - capped
// for the same reason.
const MAX_SITES_FOR_STORAGE_SCAN = 250;

interface CachedToken {
  token: string;
  expiresAt: number;
}

interface TokenCacheGlobal {
  clarity365GraphTokenCache?: Map<string, CachedToken>;
}

// Cached per app-registration (Azure tenant ID + client ID), not per Clarity365
// tenant record, since that pair is what actually identifies the credential. Kept
// on globalThis so a Next.js dev-mode hot-reload doesn't spawn a second cache and
// silently double the token-endpoint traffic. A 5-minute safety margin is
// subtracted from the real expiry so a long paginated sync can't start a request
// with a token that expires mid-flight.
const TOKEN_SAFETY_MARGIN_MS = 5 * 60_000;
const tokenCacheGlobal = globalThis as unknown as TokenCacheGlobal;
if (!tokenCacheGlobal.clarity365GraphTokenCache) {
  tokenCacheGlobal.clarity365GraphTokenCache = new Map<string, CachedToken>();
}
const tokenCache = tokenCacheGlobal.clarity365GraphTokenCache;

interface AsrSlugMapCacheGlobal {
  clarity365AsrSlugMapCache?: Map<string, string>;
}

// Microsoft's Settings Catalog metadata for the ASR root setting is global,
// tenant-agnostic catalog data (which rule slugs exist and what they're
// called), not per-tenant state - so it's fetched once per process and
// reused across every tenant in a fleet sync, on the same globalThis
// pattern as tokenCache above, rather than refetched on every single sync.
const asrSlugMapCacheGlobal = globalThis as unknown as AsrSlugMapCacheGlobal;

export interface PermissionTestResult {
  permission: string;
  scope: "Application" | "Delegated";
  description: string;
  endpoint: string;
  // Defaults to GET when omitted. Only a permission with no GET-able Graph
  // surface (e.g. ThreatHunting.Read.All - Advanced Hunting is POST-only)
  // needs this set explicitly.
  method?: "GET" | "POST";
  body?: string;
  // "unlicensed" means the Graph call failed for a reason this app can
  // positively attribute to a missing license SKU (cross-checked against the
  // tenant's actual capabilities, not guessed from Graph's error text - see
  // permission-license-check.ts) rather than a missing/unconsented API
  // permission. Distinct from "missing" specifically so the UI never tells
  // an admin to go grant a permission in Azure AD when doing so would fix
  // nothing - the tenant needs to buy a license instead.
  status: "granted" | "missing" | "unlicensed" | "untested";
  statusCode?: number;
  errorMessage?: string;
  requiredFor: string;
  // True only for permissions that let Clarity365 create/modify/delete data in
  // the live tenant, not just read it - flagged distinctly in the Permissions
  // UI so granting it is a conscious choice, not lost among read-only scopes.
  isWriteAccess?: boolean;
  // True for a permission the app doesn't need to function - it unlocks one
  // additional feature (read-only or write-capable) on top of the reporting
  // this app already provides without it. Excluded from the pass/fail rollup
  // in overallStatus so declining it never shows as a problem needing
  // attention - whether that's choosing read-only/reporting-only mode
  // (declining the one write-capable permission) or simply not having the
  // separately-consented, separately-licensed permission Advanced Hunting
  // needs (declining ThreatHunting.Read.All).
  optional?: boolean;
  // Set (alongside status: "unlicensed") by applyLicenseAwareStatus() at test
  // time - never configured up front like `optional`, since whether a given
  // tenant is actually licensed for something is only known after the SKU
  // cross-check runs. Also excluded from the pass/fail rollup, for the same
  // reason: a licensing gap isn't a consent mistake the admin needs to fix.
  unlicensed?: boolean;
}

export interface TenantPermissionReport {
  tenantId: string;
  tenantName: string;
  testedAt: string;
  overallStatus: "all_granted" | "partial" | "failed";
  permissions: PermissionTestResult[];
}

// Invalidates any cached Graph access token for this tenantId:clientId pair.
// Must be called whenever a tenant's stored credentials change - the cache
// key is keyed only by tenantId:clientId, not by the secret itself, so
// rotating just the clientSecret (the common case) would otherwise keep
// serving a token acquired under the OLD secret until it naturally expired
// on its own schedule, up to ~55 minutes later. Found live: after fixing a
// bad Axiomatic client secret via EditTenantCredentialsModal, every Graph
// call kept failing with the exact same error as before the fix - the
// tenant record had the new secret, but getGraphAccessToken() had no way to
// know its cached token was now stale for a reason other than time.
export function invalidateGraphTokenCache(credentials: { tenantId?: string; clientId?: string }): void {
  if (!credentials.tenantId || !credentials.clientId) return;
  tokenCache.delete(`${credentials.tenantId}:${credentials.clientId}`);
}

// Decodes the `roles` claim (granted application permissions) out of a Graph
// access token's JWT payload, without verifying the signature - the token
// already came from a trusted Microsoft token endpoint response, this just
// reads a claim already inside it. App-only (client-credentials) tokens list
// every app role Entra actually granted here, regardless of which endpoint
// the token is later used against - the only side-effect-free, reliable way
// to answer "is this permission granted," for two live-found reasons a
// per-permission GET/POST probe cannot:
//   1. A probe can pass on a WEAKER permission than the one being tested,
//      whenever Graph's own least-privilege table lists both a .Read.All and
//      a .ReadWrite.All variant as sufficient for that call (e.g. GET
//      deviceManagement/intents accepts either) - found live on a tenant
//      whose Permissions modal showed DeviceManagementConfiguration.
//      ReadWrite.All as "Granted" purely because Read.All was granted, while
//      the actual policy-create call failed with "Application is not
//      authorized to perform this operation."
//   2. A probe can FAIL on a genuinely granted permission when the specific
//      Graph resource provider it hits has its own backend quirk unrelated
//      to consent - found live where AuditLog.Read.All and Reports.Read.All
//      consistently returned a 401 "Lifetime validation failed, the token is
//      expired" for a token that was, by construction, issued milliseconds
//      earlier in the same run and worked fine for Policy.Read.All/
//      User.Read.All in that identical run - decoding that same token's
//      roles claim directly confirmed both permissions were genuinely
//      granted the whole time.
// Returns null (never an empty array) when the token can't be parsed, so
// callers can fall back to a live probe instead of misreporting "missing."
export function decodeAppRolesFromToken(token: string): string[] | null {
  try {
    const payloadSegment = token.split(".")[1];
    if (!payloadSegment) return null;
    const base64 = payloadSegment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const json = Buffer.from(padded, "base64").toString("utf-8");
    const payload = JSON.parse(json);
    return Array.isArray(payload.roles) ? payload.roles : [];
  } catch {
    return null;
  }
}

// Lives next to the permission list now; re-exported for existing callers.
export { isPermissionGrantedByRoles };

// Survived graphFetch()'s own short retry (see its comment) and still
// carries this exact signature - real-world Microsoft behavior is that some
// Graph resource providers (the Reports/AuditLog family, and Endpoint
// Security's configurationPolicies, confirmed live on both) can reject an
// otherwise-valid, correctly-timed token for several minutes at a stretch,
// well past what a couple of in-request retries can wait for - most often
// right after a recent app registration change (new permission consented,
// secret rotated) or a tenant's first-ever use of that specific resource,
// but not always attributable to either. Reworded generically (not "go
// grant a permission" or "go redeploy") since this same error class is
// surfaced from several unrelated call sites now (the permission self-test,
// and the AV/EDR/ASR policy read and deploy paths) - the one thing true in
// every case is that retrying the same action again shortly is the right
// move, not assuming whatever the action was trying to do is actually wrong.
const LIFETIME_VALIDATION_ERROR_PATTERN = /lifetime validation failed/i;

export function describeTransientTokenLifetimeError(rawMessage: string): string {
  if (!LIFETIME_VALIDATION_ERROR_PATTERN.test(rawMessage)) return rawMessage;
  return `${rawMessage} - this specific error is usually Microsoft's own backend rejecting an otherwise-valid token for this one resource, not a real problem with your permissions or credentials. Wait a few minutes and try the same action again before assuming something is actually wrong.`;
}

// Pure decision logic for fetchLiveTenantSnapshot's own retry-with-fresh-
// token gap (see withFreshTokenOnLifetimeError's comment for the underlying
// bug this is the same fix for). That function fetches ONE token at the top
// and reuses it across ~20 sequential sync sections instead of one token
// per call, so it can't use withFreshTokenOnLifetimeError itself - if the
// token goes bad on section 3, sections 4-20 would still run with the same
// bad token in the same pass. Extracted as its own pure, tested predicate
// because tenant-store.ts's runSync() (the actual retry orchestration: call
// fetchLiveTenantSnapshot, check this, invalidateGraphTokenCache, call it
// again) can't itself be safely unit tested - the tenant store singleton
// always opens the real production data/clarity365.db, with no test-mode
// override, so no test in this codebase imports it directly. This is the
// one piece of that decision worth getting definitively right in a test.
export function hasLifetimeValidationError(errors: string[] | undefined): boolean {
  return !!errors?.some((e) => LIFETIME_VALIDATION_ERROR_PATTERN.test(e));
}

export async function getGraphAccessToken(credentials: Tenant["credentials"]): Promise<{ token?: string; error?: string }> {
  if (!credentials.tenantId || !credentials.clientId || !credentials.clientSecret) {
    return { error: "Missing Tenant ID, Client ID, or Client Secret in tenant configuration." };
  }

  const cacheKey = `${credentials.tenantId}:${credentials.clientId}`;
  const cached = tokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return { token: cached.token };
  }

  const tokenEndpoint = `https://login.microsoftonline.com/${encodeURIComponent(credentials.tenantId)}/oauth2/v2.0/token`;
  const body = new URLSearchParams();
  body.append("client_id", credentials.clientId);
  body.append("client_secret", credentials.clientSecret);
  body.append("scope", "https://graph.microsoft.com/.default");
  body.append("grant_type", "client_credentials");

  try {
    const res = await graphFetch(
      tokenEndpoint,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      },
      { timeoutMs: 10_000 } // fail fast - the whole sync is worthless without a token
    );

    const data = await res.json();
    if (!res.ok || !data.access_token) {
      return { error: data.error_description || data.error || `Authentication failed with status ${res.status}` };
    }

    const expiresInSeconds = typeof data.expires_in === "number" ? data.expires_in : 3600;
    tokenCache.set(cacheKey, {
      token: data.access_token,
      expiresAt: Date.now() + expiresInSeconds * 1000 - TOKEN_SAFETY_MARGIN_MS,
    });
    console.log(`[Graph Client] Acquired new access token for tenant ${credentials.tenantId} (valid ${expiresInSeconds}s).`);

    return { token: data.access_token };
  } catch (err: any) {
    return { error: err.message || "Failed to reach Microsoft Entra ID token endpoint." };
  }
}

// Retries an entire Graph operation with a genuinely fresh token when its
// first attempt fails with the "Lifetime validation failed" signature.
//
// Confirmed live (Coetzee Architects, 2026-09-17): this is NOT the brief
// network blip graphFetch's own short retry (see its comment) can absorb.
// A live diagnostic - a standalone script that decrypted this tenant's real
// credentials and called Microsoft Graph directly, bypassing Clarity365
// entirely - succeeded immediately against the identical endpoint at the
// exact moment Clarity365's own code was failing with this error. Tracing
// it further showed the token our cache was serving (well within its own
// bookkeeping's ~55-minute validity window) was being genuinely rejected by
// Microsoft's Intune Settings Catalog resource provider specifically
// (deviceManagement/configurationPolicies) over real network round-trips
// (fresh request-ids from Microsoft on every attempt - not a local caching
// artifact), while that exact same token kept working fine for every other
// Graph resource. Forcing a real fresh token (invalidateGraphTokenCache +
// getGraphAccessToken again) and retrying resolved it immediately.
//
// So: Microsoft can silently invalidate a specific already-issued app-only
// token for this one resource provider well before its nominal expiry, and
// our own token cache has no way to detect that on its own - it just trusts
// its expiry clock and keeps serving the same dead token. Retrying the same
// request with the same token (what every caller did before this) can
// never recover from that; only a forced fresh token can. Bounded to one
// retry - if a genuinely fresh token still hits this, something else is
// wrong and repeating indefinitely would only mask it.
async function withFreshTokenOnLifetimeError<T extends { error?: string }>(
  credentials: Tenant["credentials"],
  operation: (token: string) => Promise<T>
): Promise<T> {
  const { token, error } = await getGraphAccessToken(credentials);
  if (error || !token) {
    return { error: `Authentication Error: ${error}` } as T;
  }

  const result = await operation(token);
  if (result.error && LIFETIME_VALIDATION_ERROR_PATTERN.test(result.error)) {
    invalidateGraphTokenCache(credentials);
    const fresh = await getGraphAccessToken(credentials);
    if (fresh.error || !fresh.token) {
      return result; // couldn't get a fresh token either - surface the original error
    }
    return operation(fresh.token);
  }
  return result;
}

export async function testAppRegistrationPermissions(tenant: Tenant): Promise<TenantPermissionReport> {
  // The list itself lives in data/graph-permissions.ts, shared with the
  // onboarding checklist and the sync's error handling so the three can't
  // drift apart. Only the fields the report needs are carried over.
  const permissionsToTest: Omit<PermissionTestResult, "status">[] = GRAPH_PERMISSIONS.map(({ grant, syncSteps, purpose, ...test }) => test);

  if (tenant.credentials.authMode === "mock") {
    return {
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      testedAt: new Date().toISOString(),
      overallStatus: "all_granted",
      permissions: permissionsToTest.map((p) => ({ ...p, status: "granted", statusCode: 200 })),
    };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return {
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      testedAt: new Date().toISOString(),
      overallStatus: "failed",
      permissions: permissionsToTest.map((p) => ({
        ...p,
        status: "missing",
        errorMessage: error || "Authentication failed before testing permissions.",
      })),
    };
  }

  let results: PermissionTestResult[] = [];

  // Decoded once per test run and reused below for every permission with no
  // genuine license dependency (see decodeAppRolesFromToken's comment for
  // the two distinct live bugs this replaces a live probe for). The handful
  // of permissions in PERMISSION_LICENSE_REQUIREMENT still need a real Graph
  // call - the roles claim alone can't distinguish "not granted" from
  // "granted but the tenant lacks the underlying license," and that
  // distinction is exactly what applyLicenseAwareStatus (below) exists to
  // surface correctly rather than sending an admin to grant a permission
  // that's already fine.
  const grantedAppRoles = decodeAppRolesFromToken(token);

  for (const perm of permissionsToTest) {
    const hasLicenseDependency = !!PERMISSION_LICENSE_REQUIREMENT[perm.permission];
    if (grantedAppRoles !== null && !hasLicenseDependency) {
      const granted = isPermissionGrantedByRoles(perm.permission, grantedAppRoles);
      results.push({
        ...perm,
        status: granted ? "granted" : "missing",
        statusCode: granted ? 200 : 403,
        errorMessage: granted
          ? undefined
          : `${perm.permission} is not present in this app registration's granted application permissions. Checked directly against the access token's roles claim (not a live endpoint probe, which can either pass on a weaker variant alone or fail on an unrelated backend quirk) - grant it with admin consent in Microsoft Entra admin center.`,
      });
      continue;
    }

    try {
      // Up to one retry, only for the specific "brand new token rejected by
      // this particular Graph resource provider" transient signature - found
      // live right after testPermissions() started forcing a fresh token on
      // every Re-Test click (see invalidateGraphTokenCache call site in
      // tenant-store.ts): AuditLog.Read.All and Reports.Read.All consistently
      // failed with a 401 "Lifetime validation failed, the token is expired"
      // on a token that was, by construction, issued milliseconds earlier in
      // this same run - while Policy.Read.All/User.Read.All succeeded with
      // that identical token in the same loop. A genuinely expired or
      // missing-scope token fails every call, not two specific ones, so this
      // is Microsoft's own backend propagation lag for those resource
      // providers specifically, not a real permission problem - retrying
      // once after a short pause resolves it without masking an actual
      // missing-permission 403/401 (which never carries this exact message).
      let res = await graphFetch(perm.endpoint, {
        method: perm.method || "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          ...(perm.body ? { "Content-Type": "application/json" } : {}),
        },
        body: perm.body,
      });
      let errJson: any = res.ok ? null : await res.json().catch(() => ({}));

      if (!res.ok && res.status === 401 && /lifetime validation failed/i.test(errJson?.error?.message || "")) {
        await new Promise((resolve) => setTimeout(resolve, 1500));
        res = await graphFetch(perm.endpoint, {
          method: perm.method || "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            ...(perm.body ? { "Content-Type": "application/json" } : {}),
          },
          body: perm.body,
        });
        errJson = res.ok ? null : await res.json().catch(() => ({}));
      }

      if (res.ok) {
        results.push({
          ...perm,
          status: "granted",
          statusCode: res.status,
        });
      } else {
        const rawMessage = errJson?.error?.message || `Access denied (${res.status} ${res.statusText})`;
        results.push({
          ...perm,
          status: "missing",
          statusCode: res.status,
          errorMessage: describeTransientTokenLifetimeError(rawMessage),
        });
      }
    } catch (e: any) {
      results.push({
        ...perm,
        status: "missing",
        errorMessage: e.message || "Network request failed",
      });
    }
  }

  // Cross-check every "missing" result against what the tenant is actually
  // licensed for, so a real licensing gap (e.g. no Intune, no Defender for
  // Endpoint P2) never reads as "go grant this permission in Azure AD" -
  // that advice would do nothing, since the license is the actual blocker.
  // Best-effort: if this call itself fails (e.g. Organization.Read.All
  // wasn't granted either), licensing-aware messaging is simply skipped for
  // this run, falling back to today's plain "missing" behavior - never a
  // hard failure of the whole permissions check.
  try {
    // No $top/$filter here - subscribedSkus doesn't support them (Microsoft's
    // own known-issues doc: unsupported query params on this endpoint "might
    // not return the expected results"), same reason the existing sync-time
    // call below (~line 1682) already omits them.
    const skusResult = await fetchAllPages<any>("https://graph.microsoft.com/v1.0/subscribedSkus", {
      Authorization: `Bearer ${token}`,
    });
    const capabilities = mapSubscribedSkusToCapabilities(skusResult.items);
    results = results.map((r) => applyLicenseAwareStatus(r, capabilities));
  } catch (e: any) {
    console.error("[Graph Client] Could not cross-check license capabilities for permissions report:", e);
  }

  // Optional permissions (currently ThreatHunting.Read.All,
  // Policy.ReadWrite.ConditionalAccess, and
  // DeviceManagementConfiguration.ReadWrite.All) and unlicensed ones are
  // both excluded from this rollup - declining an
  // optional permission is a deliberate choice, and a licensing gap isn't a
  // consent mistake the admin needs to go fix, so neither should read as
  // "you did something wrong."
  const requiredResults = results.filter((r) => !r.optional && !r.unlicensed);
  return {
    tenantId: tenant.id,
    tenantName: tenant.displayName,
    testedAt: new Date().toISOString(),
    overallStatus: requiredResults.every((r) => r.status === "granted")
      ? "all_granted"
      : requiredResults.some((r) => r.status === "granted")
      ? "partial"
      : "failed",
    permissions: results,
  };
}

export function buildGraphCaPolicyPayload(code: string, domain: string) {
  switch (code) {
    case "CA01":
      return {
        displayName: "CA01: Block legacy authentication",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          // "other" (not "otherClients") is the real Graph enum member -
          // "otherClients" isn't a valid conditionalAccessClientApp value at
          // all, and Graph rejects the whole policy object with error 1007
          // ("does not match the schema of ConditionalAccessPolicy type")
          // rather than just ignoring the bad array entry. Confirmed live
          // against Ashton John's Private School before this fix.
          clientAppTypes: ["exchangeActiveSync", "other"],
        },
        grantControls: { operator: "OR", builtInControls: ["block"] },
      };
    case "CA02":
      return {
        displayName: "CA02: Require multifactor authentication for all users",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: ["GuestsOrExternalUsers"] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
        },
        grantControls: { operator: "OR", builtInControls: ["mfa"] },
      };
    case "CA03":
      return {
        displayName: "CA03: Require multifactor authentication for admins",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: {
            includeRoles: [
              "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
              "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
              "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
              "729827e3-9c14-49f7-bb1b-9608f156bbb8", // Helpdesk Administrator
              "966707d0-3269-4727-9be2-8c3a10f19b9d", // User Administrator
              "c4e39bd9-1100-46d3-8c65-fb160da0071f", // Authentication Administrator
            ],
            excludeUsers: [],
          },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
        },
        grantControls: { operator: "OR", builtInControls: ["mfa"] },
      };
    case "CA04":
      return {
        displayName: "CA04: Require multifactor authentication for guest access",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["GuestsOrExternalUsers"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
        },
        grantControls: { operator: "OR", builtInControls: ["mfa"] },
      };
    case "CA05":
      return {
        displayName: "CA05: Require multifactor authentication for Azure management",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["797f4846-ba00-4fd7-ba43-dac1f8f63013"] },
          clientAppTypes: ["all"],
        },
        grantControls: { operator: "OR", builtInControls: ["mfa"] },
      };
    case "CA06":
      return {
        displayName: "CA06: Require multifactor authentication for risky sign-ins",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
          signInRiskLevels: ["medium", "high"],
        },
        grantControls: { operator: "OR", builtInControls: ["mfa"] },
      };
    case "CA07":
      return {
        displayName: "CA07: Require risk remediation for high-risk users",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
          userRiskLevels: ["high"],
        },
        grantControls: { operator: "AND", builtInControls: ["mfa", "passwordChange"] },
      };
    case "CA08":
      return {
        displayName: "CA08: Block Access from Untrusted Countries",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
          locations: { includeLocations: ["All"], excludeLocations: ["AllTrusted"] },
        },
        grantControls: { operator: "OR", builtInControls: ["block"] },
      };
    case "CA09":
      return {
        displayName: "CA09: Require MDM-enrolled and compliant device to access cloud apps for all users",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
          platforms: { includePlatforms: ["windows", "macOS", "iOS", "android"] },
        },
        grantControls: { operator: "OR", builtInControls: ["compliantDevice", "domainJoinedDevice"] },
      };
    case "CA10":
      return {
        displayName: "CA10: Require phishing-resistant multifactor authentication for admins",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: {
            includeRoles: [
              "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
              "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
              "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
              "966707d0-3269-4727-9be2-8c3a10f19b9d", // User Administrator
              "c4e39bd9-1100-46d3-8c65-fb160da0071f", // Authentication Administrator
            ],
            excludeUsers: [],
          },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
        },
        grantControls: {
          operator: "OR",
          authenticationStrength: { id: "00000000-0000-0000-0000-000000000004" },
        },
      };
    default:
      throw new Error(`Unsupported baseline standard code: ${code}`);
  }
}

export async function deployConditionalAccessPolicy(
  tenant: Tenant,
  baselineCode: string
): Promise<{ success: boolean; policy?: any; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    const baselineDef = CA_BASELINE_STANDARDS.find((b) => b.code === baselineCode);
    const mockPolicy = {
      id: `ca-pol-${tenant.id}-${baselineCode.toLowerCase()}`,
      displayName: `${baselineCode}: ${baselineDef?.name || "Baseline Policy"}`,
      state: "enabledForReportingButNotEnforced",
      createdDateTime: new Date().toISOString(),
      modifiedDateTime: new Date().toISOString(),
    };
    return { success: true, policy: mockPolicy };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return { success: false, error: `Authentication Error: ${error}` };
  }

  const payload = buildGraphCaPolicyPayload(baselineCode, tenant.defaultDomainName);

  try {
    const res = await graphFetch(
      "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      },
      // A network exception here is ambiguous - the POST may have already reached
      // Graph and created the policy before the response was lost. Only retry a
      // structured 429/503 HTTP response, where Graph is explicitly confirming it
      // did not process the request.
      { retryOnNetworkError: false }
    );

    const data = await res.json();
    if (!res.ok) {
      const rawMessage = data?.error?.message || `Failed to create policy in Microsoft Graph (HTTP ${res.status}: ${res.statusText})`;

      // CA05 references a specific application by fixed appId rather than
      // "All": 797f4846-ba00-4fd7-ba43-dac1f8f63013, "Microsoft Azure
      // Management" (shown as "Azure Resource Manager" in some Entra portal
      // surfaces; legacy docs also call it "Windows Azure Service
      // Management API" - all the same first-party, Microsoft-owned app).
      // Unlike a custom/registered app, this one's service principal is
      // provisioned by default in every tenant, so "ServicePrincipalNotFound"
      // below should be rare - if it ever fires, this app's own
      // Policy.ReadWrite.ConditionalAccess grant is not enough to fix it;
      // it needs a Global Administrator to run, once, in Microsoft Graph
      // PowerShell:
      //   Connect-MgGraph -Scopes "Application.ReadWrite.All"
      //   New-MgServicePrincipal -AppId "797f4846-ba00-4fd7-ba43-dac1f8f63013"
      // Deliberately NOT something Clarity365's own app registration should
      // request just for this, so this is surfaced as a one-time manual
      // script instead of an auto-fix, the same convention as every other
      // PowerShell-script fallback in this app.
      //
      // (An earlier version of this baseline incorrectly targeted appId
      // 797f3427-79cd-4827-8132-47d473d450e4, which does not correspond to a
      // real Microsoft Azure Management service principal in any tenant and
      // reliably produced ServicePrincipalNotFound - confirmed by the user
      // directly and corrected to the real, documented app ID above.)
      if (baselineCode === "CA05") {
        if (rawMessage.includes("ServicePrincipalNotFound")) {
          return {
            success: false,
            error: `${rawMessage} - The "Microsoft Azure Management" enterprise application doesn't exist in this tenant's directory yet (unusual - it's provisioned by default in most tenants). Signing in to Azure or using the Entra Conditional Access app picker will NOT fix this - neither actually provisions it. The reliable fix: as a Global Administrator, run this once in Microsoft Graph PowerShell - Connect-MgGraph -Scopes "Application.ReadWrite.All" then New-MgServicePrincipal -AppId "797f4846-ba00-4fd7-ba43-dac1f8f63013" - then retry this deploy.`,
          };
        }
        // The other CA05-specific gotcha: unlike every other baseline (which
        // targets "All" applications), CA05 references a specific
        // application by ID, which additionally requires Application.Read.All
        // (not just Policy.ReadWrite.ConditionalAccess) so Graph can resolve
        // that application object. Not proactively checked in the
        // Permissions report (see testAppRegistrationPermissions) - this is
        // the one place it's actually surfaced.
        if (res.status === 403 || /insufficient privileges|authorization_requestdenied/i.test(rawMessage)) {
          return {
            success: false,
            error: `${rawMessage} - CA05 references a specific application (Microsoft Azure Management) by ID rather than "All", which needs the Application.Read.All Graph permission (with admin consent) in addition to Policy.ReadWrite.ConditionalAccess. Grant Application.Read.All in Microsoft Entra admin center, then retry - every other baseline is unaffected.`,
          };
        }
      }

      return { success: false, error: rawMessage };
    }

    return { success: true, policy: data };
  } catch (err: any) {
    return { success: false, error: err.message || "Network error while connecting to Microsoft Graph." };
  }
}

// Maps the UI's time-range selector to both the KQL `ago()` window and the
// runHuntingQuery request's own Timespan (ISO 8601 duration) - the two must
// agree, since Timespan caps how far back Graph will even look regardless
// of what the KQL says. "all" requests a generous 180-day window (longer
// than any default retention) and lets Graph return whatever the tenant's
// own retention policy actually kept, rather than this app guessing it.
const ASR_TIME_RANGE_TO_KQL_DAYS: Record<AsrDetectionTimeRange, number> = {
  "7d": 7,
  "30d": 30,
  all: 180,
};
const ASR_TIME_RANGE_TO_TIMESPAN: Record<AsrDetectionTimeRange, string> = {
  "7d": "P7D",
  "30d": "P30D",
  all: "P180D",
};

// Pure - turns Graph's raw runHuntingQuery error into an actionable message,
// or returns the raw message unchanged when neither known pattern matches.
// Kept separate from runHuntingQuery itself so both branches are unit
// testable without a live Graph call (see graph-client.test.ts) - this is
// exactly the kind of branching logic that caused a live false-negative bug
// (see below) when it lived inline and untested.
export function classifyAdvancedHuntingError(rawMessage: string, status: number): string {
  // Case 1: the permission itself is missing. Graph's raw 403 for this
  // endpoint dumps every OTHER permission the app registration holds
  // alongside the one it's missing ("Missing application roles. API
  // required roles: ThreatHunting.Read.All, application roles: <15
  // unrelated permissions>") - accurate but unreadable, and easy to mistake
  // for "the app is broken" rather than "this one optional permission was
  // never granted." Rewritten into an actionable message the same way
  // CA05's deploy errors are, since a live user report showed this raw dump
  // reads as a bug, not an expected, ungranted-optional-permission outcome.
  if (status === 403 && /missing application roles/i.test(rawMessage) && rawMessage.includes("ThreatHunting.Read.All")) {
    return 'ASR detection activity needs the optional "ThreatHunting.Read.All" Graph permission, which has not been granted to this app registration - plus a Microsoft Defender for Endpoint P1/P2 (or equivalent Microsoft 365 E5 / Business Premium) license on this tenant. Grant ThreatHunting.Read.All with admin consent in Microsoft Entra admin center > App registrations > API permissions, then retry. Every other ASR Rules feature (rule configuration state - Block/Audit/Warn/Not Configured) already works fully without it.';
  }

  // Case 2: the permission is granted, but this specific table isn't
  // resolving for this tenant's call. CORRECTION to this branch's original
  // theory: it initially assumed this always means "Defender for Business
  // instead of Defender for Endpoint P1/P2, which categorically lacks this
  // table" - a live user directly disproved that for their own tenant (they
  // can see ASR detections for the same data in the Defender portal's own
  // Reports > Attack Surface Reduction Rules > Detections page, which a
  // Defender-for-Business-lacks-the-table explanation can't account for).
  // The message below is now deliberately non-committal about the cause -
  // see the "Lifetime validation failed" case right below for what turned
  // out to be the actual root cause on that tenant, a Graph-side issue at
  // this specific endpoint that has nothing to do with table availability.
  const tableNotFoundMatch = rawMessage.match(/Failed to resolve table or column expression named '([^']+)'/i);
  if (tableNotFoundMatch) {
    return `ASR detection activity needs the "${tableNotFoundMatch[1]}" Advanced Hunting table, which this tenant's call to Microsoft Graph couldn't resolve - the ThreatHunting.Read.All permission itself is fine. If you can see this table's data in security.microsoft.com's own Advanced Hunting or Reports pages, this is a Graph API-side issue on this specific tenant, not a real licensing gap - retry later, and if it persists, check whether this app's service principal has been separately granted access under Microsoft Defender's own app-access/role settings (distinct from the Entra permission grant). Every other ASR Rules feature (rule configuration state - Block/Audit/Warn/Not Configured) already works fully without this.`;
  }

  // Case 3: "Lifetime validation failed, the token is expired" - confirmed
  // via a live diagnostic NOT to be Clarity365's own token caching (a token
  // fetched and used within the same second was still rejected this way).
  // Observed alongside a permission that had JUST been granted - Graph's
  // core authorization check for ThreatHunting.Read.All was passing (the
  // error had changed from the Case 1 "missing application roles" 403 to
  // this different error), but something downstream in this specific
  // endpoint's own validation still rejected the token. Leading
  // hypothesis, not yet confirmed: newly granted permissions can take time
  // to propagate to the Defender/XDR backend behind this endpoint,
  // separately from Entra's own instant admin-consent UI update.
  if (status === 401 && /lifetime validation failed/i.test(rawMessage)) {
    return `ASR detection activity failed with "${rawMessage}" - this was confirmed NOT to be a Clarity365 caching issue (even a freshly-issued token was rejected the same way). If ThreatHunting.Read.All was granted recently, this can be a backend propagation delay - Microsoft's Defender/XDR services can take time to recognize a newly consented permission even though Entra shows it granted immediately. Wait a while and retry; if it persists after a day, check whether this app's service principal also needs access granted under Microsoft Defender's own app-access/role settings, separate from the Entra permission grant.`;
  }

  return rawMessage;
}

// Shared by both ASR detection functions below. Graph's runHuntingQuery
// (v1.0, not beta) returns { schema, results }, with result row keys
// camelCased regardless of how the KQL `project`/`summarize` columns were
// capitalized - e.g. a `project ActionType` column comes back as
// `row.actionType`, not `row.ActionType`.
async function runHuntingQuery(token: string, query: string, timespan: string): Promise<{ rows?: any[]; error?: string }> {
  try {
    const res = await graphFetch(
      "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
      {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ Query: query, Timespan: timespan }),
      },
      { retryOnNetworkError: false }
    );
    const data = await res.json();
    if (!res.ok) {
      const rawMessage = data?.error?.message || `Advanced Hunting query failed (HTTP ${res.status}: ${res.statusText})`;
      return { error: classifyAdvancedHuntingError(rawMessage, res.status) };
    }
    return { rows: data.results || [] };
  } catch (err: any) {
    return { error: err.message || "Network error while running the Advanced Hunting query." };
  }
}

/**
 * Aggregate ASR detection activity for every rule at once (last 30 days),
 * for the module's per-row "N events" badges. On-demand only - never part of
 * fetchLiveTenantSnapshot - since it needs a separate ThreatHunting.Read.All
 * permission and a Defender for Endpoint P2 license many tenants may not
 * have, and would slow down every sync for one module's data otherwise.
 */
export async function fetchAsrDetectionSummaries(
  tenant: Tenant,
  currentRuleStates: { ruleId: string; mode: AsrRuleMode }[],
  timeRange: AsrDetectionTimeRange = "30d"
): Promise<{ summaries?: AsrRuleActivitySummary[]; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { summaries: synthesizeMockActivity(currentRuleStates, tenant.id, timeRange) };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return { error: `Authentication Error: ${error}` };
  }

  const days = ASR_TIME_RANGE_TO_KQL_DAYS[timeRange];
  const { rows, error: queryError } = await runHuntingQuery(
    token,
    `DeviceEvents | where Timestamp > ago(${days}d) | where ActionType startswith "Asr" | summarize Count=count() by ActionType`,
    ASR_TIME_RANGE_TO_TIMESPAN[timeRange]
  );
  if (queryError) return { error: queryError };

  const actionTypeCounts: Record<string, number> = {};
  for (const row of rows || []) {
    if (row.actionType) actionTypeCounts[row.actionType] = row.count || 0;
  }
  return { summaries: buildActivitySummaries(actionTypeCounts) };
}

/**
 * Recent raw detection events for one specific rule (capped at 50 within
 * the selected time range), fetched only when that rule's drawer is
 * actually opened.
 */
export async function fetchAsrDetectionEvents(
  tenant: Tenant,
  ruleId: string,
  timeRange: AsrDetectionTimeRange = "30d"
): Promise<{ events?: AsrDetectionEvent[]; error?: string }> {
  const def = ASR_RULE_DEFINITIONS.find((d) => d.id === ruleId);
  if (!def || !def.hasAdvancedHuntingTelemetry) {
    return { events: [] };
  }

  if (tenant.credentials.authMode === "mock") {
    const now = Date.now();
    const days = ASR_TIME_RANGE_TO_KQL_DAYS[timeRange];
    const sampleFiles = ["invoice_2026.xlsm", "update_installer.exe", "quarterly_report.docm", "setup.ps1"];
    const count = Math.min(
      50,
      Math.abs(def.advancedHuntingActionTypes.reduce((acc, t) => acc + t.length, 0) + tenant.id.length) % 6 * Math.max(1, Math.round(days / 30))
    );
    const events: AsrDetectionEvent[] = Array.from({ length: count }, (_, i) => ({
      timestamp: new Date(now - i * ((days * 24) / Math.max(count, 1)) * 60 * 60 * 1000).toISOString(),
      deviceName: `DEMO-WKS-${(i % 4) + 1}`,
      actionType: def.advancedHuntingActionTypes[i % def.advancedHuntingActionTypes.length],
      fileName: sampleFiles[i % sampleFiles.length],
      initiatingProcessFileName: i % 2 === 0 ? "winword.exe" : "powershell.exe",
    }));
    return { events };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return { error: `Authentication Error: ${error}` };
  }

  const days = ASR_TIME_RANGE_TO_KQL_DAYS[timeRange];
  const actionTypesList = def.advancedHuntingActionTypes.map((t) => `"${t}"`).join(", ");
  const { rows, error: queryError } = await runHuntingQuery(
    token,
    `DeviceEvents | where Timestamp > ago(${days}d) | where ActionType in (${actionTypesList}) | project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields | order by Timestamp desc | take 50`,
    ASR_TIME_RANGE_TO_TIMESPAN[timeRange]
  );
  if (queryError) return { error: queryError };

  const events: AsrDetectionEvent[] = (rows || []).map((row: any) => ({
    timestamp: row.timestamp,
    deviceName: row.deviceName,
    actionType: row.actionType,
    fileName: row.fileName || undefined,
    folderPath: row.folderPath || undefined,
    initiatingProcessFileName: row.initiatingProcessFileName || undefined,
    initiatingProcessCommandLine: row.initiatingProcessCommandLine || undefined,
    additionalFields: (() => {
      try {
        return row.additionalFields ? JSON.parse(row.additionalFields) : undefined;
      } catch {
        return undefined;
      }
    })(),
  }));
  return { events };
}

const ASR_SETTINGS_CATALOG_ROOT_DEFINITION_ID = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules";

// Fetches (once per process, cached on globalThis - see asrSlugMapCacheGlobal
// above) Microsoft's own tenant-agnostic Settings Catalog metadata for the
// ASR root setting, then builds the slug->rule-GUID map via the pure,
// tested buildAsrSlugMap. A metadata fetch failure or an unmatched entry is
// pushed to syncErrors rather than thrown, so one missing/renamed slug never
// blocks every other rule from resolving correctly.
async function getAsrSettingsCatalogSlugMap(
  headers: HeadersInit,
  syncErrors: string[]
): Promise<Map<string, string>> {
  if (asrSlugMapCacheGlobal.clarity365AsrSlugMapCache) {
    return asrSlugMapCacheGlobal.clarity365AsrSlugMapCache;
  }

  try {
    const metadataResult = await fetchAllPages<any>(
      `https://graph.microsoft.com/beta/deviceManagement/configurationSettings?$filter=rootDefinitionId eq '${ASR_SETTINGS_CATALOG_ROOT_DEFINITION_ID}'`,
      headers
    );
    if (metadataResult.error) {
      syncErrors.push(`ASR Rules (Settings Catalog): could not load rule catalog metadata - ${metadataResult.error}`);
    }

    const { slugToRuleId, unmatchedCount } = buildAsrSlugMap(
      metadataResult.items.map((s: any) => ({
        settingDefinitionId: s.settingDefinitionId || s.id,
        displayName: s.displayName || "",
      }))
    );
    if (unmatchedCount > 0) {
      syncErrors.push(
        `ASR Rules (Settings Catalog): ${unmatchedCount} rule(s) in Microsoft's catalog could not be matched to a known ASR rule - they will be skipped rather than misattributed.`
      );
    }

    asrSlugMapCacheGlobal.clarity365AsrSlugMapCache = slugToRuleId;
    return slugToRuleId;
  } catch (err: any) {
    syncErrors.push(`ASR Rules (Settings Catalog): could not load rule catalog metadata - ${err.message || "network error"}`);
    return new Map();
  }
}

// Walks a Settings Catalog policy's /settings response to collect every
// selected leaf choice id (e.g.
// "..._blockexecutionofpotentiallyobfuscatedscripts_block"). The exact
// nested settingInstance shape below (choiceSettingValue / groupSettingCollectionValue
// / choiceSettingCollectionValue, each carrying further "children") follows
// Microsoft's generally-documented Settings Catalog pattern but was not
// verified against a live tenant response in this environment - if a real
// tenant's shape differs, this is the one place that needs correcting; the
// pure mapAsrSettingDefinitionIdsToSignals function downstream is unaffected
// either way since it only ever sees the flat string array this returns.
function flattenSettingsCatalogSelectedIds(settings: any[]): string[] {
  const ids: string[] = [];

  const visitInstance = (instance: any) => {
    if (!instance || typeof instance !== "object") return;

    const choiceValue = instance.choiceSettingValue;
    if (choiceValue) {
      if (typeof choiceValue.value === "string") ids.push(choiceValue.value);
      (choiceValue.children || []).forEach(visitInstance);
    }

    const choiceCollection = instance.choiceSettingCollectionValue;
    if (Array.isArray(choiceCollection)) {
      choiceCollection.forEach((entry: any) => {
        if (typeof entry?.value === "string") ids.push(entry.value);
        (entry?.children || []).forEach(visitInstance);
      });
    }

    const groupCollection = instance.groupSettingCollectionValue;
    if (Array.isArray(groupCollection)) {
      groupCollection.forEach((group: any) => (group?.children || []).forEach(visitInstance));
    }

    if (Array.isArray(instance.children)) {
      instance.children.forEach(visitInstance);
    }
  };

  settings.forEach((setting: any) => visitInstance(setting.settingInstance || setting));

  return ids;
}

// ==========================================
// Phase 2: Endpoint Security write path (MDE connector settings, Defender AV
// policy, ASR rule deployment) - gated in the UI/API layer behind BOTH
// Tenant.endpointSecurityWriteMode === "write_enabled" AND the
// DeviceManagementConfiguration.ReadWrite.All permission (see
// testAppRegistrationPermissions above). None of the functions below
// enforce either gate themselves - same convention as
// deployConditionalAccessPolicy, which doesn't re-check
// Policy.ReadWrite.ConditionalAccess before calling Graph either.
// ==========================================

const ANTIVIRUS_TEMPLATE_FAMILY = "endpointSecurityAntivirus";

// settingDefinitionId strings for the Defender Antivirus toggles, confirmed
// live against a real tenant's own Settings Catalog metadata
// (deviceManagement/configurationCategories -> "Microsoft Defender
// for Endpoint"/"Defender"/"Microsoft Defender Antivirus" categories, then
// configurationSettings filtered by each categoryId) - not just Microsoft's
// docs or an assumed naming pattern. That live check caught two ids this
// map previously had wrong from pattern-guessing alone:
//   - allowFullScanOnRemovableDrives: guessed "...allowfullscanonremovabledrivescanning"
//     (with "on") - the real id has no "on": "...allowfullscanremovabledrivescanning".
//   - allowUpdatesOnMeteredNetwork: guessed "...policy_config_defender_allowupdatesonmeterednetworkconnections" -
//     doesn't exist under that root at all. The real setting lives under a
//     completely different CSP node, same as disableLocalAdminMerge below:
//     "device_vendor_msft_defender_configuration_meteredconnectionupdates".
// disableLocalAdminMerge was flagged "unconfirmed" before this live check -
// it's now confirmed correct as originally written.
const DEFENDER_AV_SETTING_DEFINITION_IDS: Record<keyof DefenderAvPolicySettings, string> = {
  allowRealtimeMonitoring: "device_vendor_msft_policy_config_defender_allowrealtimemonitoring",
  allowBehaviorMonitoring: "device_vendor_msft_policy_config_defender_allowbehaviormonitoring",
  allowCloudProtection: "device_vendor_msft_policy_config_defender_allowcloudprotection",
  allowIOAVProtection: "device_vendor_msft_policy_config_defender_allowioavprotection",
  allowScriptScanning: "device_vendor_msft_policy_config_defender_allowscriptscanning",
  allowScanningNetworkFiles: "device_vendor_msft_policy_config_defender_allowscanningnetworkfiles",
  allowEmailScanning: "device_vendor_msft_policy_config_defender_allowemailscanning",
  allowArchiveScanning: "device_vendor_msft_policy_config_defender_allowarchivescanning",
  allowFullScanOnMappedNetworkDrives: "device_vendor_msft_policy_config_defender_allowfullscanonmappednetworkdrives",
  allowFullScanOnRemovableDrives: "device_vendor_msft_policy_config_defender_allowfullscanremovabledrivescanning",
  enableLowCpuPriority: "device_vendor_msft_policy_config_defender_enablelowcpupriority",
  disableCatchupFullScan: "device_vendor_msft_policy_config_defender_disablecatchupfullscan",
  disableCatchupQuickScan: "device_vendor_msft_policy_config_defender_disablecatchupquickscan",
  checkForSignaturesBeforeRunningScan: "device_vendor_msft_policy_config_defender_checkforsignaturesbeforerunningscan",
  allowUpdatesOnMeteredNetwork: "device_vendor_msft_defender_configuration_meteredconnectionupdates",
  disableLocalAdminMerge: "device_vendor_msft_defender_configuration_disablelocaladminmerge",
  allowUserUIAccess: "device_vendor_msft_policy_config_defender_allowuseruiaccess",
};

// Pure - builds the Settings Catalog "settings" array for only the fields
// the caller actually set (undefined fields are skipped, never defaulted),
// so a partial config never resets unrelated settings to some value. Every
// Defender boolean is a choice setting whose selected value is the
// settingDefinitionId with a "_1" (true) or "_0" (false) suffix - confirmed
// against a real deployed example for allowarchivescanning; this is a
// different suffix convention from ASR's _block/_audit/_warn, which is
// specific to ASR's multi-value (not boolean) choice.
export function buildDefenderAvSettingsPayload(
  desired: DefenderAvPolicySettings
): { settingInstance: any }[] {
  const settings: { settingInstance: any }[] = [];

  for (const key of Object.keys(desired) as (keyof DefenderAvPolicySettings)[]) {
    const value = desired[key];
    if (value === undefined) continue;
    const settingDefinitionId = DEFENDER_AV_SETTING_DEFINITION_IDS[key];
    if (!settingDefinitionId) continue;

    settings.push({
      settingInstance: {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        settingDefinitionId,
        choiceSettingValue: {
          "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
          value: `${settingDefinitionId}_${value ? "1" : "0"}`,
          children: [],
        },
      },
    });
  }

  return settings;
}

// Pure - the standard Intune assignment-target OData shapes every Settings
// Catalog policy's /assign action accepts. "none" -> an empty assignments
// array ("Do Not Assign" - the policy exists but affects nothing), the
// deliberate default for a fresh Phase 2 deploy so nothing is ever silently
// applied fleet-wide on first use.
export function buildIntuneAssignmentTarget(target: IntuneAssignmentTarget): { assignments: any[] } {
  if (target.mode === "none") return { assignments: [] };

  if (target.mode === "allDevices") {
    return { assignments: [{ target: { "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget" } }] };
  }
  if (target.mode === "allUsers") {
    return { assignments: [{ target: { "@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget" } }] };
  }
  if (target.mode === "allUsersAndDevices") {
    return {
      assignments: [
        { target: { "@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget" } },
        { target: { "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget" } },
      ],
    };
  }

  // "group"
  const assignments: any[] = [];
  if (target.groupId) {
    assignments.push({
      target: { "@odata.type": "#microsoft.graph.groupAssignmentTarget", groupId: target.groupId },
    });
  }
  if (target.excludeGroupId) {
    assignments.push({
      target: { "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", groupId: target.excludeGroupId },
    });
  }
  return { assignments };
}

// Pure - Intune's Settings Catalog backend (deviceManagement/configurationPolicies,
// the "DeviceConfigV2" service behind Endpoint Security policies) often
// returns its OWN raw error body as the literal STRING VALUE of Graph's
// standard `error.message` field, instead of a clean human sentence - and
// that nesting can be TWO levels deep, not one, confirmed live against two
// different real failures:
//   1. A validation error (dependent settings) - one level:
//      {"_version":3,"Message":"<the actually useful text>", ...}
//   2. An access-denied error (this tenant has no Intune license) - two
//      levels, the outer one Graph's own OData error shape wrapping the
//      SAME ConfigV2 blob as its own `.Message` string:
//      {"ErrorCode":"Forbidden","Message":"{\"_version\":3,\"Message\":\"An error has occurred - ...\",...}","Target":null,...}
// This unwraps `.Message` repeatedly (bounded depth, so a malformed or
// adversarial value can't loop forever) as long as the extracted value
// itself still looks like JSON, stopping at the first non-JSON string -
// which is the actual human-readable text in either case. Falls back to
// the original text completely unchanged whenever nothing unwraps, so
// nothing is ever hidden.
export function cleanIntuneConfigV2Error(rawMessage: string): string {
  let current = rawMessage;
  for (let depth = 0; depth < 5; depth++) {
    const trimmed = current.trim();
    if (!trimmed.startsWith("{")) break;
    let parsed: any;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      break; // Not valid JSON - `current` is the final human text.
    }
    if (typeof parsed?.Message !== "string" || parsed.Message.length === 0) break;
    current = parsed.Message;
  }

  // The ConfigV2 proxy's own "An error has occurred" is real but useless on
  // its own - confirmed live on a tenant with no Microsoft Intune license,
  // where Graph's OUTER envelope carried "ErrorCode":"Forbidden" (a genuine
  // access-denied, not the generic wording alone would suggest). Since that
  // outer ErrorCode is lost once unwrapped, detect the same signal from the
  // final generic text and add the most likely real cause rather than
  // leaving the admin with a sentence that names no cause at all.
  if (/^an error has occurred\b/i.test(current.trim())) {
    return `${current} - this generic error from Intune's backend most often means the tenant doesn't have a Microsoft Intune license (check the tenant's License & Capability Matrix), or the DeviceManagementConfiguration.ReadWrite.All permission isn't actually granted despite being requested - check the Permissions modal.`;
  }

  return current;
}

async function postIntuneAssignment(
  headers: Record<string, string>,
  policyId: string,
  assignment: IntuneAssignmentTarget
): Promise<{ error?: string }> {
  try {
    const res = await graphFetch(
      `https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('${policyId}')/assign`,
      {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify(buildIntuneAssignmentTarget(assignment)),
      },
      { retryOnNetworkError: false }
    );
    if (!res.ok) {
      const data = await res.json().catch(() => null);
      const rawMessage = data?.error?.message || `Failed to assign policy (HTTP ${res.status}: ${res.statusText})`;
      return { error: cleanIntuneConfigV2Error(rawMessage) };
    }
    return {};
  } catch (err: any) {
    return { error: err.message || "Network error while assigning the policy." };
  }
}

// Shared by every Settings Catalog deploy function (AV/EDR/ASR): creates a
// new policy, assigns it, and - when replacing an existing one - deletes
// the old one afterward. This is the ONLY way to "update" a deployed
// Settings Catalog policy's settings: confirmed live that Graph has no
// route for it at all, not just a shape Clarity365 was getting wrong.
// `settings` is a `NavigationProperty` (ContainsTarget) on
// deviceManagementConfigurationPolicy with no bound update Action/Function
// (checked the live $metadata directly), and PATCHing an individual
// settings item by its own id (e.g. .../settings('0')) is rejected outright
// by Intune's real backend with "No OData route exists ... with http verb
// PATCH" - not a validation error, a genuinely absent route. A prior
// version of this code tried `PATCH .../configurationPolicies/{id}` with
// `{ settings }` alone, which fails the same way (a navigation property
// can't be included in a PATCH to its parent). Verified this create+delete
// sequence works end-to-end against a real tenant (Coetzee Architects):
// created a new EDR policy with a changed setting, assigned it, deleted
// the old one, and confirmed exactly one policy remained with the new
// value.
//
// Deliberately create-first-then-delete-old: if create fails, the
// tenant's existing policy is untouched - never lose a working policy
// chasing an update. If the old policy is genuinely being replaced and the
// delete itself fails (rare), that's surfaced as a warning with `success:
// true` - the new policy is already live and assigned, so a leftover
// duplicate is a much smaller problem than reporting the whole deploy as
// failed.
async function createSettingsCatalogPolicyReplacing(
  headers: Record<string, string>,
  createBody: Record<string, any>,
  existingPolicyId: string | undefined,
  assignment: IntuneAssignmentTarget
): Promise<{ success: boolean; policyId?: string; error?: string }> {
  const isUpdate = !!existingPolicyId;

  try {
    const res = await graphFetch(
      "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies",
      {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify(createBody),
      },
      { retryOnNetworkError: false }
    );

    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      return {
        success: false,
        error: describeTransientTokenLifetimeError(
          cleanIntuneConfigV2Error(
            errJson?.error?.message || `Failed to create policy (HTTP ${res.status}: ${res.statusText})`
          )
        ),
      };
    }

    const policyId = (await res.json()).id;

    const assignResult = await postIntuneAssignment(headers, policyId, assignment);
    if (assignResult.error) {
      return {
        success: false,
        policyId,
        error: `Policy ${isUpdate ? "created (to replace the old one)" : "created"} but assignment failed: ${assignResult.error}`,
      };
    }

    if (isUpdate) {
      const delRes = await graphFetch(
        `https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/${existingPolicyId}`,
        { method: "DELETE", headers },
        { retryOnNetworkError: false }
      );
      if (!delRes.ok) {
        return {
          success: true,
          policyId,
          error: `Updated policy, but the previous version (${existingPolicyId}) could not be removed automatically and may need manual cleanup in Intune.`,
        };
      }
    }

    return { success: true, policyId };
  } catch (err: any) {
    return { success: false, error: err.message || "Network error while connecting to Microsoft Graph." };
  }
}

/**
 * Fetches the current Defender Antivirus Settings Catalog policy (the one
 * Clarity365 itself deployed, identified by templateFamily like the ASR
 * read path already does), if any. Read-only - safe to call regardless of
 * endpointSecurityWriteMode.
 */
export async function fetchDefenderAvPolicy(
  tenant: Tenant
): Promise<{ deployedPolicyId?: string; settings: DefenderAvPolicySettings; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { settings: {} };
  }
  return withFreshTokenOnLifetimeError(tenant.credentials, fetchDefenderAvPolicyWithToken);
}

async function fetchDefenderAvPolicyWithToken(
  token: string
): Promise<{ deployedPolicyId?: string; settings: DefenderAvPolicySettings; error?: string }> {
  const headers = { Authorization: `Bearer ${token}` };

  const policiesResult = await fetchAllPages<any>(
    `https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq '${ANTIVIRUS_TEMPLATE_FAMILY}'`,
    headers
  );
  if (policiesResult.error) return { settings: {}, error: describeTransientTokenLifetimeError(policiesResult.error) };
  if (policiesResult.items.length === 0) return { settings: {} };

  const policy = policiesResult.items[0];
  const settingsResult = await fetchAllPages<any>(
    `https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('${policy.id}')/settings`,
    headers
  );
  if (settingsResult.error)
    return { deployedPolicyId: policy.id, settings: {}, error: describeTransientTokenLifetimeError(settingsResult.error) };

  const selectedIds = new Set(flattenSettingsCatalogSelectedIds(settingsResult.items));
  const settings: DefenderAvPolicySettings = {};
  for (const key of Object.keys(DEFENDER_AV_SETTING_DEFINITION_IDS) as (keyof DefenderAvPolicySettings)[]) {
    const id = DEFENDER_AV_SETTING_DEFINITION_IDS[key];
    if (selectedIds.has(`${id}_1`)) settings[key] = true;
    else if (selectedIds.has(`${id}_0`)) settings[key] = false;
  }

  return { deployedPolicyId: policy.id, settings };
}

/**
 * Deploys (creates + assigns) a Defender Antivirus Settings Catalog policy.
 * Mock-short-circuits first like every other deploy function in this file;
 * on a live tenant, creates the policy then assigns it, surfacing Graph
 * errors directly (no CA05-style special-casing needed here yet - this is
 * the first live use of this write path, so no known failure mode has
 * turned up to special-case).
 *
 * Pass `existingPolicyId` (from a previous deploy, or fetchDefenderAvPolicy)
 * to update that same policy's settings in place via PATCH instead of
 * creating a new one - see deployEdrPolicy's comment for why this matters
 * (the UI's "Redeploy Policy" button used to silently create a duplicate AV
 * policy on every click).
 */
export async function deployDefenderAvPolicy(
  tenant: Tenant,
  desired: DefenderAvPolicySettings,
  assignment: IntuneAssignmentTarget,
  existingPolicyId?: string
): Promise<{ success: boolean; policyId?: string; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { success: true, policyId: existingPolicyId || `mock-defender-av-${tenant.id}` };
  }
  return withFreshTokenOnLifetimeError(tenant.credentials, (token) =>
    deployDefenderAvPolicyWithToken(token, desired, assignment, existingPolicyId)
  );
}

async function deployDefenderAvPolicyWithToken(
  token: string,
  desired: DefenderAvPolicySettings,
  assignment: IntuneAssignmentTarget,
  existingPolicyId?: string
): Promise<{ success: boolean; policyId?: string; error?: string }> {
  const headers = { Authorization: `Bearer ${token}` };
  const settings = buildDefenderAvSettingsPayload(desired);

  return createSettingsCatalogPolicyReplacing(
    headers,
    {
      name: `Clarity365 Defender Antivirus Policy (${new Date().toISOString().slice(0, 10)})`,
      description: "Deployed by Clarity365 - Endpoint Security write-enabled mode.",
      platforms: "windows10",
      technologies: "mdm",
      roleScopeTagIds: ["0"],
      templateReference: { templateFamily: ANTIVIRUS_TEMPLATE_FAMILY },
      settings,
    },
    existingPolicyId,
    assignment
  );
}

// Category "Microsoft Defender for Endpoint" in Microsoft's own Settings
// Catalog metadata - confirmed live (deviceManagement/configurationCategories
// + configurationSettings), the same way ANTIVIRUS's settings were. Unlike
// the AV/ASR template families (both independently confirmed via real
// deployed policy examples), this exact templateFamily string is NOT
// independently confirmed the same way - it follows the same
// "endpointSecurity<PolicyName>" convention Microsoft uses for the other
// two, but verify it live (does Graph accept the create, does the policy
// render correctly under Endpoint security > Endpoint detection and
// response in the portal) before trusting this on a real tenant.
const EDR_POLICY_TEMPLATE_FAMILY = "endpointSecurityEndpointDetectionAndResponse";

// Both settingDefinitionIds and their exact choice values were read directly
// off a live tenant's Settings Catalog metadata for the "Microsoft Defender
// for Endpoint" category (categoryId 577d5951-fc56-4906-90bc-2c508c6611ad on
// the tenant checked) - not guessed, and not the same naming convention as
// the AV settings (a completely different CSP root:
// Device/Vendor/MSFT/WindowsAdvancedThreatProtection, not Policy/Config/Defender).
// "configurationtype" is a string-valued choice ("AutoFromConnector" is the
// only value this app exposes - "Onboard"/"Offboard" both need a signed
// blob file pasted in, out of scope for a plain toggle); "samplesharing" is
// a 0/1 integer-valued choice like the AV booleans.
const EDR_CONFIGURATION_TYPE_SETTING_ID = "device_vendor_msft_windowsadvancedthreatprotection_configurationtype";
const EDR_SAMPLE_SHARING_SETTING_ID = "device_vendor_msft_windowsadvancedthreatprotection_configuration_samplesharing";
// Confirmed live, via a real deploy attempt: choosing "AutoFromConnector"
// alone is rejected by Graph with "...with dependent settings doesnt
// contain required dependent settings. Required dependent settings are
// device_vendor_msft_windowsadvancedthreatprotection_onboarding_fromconnector".
// This dependent setting (queried directly to confirm its shape rather than
// guessed) is a `deviceManagementConfigurationSimpleSettingInstance` holding
// a `deviceManagementConfigurationSecretSettingValue` - a plain string
// value, not a choice. Its own description says it "Set[s] ... Onboarding
// blob and initiate[s] onboarding" - for the Auto-from-connector path,
// Intune's own docs (deploy-edr.md) say the real onboarding package is
// fetched from the established Intune<->Defender connector automatically,
// so this field's actual string content is very likely a required
// placeholder Intune replaces server-side, not something Clarity365 needs
// to supply the real blob for - `valueState: "notEncrypted"` is required
// (the only valid non-default enum member for a plaintext value we're
// submitting - "invalid" is Graph's own empty-state sentinel,
// "encryptedValueToken" is only for round-tripping a value Graph already
// encrypted and handed back).
const EDR_ONBOARDING_FROM_CONNECTOR_SETTING_ID = "device_vendor_msft_windowsadvancedthreatprotection_onboarding_fromconnector";

// Pure - mirrors buildDefenderAvSettingsPayload's "only emit what's
// explicitly set" behavior, but each field uses its own confirmed choice
// value shape rather than one shared _1/_0 convention.
export function buildEdrPolicySettingsPayload(desired: EdrPolicySettings): { settingInstance: any }[] {
  const settings: { settingInstance: any }[] = [];

  // Only "true" emits a setting - this is a string choice ("AutoFromConnector"
  // /"Onboard"/"Offboard"), not a boolean, so there's no clean "off" value to
  // send; "false"/undefined both mean "leave this Not Configured" by simply
  // omitting the setting instance entirely.
  if (desired.autoFromConnector) {
    settings.push({
      settingInstance: {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        settingDefinitionId: EDR_CONFIGURATION_TYPE_SETTING_ID,
        choiceSettingValue: {
          "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
          value: `${EDR_CONFIGURATION_TYPE_SETTING_ID}_autofromconnector`,
          // Required dependent child - see the comment above
          // EDR_ONBOARDING_FROM_CONNECTOR_SETTING_ID for why this exists.
          children: [
            {
              "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
              settingDefinitionId: EDR_ONBOARDING_FROM_CONNECTOR_SETTING_ID,
              simpleSettingValue: {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSecretSettingValue",
                value: "AutoFromConnector",
                valueState: "notEncrypted",
              },
            },
          ],
        },
      },
    });
  }

  if (desired.sampleSharingAll !== undefined) {
    settings.push({
      settingInstance: {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        settingDefinitionId: EDR_SAMPLE_SHARING_SETTING_ID,
        choiceSettingValue: {
          "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
          value: `${EDR_SAMPLE_SHARING_SETTING_ID}_${desired.sampleSharingAll ? "1" : "0"}`,
          children: [],
        },
      },
    });
  }

  return settings;
}

/**
 * Reads the current Clarity365-deployed EDR policy, if any. Mirrors
 * fetchDefenderAvPolicy's shape exactly - see that function for the
 * templateFamily-filter/settings-read pattern being reused here.
 */
export async function fetchEdrPolicy(
  tenant: Tenant
): Promise<{ deployedPolicyId?: string; settings: EdrPolicySettings; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { settings: {} };
  }
  return withFreshTokenOnLifetimeError(tenant.credentials, fetchEdrPolicyWithToken);
}

async function fetchEdrPolicyWithToken(
  token: string
): Promise<{ deployedPolicyId?: string; settings: EdrPolicySettings; error?: string }> {
  const headers = { Authorization: `Bearer ${token}` };

  // First diagnosed live on this exact call, on Coetzee Architects: this
  // resource (deviceManagement/configurationPolicies) rejected an
  // already-issued, not-yet-expired-by-our-own-clock token while every
  // other resource kept accepting the same token - see
  // withFreshTokenOnLifetimeError's own comment for the full live
  // diagnosis. That wrapper (applied by the caller above) is what actually
  // recovers from this now, not a same-token retry inside graphFetch.
  const policiesResult = await fetchAllPages<any>(
    `https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq '${EDR_POLICY_TEMPLATE_FAMILY}'`,
    headers
  );
  if (policiesResult.error) return { settings: {}, error: describeTransientTokenLifetimeError(policiesResult.error) };
  if (policiesResult.items.length === 0) return { settings: {} };

  const policy = policiesResult.items[0];
  const settingsResult = await fetchAllPages<any>(
    `https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('${policy.id}')/settings`,
    headers
  );
  if (settingsResult.error)
    return { deployedPolicyId: policy.id, settings: {}, error: describeTransientTokenLifetimeError(settingsResult.error) };

  const selectedIds = new Set(flattenSettingsCatalogSelectedIds(settingsResult.items));
  const settings: EdrPolicySettings = {};
  if (selectedIds.has(`${EDR_CONFIGURATION_TYPE_SETTING_ID}_autofromconnector`)) settings.autoFromConnector = true;
  if (selectedIds.has(`${EDR_SAMPLE_SHARING_SETTING_ID}_1`)) settings.sampleSharingAll = true;
  else if (selectedIds.has(`${EDR_SAMPLE_SHARING_SETTING_ID}_0`)) settings.sampleSharingAll = false;

  return { deployedPolicyId: policy.id, settings };
}

/**
 * Deploys an Endpoint Detection and Response Settings Catalog policy.
 * Mirrors deployDefenderAvPolicy's shape exactly. Pass `existingPolicyId`
 * (the id returned by a previous deploy, or by fetchEdrPolicy) to update
 * that same policy's settings in place via PATCH instead of creating a new
 * one - without it, every call POSTs a brand-new policy, which is how the
 * UI's "Redeploy Policy" button used to silently pile up duplicate EDR
 * policies in Intune on every click instead of updating the existing one.
 */
export async function deployEdrPolicy(
  tenant: Tenant,
  desired: EdrPolicySettings,
  assignment: IntuneAssignmentTarget,
  existingPolicyId?: string
): Promise<{ success: boolean; policyId?: string; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { success: true, policyId: existingPolicyId || `mock-edr-policy-${tenant.id}` };
  }
  return withFreshTokenOnLifetimeError(tenant.credentials, (token) =>
    deployEdrPolicyWithToken(token, desired, assignment, existingPolicyId)
  );
}

async function deployEdrPolicyWithToken(
  token: string,
  desired: EdrPolicySettings,
  assignment: IntuneAssignmentTarget,
  existingPolicyId?: string
): Promise<{ success: boolean; policyId?: string; error?: string }> {
  const headers = { Authorization: `Bearer ${token}` };

  const settings = buildEdrPolicySettingsPayload(desired);
  if (settings.length === 0) {
    return { success: false, error: "No EDR policy settings were selected - nothing to deploy." };
  }

  return createSettingsCatalogPolicyReplacing(
    headers,
    {
      name: `CLN - EDR Policy (${new Date().toISOString().slice(0, 10)})`,
      description: "Deployed by CLN Clarity365 - Endpoint security",
      platforms: "windows10",
      technologies: "mdm",
      roleScopeTagIds: ["0"],
      templateReference: { templateFamily: EDR_POLICY_TEMPLATE_FAMILY },
      settings,
    },
    existingPolicyId,
    assignment
  );
}

// Category "BitLocker" in Microsoft's own Settings Catalog metadata
// (confirmed live the same way AV/EDR's setting maps were, via a temporary
// tenant-agnostic category/setting lookup) - the direct CSP category
// (Device/Vendor/MSFT/BitLocker) Intune's "Endpoint Security > Disk
// encryption > BitLocker" profile uses, not the separate "BitLocker Drive
// Encryption" Administrative Templates/GPO category. templateFamily value
// confirmed against the real beta $metadata enum (deviceManagementConfigurationTemplateFamily,
// member "endpointSecurityDiskEncryption") - not just following the naming
// convention by guesswork the way EDR's was originally.
const BITLOCKER_TEMPLATE_FAMILY = "endpointSecurityDiskEncryption";

const BITLOCKER_BOOLEAN_SETTING_DEFINITION_IDS: Record<
  "requireDeviceEncryption" | "allowStandardUserEncryption" | "allowWarningForOtherDiskEncryption",
  string
> = {
  requireDeviceEncryption: "device_vendor_msft_bitlocker_requiredeviceencryption",
  allowStandardUserEncryption: "device_vendor_msft_bitlocker_allowstandarduserencryption",
  allowWarningForOtherDiskEncryption: "device_vendor_msft_bitlocker_allowwarningforotherdiskencryption",
};

const BITLOCKER_RECOVERY_ROTATION_SETTING_ID = "device_vendor_msft_bitlocker_configurerecoverypasswordrotation";
// Confirmed live: 0 = rotation off, 1 = on for Entra ID-joined devices only
// (Microsoft's own default when this setting is left unconfigured), 2 = on
// for both Entra ID-joined and hybrid-joined devices.
const BITLOCKER_RECOVERY_ROTATION_VALUE: Record<Exclude<BitLockerPolicySettings["recoveryPasswordRotation"], undefined>, string> = {
  off: "0",
  entraIdOnly: "1",
  entraIdAndHybrid: "2",
};

// Pure - mirrors buildDefenderAvSettingsPayload's "only emit what's
// explicitly set" behavior. The three boolean settings share the same
// choice-value _1/_0 (enabled/disabled) convention AV's booleans use;
// recoveryPasswordRotation is its own three-way choice, handled separately.
export function buildBitLockerSettingsPayload(desired: BitLockerPolicySettings): { settingInstance: any }[] {
  const settings: { settingInstance: any }[] = [];

  for (const key of Object.keys(BITLOCKER_BOOLEAN_SETTING_DEFINITION_IDS) as (keyof typeof BITLOCKER_BOOLEAN_SETTING_DEFINITION_IDS)[]) {
    const value = desired[key];
    if (value === undefined) continue;
    const id = BITLOCKER_BOOLEAN_SETTING_DEFINITION_IDS[key];
    settings.push({
      settingInstance: {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        settingDefinitionId: id,
        choiceSettingValue: { value: `${id}_${value ? "1" : "0"}`, children: [] },
      },
    });
  }

  if (desired.recoveryPasswordRotation !== undefined) {
    settings.push({
      settingInstance: {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        settingDefinitionId: BITLOCKER_RECOVERY_ROTATION_SETTING_ID,
        choiceSettingValue: {
          value: `${BITLOCKER_RECOVERY_ROTATION_SETTING_ID}_${BITLOCKER_RECOVERY_ROTATION_VALUE[desired.recoveryPasswordRotation]}`,
          children: [],
        },
      },
    });
  }

  return settings;
}

/**
 * Reads the current Clarity365-deployed BitLocker policy, if any. Mirrors
 * fetchDefenderAvPolicy's shape exactly.
 */
export async function fetchBitLockerPolicy(
  tenant: Tenant
): Promise<{ deployedPolicyId?: string; settings: BitLockerPolicySettings; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { settings: {} };
  }
  return withFreshTokenOnLifetimeError(tenant.credentials, fetchBitLockerPolicyWithToken);
}

async function fetchBitLockerPolicyWithToken(
  token: string
): Promise<{ deployedPolicyId?: string; settings: BitLockerPolicySettings; error?: string }> {
  const headers = { Authorization: `Bearer ${token}` };

  const policiesResult = await fetchAllPages<any>(
    `https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq '${BITLOCKER_TEMPLATE_FAMILY}'`,
    headers
  );
  if (policiesResult.error) return { settings: {}, error: describeTransientTokenLifetimeError(policiesResult.error) };
  if (policiesResult.items.length === 0) return { settings: {} };

  const policy = policiesResult.items[0];
  const settingsResult = await fetchAllPages<any>(
    `https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('${policy.id}')/settings`,
    headers
  );
  if (settingsResult.error)
    return { deployedPolicyId: policy.id, settings: {}, error: describeTransientTokenLifetimeError(settingsResult.error) };

  const selectedIds = new Set(flattenSettingsCatalogSelectedIds(settingsResult.items));
  const settings: BitLockerPolicySettings = {};
  for (const key of Object.keys(BITLOCKER_BOOLEAN_SETTING_DEFINITION_IDS) as (keyof typeof BITLOCKER_BOOLEAN_SETTING_DEFINITION_IDS)[]) {
    const id = BITLOCKER_BOOLEAN_SETTING_DEFINITION_IDS[key];
    if (selectedIds.has(`${id}_1`)) settings[key] = true;
    else if (selectedIds.has(`${id}_0`)) settings[key] = false;
  }
  for (const [mode, value] of Object.entries(BITLOCKER_RECOVERY_ROTATION_VALUE)) {
    if (selectedIds.has(`${BITLOCKER_RECOVERY_ROTATION_SETTING_ID}_${value}`)) {
      settings.recoveryPasswordRotation = mode as BitLockerPolicySettings["recoveryPasswordRotation"];
      break;
    }
  }

  return { deployedPolicyId: policy.id, settings };
}

/**
 * Deploys (creates, assigns, and - when replacing an existing deploy -
 * deletes the old one, via createSettingsCatalogPolicyReplacing) a
 * BitLocker Settings Catalog policy. Mirrors deployDefenderAvPolicy's shape
 * exactly.
 */
export async function deployBitLockerPolicy(
  tenant: Tenant,
  desired: BitLockerPolicySettings,
  assignment: IntuneAssignmentTarget,
  existingPolicyId?: string
): Promise<{ success: boolean; policyId?: string; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { success: true, policyId: existingPolicyId || `mock-bitlocker-${tenant.id}` };
  }
  return withFreshTokenOnLifetimeError(tenant.credentials, (token) =>
    deployBitLockerPolicyWithToken(token, desired, assignment, existingPolicyId)
  );
}

async function deployBitLockerPolicyWithToken(
  token: string,
  desired: BitLockerPolicySettings,
  assignment: IntuneAssignmentTarget,
  existingPolicyId?: string
): Promise<{ success: boolean; policyId?: string; error?: string }> {
  const headers = { Authorization: `Bearer ${token}` };
  const settings = buildBitLockerSettingsPayload(desired);
  if (settings.length === 0) {
    return { success: false, error: "No BitLocker policy settings were selected - nothing to deploy." };
  }

  return createSettingsCatalogPolicyReplacing(
    headers,
    {
      name: `CLN - BitLocker Policy (${new Date().toISOString().slice(0, 10)})`,
      description: "Deployed by CLN Clarity365 - Endpoint security",
      platforms: "windows10",
      technologies: "mdm",
      roleScopeTagIds: ["0"],
      templateReference: { templateFamily: BITLOCKER_TEMPLATE_FAMILY },
      settings,
    },
    existingPolicyId,
    assignment
  );
}

// Pure - builds the ASR collection-setting children array (one choice
// setting per requested rule) plus the list of ruleIds that couldn't be
// matched to a slug (unknown to Microsoft's catalog metadata, or the
// metadata fetch failed) so the caller can surface a partial-success
// message rather than silently dropping rules. Confirmed against a real
// deployed Settings Catalog ASR policy - the choice suffix is "_audit", not
// "_auditmode"; the read side (asr-configuration-mapper.ts) tolerates both
// since it was written defensively before this was confirmed, but the
// write side must emit the one real value.
export function buildAsrRuleSettingsChildren(
  desiredModes: Record<string, Exclude<AsrRuleMode, "not_configured">>,
  ruleIdToSlug: Map<string, string>
): { children: any[]; skippedRuleIds: string[] } {
  const modeToSuffix: Record<Exclude<AsrRuleMode, "not_configured">, string> = {
    block: "block",
    audit: "audit",
    warn: "warn",
  };

  const children: any[] = [];
  const skippedRuleIds: string[] = [];
  for (const [ruleId, mode] of Object.entries(desiredModes)) {
    const slug = ruleIdToSlug.get(ruleId);
    if (!slug) {
      skippedRuleIds.push(ruleId);
      continue;
    }
    const value = `${ASR_SETTINGS_CATALOG_ROOT_DEFINITION_ID}_${slug}_${modeToSuffix[mode]}`;
    children.push({
      "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
      settingDefinitionId: `${ASR_SETTINGS_CATALOG_ROOT_DEFINITION_ID}_${slug}`,
      choiceSettingValue: { "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue", value, children: [] },
    });
  }

  return { children, skippedRuleIds };
}

/**
 * Deploys ASR rules with per-rule Block/Audit/Warn modes via the same
 * Settings Catalog surface the read path (getAsrSettingsCatalogSlugMap)
 * already resolves rule GUIDs against - reused here by inverting the
 * slug->ruleId map this function already builds and caches.
 *
 * Pass `existingPolicyId` (from a previous deploy, or the ASR module's own
 * read path) to update that same policy's settings in place via PATCH
 * instead of creating a new one - see deployEdrPolicy's comment for why
 * this matters (the UI's "Redeploy Policy" button used to silently create
 * a duplicate ASR policy on every click).
 */
export async function deployAsrRulePolicy(
  tenant: Tenant,
  desiredModes: Record<string, Exclude<AsrRuleMode, "not_configured">>,
  assignment: IntuneAssignmentTarget,
  existingPolicyId?: string
): Promise<{ success: boolean; policyId?: string; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { success: true, policyId: existingPolicyId || `mock-asr-policy-${tenant.id}` };
  }
  return withFreshTokenOnLifetimeError(tenant.credentials, (token) =>
    deployAsrRulePolicyWithToken(token, desiredModes, assignment, existingPolicyId)
  );
}

async function deployAsrRulePolicyWithToken(
  token: string,
  desiredModes: Record<string, Exclude<AsrRuleMode, "not_configured">>,
  assignment: IntuneAssignmentTarget,
  existingPolicyId?: string
): Promise<{ success: boolean; policyId?: string; error?: string }> {
  const headers = { Authorization: `Bearer ${token}` };
  const syncErrors: string[] = [];

  const slugToRuleId = await getAsrSettingsCatalogSlugMap(headers, syncErrors);
  const ruleIdToSlug = new Map<string, string>();
  slugToRuleId.forEach((ruleId, slug) => ruleIdToSlug.set(ruleId, slug));

  const { children, skippedRuleIds } = buildAsrRuleSettingsChildren(desiredModes, ruleIdToSlug);

  if (children.length === 0) {
    return { success: false, error: "No requested ASR rules could be matched to Microsoft's Settings Catalog metadata - nothing to deploy." };
  }

  const settings = [
    {
      settingInstance: {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
        settingDefinitionId: ASR_SETTINGS_CATALOG_ROOT_DEFINITION_ID,
        groupSettingCollectionValue: [{ children }],
      },
    },
  ];

  const result = await createSettingsCatalogPolicyReplacing(
    headers,
    {
      name: `Clarity365 ASR Rules Policy (${new Date().toISOString().slice(0, 10)})`,
      description: "Deployed by Clarity365 - Endpoint Security write-enabled mode.",
      platforms: "windows10",
      technologies: "mdm",
      roleScopeTagIds: ["0"],
      templateReference: { templateFamily: "endpointSecurityAttackSurfaceReduction" },
      settings,
    },
    existingPolicyId,
    assignment
  );

  if (result.success && skippedRuleIds.length > 0) {
    return {
      ...result,
      error: `${existingPolicyId ? "Updated" : "Deployed"}, but ${skippedRuleIds.length} rule(s) could not be matched to Microsoft's catalog metadata and were skipped: ${skippedRuleIds.join(", ")}`,
    };
  }

  return result;
}

/**
 * PATCHes the MDE connector's own settings (deviceManagement/mobileThreatDefenseConnectors/{id}).
 * Unlike the Settings Catalog writes above, this resource has NO
 * report-only/preview concept at all - it's a single tenant-wide live
 * setting, and a PATCH takes effect immediately. There is no safe default
 * to fall back on here, so the caller (the UI) is responsible for an
 * explicit "this takes effect immediately, tenant-wide" confirmation
 * before this function is ever called - this function itself has no way
 * to make the change any safer than that.
 */
export async function updateMdeConnectorSettings(
  tenant: Tenant,
  connectorId: string,
  patch: Partial<MdeConnectorSettings>
): Promise<{ success: boolean; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { success: true };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return { success: false, error: `Authentication Error: ${error}` };
  }

  const { id: _omitId, partnerState: _omitPartnerState, lastHeartbeatDateTime: _omitHeartbeat, ...writableFields } = patch;

  try {
    const res = await graphFetch(
      `https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors/${connectorId}`,
      {
        method: "PATCH",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(writableFields),
      },
      { retryOnNetworkError: false }
    );
    if (!res.ok) {
      const data = await res.json().catch(() => null);
      return { success: false, error: cleanIntuneConfigV2Error(data?.error?.message || `Failed to update connector settings (HTTP ${res.status}: ${res.statusText})`) };
    }
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message || "Network error while connecting to Microsoft Graph." };
  }
}

// Flattens a legacy "Endpoint Security Template" intent's definitionValues
// (each an { id, definitionId, valueJson } row - definitionId is prefixed
// with "deviceConfiguration--windows10EndpointProtectionConfiguration_")
// into the same { propertyName, rawValue } shape the classic Device
// Configuration profile surface already produces directly, so both funnel
// through the one shared mapNamedPropertyValuesToSignals function.
const INTENT_DEFINITION_ID_PREFIX = "deviceConfiguration--windows10EndpointProtectionConfiguration_";

function extractIntentAsrProperties(definitionValues: any[]): { propertyName: string; rawValue: string }[] {
  const properties: { propertyName: string; rawValue: string }[] = [];

  for (const entry of definitionValues) {
    const definitionId: string = entry.definitionId || "";
    if (!definitionId.startsWith(INTENT_DEFINITION_ID_PREFIX)) continue;
    const propertyName = definitionId.slice(INTENT_DEFINITION_ID_PREFIX.length);

    let rawValue: unknown = entry.value;
    if (rawValue == null && typeof entry.valueJson === "string") {
      try {
        rawValue = JSON.parse(entry.valueJson);
      } catch {
        continue;
      }
    }
    if (typeof rawValue === "string") properties.push({ propertyName, rawValue });
  }

  return properties;
}

// The real count of named fetch steps below (1 through 8.97) - kept as one
// source of truth so the progress percentage this drives can never silently
// drift out of sync with the steps actually being reported, the way a
// hand-maintained duplicate count would. Steps 9/10 (local computation,
// snapshot assembly) aren't included - they're fast enough that reaching
// 100% right at the last Graph fetch reads correctly.
export const TOTAL_SYNC_STEPS = 26;

// Maps one raw Graph conditionalAccessPolicy into Clarity365's CAPolicyRule
// shape. Pulled out of fetchLiveTenantSnapshot's inline .map() so this
// mapping/classification step is unit-testable directly (same convention as
// secure-score-mapper.ts) - this exact function is where the CA04
// includeGuestsOrExternalUsers bug lived, and it had zero test coverage of
// its own before this extraction (only the pure ca-baseline-matcher.ts
// functions it calls were tested in isolation).
export function mapConditionalAccessPolicy(p: any): CAPolicyRule {
  const detectedCode = classifyPolicyBaselineCode(p);
  const baselineDef = CA_BASELINE_STANDARDS.find((b) => b.code === detectedCode);

  // Graph's grantControls.authenticationStrength is a sibling object to
  // builtInControls, not an entry inside it - encode its presence as a marker
  // string in the array (matching this app's own convention, e.g. the
  // "authenticationStrength:PhishingResistantMFA" strings used when Clarity365
  // deploys its own CA10 policy) so ca-baseline-matcher.ts's array-based
  // hasAuthStrengthOrSession/controlsInclude checks can see it.
  const builtInControls: string[] = p.grantControls?.builtInControls || [];
  const authStrengthName = p.grantControls?.authenticationStrength?.displayName || p.grantControls?.authenticationStrength?.id;
  const grantControls = authStrengthName ? [...builtInControls, `authenticationStrength:${authStrengthName}`] : builtInControls;

  // Fields the Security Simulations engine needs that this mapper used to
  // drop (see ai-context-vault/Optimization/Security Simulations Plan.md).
  const extended = mapCaPolicyExtendedFields(p);

  return {
    id: p.id,
    name: p.displayName,
    baselineCode: detectedCode,
    baselineTitle: baselineDef?.name,
    state: p.state as any,
    modifiedDateTime: p.modifiedDateTime || new Date().toISOString(),
    createdDateTime: p.createdDateTime || new Date().toISOString(),
    grantControls,
    conditions: {
      // Guest/external-user targeting moved from a plain "GuestsOrExternalUsers"
      // string inside includeUsers/excludeUsers to a structured
      // includeGuestsOrExternalUsers/excludeGuestsOrExternalUsers object - Graph
      // still silently accepts (and auto-upgrades) the deprecated string on
      // create, but a live GET only ever returns the new structured field, never
      // the string. Without this, includeUsers/excludeUsers come back empty for
      // a CA04 (or CA02's guest exclusion) policy that is genuinely correctly
      // configured, and re-validation against this mapped shape falsely reports
      // it as Misconfigured even though the raw sync-time classification (which
      // reads the raw Graph response directly, not this mapped shape) got it
      // right. Re-encoded as the same "GuestsOrExternalUsers" marker string
      // ca-baseline-matcher.ts's targetsGuests() already looks for, so no
      // matcher change is needed - confirmed live against a real dmafrica CA04
      // policy Graph had already silently upgraded this way.
      users: {
        // No "|| includeRoles" fallback here on purpose: Graph always
        // returns includeUsers as an array (empty, never omitted) for a
        // role-scoped policy, and [] is truthy in JS, so that fallback
        // could never actually fire - found during a follow-up review as
        // dead code with the exact same "empty array masks a real value"
        // shape as the CA04 bug above, just not currently symptomatic
        // because targetsAdminRoles() already reads includeRoles from its
        // own preserved field below, not from this array. Merging role
        // GUIDs into include would also be semantically wrong regardless
        // (they aren't user/group identifiers, and other checks scan
        // include specifically for "All"/"GuestsOrExternalUsers" markers).
        include: [
          ...(p.conditions?.users?.includeUsers || []),
          ...(p.conditions?.users?.includeGuestsOrExternalUsers ? ["GuestsOrExternalUsers"] : []),
        ],
        exclude: [
          ...(p.conditions?.users?.excludeUsers || []),
          ...(p.conditions?.users?.excludeGuestsOrExternalUsers ? ["GuestsOrExternalUsers"] : []),
        ],
        excludeGroupIds: p.conditions?.users?.excludeGroups || [],
        includeRoles: p.conditions?.users?.includeRoles || [],
        ...extended.users,
      },
      applications: {
        include: p.conditions?.applications?.includeApplications || [],
        exclude: p.conditions?.applications?.excludeApplications || [],
        ...extended.applications,
      },
      clientAppTypes: p.conditions?.clientAppTypes || [],
      // Previously dropped entirely - CA06 (signInRiskLevels), CA07
      // (userRiskLevels), and CA08 (locations) all validate structurally
      // against these fields, so a live-synced policy that legitimately
      // satisfies them was still failing re-validation against the stored
      // snapshot even though the initial sync-time classification (run
      // against the raw Graph response above) correctly detected the code.
      platforms: {
        include: p.conditions?.platforms?.includePlatforms || [],
        exclude: p.conditions?.platforms?.excludePlatforms || [],
      },
      locations: {
        include: p.conditions?.locations?.includeLocations || [],
        exclude: p.conditions?.locations?.excludeLocations || [],
      },
      userRiskLevels: p.conditions?.userRiskLevels || [],
      signInRiskLevels: p.conditions?.signInRiskLevels || [],
      ...extended.conditions,
    },
    grantOperator: extended.grantOperator,
    sessionControls: extended.sessionControls,
    matchesBaseline: !!detectedCode,
  };
}

export async function fetchLiveTenantSnapshot(
  tenant: Tenant,
  existingSnapshot?: TenantSecuritySnapshot,
  onExoRefreshRotated?: (newRefreshToken: string) => void,
  onProgress?: (step: string, stepIndex: number, totalSteps: number) => void
): Promise<{ snapshot?: TenantSecuritySnapshot; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { snapshot: existingSnapshot };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return { error: `Authentication Error: ${error}` };
  }

  const headers = { Authorization: `Bearer ${token}` };
  const syncErrors: string[] = [];

  // Exchange Online access, checked once per sync: app-only (Exchange.ManageAsApp
  // + an Entra role, no sign-in) first, else the older delegated sign-in. The
  // app-only result is saved on the tenant below so the modules and the
  // Permissions check show the current status. See ai-context-vault/
  // Optimization/Exchange App-Only Access Plan.md.
  const exoApp = await getExoAppOnlyAccess(tenant.credentials);
  const exoCredentials = exoApp.access ? { ...tenant.credentials, exoAppAccess: exoApp.access } : tenant.credentials;
  const exoAvailable = getExchangeAccess(exoCredentials).available;

  // 1. Fetch Conditional Access Policies
  onProgress?.("Conditional Access policies", 1, TOTAL_SYNC_STEPS);
  let livePolicies: CAPolicyRule[] = [];
  try {
    const caResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
      headers
    );
    if (caResult.error) syncErrors.push(`Conditional Access policies: ${caResult.error}`);

    livePolicies = caResult.items.map(mapConditionalAccessPolicy);
  } catch (err: any) {
    console.error("[Graph Client] Error fetching CA policies:", err);
    syncErrors.push(`Conditional Access policies: ${err.message || "Unexpected error while processing policies."}`);
  }

  // 2. Fetch Users & Directory Roles
  onProgress?.("Users & directory roles", 2, TOTAL_SYNC_STEPS);
  let usersList: TenantAccountSummary["users"] = [];
  const adminUserRolesMap = new Map<string, string[]>(); // userId -> roleNames[]
  const adminUserRoleTemplateIdsMap = new Map<string, string[]>(); // userId -> role template GUIDs (lower-case)

  try {
    const usersResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/users?$top=999&$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,createdDateTime,assignedLicenses,userType,signInActivity",
      headers
    );
    if (usersResult.error) syncErrors.push(`Users: ${usersResult.error}`);

    usersList = usersResult.items.map((u: any) => {
      const isGuest = u.userType?.toLowerCase() === "guest";
      const hasLicense = u.assignedLicenses && u.assignedLicenses.length > 0;
      const isEnabled = u.accountEnabled !== false;
      let classification: "licensed" | "unlicensed_active" | "disabled" | "guest" = "licensed";

      if (!isEnabled) {
        classification = "disabled";
      } else if (isGuest) {
        classification = "guest";
      } else if (hasLicense) {
        classification = "licensed";
      } else {
        classification = "unlicensed_active";
      }

      return {
        id: u.id,
        userPrincipalName: u.userPrincipalName,
        displayName: u.displayName || u.userPrincipalName,
        classification,
        licenses: u.assignedLicenses ? u.assignedLicenses.map((l: any) => l.skuId) : [],
        accountEnabled: isEnabled,
        department: u.department || "General",
        createdDateTime: u.createdDateTime || new Date().toISOString(),
        // signInActivity.lastSignInDateTime is Graph's authoritative "last
        // interactive sign-in" - undefined for a user who has never signed in
        // (requires AuditLog.Read.All, already held for auditLogs/signIns below).
        lastSignInDateTime: u.signInActivity?.lastSignInDateTime || undefined,
        riskFlag: classification === "unlicensed_active" ? "Active account without license assigned." : undefined,
      };
    });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching users:", err);
    syncErrors.push(`Users: ${err.message || "Unexpected error while processing users."}`);
  }

  try {
    // Query Directory Roles to identify privileged admins. $top on the expanded
    // members collection raises Graph's default expand page size; Graph does not
    // support @odata.nextLink cursoring *within* an expanded property, so an
    // exceptionally large single role's membership could still be capped here.
    const DIRECTORY_ROLES_URL = "https://graph.microsoft.com/v1.0/directoryRoles?$expand=members($top=999)";
    let rolesResult = await fetchAllPages<any>(DIRECTORY_ROLES_URL, headers);
    // Microsoft intermittently answers this call with "internal server
    // error" (3 of 10 live tenants on 2026-09-30). Try once more, then
    // rebuild the same user -> roles map from roleAssignments, which the
    // same permission covers. Only if both fail is it a sync error.
    if (rolesResult.error && rolesResult.items.length === 0) {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      rolesResult = await fetchAllPages<any>(DIRECTORY_ROLES_URL, headers);
    }
    if (rolesResult.error && rolesResult.items.length === 0) {
      const assignments = await fetchAllPages<any>("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition", headers);
      if (assignments.error && assignments.items.length === 0) {
        syncErrors.push(`Directory roles: ${rolesResult.error}`);
      } else {
        const maps = buildAdminRoleMapsFromRoleAssignments(assignments.items);
        maps.rolesByPrincipal.forEach((names, id) => adminUserRolesMap.set(id, names));
        maps.templateIdsByPrincipal.forEach((ids, id) => adminUserRoleTemplateIdsMap.set(id, ids));
      }
    } else if (rolesResult.error) {
      syncErrors.push(`Directory roles: ${rolesResult.error}`);
    }

    rolesResult.items.forEach((role: any) => {
      const roleName = role.displayName || "Directory Role";
      const roleTemplateId: string | undefined = typeof role.roleTemplateId === "string" ? role.roleTemplateId.toLowerCase() : undefined;
      if (role.members && Array.isArray(role.members)) {
        role.members.forEach((m: any) => {
          if (m.id) {
            const existing = adminUserRolesMap.get(m.id) || [];
            existing.push(roleName);
            adminUserRolesMap.set(m.id, existing);
            // Security Simulations: CA targets roles by template GUID, so keep
            // the exact id rather than re-deriving it from the display name.
            if (roleTemplateId) {
              const ids = adminUserRoleTemplateIdsMap.get(m.id) || [];
              if (!ids.includes(roleTemplateId)) ids.push(roleTemplateId);
              adminUserRoleTemplateIdsMap.set(m.id, ids);
            }
          }
        });
      }
    });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching directory roles:", err);
    syncErrors.push(`Directory roles: ${err.message || "Unexpected error while processing roles."}`);
  }

  // 3. Fetch Sign-In Logs
  onProgress?.("Sign-in logs", 3, TOTAL_SYNC_STEPS);
  let signInsList: SignInEvent[] = [];
  let signInCoverage: SignInCoverage | undefined;
  try {
    // Some tenant configurations reject a $top=250 audit log request with 400;
    // fall back to a smaller page size for the first page, then paginate normally.
    // Sign-in volume can be very high, so this is capped tighter than other lists.
    // Newest first, limited to the last SIGN_IN_WINDOW_DAYS days and to 20
    // pages. This endpoint is slow on busy tenants (30s timeouts seen live),
    // so it gets a longer per-page timeout. Reaching the page limit is a
    // known cap, not a failure: it's recorded as coverage (shown wherever
    // sign-ins are used) instead of marking the tenant degraded.
    const signInWindowStart = new Date(Date.now() - SIGN_IN_WINDOW_DAYS * 24 * 60 * 60 * 1000).toISOString().slice(0, 19) + "Z";
    const signInFilter = `$filter=createdDateTime ge ${signInWindowStart}`;
    // Beta is tried first because only it reports how each sign-in was
    // authenticated (MFA required or not, and the method) - v1.0 has no such
    // fields. Beta returns a superset of v1.0, so the mapping below is the
    // same either way; if beta refuses, the v1.0 candidates take over and the
    // authentication details are simply absent ("not reported").
    const signInsResult = await fetchAllPages<any>(
      [
        `https://graph.microsoft.com/beta/auditLogs/signIns?$top=250&${signInFilter}`,
        `https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=250&${signInFilter}`,
        `https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100&${signInFilter}`,
        "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100",
      ],
      headers,
      20,
      { timeoutMs: 90_000 }
    );
    const signInError = signInsResult.hitPageCap ? undefined : signInsResult.error;
    if (signInError) syncErrors.push(`Sign-in logs: ${signInError}`);

    signInsList = signInsResult.items.map((s: any) => {
      const appliedPolicies = (s.appliedConditionalAccessPolicies || []).map((p: any) => ({
        id: p.id || "",
        displayName: p.displayName || "Conditional Access Policy",
        result: p.result || "notApplied",
        enforcedGrantControls: p.enforcedGrantControls || [],
        enforcedSessionControls: p.enforcedSessionControls || [],
      }));

      const hasReportOnlyFailure = appliedPolicies.some(
        (p: any) => p.result === "reportOnlyFailure"
      );
      const reportOnlyFailedPolicies = appliedPolicies
        .filter((p: any) => p.result === "reportOnlyFailure")
        .map((p: any) => p.displayName);

      const isBlocked =
        appliedPolicies.some((p: any) => p.result === "failure") ||
        s.status?.errorCode === 53003;
      const isFailed = s.status?.errorCode !== 0;

      let status: SignInStatus = "success";
      if (isBlocked) {
        status = "ca_blocked";
      } else if (hasReportOnlyFailure) {
        status = "report_only_failed";
      } else if (isFailed) {
        status = "failed";
      }

      const errorCode = s.status?.errorCode || 0;
      let failureReason = s.status?.failureReason;
      if (!failureReason || failureReason === "Other." || failureReason === "None") {
        if (s.status?.additionalDetails) {
          failureReason = s.status.additionalDetails;
        } else if (errorCode !== 0) {
          failureReason = `Error ${errorCode}: Authentication or conditional access requirement not met`;
        } else {
          failureReason = "Authentication successful (All controls satisfied)";
        }
      }

      return {
        id: s.id,
        createdDateTime: s.createdDateTime || new Date().toISOString(),
        authentication: mapSignInAuthentication(s),
        userType: s.userType === "guest" || s.userType === "member" ? s.userType : undefined,
        asn: typeof s.autonomousSystemNumber === "number" ? s.autonomousSystemNumber : undefined,
        userPrincipalName: s.userPrincipalName || "unknown@domain.com",
        userDisplayName: s.userDisplayName || s.userPrincipalName || "Unknown User",
        userId: s.userId || "",
        ipAddress: s.ipAddress || "0.0.0.0",
        location: {
          city: s.location?.city || "Unknown",
          state: s.location?.state || "",
          country: s.location?.countryOrRegion || "Unknown",
        },
        clientApp: s.clientAppUsed || "Browser",
        appDisplayName: s.appDisplayName || "Microsoft 365 Cloud App",
        status,
        errorCode,
        failureReason,
        isRisky:
          s.riskLevelDuringSignIn === "medium" ||
          s.riskLevelDuringSignIn === "high" ||
          s.riskState === "atRisk",
        riskLevel: (s.riskLevelDuringSignIn || s.riskLevelAggregated || "none").toLowerCase() as any,
        deviceDetail: {
          deviceId: s.deviceDetail?.deviceId || "",
          displayName: s.deviceDetail?.displayName || "",
          operatingSystem: s.deviceDetail?.operatingSystem || "Unknown OS",
          browser: s.deviceDetail?.browser || "Unknown Browser",
          isCompliant: !!s.deviceDetail?.isCompliant,
          isManaged: !!s.deviceDetail?.isManaged,
          trustType: s.deviceDetail?.trustType || undefined,
        },
        appliedConditionalAccessPolicies: appliedPolicies,
        hasReportOnlyFailure,
        reportOnlyFailedPolicies,
      };
    });
    signInCoverage = computeSignInCoverage(signInsList, { hitLimit: signInsResult.hitPageCap, error: signInError });
    signInCoverage.hasAuthDetails = signInsList.some((s) => !!s.authentication);
  } catch (err: any) {
    console.error("[Graph Client] Error fetching sign-in logs:", err);
    syncErrors.push(`Sign-in logs: ${err.message || "Unexpected error while processing sign-in logs."}`);
  }

  // 4. Fetch MFA & Authentication Methods
  onProgress?.("MFA & authentication methods", 4, TOTAL_SYNC_STEPS);
  let mfaProfilesList: UserMfaProfile[] = [];
  try {
    const mfaResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999",
      headers
    );
    if (mfaResult.error) syncErrors.push(`MFA registration details: ${mfaResult.error}`);

    const hasCaMfaEnforced = livePolicies.some(
      (p) => (p.baselineCode === "CA02" || p.baselineCode === "CA03") && p.state === "enabled"
    );

    if (mfaResult.items.length > 0) {
      const registrationMap = new Map<string, any>();
      mfaResult.items.forEach((reg: any) => {
        registrationMap.set(reg.id || reg.userPrincipalName?.toLowerCase(), reg);
      });

      mfaProfilesList = usersList.map((u) => {
        const reg = registrationMap.get(u.id) || registrationMap.get(u.userPrincipalName.toLowerCase());
        const roles = adminUserRolesMap.get(u.id) || [];
        const isAdmin = roles.length > 0 || (reg && !!reg.isAdmin);

        const { registeredMethods, defaultMethod, mfaRegistered, isWeakAuth, authStrength } = classifyUserAuthMethods(
          reg?.methodsRegistered,
          reg ? !!reg.isMfaRegistered : false
        );

        return {
          id: u.id,
          userPrincipalName: u.userPrincipalName,
          displayName: u.displayName,
          jobTitle: "Enterprise User",
          department: u.department || "General",
          accountEnabled: u.accountEnabled,
          isAdmin,
          adminRoles: roles.length > 0 ? roles : isAdmin ? [UNCONFIRMED_ADMIN_ROLE_LABEL] : undefined,
          // Only real directory-role memberships - never the placeholder label
          // above, which is inferred from the registration report alone.
          adminRoleTemplateIds: adminUserRoleTemplateIdsMap.get(u.id),
          mfaRegistered,
          mfaEnforcedByPolicy: hasCaMfaEnforced || isAdmin,
          defaultMethod,
          registeredMethods: registeredMethods.length > 0 ? registeredMethods : ["none"],
          isWeakAuth,
          passwordLastSetDateTime: u.createdDateTime,
          // Prefer the authoritative signInActivity value captured on the user
          // object above; fall back to the most recent audit log sign-in event,
          // and finally "" (never signed in) - NOT today's date, which would
          // misrepresent every unused account as active.
          lastSignInDateTime:
            u.lastSignInDateTime ||
            signInsList.find((s) => s.userPrincipalName.toLowerCase() === u.userPrincipalName.toLowerCase())
              ?.createdDateTime ||
            "",
          isSsprRegistered: reg ? !!reg.isSsprRegistered : false,
          isPasswordlessCapable: reg ? !!reg.isPasswordlessCapable : defaultMethod === "passkey_fido2",
          methodsCount: registeredMethods.length,
          authStrength,
        };
      });
    }

    // Fallback: If registration report was forbidden or returned 0 rows, synthesize profiles from directory users & sign-in logs
    if (mfaProfilesList.length === 0 && usersList.length > 0) {
      mfaProfilesList = usersList.map((u) => {
        const roles = adminUserRolesMap.get(u.id) || [];
        const isAdmin = roles.length > 0;

        // Check if user has successful sign-ins with MFA controls satisfied
        const userSignIns = signInsList.filter((s) => s.userPrincipalName.toLowerCase() === u.userPrincipalName.toLowerCase());
        const hasPassedMfaInSignIns = userSignIns.some((s) => s.status === "success");

        const defaultMethod = hasPassedMfaInSignIns ? "ms_authenticator_push" : "none";
        const mfaRegistered = hasPassedMfaInSignIns;
        const isWeakAuth = !mfaRegistered;

        return {
          id: u.id,
          userPrincipalName: u.userPrincipalName,
          displayName: u.displayName,
          jobTitle: isAdmin ? "Directory Administrator" : "Enterprise User",
          department: u.department || "General",
          accountEnabled: u.accountEnabled,
          isAdmin,
          adminRoles: roles.length > 0 ? roles : undefined,
          adminRoleTemplateIds: adminUserRoleTemplateIdsMap.get(u.id),
          mfaRegistered,
          mfaEnforcedByPolicy: hasCaMfaEnforced || isAdmin,
          defaultMethod,
          registeredMethods: mfaRegistered ? ["ms_authenticator_push"] : ["none"],
          isWeakAuth,
          passwordLastSetDateTime: u.createdDateTime,
          lastSignInDateTime: u.lastSignInDateTime || userSignIns[0]?.createdDateTime || "",
          isSsprRegistered: mfaRegistered,
          isPasswordlessCapable: false,
          methodsCount: mfaRegistered ? 1 : 0,
          authStrength: mfaRegistered ? "strong" : "none",
        };
      });
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching MFA registration details:", err);
    syncErrors.push(`MFA registration details: ${err.message || "Unexpected error while processing MFA data."}`);
  }

  // 5. Fetch Intune Managed Devices
  onProgress?.("Intune managed devices", 5, TOTAL_SYNC_STEPS);
  let intuneDevices: IntuneDevice[] = [];
  try {
    const devicesResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=999&$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime,model,manufacturer,serialNumber,imei,enrolledDateTime,managementAgent,managedDeviceOwnerType,deviceEnrollmentType,totalStorageSpaceInBytes,freeStorageSpaceInBytes,deviceCategoryDisplayName,azureADDeviceId,jailBroken,complianceGracePeriodExpirationDateTime,wiFiMacAddress",
      headers
    );
    if (devicesResult.error) syncErrors.push(`Intune devices: ${devicesResult.error}`);
    intuneDevices = devicesResult.items.map(mapManagedDeviceToIntuneDevice);
  } catch (err: any) {
    console.error("[Graph Client] Error fetching Intune devices:", err);
    syncErrors.push(`Intune devices: ${err.message || "Unexpected error while processing devices."}`);
  }

  onProgress?.("Intune Endpoint Security policies", 6, TOTAL_SYNC_STEPS);
  // 6. Fetch Intune Endpoint Security policy counts (tenant-wide aggregates,
  // not per-device). Endpoint Security "Intents" is a Graph beta surface -
  // category matching here is best-effort and worth confirming against a
  // real tenant; a failure here doesn't block the device inventory above.
  let antivirusPoliciesCount = 0;
  let edrPoliciesCount = 0;
  // Hoisted so the ASR configuration section below can reuse this same list
  // (it's the "Endpoint Security Templates" intents surface) instead of
  // issuing a second, identical $expand=categories request.
  let intentsItems: any[] = [];
  try {
    const intentsResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/beta/deviceManagement/intents?$expand=categories",
      headers
    );
    if (intentsResult.error) syncErrors.push(`Intune Endpoint Security policies: ${intentsResult.error}`);
    intentsItems = intentsResult.items;
    intentsItems.forEach((intent: any) => {
      const categoryNames: string[] = (intent.categories || []).map((c: any) => (c.displayName || "").toLowerCase());
      if (categoryNames.some((c) => c.includes("antivirus"))) antivirusPoliciesCount++;
      if (categoryNames.some((c) => c.includes("detection and response") || c.includes("edr"))) edrPoliciesCount++;
    });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching Intune Endpoint Security policies:", err);
    syncErrors.push(`Intune Endpoint Security policies: ${err.message || "Unexpected error while processing policies."}`);
  }

  onProgress?.("Attack Surface Reduction rule configuration", 7, TOTAL_SYNC_STEPS);
  // 6b. Fetch real Attack Surface Reduction rule configuration state. Real
  // tenants can configure ASR rules via up to three independent, mergeable
  // Intune surfaces (verified against Microsoft Learn, not guessed) - a
  // partial implementation covering only one would silently under-report
  // for tenants using another, which is exactly the class of bug this
  // section exists to close (see ai-context-vault/Optimization/Optimization
  // Plan.md item 7). All signal collection/merge logic lives in the pure,
  // tested asr-configuration-mapper.ts; this section only walks raw Graph
  // JSON into the flat shapes those functions expect.
  const asrSignals: AsrConfigSignal[] = [];
  let asrConfigFetchSucceeded = false;

  // Surface 1: modern Settings Catalog ("Endpoint security > Attack surface
  // reduction policy"). Microsoft's own docs say most tenants use this
  // format today, making it the highest-value of the three.
  try {
    const catalogPoliciesResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq 'endpointSecurityAttackSurfaceReduction'",
      headers
    );
    if (catalogPoliciesResult.error) {
      syncErrors.push(`ASR Rules (Settings Catalog): ${catalogPoliciesResult.error}`);
    } else {
      asrConfigFetchSucceeded = true;
    }

    if (catalogPoliciesResult.items.length > 0) {
      const slugToRuleId = await getAsrSettingsCatalogSlugMap(headers, syncErrors);

      for (const policy of catalogPoliciesResult.items) {
        const settingsResult = await fetchAllPages<any>(
          `https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('${policy.id}')/settings`,
          headers
        );
        if (settingsResult.error) {
          syncErrors.push(`ASR Rules (Settings Catalog): ${settingsResult.error}`);
          continue;
        }
        const selectedIds = flattenSettingsCatalogSelectedIds(settingsResult.items);
        const policyName = policy.name || policy.displayName || "Attack Surface Reduction Policy";
        asrSignals.push(...mapAsrSettingDefinitionIdsToSignals(selectedIds, policyName, slugToRuleId));
      }
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching ASR Settings Catalog policies:", err);
    syncErrors.push(`ASR Rules (Settings Catalog): ${err.message || "Unexpected error while processing policies."}`);
  }

  // Surface 2: legacy classic Device Configuration profile ("Endpoint
  // protection" profile, windows10EndpointProtectionConfiguration). Simplest
  // to read - each rule is a flat, named top-level property - but only 15 of
  // the 19 catalog rules are expressible in this older schema.
  try {
    const deviceConfigResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations",
      headers
    );
    if (deviceConfigResult.error) {
      syncErrors.push(`ASR Rules (Device Configuration): ${deviceConfigResult.error}`);
    } else {
      asrConfigFetchSucceeded = true;
    }

    deviceConfigResult.items
      .filter((c: any) => c["@odata.type"] === "#microsoft.graph.windows10EndpointProtectionConfiguration")
      .forEach((profile: any) => {
        const properties = Object.keys(LEGACY_ASR_PROPERTY_TO_RULE_ID)
          .filter((propertyName) => profile[propertyName] != null)
          .map((propertyName) => ({ propertyName, rawValue: profile[propertyName] }));
        const profileName = profile.displayName || "Endpoint Protection Profile";
        asrSignals.push(...mapNamedPropertyValuesToSignals(properties, profileName));
      });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching ASR device configuration profiles:", err);
    syncErrors.push(`ASR Rules (Device Configuration): ${err.message || "Unexpected error while processing profiles."}`);
  }

  // Surface 3: older "Endpoint Security Templates" intent-based policies -
  // being phased out in favor of the Settings Catalog but not yet retired.
  // Reuses intentsItems already fetched above instead of a second request,
  // and the exact same category-name-matching convention already
  // established there for antivirus/EDR.
  try {
    const asrIntents = intentsItems.filter((intent: any) => {
      const categoryNames: string[] = (intent.categories || []).map((c: any) => (c.displayName || "").toLowerCase());
      return categoryNames.some((c) => c.includes("attack surface reduction"));
    });

    for (const intent of asrIntents) {
      const definitionValuesResult = await fetchAllPages<any>(
        `https://graph.microsoft.com/beta/deviceManagement/intents('${intent.id}')/definitionValues?$expand=settingInstances`,
        headers
      );
      if (definitionValuesResult.error) {
        syncErrors.push(`ASR Rules (Endpoint Security Templates): ${definitionValuesResult.error}`);
        continue;
      }
      asrConfigFetchSucceeded = true;
      const properties = extractIntentAsrProperties(definitionValuesResult.items);
      const intentName = intent.displayName || "Endpoint Security Template";
      asrSignals.push(...mapNamedPropertyValuesToSignals(properties, intentName));
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching ASR Endpoint Security Template policies:", err);
    syncErrors.push(`ASR Rules (Endpoint Security Templates): ${err.message || "Unexpected error while processing policies."}`);
  }

  // If literally every surface failed, leave asrRules untouched below
  // (preserves last-good data on a transient/permission failure) rather than
  // overwriting it with a confident-looking but empty result.
  const asrRulesLive: AsrRuleState[] | null = asrConfigFetchSucceeded ? mergeAsrRuleStates(asrSignals) : null;

  onProgress?.("Microsoft Secure Score", 8, TOTAL_SYNC_STEPS);
  // 7. Fetch Microsoft Secure Score & control profiles
  let secureScoreData: TenantSecureScore | null = null;
  try {
    const scoresResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/security/secureScores?$top=100",
      headers
    );
    if (scoresResult.error) syncErrors.push(`Secure Score: ${scoresResult.error}`);

    if (scoresResult.items.length > 0) {
      const profilesResult = await fetchAllPages<any>(
        "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$top=999",
        headers
      );
      if (profilesResult.error) syncErrors.push(`Secure Score control profiles: ${profilesResult.error}`);

      const profileMap = new Map<string, any>();
      profilesResult.items.forEach((p: any) => profileMap.set(p.id, p));

      const historyEntries = scoresResult.items.map((s: any) => ({
        createdDateTime: s.createdDateTime,
        currentScore: s.currentScore || 0,
        maxScore: s.maxScore || 0,
      }));

      const latest = [...scoresResult.items].sort(
        (a: any, b: any) => new Date(b.createdDateTime).getTime() - new Date(a.createdDateTime).getTime()
      )[0];

      const controls = (latest.controlScores || []).map((cs: any) =>
        mapSecureScoreControl(cs, profileMap.get(cs.controlName))
      );

      // Company branding isn't a real Microsoft Secure Score control - it's
      // Clarity365's own recommendation, appended after the Microsoft-sourced
      // ones. Best-effort and isolated in its own try: reuses the
      // Organization.Read.All permission already required elsewhere, but if
      // this one call fails for any reason, the rest of Secure Score should
      // still load rather than losing all 70+ real controls over one extra.
      try {
        const brandingResult = await fetchAllPages<any>(
          `https://graph.microsoft.com/v1.0/organization/${tenant.credentials.tenantId}/branding/localizations`,
          headers
        );
        if (!brandingResult.error) {
          controls.push(buildCompanyBrandingControl(brandingResult.items));
        }
      } catch {
        // Bonus control only - omit it from this sync rather than failing
        // the whole Secure Score section over it.
      }

      secureScoreData = {
        currentScore: latest.currentScore || 0,
        maxScore: latest.maxScore || 0,
        percentage: latest.maxScore > 0 ? Math.round((latest.currentScore / latest.maxScore) * 1000) / 10 : 0,
        delta30Days: computeScoreDelta(historyEntries, 30),
        delta90Days: computeScoreDelta(historyEntries, 90),
        industryBenchmark: extractIndustryBenchmark(latest.averageComparativeScores),
        history: buildSecureScoreHistory(historyEntries),
        controls,
      };
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching Secure Score:", err);
    syncErrors.push(`Secure Score: ${err.message || "Unexpected error while processing secure score."}`);
  }

  onProgress?.("Defender for Office 365 policies & TABL", 9, TOTAL_SYNC_STEPS);
  // 8. Fetch MDO Policies & TABL via Exchange Online (see exo-client.ts -
  // Defender for Office 365 policies aren't reachable via standard Graph).
  // Skipped silently (not pushed as a sync error) if Exchange Online hasn't
  // been connected yet, since that's a separate, optional credential from
  // the Graph client secret used everywhere else - its absence isn't a
  // fault, just a not-yet-configured feature. If it IS connected, a fetch
  // failure IS surfaced as a real sync error.
  let mdoPolicies: MdoThreatPolicy[] | null = null;
  let mdoTabl: TablEntry[] | null = null;
  if (exoAvailable) {
    try {
      const { policies, tabl, policyErrors, tablErrors } = await fetchMdoPoliciesAndTabl(tenant, onExoRefreshRotated);
      policyErrors.forEach((e) => syncErrors.push(`MDO Policies: ${e}`));
      tablErrors.forEach((e) => syncErrors.push(`MDO TABL: ${e}`));
      mdoPolicies = policies;
      mdoTabl = tabl;
    } catch (err: any) {
      console.error("[Graph Client] Error fetching MDO policies via Exchange Online:", err);
      syncErrors.push(`MDO Policies: ${err.message || "Unexpected error while processing Exchange Online data."}`);
    }
  }

  onProgress?.("MDO threat detections", 10, TOTAL_SYNC_STEPS);
  // 8.5. Fetch MDO-sourced threat detections via Microsoft Graph's Security
  // Alerts API. Independent of the Exchange Online connection above (this is
  // a plain Graph client-secret call, same as Secure Score/Intune) - useful
  // even for a tenant that hasn't connected EXO at all. Scoped to the last 30
  // days to match the "Threats Detected (30d)" framing in the UI. Exact OData
  // filter syntax/field names below are based on the documented alerts_v2
  // schema - worth confirming against a live tenant, same caveat as
  // mdo-mapper.ts's other Exchange-shape assumptions.
  let mdoAlerts: MdoThreatAlert[] | null = null;
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const filter = `serviceSource eq 'microsoftDefenderForOffice365' and createdDateTime ge ${thirtyDaysAgo}`;
    const alertsResult = await fetchAllPages<any>(
      `https://graph.microsoft.com/v1.0/security/alerts_v2?$filter=${encodeURIComponent(filter)}&$top=999`,
      headers
    );
    if (alertsResult.error) syncErrors.push(`MDO Threat Alerts: ${alertsResult.error}`);
    mdoAlerts = alertsResult.items.map(mapMdoAlert);
  } catch (err: any) {
    console.error("[Graph Client] Error fetching MDO threat alerts:", err);
    syncErrors.push(`MDO Threat Alerts: ${err.message || "Unexpected error while processing threat alerts."}`);
  }

  onProgress?.("Mailbox delegations & forwarding rules", 11, TOTAL_SYNC_STEPS);
  // 8.6. Fetch live mailbox delegations, forwarding rules, and mailbox-audit
  // status via the same Exchange Online connection MDO uses (Module 6/7).
  // Gated the same way as MDO policies above - skipped silently if EXO isn't
  // connected, surfaced as a real sync error (prefixed "Mailflow:") if it is
  // connected but the fetch fails.
  let mailboxesLive: MailboxItem[] | null = null;
  let emailForwardingLive: EmailForwardingRule[] | null = null;
  let transportRulesLive: MailflowTransportRule[] | null = null;
  let connectorsLive: MailflowConnector[] | null = null;
  let remoteDomainAutoForwardBlocked: boolean | null | undefined = undefined;
  let externalSenderTagEnabled: boolean | null | undefined = undefined;
  let mailboxAuditingEnabled: boolean | null | undefined = undefined;
  if (exoAvailable) {
    try {
      const result = await fetchMailflowData(tenant, onExoRefreshRotated);
      result.errors.forEach((e) => syncErrors.push(`Mailflow: ${e}`));
      // Cross-reference the Graph license data already fetched for Module 5
      // (usersList, step 2) rather than making a second call for the same
      // information - Get-Mailbox itself has no license concept.
      const licensedUpns = new Set(
        usersList.filter((u) => u.classification === "licensed").map((u) => u.userPrincipalName.toLowerCase())
      );
      mailboxesLive = result.mailboxes.map((mbx) => ({
        ...mbx,
        hasDirectLicense: licensedUpns.has(mbx.userPrincipalName.toLowerCase()),
      }));
      emailForwardingLive = result.emailForwarding;
      transportRulesLive = result.transportRules;
      connectorsLive = result.connectors;
      remoteDomainAutoForwardBlocked = result.remoteDomainAutoForwardBlocked;
      externalSenderTagEnabled = result.externalSenderTagEnabled;
      mailboxAuditingEnabled = result.mailboxAuditingEnabled;
    } catch (err: any) {
      console.error("[Graph Client] Error fetching mailflow data via Exchange Online:", err);
      syncErrors.push(`Mailflow: ${err.message || "Unexpected error while processing mailbox/forwarding data."}`);
    }
  }

  onProgress?.("Domain authentication (SPF/DKIM/DMARC)", 12, TOTAL_SYNC_STEPS);
  // 8.7. Domain Authentication (SPF/DKIM/DMARC). DKIM comes from the EXO
  // connection above; SPF/DMARC are plain public DNS TXT lookups run for
  // every accepted domain, independent of any Microsoft 365 credential -
  // but the accepted-domain list itself still needs EXO's
  // Get-AcceptedDomain, so this whole step is gated the same way as the
  // rest of Exchange & Mailflow rather than running standalone.
  let domainAuthLive: DomainAuthStatus[] | null = null;
  if (exoAvailable) {
    try {
      const { domains, dkimByDomain, errors: domainErrors } = await fetchAcceptedDomainsAndDkim(tenant, onExoRefreshRotated);
      domainErrors.forEach((e) => syncErrors.push(`Domain Auth: ${e}`));
      domainAuthLive = await Promise.all(
        domains.map(async ({ domain, isDefaultDomain }) => {
          const [spf, dmarc] = await Promise.all([checkSpfRecord(domain), checkDmarcRecord(domain)]);
          return {
            domain,
            isDefaultDomain,
            dkim: dkimByDomain.get(domain) || {
              status: "fail" as const,
              detail: "DKIM has never been configured for this domain.",
              recommendation: "Run Enable-DkimSigningConfig, then publish the two CNAME selector records Exchange provides at your DNS host.",
            },
            spf,
            dmarc,
          };
        })
      );
    } catch (err: any) {
      console.error("[Graph Client] Error checking domain authentication:", err);
      syncErrors.push(`Domain Auth: ${err.message || "Unexpected error while checking SPF/DKIM/DMARC."}`);
    }
  }

  onProgress?.("Groups & distribution lists", 13, TOTAL_SYNC_STEPS);
  // 8.8. Groups & Distribution - pure Graph, independent of the EXO
  // connection above. Exchange has no bulk "every group's owners/members"
  // endpoint any more than it does for mailboxes, so the same N+1-with-a-cap
  // shape from the mailflow mailbox scan applies here: one extra owners +
  // members round trip per group, capped for sync performance.
  let groupsLive: TenantGroup[] | null = null;
  let groupExpirationPolicyEnabled: boolean | undefined;
  let groupSelfServiceCreationRestricted: boolean | undefined;
  let groupNamingPolicyEnabled: boolean | undefined;
  try {
    const groupsResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/groups?$top=999&$select=id,displayName,mailNickname,groupTypes,mailEnabled,securityEnabled,isAssignableToRole,onPremisesSyncEnabled,createdDateTime,membershipRule",
      headers
    );
    if (groupsResult.error) syncErrors.push(`Groups: ${groupsResult.error}`);

    const cappedGroups = groupsResult.items.slice(0, MAX_GROUPS_FOR_MEMBER_SCAN);
    if (groupsResult.items.length > MAX_GROUPS_FOR_MEMBER_SCAN) {
      syncErrors.push(
        `Groups: Owner/member scan capped at the first ${MAX_GROUPS_FOR_MEMBER_SCAN} groups for sync performance - this tenant may have more.`
      );
    }

    groupsLive = await Promise.all(
      cappedGroups.map(async (raw: any) => {
        const [ownersResult, membersResult] = await Promise.all([
          fetchAllPages<any>(`https://graph.microsoft.com/v1.0/groups/${raw.id}/owners?$select=userPrincipalName&$top=100`, headers, 1),
          fetchAllPages<any>(
            `https://graph.microsoft.com/v1.0/groups/${raw.id}/members?$select=userPrincipalName,userType&$top=100`,
            headers,
            1
          ),
        ]);
        const ownerNames = ownersResult.items.map((o: any) => o.userPrincipalName).filter(Boolean);
        return mapGroup(raw, ownerNames, membersResult.items);
      })
    );

    // GET /groupSettings - tenant-wide expiration/self-service-creation/naming
    // policy. A 403 here (missing permission) is common and shouldn't block
    // the rest of the group data above from being used.
    const settingsResult = await fetchAllPages<any>("https://graph.microsoft.com/v1.0/groupSettings", headers);
    if (settingsResult.error) {
      syncErrors.push(`Group Settings: ${settingsResult.error}`);
    } else {
      groupExpirationPolicyEnabled = mapGroupExpirationPolicyEnabled(settingsResult.items);
      groupSelfServiceCreationRestricted = mapGroupSelfServiceCreationRestricted(settingsResult.items);
      groupNamingPolicyEnabled = mapGroupNamingPolicyEnabled(settingsResult.items);
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching groups:", err);
    syncErrors.push(`Groups: ${err.message || "Unexpected error while processing groups."}`);
  }

  onProgress?.("SharePoint & OneDrive storage", 14, TOTAL_SYNC_STEPS);
  // 8.9. SharePoint, OneDrive & Storage - depends on groupsLive (fetched
  // above) to resolve a team site's owner via its linked M365 group. No bulk
  // "every site's storage quota" Graph endpoint exists any more than for
  // groups' owners/members, so the same N+1-with-a-cap shape applies: one
  // extra drive-quota round trip per site, capped for sync performance.
  let sharePointLive: SharePointTenantPolicy | null = null;
  try {
    let tenantSharingLevel: SharePointTenantPolicy["tenantSharingLevel"] = "NewAndExistingGuests";
    let defaultLinkType: SharePointTenantPolicy["defaultLinkType"] = "Internal";
    let anonymousLinkExpirationDays = 0;
    // Security Simulations Stage 5: the rest of the same settings response
    // (resharing, unmanaged sync, domain restrictions, legacy auth, idle
    // sign-out) - no extra call.
    let sharePointSecurity: ReturnType<typeof mapSharePointSecuritySettings> = {};

    const settingsRes = await graphFetch("https://graph.microsoft.com/v1.0/admin/sharepoint/settings", { headers });
    if (settingsRes.ok) {
      const settingsRaw = await settingsRes.json();
      ({ tenantSharingLevel, defaultLinkType, anonymousLinkExpirationDays } = mapTenantSharingSettings(settingsRaw));
      sharePointSecurity = mapSharePointSecuritySettings(settingsRaw);
    } else {
      syncErrors.push(`SharePoint Settings: HTTP ${settingsRes.status} while reading tenant sharing settings.`);
    }

    const sitesResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/sites?search=*&$select=id,displayName,name,webUrl,createdDateTime,lastModifiedDateTime,sharepointIds",
      headers
    );
    if (sitesResult.error) syncErrors.push(`SharePoint Sites: ${sitesResult.error}`);

    const cappedSites = sitesResult.items.slice(0, MAX_SITES_FOR_STORAGE_SCAN);
    if (sitesResult.items.length > MAX_SITES_FOR_STORAGE_SCAN) {
      syncErrors.push(
        `SharePoint Sites: Storage scan capped at the first ${MAX_SITES_FOR_STORAGE_SCAN} sites for sync performance - this tenant may have more.`
      );
    }

    const groupsById = new Map<string, TenantGroup>((groupsLive || []).map((g) => [g.id, g]));

    const sites = await Promise.all(
      cappedSites.map(async (raw: any) => {
        const driveRes = await graphFetch(`https://graph.microsoft.com/v1.0/sites/${raw.id}/drive?$select=quota`, { headers }, { maxRetries: 1 });
        const driveQuota = driveRes.ok ? (await driveRes.json())?.quota : undefined;
        return mapSharePointSite(raw, driveQuota, tenantSharingLevel, groupsById);
      })
    );

    const totalStorageUsedTB = sites.reduce((sum, s) => sum + s.storageUsedGB, 0) / 1024;
    const totalStorageAllocatedTB = sites.reduce((sum, s) => sum + s.storageAllocatedGB, 0) / 1024;

    sharePointLive = {
      tenantSharingLevel,
      defaultLinkType,
      anonymousLinkExpirationDays,
      ...sharePointSecurity,
      totalStorageAllocatedTB,
      totalStorageUsedTB,
      sites,
    };
  } catch (err: any) {
    console.error("[Graph Client] Error fetching SharePoint data:", err);
    syncErrors.push(`SharePoint: ${err.message || "Unexpected error while processing SharePoint sites."}`);
  }

  onProgress?.("App registrations & enterprise applications", 15, TOTAL_SYNC_STEPS);
  // 8.95. Fetch App Registrations & Enterprise Applications (Module 9)
  let appRegistrationsLive: AppRegistrationItem[] | null = null;
  let secretExpiry: SecretExpiry | undefined;
  try {
    const appsResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/applications?$top=999&$select=id,appId,displayName,publisherDomain,createdDateTime,keyCredentials,passwordCredentials,requiredResourceAccess,signInAudience",
      headers
    );
    if (appsResult.error) {
      syncErrors.push(`App Registrations: ${appsResult.error}`);
    } else {
      appRegistrationsLive = appsResult.items.map(mapAppRegistration);
      // Clarity365's own app is in this list: note when the secret it signs
      // in with expires, so the UI can warn before every module stops.
      const ownApp = appsResult.items.find((a: any) => a?.appId && a.appId === tenant.credentials.clientId);
      secretExpiry = resolveOwnAppSecretExpiry(ownApp, tenant.credentials.clientSecret);
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching app registrations:", err);
    syncErrors.push(`App Registrations: ${err.message || "Unexpected error while processing applications."}`);
  }

  onProgress?.("Subscribed SKUs & license capabilities", 16, TOTAL_SYNC_STEPS);
  // 8.96. Fetch Subscribed SKUs & detect Tenant Capabilities / Licenses
  let capabilitiesLive: TenantCapability[] | null = null;
  let licenseSkusLive: TenantLicenseSku[] | null = null;
  const skuIdToPartNumber = new Map<string, string>();
  try {
    const skusResult = await fetchAllPages<any>("https://graph.microsoft.com/v1.0/subscribedSkus", headers);
    if (skusResult.error) {
      syncErrors.push(`Tenant Licenses (SubscribedSkus): ${skusResult.error}`);
    } else if (skusResult.items.length > 0) {
      capabilitiesLive = mapSubscribedSkusToCapabilities(skusResult.items);
      licenseSkusLive = skusResult.items.map((s: any) => {
        const consumedUnits = s.consumedUnits || 0;
        const enabledUnits = s.prepaidUnits?.enabled || 0;
        return {
          skuId: s.skuId,
          skuPartNumber: s.skuPartNumber,
          consumedUnits,
          enabledUnits,
          availableUnits: Math.max(0, enabledUnits - consumedUnits),
        };
      });
      skusResult.items.forEach((s: any) => {
        if (s.skuId && s.skuPartNumber) skuIdToPartNumber.set(s.skuId, s.skuPartNumber);
      });
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching subscribed SKUs:", err);
    syncErrors.push(`Tenant Licenses: ${err.message || "Unexpected error while processing subscribed SKUs."}`);
  }

  // Resolve per-user assignedLicenses skuId GUIDs (fetched in step 2 above, before this
  // tenant-wide SKU list was available) into human-readable skuPartNumber tokens, e.g.
  // "SPE_E5" - required for any per-user license-name matching (see admin-hygiene-matcher.ts).
  if (skuIdToPartNumber.size > 0 && usersList.length > 0) {
    usersList = usersList.map((u) => ({
      ...u,
      licenses: u.licenses.map((skuId) => skuIdToPartNumber.get(skuId) || skuId),
    }));
  }

  onProgress?.("Microsoft Defender XDR incidents", 17, TOTAL_SYNC_STEPS);
  // 8.97. Fetch Microsoft Defender XDR Incidents (Module 8.6: SOC & Event Response)
  let incidentsLive: SecurityIncidentItem[] | null = null;
  try {
    const incidentsResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/security/incidents?$top=50&$expand=alerts",
      headers
    );
    if (incidentsResult.error) {
      syncErrors.push(`Security Incidents: ${incidentsResult.error}`);
    } else if (incidentsResult.items.length > 0) {
      incidentsLive = incidentsResult.items.map(mapSecurityIncident);
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching security incidents:", err);
    syncErrors.push(`Security Incidents: ${err.message || "Unexpected error while processing incidents."}`);
  }

  // Fallback: If tenant doesn't have Defender XDR incidents, synthesize from MDO alerts
  if (!incidentsLive && mdoAlerts && mdoAlerts.length > 0) {
    incidentsLive = synthesizeIncidentsFromMdoAlerts(mdoAlerts);
  }

  onProgress?.("Microsoft Defender for Endpoint connector settings", 18, TOTAL_SYNC_STEPS);
  // 8.98. Fetch the MDE connector's own configuration (the "Defender and MEM
  // Reporting" settings blade) - deviceManagement/mobileThreatDefenseConnectors,
  // v1.0 fields plus beta-only additions (macOS, Windows MAM, iOS cert sync -
  // see MdeConnectorSettings). Beta throughout for one consistent shape rather
  // than a v1.0 call plus a second beta call for the extra fields. A tenant
  // that has never configured this connector at all returns an empty array,
  // not an error - left undefined in that case rather than a fake object.
  let mdeConnectorSettings: MdeConnectorSettings | undefined;
  try {
    const connectorResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors",
      headers
    );
    if (connectorResult.error) {
      syncErrors.push(`MDE connector settings: ${connectorResult.error}`);
    } else if (connectorResult.items.length > 0) {
      mdeConnectorSettings = mapMdeConnectorSettings(connectorResult.items[0]);
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching MDE connector settings:", err);
    syncErrors.push(`MDE connector settings: ${err.message || "Unexpected error while processing connector settings."}`);
  }

  onProgress?.("Microsoft Defender for Endpoint onboarding status", 19, TOTAL_SYNC_STEPS);
  // 8.99. Fetch per-device MDE onboarding status - the real Defender
  // telemetry intune-mapper.ts's own comment says would be needed to
  // replace the compliance-state-derived edrOnboardingState approximation
  // (see applyRealEdrOnboardingStates, applied to intuneDevices below).
  let atpOnboardingStates: AtpOnboardingDeviceState[] = [];
  try {
    const onboardingResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/beta/deviceManagement/advancedThreatProtectionOnboardingStateSummary/advancedThreatProtectionOnboardingDeviceSettingStates",
      headers
    );
    if (onboardingResult.error) {
      syncErrors.push(`MDE onboarding status: ${onboardingResult.error}`);
    } else {
      atpOnboardingStates = onboardingResult.items.map(mapAtpOnboardingDeviceState);
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching MDE onboarding status:", err);
    syncErrors.push(`MDE onboarding status: ${err.message || "Unexpected error while processing onboarding status."}`);
  }

  if (atpOnboardingStates.length > 0) {
    intuneDevices = applyRealEdrOnboardingStates(intuneDevices, atpOnboardingStates);
  }

  onProgress?.("Intune device compliance reasons", 20, TOTAL_SYNC_STEPS);
  // 8.995. Fetch per-setting compliance breakdown -
  // deviceCompliancePolicySettingStateSummaries is a fleet-wide (not
  // per-device) v1.0 Graph resource, confirmed not deprecated: one row per
  // distinct setting actually checked by an assigned compliance policy
  // (e.g. "Require BitLocker", "Require Threat scan" i.e. Defender
  // Antimalware, "Minimum OS version"), each with its own nested
  // deviceComplianceSettingStates collection listing exactly which devices
  // fail it and why - see
  // ai-context-vault/Optimization/Intune Non-Compliance Reasons Plan.md.
  // Same DeviceManagementConfiguration.Read.All permission already required
  // for the managedDevices fetch above - no new consent needed. Bounded by
  // the number of distinct settings a tenant's compliance policies actually
  // check (realistically single digits to ~20), not by device count, so
  // this stays a small, fleet-wide fetch rather than an expensive
  // per-device drill-down.
  try {
    const summariesResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicySettingStateSummaries?$top=999",
      headers
    );
    if (summariesResult.error) {
      syncErrors.push(`Intune compliance setting summaries: ${summariesResult.error}`);
    } else {
      const reasonRows: { deviceName: string; reason: DeviceComplianceReason }[] = [];
      for (const summary of summariesResult.items) {
        if (!summary?.id) continue;
        const statesResult = await fetchAllPages<any>(
          `https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicySettingStateSummaries/${summary.id}/deviceComplianceSettingStates?$top=999`,
          headers
        );
        if (statesResult.error) {
          syncErrors.push(`Intune compliance setting states (${summary.settingName || summary.id}): ${statesResult.error}`);
          continue;
        }
        for (const raw of statesResult.items) {
          const mapped = mapDeviceComplianceSettingStateRow(raw);
          if (mapped) reasonRows.push(mapped);
        }
      }
      if (reasonRows.length > 0) {
        intuneDevices = applyDeviceComplianceReasons(intuneDevices, reasonRows);
      }
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching Intune compliance setting states:", err);
    syncErrors.push(`Intune compliance setting states: ${err.message || "Unexpected error while processing compliance reasons."}`);
  }

  onProgress?.("Conditional Access named locations & session controls", 21, TOTAL_SYNC_STEPS);
  // 8.996. Security Simulations Stage 1 (see ai-context-vault/Optimization/
  // Security Simulations Plan.md). Named locations resolve the location
  // GUIDs on each CA policy into countries / IP ranges - without them no
  // "sign-in from a foreign country" question can be answered. Same
  // Policy.Read.All permission the CA policy fetch already uses.
  let namedLocationsLive: CaNamedLocation[] | null = null;
  try {
    const locResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations",
      headers
    );
    if (locResult.error) {
      syncErrors.push(`Named locations: ${locResult.error}`);
    } else {
      namedLocationsLive = locResult.items.map(mapNamedLocation).filter((l): l is CaNamedLocation => l !== null);
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching named locations:", err);
    syncErrors.push(`Named locations: ${err.message || "Unexpected error while processing named locations."}`);
  }

  // Token protection (secureSignInSession) and continuous access evaluation
  // exist only on the beta endpoint - confirmed against Microsoft Learn
  // 2026-09-29, v1.0's sessionControls has neither. Best-effort and
  // deliberately NOT reported as a sync error: the v1.0 policy list above is
  // authoritative, and a failure here just leaves both fields undefined
  // ("not assessed"), never false.
  if (livePolicies.length > 0) {
    try {
      const betaResult = await fetchAllPages<any>(
        "https://graph.microsoft.com/beta/identity/conditionalAccess/policies?$select=id,sessionControls",
        headers
      );
      if (!betaResult.error) {
        const extrasById = new Map<string, Pick<CaSessionControls, "tokenProtection" | "continuousAccessEvaluation">>();
        for (const item of betaResult.items) {
          if (item?.id) extrasById.set(item.id, mapCaBetaSessionExtras(item));
        }
        livePolicies = applyCaBetaSessionExtras(livePolicies, extrasById);
      }
    } catch (err: any) {
      console.warn("[Graph Client] Beta CA session-control read failed (non-fatal):", err?.message || err);
    }
  }

  onProgress?.("Tenant identity settings (security defaults, consent, guests)", 22, TOTAL_SYNC_STEPS);
  // 8.997. Three single-object policy reads (all Policy.Read.All, already
  // held). Each is independent - one failing leaves only its own fields
  // undefined in mapTenantIdentitySettings, never the others.
  let identitySettingsLive: TenantIdentitySettings | null = null;
  {
    const readPolicy = async (url: string, label: string): Promise<any | undefined> => {
      try {
        const res = await graphFetch(url, { headers });
        if (!res.ok) {
          syncErrors.push(`${label}: HTTP ${res.status}`);
          return undefined;
        }
        return await res.json();
      } catch (err: any) {
        console.error(`[Graph Client] Error fetching ${label}:`, err);
        syncErrors.push(`${label}: ${err.message || "Unexpected error."}`);
        return undefined;
      }
    };
    const [securityDefaults, authorizationPolicy, adminConsentPolicy] = await Promise.all([
      readPolicy("https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", "Security defaults"),
      readPolicy("https://graph.microsoft.com/v1.0/policies/authorizationPolicy", "Authorization policy"),
      readPolicy("https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy", "Admin consent workflow"),
    ]);
    if (securityDefaults || authorizationPolicy || adminConsentPolicy) {
      identitySettingsLive = mapTenantIdentitySettings(securityDefaults, authorizationPolicy, adminConsentPolicy);
    }
  }

  onProgress?.("Exchange audit & legacy protocol settings", 23, TOTAL_SYNC_STEPS);
  // 8.998. Security Simulations Stage 5 - unified audit log ingestion, the
  // org-wide SMTP AUTH switch, and per-mailbox POP/IMAP/ActiveSync/SMTP
  // AUTH. Only when Exchange is connected; otherwise left undefined ("not
  // assessed"), never false.
  let exchangeSecurityLive: ExchangeSecuritySettings | null = null;
  if (exoAvailable) {
    try {
      const { settings, errors } = await fetchExchangeSecuritySettings(tenant, onExoRefreshRotated);
      errors.forEach((e) => syncErrors.push(`Exchange security settings: ${e}`));
      exchangeSecurityLive = settings;
    } catch (err: any) {
      console.error("[Graph Client] Error fetching Exchange security settings:", err);
      syncErrors.push(`Exchange security settings: ${err.message || "Unexpected error."}`);
    }
  }

  onProgress?.("Privileged role assignments (PIM)", 24, TOTAL_SYNC_STEPS);
  // 8.999. Directory role assignments with their PIM state. PIM's schedule
  // instances need Entra ID P2; without it the call fails and the plain
  // roleAssignments list (active only, no schedule) is used instead, and
  // labelled as such. RoleManagement.Read.Directory covers both.
  let privilegedRolesLive: PrivilegedRoleAssignments | null = null;
  try {
    // No $expand=principal on the PIM calls: the first live sync (2026-09-30)
    // fell back to the non-PIM list on every tenant, P2 or not, and the
    // expansion was the likeliest cause. Principals are resolved below from
    // the users and groups this sync already fetched.
    const [eligible, active] = await Promise.all([
      fetchAllPages<any>("https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances", headers),
      fetchAllPages<any>("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances", headers),
    ]);
    if (!eligible.error && !active.error) {
      privilegedRolesLive = { source: "pim", assignments: mapPimAssignments(eligible.items, active.items) };
    } else {
      const pimUnavailableReason = eligible.error || active.error;
      const fallback = await fetchAllPages<any>("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal", headers);
      if (fallback.error) {
        syncErrors.push(`Privileged role assignments: ${fallback.error}`);
      } else {
        privilegedRolesLive = { source: "roleAssignments", assignments: mapRoleAssignmentsFallback(fallback.items), pimUnavailableReason };
      }
    }
    // Fill in principals the API didn't expand, from data already fetched.
    if (privilegedRolesLive) {
      const usersById = new Map(usersList.map((u) => [u.id, u]));
      const groupsById = new Map((groupsLive || []).map((g) => [g.id, g]));
      privilegedRolesLive.assignments = privilegedRolesLive.assignments.map((a) => {
        if (a.principalType !== "unknown") return a;
        const user = usersById.get(a.principalId);
        if (user) return { ...a, principalType: "user", principalDisplayName: user.displayName, principalUserPrincipalName: user.userPrincipalName };
        const group = groupsById.get(a.principalId);
        if (group) return { ...a, principalType: "group", principalDisplayName: group.displayName };
        return a;
      });
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching privileged role assignments:", err);
    syncErrors.push(`Privileged role assignments: ${err.message || "Unexpected error."}`);
  }

  onProgress?.("OAuth consent grants", 25, TOTAL_SYNC_STEPS);
  // 8.9995. Delegated permission grants: which apps users (or admins) have
  // consented to, and with which scopes. Needs Directory.Read.All (or
  // DelegatedPermissionGrant.Read.All); a tenant that granted only
  // Organization.Read.All gets an error here and the data stays "not
  // assessed". Capped at 20 pages; app details resolved for up to 60 apps.
  let oauthGrantsLive: OAuthConsentGrantSummary | null = null;
  try {
    const OAUTH_GRANT_PAGE_CAP = 20;
    const grantsResult = await fetchAllPages<any>("https://graph.microsoft.com/v1.0/oauth2PermissionGrants", headers, OAUTH_GRANT_PAGE_CAP);
    if (grantsResult.error && grantsResult.items.length === 0) {
      // A missing optional permission isn't a sync failure - record it on the
      // data (so the scenario says exactly what to grant) instead of marking
      // the tenant degraded. Anything else is a real error.
      const missingPermission = /insufficient privileges|authorization_requestdenied|forbidden|403/i.test(grantsResult.error);
      oauthGrantsLive = { grants: [], truncated: false, unavailable: missingPermission ? "missingPermission" : "error", unavailableDetail: grantsResult.error };
      if (!missingPermission) syncErrors.push(`OAuth consent grants: ${grantsResult.error}`);
    } else {
      const clientIds = [...new Set(grantsResult.items.map((g: any) => g.clientId).filter(Boolean))].slice(0, 60) as string[];
      const servicePrincipals = new Map<string, ServicePrincipalInfo>();
      await Promise.all(
        clientIds.map(async (id) => {
          const res = await graphFetch(
            `https://graph.microsoft.com/v1.0/servicePrincipals/${id}?$select=id,displayName,publisherName,verifiedPublisher,appOwnerOrganizationId`,
            { headers },
            { maxRetries: 1 }
          );
          if (res.ok) servicePrincipals.set(id, await res.json());
        })
      );
      oauthGrantsLive = {
        grants: aggregateOAuthGrants(grantsResult.items, servicePrincipals),
        truncated: !!grantsResult.error,
      };
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching OAuth consent grants:", err);
    syncErrors.push(`OAuth consent grants: ${err.message || "Unexpected error."}`);
  }

  onProgress?.("Alert policies", 26, TOTAL_SYNC_STEPS);
  // 8.9996. Microsoft 365 alert policies, for the Security Scenarios "someone
  // is alerted if ..." checks. Read through Security & Compliance PowerShell
  // as the app itself (scc-client.ts) - same setup as Exchange app-only
  // access. Never a sync error: a tenant without that setup, or a routing
  // change on Microsoft's side, is recorded on the data as "couldn't be
  // read" and the checks say so.
  let alertPoliciesLive: AlertPolicyInventory | null = null;
  try {
    alertPoliciesLive = await fetchAlertPolicyInventory(tenant, headers);
  } catch (err: any) {
    console.error("[Graph Client] Error fetching alert policies:", err);
  }

  // 9. Compute baseline coverage
  const deployedBaselineCodes = new Set(livePolicies.map((p) => p.baselineCode).filter(Boolean));
  const coveragePercent = computeBaselineCoveragePercent(deployedBaselineCodes.size, CA_BASELINE_STANDARDS.length);

  // Missing-permission refusals are resolved against what the token actually
  // carries: a required permission becomes one plain "grant X" line, a
  // declined optional one isn't an error at all (see sync-permission-errors.ts).
  const resolvedErrors = resolveSyncErrors(syncErrors, decodeAppRolesFromToken(token));
  const syncHealth: SyncHealth = {
    isPartial: resolvedErrors.errors.length > 0,
    errors: resolvedErrors.errors,
    missingPermissions: resolvedErrors.missingPermissions,
    lastAttemptAt: new Date().toISOString(),
  };

  // 10. Build or update snapshot. The fields below are all overwritten immediately
  // after with the data just fetched - createBlankSnapshot only needs to supply a
  // structurally valid starting point for a tenant's first-ever sync.
  const base = existingSnapshot || createBlankSnapshot(tenant);

  base.tenant = {
    ...tenant,
    // secretExpiry: refreshed when this sync could read it, otherwise the last known value stays.
    credentials: secretExpiry ? { ...exoCredentials, secretExpiry } : exoCredentials,
    lastSyncTimestamp: new Date().toISOString(),
    connectionStatus: syncHealth.isPartial ? "degraded" : "healthy",
  };
  base.syncHealth = syncHealth;
  base.syncSchemaVersion = SNAPSHOT_SYNC_SCHEMA_VERSION;
  base.conditionalAccess = {
    baselineCoverageScore: coveragePercent,
    baselineDefinitions: CA_BASELINE_STANDARDS,
    policies: livePolicies.length > 0 ? livePolicies : base.conditionalAccess.policies,
    namedLocations: namedLocationsLive !== null ? namedLocationsLive : base.conditionalAccess.namedLocations,
  };
  if (identitySettingsLive !== null) {
    base.identitySettings = identitySettingsLive;
  }
  if (exchangeSecurityLive !== null) {
    base.exchangeSecurity = exchangeSecurityLive;
  }
  if (privilegedRolesLive !== null) {
    base.privilegedRoleAssignments = privilegedRolesLive;
  }
  if (oauthGrantsLive !== null) {
    base.oauthConsentGrants = oauthGrantsLive;
  }
  if (alertPoliciesLive !== null) {
    base.alertPolicies = alertPoliciesLive;
  }

  if (mfaProfilesList.length > 0) {
    base.mfaAudit = mfaProfilesList;
  }

  if (signInsList.length > 0) {
    base.signIns = signInsList;
    // Kept in step with the list it describes: when nothing new was loaded
    // the previous sign-ins (and their coverage) stay.
    base.signInCoverage = signInCoverage;
  }

  if (usersList.length > 0) {
    base.accountClassification = {
      totalAccounts: usersList.length,
      licensedUsersCount: usersList.filter((u) => u.classification === "licensed").length,
      unlicensedActiveCount: usersList.filter((u) => u.classification === "unlicensed_active").length,
      disabledAccountsCount: usersList.filter((u) => u.classification === "disabled").length,
      guestAccountsCount: usersList.filter((u) => u.classification === "guest").length,
      users: usersList,
    };
  }

  if (intuneDevices.length > 0) {
    const compliantCount = intuneDevices.filter((d) => d.complianceState === "compliant").length;
    base.intune = {
      totalDevices: intuneDevices.length,
      compliantDevices: compliantCount,
      nonCompliantDevices: intuneDevices.length - compliantCount,
      antivirusPoliciesCount,
      edrPoliciesCount,
      devices: intuneDevices,
      mdeConnectorSettings: mdeConnectorSettings || base.intune?.mdeConnectorSettings,
      onboardingStates: atpOnboardingStates.length > 0 ? atpOnboardingStates : base.intune?.onboardingStates,
    };
  }

  // Only overwrite when at least one of the three surfaces succeeded -
  // preserves the last-good result on a transient/permission failure rather
  // than replacing it with a confident-looking but empty one.
  if (asrRulesLive !== null) {
    base.asrRules = asrRulesLive;
  }

  if (secureScoreData) {
    base.secureScore = secureScoreData;
  }

  if (capabilitiesLive !== null) {
    base.capabilities = capabilitiesLive;
  }

  if (licenseSkusLive !== null) {
    base.licenseSkus = licenseSkusLive;
  }

  if (appRegistrationsLive !== null) {
    base.appRegistrations = appRegistrationsLive;
  }

  if (incidentsLive !== null) {
    base.incidents = incidentsLive;
  } else if (!base.incidents) {
    base.incidents = [];
  }

  // Each of the three mdoThreat fields comes from an independent source (EXO
  // for policies/tabl, Graph Security Alerts for alerts) and falls back to
  // whatever the previous snapshot had whenever this sync's fetch for that
  // field specifically didn't run or didn't return data.
  if (mailboxesLive !== null) {
    base.mailboxes = mailboxesLive;
  }
  if (emailForwardingLive !== null) {
    base.emailForwarding = emailForwardingLive;
  }
  if (transportRulesLive !== null) {
    base.mailflowTransportRules = transportRulesLive;
  }
  if (connectorsLive !== null) {
    base.mailflowConnectors = connectorsLive;
  }
  if (remoteDomainAutoForwardBlocked !== undefined && remoteDomainAutoForwardBlocked !== null) {
    base.remoteDomainAutoForwardBlocked = remoteDomainAutoForwardBlocked;
  }
  if (externalSenderTagEnabled !== undefined && externalSenderTagEnabled !== null) {
    base.externalSenderTagEnabled = externalSenderTagEnabled;
  }
  if (domainAuthLive !== null) {
    base.domainAuth = domainAuthLive;
  }
  if (groupsLive !== null) {
    base.groups = groupsLive;
  }
  if (groupExpirationPolicyEnabled !== undefined) {
    base.groupExpirationPolicyEnabled = groupExpirationPolicyEnabled;
  }
  if (groupSelfServiceCreationRestricted !== undefined) {
    base.groupSelfServiceCreationRestricted = groupSelfServiceCreationRestricted;
  }
  if (groupNamingPolicyEnabled !== undefined) {
    base.groupNamingPolicyEnabled = groupNamingPolicyEnabled;
  }
  if (sharePointLive !== null) {
    base.sharePoint = sharePointLive;
  }
  // Distinguish "never synced" (leave whatever the snapshot already had,
  // including undefined) from "synced but the Get-OrganizationConfig call
  // itself failed" (null - treated the same as never synced, since there's
  // nothing new to show) from an actual true/false result.
  if (mailboxAuditingEnabled !== undefined && mailboxAuditingEnabled !== null) {
    base.mailboxAuditingEnabled = mailboxAuditingEnabled;
  }

  base.mdoThreat = {
    policies: mdoPolicies !== null ? mdoPolicies : base.mdoThreat.policies,
    // A successful live fetch replaces the synced portion of the list, but
    // preserves any entry added locally while writes were disabled (or
    // before EXO was connected) - those never exist in the real Tenant
    // Allow/Block List, so a Get-TenantAllowBlockListItems fetch can never
    // return them, and replacing wholesale would silently delete them.
    // See tenant-store.addTablEntry, which is what sets isLocalOnly.
    tabl: mdoTabl !== null ? [...base.mdoThreat.tabl.filter((e) => e.isLocalOnly), ...mdoTabl] : base.mdoThreat.tabl,
    alerts: mdoAlerts !== null ? mdoAlerts : base.mdoThreat.alerts,
  };

  // Compute High Risk Threat Indicators from freshly aggregated data
  const unprotectedAdmins = (base.mfaAudit || []).filter(
    (u) => u.isAdmin && (u.isWeakAuth || !u.mfaRegistered)
  ).length;
  const highRiskApps = (base.appRegistrations || []).filter(
    (a) => a.riskCategory === "critical" || a.riskCategory === "high"
  ).length;

  base.highRiskThreatIndicators = {
    unprotectedAdminsCount: unprotectedAdmins,
    highRiskAppRegistrationsCount: highRiskApps,
  };

  return { snapshot: base };
}
