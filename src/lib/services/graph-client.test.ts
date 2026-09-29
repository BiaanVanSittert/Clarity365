import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  buildDefenderAvSettingsPayload,
  buildIntuneAssignmentTarget,
  buildAsrRuleSettingsChildren,
  classifyAdvancedHuntingError,
  buildEdrPolicySettingsPayload,
  cleanIntuneConfigV2Error,
  decodeAppRolesFromToken,
  describeTransientTokenLifetimeError,
  isPermissionGrantedByRoles,
  fetchEdrPolicy,
  deployEdrPolicy,
  buildBitLockerSettingsPayload,
  fetchBitLockerPolicy,
  deployBitLockerPolicy,
  invalidateGraphTokenCache,
  hasLifetimeValidationError,
  mapConditionalAccessPolicy,
} from "./graph-client";
import { RECOMMENDED_BITLOCKER_POLICY } from "@/lib/types";
import type { Tenant } from "@/lib/types";

function fakeTenant(overrides: Partial<Tenant["credentials"]> = {}): Tenant {
  return {
    id: "tenant-test",
    displayName: "Test Tenant",
    defaultDomainName: "test.onmicrosoft.com",
    organizationId: "org-test",
    primaryContact: "admin@test.onmicrosoft.com",
    tier: "M365_E5",
    createdDate: new Date().toISOString(),
    lastSyncTimestamp: new Date().toISOString(),
    connectionStatus: "healthy",
    credentials: {
      authMode: "secret",
      tenantId: "tid-lifetime-test",
      clientId: "cid-lifetime-test",
      clientSecret: "shh",
      ...overrides,
    },
  } as Tenant;
}

function fakeJwt(payload: object): string {
  const base64url = (obj: object) =>
    Buffer.from(JSON.stringify(obj)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${base64url({ alg: "RS256", typ: "JWT" })}.${base64url(payload)}.fake-signature`;
}

describe("buildDefenderAvSettingsPayload", () => {
  it("emits a choice setting with a _1 suffix for a true value", () => {
    const settings = buildDefenderAvSettingsPayload({ allowArchiveScanning: true });
    expect(settings).toHaveLength(1);
    expect(settings[0].settingInstance.settingDefinitionId).toBe(
      "device_vendor_msft_policy_config_defender_allowarchivescanning"
    );
    expect(settings[0].settingInstance.choiceSettingValue.value).toBe(
      "device_vendor_msft_policy_config_defender_allowarchivescanning_1"
    );
  });

  it("emits a choice setting with a _0 suffix for a false value", () => {
    const settings = buildDefenderAvSettingsPayload({ allowRealtimeMonitoring: false });
    expect(settings[0].settingInstance.choiceSettingValue.value).toBe(
      "device_vendor_msft_policy_config_defender_allowrealtimemonitoring_0"
    );
  });

  it("skips fields the caller never set, so a partial config never resets unrelated settings", () => {
    const settings = buildDefenderAvSettingsPayload({ allowArchiveScanning: true, allowBehaviorMonitoring: undefined });
    expect(settings).toHaveLength(1);
  });

  it("builds one entry per set field, in no particular guaranteed order", () => {
    const settings = buildDefenderAvSettingsPayload({
      allowArchiveScanning: true,
      allowEmailScanning: false,
      allowUserUIAccess: true,
    });
    const ids = settings.map((s) => s.settingInstance.settingDefinitionId).sort();
    expect(ids).toEqual(
      [
        "device_vendor_msft_policy_config_defender_allowarchivescanning",
        "device_vendor_msft_policy_config_defender_allowemailscanning",
        "device_vendor_msft_policy_config_defender_allowuseruiaccess",
      ].sort()
    );
  });

  // Regression tests for two ids a live catalog lookup found wrong, and one
  // field (allowCloudProtection) that was missing entirely - see
  // DEFENDER_AV_SETTING_DEFINITION_IDS' comment in graph-client.ts.
  it("uses the confirmed id for allowFullScanOnRemovableDrives (no 'on' before 'removable')", () => {
    const settings = buildDefenderAvSettingsPayload({ allowFullScanOnRemovableDrives: true });
    expect(settings[0].settingInstance.settingDefinitionId).toBe(
      "device_vendor_msft_policy_config_defender_allowfullscanremovabledrivescanning"
    );
  });

  it("uses the confirmed id for allowUpdatesOnMeteredNetwork (a different CSP root entirely)", () => {
    const settings = buildDefenderAvSettingsPayload({ allowUpdatesOnMeteredNetwork: true });
    expect(settings[0].settingInstance.settingDefinitionId).toBe(
      "device_vendor_msft_defender_configuration_meteredconnectionupdates"
    );
  });

  it("supports allowCloudProtection", () => {
    const settings = buildDefenderAvSettingsPayload({ allowCloudProtection: true });
    expect(settings[0].settingInstance.settingDefinitionId).toBe(
      "device_vendor_msft_policy_config_defender_allowcloudprotection"
    );
    expect(settings[0].settingInstance.choiceSettingValue.value).toBe(
      "device_vendor_msft_policy_config_defender_allowcloudprotection_1"
    );
  });
});

describe("buildEdrPolicySettingsPayload", () => {
  it("emits the confirmed 'AutoFromConnector' choice value when enabled", () => {
    const settings = buildEdrPolicySettingsPayload({ autoFromConnector: true });
    expect(settings).toHaveLength(1);
    expect(settings[0].settingInstance.settingDefinitionId).toBe(
      "device_vendor_msft_windowsadvancedthreatprotection_configurationtype"
    );
    expect(settings[0].settingInstance.choiceSettingValue.value).toBe(
      "device_vendor_msft_windowsadvancedthreatprotection_configurationtype_autofromconnector"
    );
  });

  // Regression test for a real live deploy failure: Graph rejected
  // "AutoFromConnector" alone with "doesnt contain required dependent
  // settings" until this child was added.
  it("includes the required onboarding_fromconnector dependent child setting", () => {
    const settings = buildEdrPolicySettingsPayload({ autoFromConnector: true });
    const children = settings[0].settingInstance.choiceSettingValue.children;
    expect(children).toHaveLength(1);
    expect(children[0].settingDefinitionId).toBe(
      "device_vendor_msft_windowsadvancedthreatprotection_onboarding_fromconnector"
    );
    expect(children[0].simpleSettingValue.valueState).toBe("notEncrypted");
    expect(typeof children[0].simpleSettingValue.value).toBe("string");
    expect(children[0].simpleSettingValue.value.length).toBeGreaterThan(0);
  });

  it("emits nothing for autoFromConnector when false or unset - there's no clean 'off' choice value", () => {
    expect(buildEdrPolicySettingsPayload({ autoFromConnector: false })).toHaveLength(0);
    expect(buildEdrPolicySettingsPayload({})).toHaveLength(0);
  });

  it("emits the confirmed 0/1 integer choice values for sampleSharingAll", () => {
    const enabled = buildEdrPolicySettingsPayload({ sampleSharingAll: true });
    const disabled = buildEdrPolicySettingsPayload({ sampleSharingAll: false });
    expect(enabled[0].settingInstance.choiceSettingValue.value).toBe(
      "device_vendor_msft_windowsadvancedthreatprotection_configuration_samplesharing_1"
    );
    expect(disabled[0].settingInstance.choiceSettingValue.value).toBe(
      "device_vendor_msft_windowsadvancedthreatprotection_configuration_samplesharing_0"
    );
  });

  it("can combine both settings in one payload", () => {
    const settings = buildEdrPolicySettingsPayload({ autoFromConnector: true, sampleSharingAll: true });
    expect(settings).toHaveLength(2);
  });
});

describe("buildBitLockerSettingsPayload", () => {
  it("emits the confirmed 0/1 choice values for each boolean setting", () => {
    const enabled = buildBitLockerSettingsPayload({ requireDeviceEncryption: true });
    expect(enabled[0].settingInstance.settingDefinitionId).toBe("device_vendor_msft_bitlocker_requiredeviceencryption");
    expect(enabled[0].settingInstance.choiceSettingValue.value).toBe(
      "device_vendor_msft_bitlocker_requiredeviceencryption_1"
    );

    const disabled = buildBitLockerSettingsPayload({ allowWarningForOtherDiskEncryption: false });
    expect(disabled[0].settingInstance.choiceSettingValue.value).toBe(
      "device_vendor_msft_bitlocker_allowwarningforotherdiskencryption_0"
    );
  });

  it("skips a boolean field the caller never set, so a partial config never resets unrelated settings", () => {
    const settings = buildBitLockerSettingsPayload({ requireDeviceEncryption: true, allowStandardUserEncryption: undefined });
    expect(settings).toHaveLength(1);
  });

  it("emits the confirmed 0/1/2 integer choice values for recoveryPasswordRotation", () => {
    expect(buildBitLockerSettingsPayload({ recoveryPasswordRotation: "off" })[0].settingInstance.choiceSettingValue.value).toBe(
      "device_vendor_msft_bitlocker_configurerecoverypasswordrotation_0"
    );
    expect(
      buildBitLockerSettingsPayload({ recoveryPasswordRotation: "entraIdOnly" })[0].settingInstance.choiceSettingValue.value
    ).toBe("device_vendor_msft_bitlocker_configurerecoverypasswordrotation_1");
    expect(
      buildBitLockerSettingsPayload({ recoveryPasswordRotation: "entraIdAndHybrid" })[0].settingInstance.choiceSettingValue.value
    ).toBe("device_vendor_msft_bitlocker_configurerecoverypasswordrotation_2");
  });

  it("combines all four settings in one payload, matching the recommended baseline", () => {
    const settings = buildBitLockerSettingsPayload(RECOMMENDED_BITLOCKER_POLICY);
    expect(settings).toHaveLength(4);
  });

  it("emits nothing for an empty settings object", () => {
    expect(buildBitLockerSettingsPayload({})).toHaveLength(0);
  });
});

describe("buildIntuneAssignmentTarget", () => {
  it("returns an empty assignments array for 'none' (Do Not Assign)", () => {
    expect(buildIntuneAssignmentTarget({ mode: "none" })).toEqual({ assignments: [] });
  });

  it("targets all devices", () => {
    expect(buildIntuneAssignmentTarget({ mode: "allDevices" })).toEqual({
      assignments: [{ target: { "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget" } }],
    });
  });

  it("targets all licensed users", () => {
    expect(buildIntuneAssignmentTarget({ mode: "allUsers" })).toEqual({
      assignments: [{ target: { "@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget" } }],
    });
  });

  it("targets all users and all devices together", () => {
    expect(buildIntuneAssignmentTarget({ mode: "allUsersAndDevices" })).toEqual({
      assignments: [
        { target: { "@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget" } },
        { target: { "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget" } },
      ],
    });
  });

  it("targets a specific group by id", () => {
    expect(buildIntuneAssignmentTarget({ mode: "group", groupId: "grp-1" })).toEqual({
      assignments: [{ target: { "@odata.type": "#microsoft.graph.groupAssignmentTarget", groupId: "grp-1" } }],
    });
  });

  it("adds an exclusion target alongside an include target when both are given", () => {
    const result = buildIntuneAssignmentTarget({ mode: "group", groupId: "grp-1", excludeGroupId: "grp-2" });
    expect(result.assignments).toHaveLength(2);
    expect(result.assignments[1]).toEqual({
      target: { "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", groupId: "grp-2" },
    });
  });

  it("returns no assignments for a 'group' mode with no groupId set", () => {
    expect(buildIntuneAssignmentTarget({ mode: "group" })).toEqual({ assignments: [] });
  });
});

describe("buildAsrRuleSettingsChildren", () => {
  const RANSOMWARE_ID = "c1db55ab-c21a-4637-bb3f-a12568109d35";
  const ROOT_PREFIX = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules";

  it("builds a choice setting child using the confirmed _audit suffix (not _auditmode)", () => {
    const ruleIdToSlug = new Map([[RANSOMWARE_ID, "useadvancedprotectionagainstransomware"]]);
    const { children, skippedRuleIds } = buildAsrRuleSettingsChildren({ [RANSOMWARE_ID]: "audit" }, ruleIdToSlug);

    expect(skippedRuleIds).toHaveLength(0);
    expect(children).toHaveLength(1);
    expect(children[0].settingDefinitionId).toBe(`${ROOT_PREFIX}_useadvancedprotectionagainstransomware`);
    expect(children[0].choiceSettingValue.value).toBe(`${ROOT_PREFIX}_useadvancedprotectionagainstransomware_audit`);
  });

  it("uses the exact _block / _warn suffixes for the other two modes", () => {
    const ruleIdToSlug = new Map([[RANSOMWARE_ID, "slug"]]);
    const blockResult = buildAsrRuleSettingsChildren({ [RANSOMWARE_ID]: "block" }, ruleIdToSlug);
    const warnResult = buildAsrRuleSettingsChildren({ [RANSOMWARE_ID]: "warn" }, ruleIdToSlug);
    expect(blockResult.children[0].choiceSettingValue.value).toBe(`${ROOT_PREFIX}_slug_block`);
    expect(warnResult.children[0].choiceSettingValue.value).toBe(`${ROOT_PREFIX}_slug_warn`);
  });

  it("skips a rule with no known slug rather than sending a guessed definition id", () => {
    const { children, skippedRuleIds } = buildAsrRuleSettingsChildren({ "unknown-rule-id": "block" }, new Map());
    expect(children).toHaveLength(0);
    expect(skippedRuleIds).toEqual(["unknown-rule-id"]);
  });
});

describe("decodeAppRolesFromToken", () => {
  it("returns the granted roles claim from a real-shaped app-only token", () => {
    const token = fakeJwt({ roles: ["User.Read.All", "DeviceManagementConfiguration.Read.All"] });
    expect(decodeAppRolesFromToken(token)).toEqual(["User.Read.All", "DeviceManagementConfiguration.Read.All"]);
  });

  it("does not report the ReadWrite variant granted when only the weaker Read.All role is present - the live Coetzee Architects bug", () => {
    // Captured live: this app registration's Permissions modal showed
    // DeviceManagementConfiguration.ReadWrite.All as "Granted" because the
    // old self-test GETs deviceManagement/intents, which Graph accepts with
    // either the Read.All or ReadWrite.All role - so it passed on Read.All
    // alone, while the actual EDR policy deploy failed with "Application is
    // not authorized to perform this operation." Decoding the roles claim
    // directly must NOT make the same mistake.
    const token = fakeJwt({ roles: ["DeviceManagementConfiguration.Read.All"] });
    const roles = decodeAppRolesFromToken(token);
    expect(roles).not.toBeNull();
    expect(roles).not.toContain("DeviceManagementConfiguration.ReadWrite.All");
  });

  it("returns an empty array, not null, when the token has no roles claim at all", () => {
    const token = fakeJwt({ aud: "https://graph.microsoft.com" });
    expect(decodeAppRolesFromToken(token)).toEqual([]);
  });

  it("returns null for a malformed token instead of throwing", () => {
    expect(decodeAppRolesFromToken("not-a-real-jwt")).toBeNull();
    expect(decodeAppRolesFromToken("")).toBeNull();
  });
});

describe("isPermissionGrantedByRoles", () => {
  it("matches a plain single permission string", () => {
    expect(isPermissionGrantedByRoles("Policy.Read.All", ["Policy.Read.All", "User.Read.All"])).toBe(true);
    expect(isPermissionGrantedByRoles("Policy.Read.All", ["User.Read.All"])).toBe(false);
  });

  it("matches a compound 'X / Y' permission field if either alternative is granted", () => {
    // Several rows in testAppRegistrationPermissions list two Graph
    // permissions Microsoft accepts interchangeably for the same call
    // (e.g. "Reports.Read.All / UserAuthenticationMethod.Read.All") - proof
    // this is real, not hypothetical: decoding a live Coetzee Architects
    // token showed only "UserAuthenticationMethod.Read.All" and
    // "Reports.Read.All" as separate entries, either of which must count.
    const field = "Reports.Read.All / UserAuthenticationMethod.Read.All";
    expect(isPermissionGrantedByRoles(field, ["UserAuthenticationMethod.Read.All"])).toBe(true);
    expect(isPermissionGrantedByRoles(field, ["Reports.Read.All"])).toBe(true);
    expect(isPermissionGrantedByRoles(field, ["Group.Read.All"])).toBe(false);
  });
});

describe("describeTransientTokenLifetimeError", () => {
  it("appends a propagation-delay explanation to Microsoft's 'Lifetime validation failed' message", () => {
    // Captured live on Coetzee Architects, right after forcing a fresh
    // access token on every Re-Test Permissions click: AuditLog.Read.All and
    // Reports.Read.All failed this exact way while Policy.Read.All and
    // User.Read.All succeeded with the identical token in the same run -
    // proof this isn't a real missing-permission error, since one token
    // can't be both valid and expired at once.
    const raw = "Lifetime validation failed, the token is expired.";
    const result = describeTransientTokenLifetimeError(raw);
    expect(result).toContain(raw);
    expect(result).toContain("Microsoft's own backend");
    expect(result).not.toContain("Grant it with admin consent");
  });

  it("leaves an unrelated error message untouched", () => {
    const raw = "Insufficient privileges to complete the operation.";
    expect(describeTransientTokenLifetimeError(raw)).toBe(raw);
  });
});

describe("withFreshTokenOnLifetimeError (via fetchEdrPolicy)", () => {
  // Live-diagnosed on Coetzee Architects: a token our own cache considered
  // valid was genuinely rejected by Microsoft's Intune Settings Catalog
  // resource specifically (deviceManagement/configurationPolicies) over a
  // real network round-trip, while the same token worked for every other
  // resource. graphFetch's own short retry (see its comment) exhausts
  // itself retrying with that SAME doomed token and gives up; only forcing
  // a genuinely fresh token (invalidateGraphTokenCache + a new
  // client_credentials fetch) recovers - this simulates exactly that
  // sequence end-to-end through the real fetchEdrPolicy/getGraphAccessToken/
  // graphFetch stack, mocking only the network boundary.
  const tenant = fakeTenant();

  beforeEach(() => {
    vi.useFakeTimers();
    invalidateGraphTokenCache(tenant.credentials);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    invalidateGraphTokenCache(tenant.credentials);
  });

  function mockJsonResponse(status: number, body: unknown) {
    return {
      status,
      ok: status >= 200 && status < 300,
      headers: { get: () => null },
      json: async () => body,
      text: async () => JSON.stringify(body),
      clone() {
        return mockJsonResponse(status, body);
      },
    } as unknown as Response;
  }

  it("invalidates the cached token and retries once with a fresh one when the first token is rejected tenant-resource-wide", async () => {
    let tokenCallCount = 0;
    const lifetimeErrorBody = { error: { message: "Lifetime validation failed, the token is expired." } };

    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.includes("/oauth2/v2.0/token")) {
        tokenCallCount++;
        return mockJsonResponse(200, { access_token: `token-${tokenCallCount}`, expires_in: 3600 });
      }
      if (url.includes("/deviceManagement/configurationPolicies")) {
        const authHeader = (init?.headers as Record<string, string> | undefined)?.Authorization;
        if (authHeader === "Bearer token-1") {
          // Every attempt with the first (bad) token fails - including
          // graphFetch's own internal retries of that same token.
          return mockJsonResponse(401, lifetimeErrorBody);
        }
        // A genuinely fresh token (token-2) succeeds immediately.
        return mockJsonResponse(200, { value: [] });
      }
      throw new Error(`Unexpected URL in test: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const resultPromise = fetchEdrPolicy(tenant);
    await vi.runAllTimersAsync();
    const result = await resultPromise;

    expect(result.error).toBeUndefined();
    expect(tokenCallCount).toBe(2); // first token, then one forced fresh re-fetch
  });

  it("does not retry with a fresh token for an unrelated, real error", async () => {
    let tokenCallCount = 0;
    const fetchMock = vi.fn(async (url: string) => {
      if (url.includes("/oauth2/v2.0/token")) {
        tokenCallCount++;
        return mockJsonResponse(200, { access_token: `token-${tokenCallCount}`, expires_in: 3600 });
      }
      if (url.includes("/deviceManagement/configurationPolicies")) {
        return mockJsonResponse(403, { error: { message: "Insufficient privileges to complete the operation." } });
      }
      throw new Error(`Unexpected URL in test: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const resultPromise = fetchEdrPolicy(tenant);
    await vi.runAllTimersAsync();
    const result = await resultPromise;

    expect(result.error).toContain("Insufficient privileges");
    expect(tokenCallCount).toBe(1); // never worth burning a second token on a real, unrelated error
  });
});

describe("createSettingsCatalogPolicyReplacing (via deployEdrPolicy)", () => {
  // Live-diagnosed on Coetzee Architects (2026-09-17): Graph has NO route to
  // update a Settings Catalog policy's settings in place. `settings` is a
  // NavigationProperty (ContainsTarget) on deviceManagementConfigurationPolicy
  // with no bound update Action/Function (confirmed against the real beta
  // $metadata), and PATCHing an individual settings item by its own id is
  // rejected outright by Intune's real backend with "No OData route exists
  // ... with http verb PATCH" - not a validation error, a genuinely absent
  // route. The only way to change settings is create a new policy and
  // delete the old one - verified live end-to-end against Coetzee (created
  // a new EDR policy with a changed setting, assigned it, deleted the old
  // one, confirmed exactly one policy remained with the new value). These
  // tests simulate that same sequence through the real
  // deployEdrPolicy/createSettingsCatalogPolicyReplacing stack, mocking
  // only the network boundary.
  const tenant = fakeTenant({ tenantId: "tid-deploy-test", clientId: "cid-deploy-test" });
  const settings = { autoFromConnector: true };
  const assignment = { mode: "none" as const };

  beforeEach(() => {
    invalidateGraphTokenCache(tenant.credentials);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    invalidateGraphTokenCache(tenant.credentials);
  });

  function mockResponse(status: number, body: unknown = {}) {
    return {
      status,
      ok: status >= 200 && status < 300,
      headers: { get: () => null },
      json: async () => body,
      text: async () => JSON.stringify(body),
      clone() {
        return mockResponse(status, body);
      },
    } as unknown as Response;
  }

  it("creates a new policy, assigns it, and deletes the old one when replacing an existing deploy", async () => {
    const calls: { method: string; url: string }[] = [];
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method || "GET";
      calls.push({ method, url });
      if (url.includes("/oauth2/v2.0/token")) return mockResponse(200, { access_token: "tok", expires_in: 3600 });
      if (method === "POST" && url.endsWith("/configurationPolicies")) return mockResponse(201, { id: "new-policy-id" });
      if (method === "POST" && url.includes("/assign")) return mockResponse(200);
      if (method === "DELETE" && url.includes("old-policy-id")) return mockResponse(200);
      throw new Error(`Unexpected call in test: ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await deployEdrPolicy(tenant, settings, assignment, "old-policy-id");

    expect(result).toEqual({ success: true, policyId: "new-policy-id" });
    expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/configurationPolicies"))).toBe(true);
    expect(calls.some((c) => c.method === "DELETE" && c.url.includes("old-policy-id"))).toBe(true);
  });

  it("does not attempt to delete anything on a first-ever deploy (no existingPolicyId)", async () => {
    const calls: { method: string; url: string }[] = [];
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method || "GET";
      calls.push({ method, url });
      if (url.includes("/oauth2/v2.0/token")) return mockResponse(200, { access_token: "tok", expires_in: 3600 });
      if (method === "POST" && url.endsWith("/configurationPolicies")) return mockResponse(201, { id: "first-policy-id" });
      if (method === "POST" && url.includes("/assign")) return mockResponse(200);
      throw new Error(`Unexpected call in test: ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await deployEdrPolicy(tenant, settings, assignment);

    expect(result).toEqual({ success: true, policyId: "first-policy-id" });
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
  });

  it("still reports success with a cleanup warning when the new policy is created but deleting the old one fails", async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method || "GET";
      if (url.includes("/oauth2/v2.0/token")) return mockResponse(200, { access_token: "tok", expires_in: 3600 });
      if (method === "POST" && url.endsWith("/configurationPolicies")) return mockResponse(201, { id: "new-policy-id" });
      if (method === "POST" && url.includes("/assign")) return mockResponse(200);
      if (method === "DELETE") return mockResponse(500, { error: { message: "Internal server error" } });
      throw new Error(`Unexpected call in test: ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await deployEdrPolicy(tenant, settings, assignment, "old-policy-id");

    expect(result.success).toBe(true);
    expect(result.policyId).toBe("new-policy-id");
    expect(result.error).toContain("manual cleanup");
  });
});

describe("fetchBitLockerPolicy / deployBitLockerPolicy", () => {
  // The shared createSettingsCatalogPolicyReplacing() mechanism is already
  // thoroughly covered above (via deployEdrPolicy) - these just confirm
  // BitLocker's own wiring (templateFamily, settings builder, read-back
  // parsing) is correct, not the shared create/delete logic again.
  const tenant = fakeTenant({ tenantId: "tid-bitlocker-test", clientId: "cid-bitlocker-test" });

  beforeEach(() => invalidateGraphTokenCache(tenant.credentials));
  afterEach(() => {
    vi.unstubAllGlobals();
    invalidateGraphTokenCache(tenant.credentials);
  });

  function mockResponse(status: number, body: unknown = {}) {
    return {
      status,
      ok: status >= 200 && status < 300,
      headers: { get: () => null },
      json: async () => body,
      text: async () => JSON.stringify(body),
      clone() {
        return mockResponse(status, body);
      },
    } as unknown as Response;
  }

  it("fetchBitLockerPolicy correctly parses a deployed policy's real settings, including the 3-way recovery rotation choice", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.includes("/oauth2/v2.0/token")) return mockResponse(200, { access_token: "tok", expires_in: 3600 });
      if (url.includes("/configurationPolicies?")) return mockResponse(200, { "@odata.count": 1, value: [{ id: "bl-policy-id" }] });
      if (url.includes("/settings")) {
        return mockResponse(200, {
          value: [
            {
              settingInstance: {
                settingDefinitionId: "device_vendor_msft_bitlocker_requiredeviceencryption",
                choiceSettingValue: { value: "device_vendor_msft_bitlocker_requiredeviceencryption_1", children: [] },
              },
            },
            {
              settingInstance: {
                settingDefinitionId: "device_vendor_msft_bitlocker_configurerecoverypasswordrotation",
                choiceSettingValue: { value: "device_vendor_msft_bitlocker_configurerecoverypasswordrotation_2", children: [] },
              },
            },
          ],
        });
      }
      throw new Error(`Unexpected call in test: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await fetchBitLockerPolicy(tenant);

    expect(result.deployedPolicyId).toBe("bl-policy-id");
    expect(result.settings.requireDeviceEncryption).toBe(true);
    expect(result.settings.recoveryPasswordRotation).toBe("entraIdAndHybrid");
    expect(result.settings.allowStandardUserEncryption).toBeUndefined(); // never configured - not the same as false
  });

  it("deployBitLockerPolicy creates a new policy under the confirmed endpointSecurityDiskEncryption templateFamily", async () => {
    let createBody: any;
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method || "GET";
      if (url.includes("/oauth2/v2.0/token")) return mockResponse(200, { access_token: "tok", expires_in: 3600 });
      if (method === "POST" && url.endsWith("/configurationPolicies")) {
        createBody = JSON.parse(init!.body as string);
        return mockResponse(201, { id: "new-bitlocker-id" });
      }
      if (method === "POST" && url.includes("/assign")) return mockResponse(200);
      throw new Error(`Unexpected call in test: ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await deployBitLockerPolicy(tenant, RECOMMENDED_BITLOCKER_POLICY, { mode: "none" });

    expect(result).toEqual({ success: true, policyId: "new-bitlocker-id" });
    expect(createBody.templateReference.templateFamily).toBe("endpointSecurityDiskEncryption");
    expect(createBody.settings).toHaveLength(4);
  });

  it("refuses to deploy an empty settings object rather than silently sending nothing", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.includes("/oauth2/v2.0/token")) return mockResponse(200, { access_token: "tok", expires_in: 3600 });
      throw new Error(`Unexpected call in test: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await deployBitLockerPolicy(tenant, {}, { mode: "none" });
    expect(result).toEqual({ success: false, error: "No BitLocker policy settings were selected - nothing to deploy." });
  });
});

describe("classifyAdvancedHuntingError", () => {
  it("rewrites a missing-permission 403 into an actionable message naming ThreatHunting.Read.All", () => {
    const raw =
      "Missing application roles. API required roles: ThreatHunting.Read.All, application roles: Policy.Read.ConditionalAccess,DeviceManagementManagedDevices.Read.All";
    const result = classifyAdvancedHuntingError(raw, 403);
    expect(result).toContain("ThreatHunting.Read.All");
    expect(result).toContain("has not been granted");
    expect(result).not.toContain("DeviceManagementManagedDevices.Read.All");
  });

  it("rewrites a table-not-found error into a non-committal explanation, not a permission one", () => {
    const raw = "'where' operator: Failed to resolve table or column expression named 'DeviceEvents'. Fix semantic errors in your query.";
    const result = classifyAdvancedHuntingError(raw, 400);
    expect(result).toContain("DeviceEvents");
    expect(result).toContain("permission itself is fine");
    expect(result).not.toContain("has not been granted");
  });

  it("does not misclassify a genuine table-not-found error as a missing-permission one", () => {
    const raw = "Failed to resolve table or column expression named 'DeviceEvents'";
    const result = classifyAdvancedHuntingError(raw, 400);
    expect(result).not.toContain("has not been granted");
  });

  it("passes through an unrecognized error message unchanged", () => {
    const raw = "Some other Graph error Clarity365 doesn't specifically handle.";
    expect(classifyAdvancedHuntingError(raw, 500)).toBe(raw);
  });

  it("does not rewrite a 403 that isn't about ThreatHunting.Read.All", () => {
    const raw = "Missing application roles. API required roles: SomeOther.Permission.All, application roles: Policy.Read.All";
    expect(classifyAdvancedHuntingError(raw, 403)).toBe(raw);
  });

  it("rewrites a 401 lifetime-validation error into a propagation-delay explanation, not a caching one", () => {
    const raw = "Lifetime validation failed, the token is expired.";
    const result = classifyAdvancedHuntingError(raw, 401);
    expect(result).toContain("NOT to be a Clarity365 caching issue");
    expect(result).toContain("propagation delay");
  });

  it("does not misfire the lifetime-validation rewrite on an unrelated 401", () => {
    const raw = "Access token is missing or malformed.";
    expect(classifyAdvancedHuntingError(raw, 401)).toBe(raw);
  });
});

describe("cleanIntuneConfigV2Error", () => {
  // The exact raw error text captured live when a real EDR policy deploy
  // failed - Intune's Settings Catalog backend put its own JSON error body
  // as the literal string value of Graph's error.message field, and the UI
  // showed the whole thing verbatim before this fix.
  const REAL_CAPTURED_ERROR =
    '{"_version": 3, "Message": "device_vendor_msft_windowsadvancedthreatprotection_configurationtype: Selected option device_vendor_msft_windowsadvancedthreatprotection_configurationtype_autofromconnector with dependent settings doesnt contain required dependent settings. Required dependent settings are device_vendor_msft_windowsadvancedthreatprotection_onboarding_fromconnector - Operation ID (for customer support): 00000000-0000-0000-0000-000000000000 - Activity ID: 9a690c52-4662-432b-829b-3f229ca7a594 - Url: https://proxy.msub07.manage.microsoft.com/DeviceConfigV2/DCV2GraphService/de147310-ffff-6297-0304-091201122601/deviceManagement/configurationPolicies?api-version=5026-05-26", "CustomApiErrorPhrase": "", "RetryAfter": null, "ErrorSourceService": "", "HttpHeaders": "{}" }';

  it("extracts just the human Message field from a real captured Intune ConfigV2 error blob", () => {
    const result = cleanIntuneConfigV2Error(REAL_CAPTURED_ERROR);
    expect(result).toContain("doesnt contain required dependent settings");
    expect(result).not.toContain("_version");
    expect(result).not.toContain("CustomApiErrorPhrase");
  });

  it("passes through a plain, non-JSON error message unchanged", () => {
    const raw = "Insufficient privileges to complete the operation.";
    expect(cleanIntuneConfigV2Error(raw)).toBe(raw);
  });

  it("passes through JSON that doesn't have a string Message field unchanged", () => {
    const raw = '{"error": "something else", "code": 400}';
    expect(cleanIntuneConfigV2Error(raw)).toBe(raw);
  });

  it("passes through malformed JSON unchanged rather than throwing", () => {
    const raw = '{"_version": 3, "Message": "unterminated';
    expect(() => cleanIntuneConfigV2Error(raw)).not.toThrow();
    expect(cleanIntuneConfigV2Error(raw)).toBe(raw);
  });

  // Regression test for a second real live failure - this one TWO levels
  // deep (Graph's own OData error envelope, itself wrapping the same
  // ConfigV2 blob as Case 1 above, as its own .Message string). Captured on
  // a tenant with no Microsoft Intune license - the inner message alone
  // ("An error has occurred...") names no cause, so this also verifies the
  // likely-cause sentence gets appended.
  const REAL_DOUBLE_NESTED_ERROR =
    '{"ErrorCode":"Forbidden","Message":"{\\r\\n  \\"_version\\": 3,\\r\\n  \\"Message\\": \\"An error has occurred - Operation ID (for customer support): 00000000-0000-0000-0000-000000000000 - Activity ID: 308c0813-89ec-48a0-b3e3-8e5b1d8e891a - Url: https://proxy.msub06.manage.microsoft.com/DeviceConfigV2/DCV2GraphService/de147310-ffff-2253-0304-091400160691/deviceManagement/configurationPolicies?api-version=5026-05-26\\",\\r\\n  \\"CustomApiErrorPhrase\\": \\"\\",\\r\\n  \\"RetryAfter\\": null,\\r\\n  \\"ErrorSourceService\\": \\"\\",\\r\\n  \\"HttpHeaders\\": \\"{\\\\\\"WWW-Authenticate\\\\\\":\\\\\\"Bearer\\\\\\"}\\"\\r\\n}","Target":null,"Details":null,"InnerError":null,"InstanceAnnotations":[]}';

  it("unwraps two levels of nested JSON from a real captured double-wrapped error", () => {
    const result = cleanIntuneConfigV2Error(REAL_DOUBLE_NESTED_ERROR);
    expect(result).not.toContain("ErrorCode");
    expect(result).not.toContain("_version");
    expect(result).toContain("An error has occurred");
  });

  it("appends the likely-cause sentence when the fully-unwrapped message is Intune's generic 'An error has occurred'", () => {
    const result = cleanIntuneConfigV2Error(REAL_DOUBLE_NESTED_ERROR);
    expect(result).toContain("Microsoft Intune license");
    expect(result).toContain("DeviceManagementConfiguration.ReadWrite.All");
  });

  it("does not append the likely-cause sentence to a specific, already-useful message", () => {
    const result = cleanIntuneConfigV2Error(REAL_CAPTURED_ERROR);
    expect(result).not.toContain("Microsoft Intune license");
  });
});

describe("hasLifetimeValidationError", () => {
  // The decision logic behind fetchLiveTenantSnapshot's own retry gap (see
  // that function's fix in tenant-store.ts's runSync()) - extracted here
  // specifically because runSync itself can't be safely unit tested (the
  // tenant store singleton always opens the real production
  // data/clarity365.db, with no test-mode override).
  it("returns true when any error in the list carries the lifetime-validation signature", () => {
    expect(
      hasLifetimeValidationError([
        "Users: some other error",
        "Conditional Access policies: Lifetime validation failed, the token is expired.",
      ])
    ).toBe(true);
  });

  it("is case-insensitive and matches as a substring, same as the message Graph actually sends", () => {
    expect(hasLifetimeValidationError(["LIFETIME VALIDATION FAILED, the token is expired."])).toBe(true);
  });

  it("returns false when no error matches, including an empty list", () => {
    expect(hasLifetimeValidationError(["Users: Insufficient privileges to complete the operation."])).toBe(false);
    expect(hasLifetimeValidationError([])).toBe(false);
  });

  it("returns false for undefined, so a snapshot with no syncHealth.errors at all is never mistaken for this", () => {
    expect(hasLifetimeValidationError(undefined)).toBe(false);
  });
});

describe("mapConditionalAccessPolicy", () => {
  // Real shape captured live from dmafrica's tenant: Graph accepted the
  // deprecated includeUsers: ["GuestsOrExternalUsers"] string on create and
  // silently upgraded it, but a live GET only ever returns the structured
  // includeGuestsOrExternalUsers object - includeUsers itself comes back
  // empty. Before the fix, this exact raw shape produced baselineCode: null
  // and matchesBaseline: false for a policy that was genuinely correct and
  // being enforced by Microsoft the whole time - see [[Conditional Access
  // Policy Scanner]] in the vault for the full trace.
  it("classifies a real CA04 policy correctly via includeGuestsOrExternalUsers, not the deprecated includeUsers string (regression: dmafrica false-Misconfigured bug)", () => {
    const raw = {
      id: "fcc312ae-4e63-4450-a0f2-2943cb124af0",
      displayName: "CA04: Require multifactor authentication for guest access",
      state: "enabled",
      modifiedDateTime: "2026-09-18T08:05:21.0267453Z",
      createdDateTime: "2026-09-18T08:04:33.226062Z",
      grantControls: { builtInControls: ["mfa"] },
      conditions: {
        users: {
          includeUsers: [],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
          excludeGuestsOrExternalUsers: null,
          includeGuestsOrExternalUsers: {
            guestOrExternalUserTypes: "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider",
            externalTenants: { membershipKind: "all" },
          },
        },
        applications: { includeApplications: ["All"], excludeApplications: [] },
        clientAppTypes: ["all"],
      },
    };

    const mapped = mapConditionalAccessPolicy(raw);
    expect(mapped.baselineCode).toBe("CA04");
    expect(mapped.matchesBaseline).toBe(true);
    expect(mapped.conditions.users.include).toContain("GuestsOrExternalUsers");
  });

  it("maps a CA03 admin-role-scoped policy without spuriously merging role GUIDs into conditions.users.include", () => {
    const raw = {
      id: "admin-policy-1",
      displayName: "CA03: Require multifactor authentication for admins",
      state: "enabledForReportingButNotEnforced",
      grantControls: { builtInControls: ["mfa"] },
      conditions: {
        users: {
          includeUsers: [],
          includeRoles: ["62e90394-69f5-4237-9190-012177145e10"],
        },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["all"],
      },
    };

    const mapped = mapConditionalAccessPolicy(raw);
    expect(mapped.baselineCode).toBe("CA03");
    expect(mapped.conditions.users.includeRoles).toEqual(["62e90394-69f5-4237-9190-012177145e10"]);
    // The role GUID must not also leak into `include` - that field is for
    // user/group identifiers and the "All"/"GuestsOrExternalUsers" markers,
    // not role ids.
    expect(mapped.conditions.users.include).toEqual([]);
  });

  it("preserves platforms/locations/risk-level conditions needed for CA06/CA07/CA08 re-validation", () => {
    const raw = {
      id: "risk-policy-1",
      displayName: "CA06: Require MFA for risky sign-ins",
      state: "enabled",
      grantControls: { builtInControls: ["mfa"] },
      conditions: {
        users: { includeUsers: ["All"] },
        applications: { includeApplications: ["All"] },
        clientAppTypes: ["all"],
        signInRiskLevels: ["medium", "high"],
        userRiskLevels: ["high"],
        platforms: { includePlatforms: ["all"], excludePlatforms: ["android"] },
        locations: { includeLocations: ["All"], excludeLocations: ["AllTrusted"] },
      },
    };

    const mapped = mapConditionalAccessPolicy(raw);
    expect(mapped.conditions.signInRiskLevels).toEqual(["medium", "high"]);
    expect(mapped.conditions.userRiskLevels).toEqual(["high"]);
    expect(mapped.conditions.platforms).toEqual({ include: ["all"], exclude: ["android"] });
    expect(mapped.conditions.locations).toEqual({ include: ["All"], exclude: ["AllTrusted"] });
  });

  it("falls back to null baselineCode/false matchesBaseline for a custom policy that matches no standard", () => {
    const raw = {
      id: "custom-1",
      displayName: "Block risky countries",
      state: "enabled",
      grantControls: { builtInControls: ["block"] },
      conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["All"] }, clientAppTypes: ["all"] },
    };

    const mapped = mapConditionalAccessPolicy(raw);
    expect(mapped.baselineCode).toBeNull();
    expect(mapped.matchesBaseline).toBe(false);
  });
});
