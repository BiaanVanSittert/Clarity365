import { Tenant, TenantSecuritySnapshot } from "../types";
import { CA_BASELINE_STANDARDS } from "./baseline-definitions";

// Single source of truth for "a tenant with no live data yet" — used both when a
// brand-new tenant is added and as the seed a live Graph sync starts from before
// overwriting the sections it actually fetches. Previously duplicated (with drifting
// placeholder numbers) between tenant-store.ts and graph-client.ts.
export function createBlankSnapshot(tenant: Tenant): TenantSecuritySnapshot {
  return {
    tenant,
    capabilities: [
      { id: "cap-entra", name: "Microsoft Entra ID P1/P2", category: "Identity", licensed: true, tier: "Active", description: "Identity and Access Management" },
      { id: "cap-intune", name: "Microsoft Intune", category: "Endpoint", licensed: true, tier: "Active", description: "Endpoint Management" },
      { id: "cap-mde", name: "Defender for Endpoint", category: "Endpoint", licensed: true, tier: "Active", description: "EDR Protection" },
      { id: "cap-mdo", name: "Defender for Office 365", category: "Threat", licensed: true, tier: "Active", description: "Email & Collaboration Threat Protection" },
    ],
    secureScore: {
      currentScore: 0,
      maxScore: 0,
      percentage: 0,
      delta30Days: 0,
      delta90Days: 0,
      industryBenchmark: 0,
      history: [],
      controls: [],
    },
    conditionalAccess: {
      baselineCoverageScore: 0,
      baselineDefinitions: CA_BASELINE_STANDARDS,
      policies: [],
    },
    signIns: [],
    mfaAudit: [],
    accountClassification: {
      totalAccounts: 0,
      licensedUsersCount: 0,
      unlicensedActiveCount: 0,
      disabledAccountsCount: 0,
      guestAccountsCount: 0,
      users: [],
    },
    mailboxes: [],
    emailForwarding: [],
    mdoThreat: {
      policies: [],
      tabl: [],
      alerts: [],
    },
    appRegistrations: [],
    intune: {
      antivirusPoliciesCount: 0,
      edrPoliciesCount: 0,
      compliantDevices: 0,
      nonCompliantDevices: 0,
      totalDevices: 0,
      devices: [],
    },
    groups: [],
    sharePoint: {
      tenantSharingLevel: "NewAndExistingGuests",
      defaultLinkType: "Internal",
      anonymousLinkExpirationDays: 30,
      totalStorageAllocatedTB: 0,
      totalStorageUsedTB: 0,
      sites: [],
    },
    highRiskThreatIndicators: {
      externalForwardingCount: 0,
      openSharePointSitesCount: 0,
      unprotectedAdminsCount: 0,
      highRiskAppRegistrationsCount: 0,
    },
  };
}
