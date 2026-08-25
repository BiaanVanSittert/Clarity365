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
      currentScore: 420,
      maxScore: 650,
      percentage: 64.6,
      delta30Days: 1.5,
      delta90Days: 5.0,
      industryBenchmark: 61.2,
      history: [
        { date: "2026-05-20", score: 390, maxScore: 650, percentage: 60.0 },
        { date: "2026-06-20", score: 405, maxScore: 650, percentage: 62.3 },
        { date: "2026-07-20", score: 415, maxScore: 650, percentage: 63.8 },
        { date: "2026-08-20", score: 420, maxScore: 650, percentage: 64.6 },
      ],
      controls: [
        {
          id: "SEC-GEN-01",
          title: "Require MFA for administrative roles",
          category: "Identity",
          scoreCurrent: 50,
          scoreMax: 50,
          implementationCost: "Low",
          userImpact: "Low",
          status: "Completed",
          actionType: "Policy",
          remediationSummary: "Enforced globally via Conditional Access.",
        },
        {
          id: "SEC-GEN-02",
          title: "Block legacy authentication protocols (CA02)",
          category: "Identity",
          scoreCurrent: 0,
          scoreMax: 35,
          implementationCost: "Low",
          userImpact: "Low",
          status: "Unresolved",
          actionType: "Policy",
          remediationSummary: "Legacy auth protocols still permitted.",
        },
      ],
    },
    conditionalAccess: {
      baselineCoverageScore: 60,
      baselineDefinitions: CA_BASELINE_STANDARDS,
      policies: [
        {
          id: `ca-pol-${tenant.id}-01`,
          name: "CA01: Require MFA for All Administrators",
          baselineCode: "CA01",
          baselineTitle: "Require MFA for All Administrators",
          state: "enabled",
          modifiedDateTime: new Date().toISOString(),
          createdDateTime: new Date().toISOString(),
          grantControls: ["mfa"],
          conditions: {
            users: { include: ["DirectoryRole:GlobalAdmin"], exclude: [] },
            applications: { include: ["All"], exclude: [] },
            clientAppTypes: ["all"],
          },
          matchesBaseline: true,
        },
      ],
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
    },
    appRegistrations: [],
    intune: {
      antivirusPoliciesCount: 1,
      edrPoliciesCount: 1,
      compliantDevices: 120,
      nonCompliantDevices: 15,
      totalDevices: 135,
      devices: [],
    },
    groups: [],
    sharePoint: {
      tenantSharingLevel: "NewAndExistingGuests",
      defaultLinkType: "Internal",
      anonymousLinkExpirationDays: 30,
      totalStorageAllocatedTB: 5.0,
      totalStorageUsedTB: 1.2,
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
