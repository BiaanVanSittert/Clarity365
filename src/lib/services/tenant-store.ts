import { Tenant, TenantSecuritySnapshot, SystemSettings } from "../types";
import { INITIAL_TENANTS, MOCK_TENANT_DATA } from "../data/mock-tenants";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";

// In-memory runtime store for server-side operations
class TenantStore {
  private tenants: Map<string, Tenant> = new Map();
  private snapshots: Map<string, TenantSecuritySnapshot> = new Map();
  private settings: SystemSettings = {
    enableMcpServer: true,
    mcpServerPort: 8365,
    allowToolExecution: true,
    autoSyncIntervalMinutes: 30,
    auditLogRetentionDays: 90,
    defaultTheme: "light",
    tableDensity: "compact",
  };

  constructor() {
    this.seedDefaults();
  }

  private seedDefaults() {
    INITIAL_TENANTS.forEach((t) => {
      this.tenants.set(t.id, t);
      if (MOCK_TENANT_DATA[t.id]) {
        this.snapshots.set(t.id, { ...MOCK_TENANT_DATA[t.id] });
      }
    });
  }

  public getAllTenants(): Tenant[] {
    return Array.from(this.tenants.values());
  }

  public getTenant(id: string): Tenant | undefined {
    return this.tenants.get(id);
  }

  public getSnapshot(tenantId: string): TenantSecuritySnapshot | undefined {
    // If tenant exists but snapshot doesn't, generate a default one
    let snapshot = this.snapshots.get(tenantId);
    if (!snapshot && this.tenants.has(tenantId)) {
      const tenant = this.tenants.get(tenantId)!;
      snapshot = this.generateBlankSnapshot(tenant);
      this.snapshots.set(tenantId, snapshot);
    }
    return snapshot;
  }

  public addTenant(tenantData: Partial<Tenant>): Tenant {
    const id = tenantData.id || `tenant-${Date.now().toString(36)}`;
    const newTenant: Tenant = {
      id,
      displayName: tenantData.displayName || "New Microsoft 365 Tenant",
      defaultDomainName: tenantData.defaultDomainName || "newtenant.onmicrosoft.com",
      organizationId: tenantData.organizationId || crypto.randomUUID(),
      primaryContact: tenantData.primaryContact || "admin@newtenant.onmicrosoft.com",
      tier: tenantData.tier || "M365_E5",
      createdDate: new Date().toISOString(),
      lastSyncTimestamp: new Date().toISOString(),
      connectionStatus: "healthy",
      credentials: tenantData.credentials || {
        tenantId: tenantData.organizationId || crypto.randomUUID(),
        authMode: "mock",
        status: "connected",
      },
      isDemo: tenantData.isDemo ?? false,
    };

    this.tenants.set(id, newTenant);
    const snapshot = this.generateBlankSnapshot(newTenant);
    this.snapshots.set(id, snapshot);
    return newTenant;
  }

  public updateTenant(id: string, updates: Partial<Tenant>): Tenant | undefined {
    const existing = this.tenants.get(id);
    if (!existing) return undefined;
    const updated = { ...existing, ...updates, lastSyncTimestamp: new Date().toISOString() };
    this.tenants.set(id, updated);
    const snap = this.snapshots.get(id);
    if (snap) {
      snap.tenant = updated;
    }
    return updated;
  }

  public removeTenant(id: string): boolean {
    const exists = this.tenants.has(id);
    if (exists) {
      this.tenants.delete(id);
      this.snapshots.delete(id);
    }
    return exists;
  }

  public addTablEntry(tenantId: string, entry: Omit<TenantSecuritySnapshot["mdoThreat"]["tabl"][0], "id" | "dateAdded">) {
    const snap = this.getSnapshot(tenantId);
    if (!snap) return null;
    const newEntry = {
      ...entry,
      id: `tabl-${Date.now().toString(36)}`,
      dateAdded: new Date().toISOString(),
    };
    snap.mdoThreat.tabl.unshift(newEntry);
    return newEntry;
  }

  public removeTablEntry(tenantId: string, entryId: string): boolean {
    const snap = this.getSnapshot(tenantId);
    if (!snap) return false;
    const initialLen = snap.mdoThreat.tabl.length;
    snap.mdoThreat.tabl = snap.mdoThreat.tabl.filter((e) => e.id !== entryId);
    return snap.mdoThreat.tabl.length < initialLen;
  }

  public addGroup(tenantId: string, group: Omit<TenantSecuritySnapshot["groups"][0], "id" | "createdDateTime">) {
    const snap = this.getSnapshot(tenantId);
    if (!snap) return null;
    const newGroup = {
      ...group,
      id: `grp-${Date.now().toString(36)}`,
      createdDateTime: new Date().toISOString(),
    };
    snap.groups.unshift(newGroup);
    return newGroup;
  }

  public updateSharePointPolicy(
    tenantId: string,
    updates: Partial<Pick<TenantSecuritySnapshot["sharePoint"], "tenantSharingLevel" | "defaultLinkType" | "anonymousLinkExpirationDays">>
  ) {
    const snap = this.getSnapshot(tenantId);
    if (!snap) return null;
    snap.sharePoint = { ...snap.sharePoint, ...updates };
    return snap.sharePoint;
  }

  public getSettings(): SystemSettings {
    return this.settings;
  }

  public updateSettings(updates: Partial<SystemSettings>): SystemSettings {
    this.settings = { ...this.settings, ...updates };
    return this.settings;
  }

  private generateBlankSnapshot(tenant: Tenant): TenantSecuritySnapshot {
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
        totalAccounts: 150,
        licensedUsersCount: 135,
        unlicensedActiveCount: 5,
        disabledAccountsCount: 10,
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
}

// Global singleton instance
const globalForTenantStore = globalThis as unknown as { tenantStore: TenantStore };
export const tenantStore = globalForTenantStore.tenantStore || new TenantStore();
if (process.env.NODE_ENV !== "production") globalForTenantStore.tenantStore = tenantStore;
