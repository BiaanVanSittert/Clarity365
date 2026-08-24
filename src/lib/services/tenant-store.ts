import fs from "fs";
import path from "path";
import { Tenant, TenantSecuritySnapshot, SystemSettings } from "../types";
import { INITIAL_TENANTS, MOCK_TENANT_DATA } from "../data/mock-tenants";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { encryptSecret, decryptSecret, isEncrypted, SECRET_MASK } from "./crypto";
import {
  fetchLiveTenantSnapshot,
  testAppRegistrationPermissions,
  deployConditionalAccessPolicy,
  TenantPermissionReport,
} from "./graph-client";

interface AuthConfig {
  passwordHash: string;
  updatedAt: string;
}

// Persistent disk + in-memory store for multi-tenant configurations and snapshots
class TenantStore {
  private tenants: Map<string, Tenant> = new Map();
  private snapshots: Map<string, TenantSecuritySnapshot> = new Map();
  private authConfig: AuthConfig | null = null;
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
    this.loadFromDisk();
  }

  private getStorePath(): string {
    return path.join(process.cwd(), "data", "clarity-store.json");
  }

  private loadFromDisk() {
    let loadedFromDisk = false;
    try {
      const storePath = this.getStorePath();
      if (fs.existsSync(storePath)) {
        const raw = fs.readFileSync(storePath, "utf-8");
        const parsed = JSON.parse(raw);
        if (parsed.tenants && Array.isArray(parsed.tenants)) {
          parsed.tenants.forEach((t: Tenant) => this.tenants.set(t.id, t));
        }
        if (parsed.snapshots && typeof parsed.snapshots === "object") {
          Object.entries(parsed.snapshots).forEach(([k, v]) => {
            this.snapshots.set(k, v as TenantSecuritySnapshot);
          });
        }
        if (parsed.settings) {
          this.settings = { ...this.settings, ...parsed.settings };
        }
        if (parsed.authConfig) {
          this.authConfig = parsed.authConfig;
        }
        // If loaded existing data successfully, ensure all tenants have snapshots
        this.tenants.forEach((t) => {
          if (!this.snapshots.has(t.id)) {
            if (MOCK_TENANT_DATA[t.id]) {
              this.snapshots.set(t.id, { ...MOCK_TENANT_DATA[t.id] });
            } else {
              this.snapshots.set(t.id, this.generateBlankSnapshot(t));
            }
          }
        });
        loadedFromDisk = true;
      }
    } catch (err) {
      console.error("[Clarity365 Store] Error reading persistence store from disk", err);
    }

    if (!loadedFromDisk) {
      // Default initialization when no disk file exists (or it was unreadable)
      this.seedDefaults();
      this.saveToDisk();
      return;
    }

    // Migrate any legacy plaintext client secrets (from pre-encryption versions of the
    // store) to AES-256-GCM at rest. Never allowed to fall back to reseeding — a failed
    // migration (e.g. missing CLARITY365_ENCRYPTION_KEY) just leaves that tenant's secret
    // as-is with a warning, rather than risking real tenant data.
    this.migrateLegacyPlaintextSecrets();
  }

  private migrateLegacyPlaintextSecrets() {
    let migrated = false;
    this.tenants.forEach((t, id) => {
      const secret = t.credentials.clientSecret;
      if (!secret || isEncrypted(secret)) return;
      try {
        const encrypted = this.encryptTenantSecret(t);
        this.tenants.set(id, encrypted);
        const snap = this.snapshots.get(id);
        if (snap) snap.tenant = encrypted;
        migrated = true;
      } catch (err) {
        console.error(
          `[Clarity365 Store] Could not encrypt legacy plaintext client secret for tenant '${id}'. ` +
            `Set CLARITY365_ENCRYPTION_KEY and restart to migrate it.`,
          err
        );
      }
    });
    if (migrated) {
      console.log("[Clarity365 Store] Migrated legacy plaintext client secret(s) to encrypted storage.");
      this.saveToDisk();
    }
  }

  private saveToDisk() {
    try {
      const storePath = this.getStorePath();
      const dataDir = path.dirname(storePath);
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }
      const payload = {
        tenants: Array.from(this.tenants.values()),
        snapshots: Object.fromEntries(this.snapshots.entries()),
        settings: this.settings,
        authConfig: this.authConfig,
        lastSaved: new Date().toISOString(),
      };
      fs.writeFileSync(storePath, JSON.stringify(payload, null, 2), "utf-8");
    } catch (err) {
      console.error("[Clarity365 Store] Error saving store to disk", err);
    }
  }

  private seedDefaults() {
    INITIAL_TENANTS.forEach((t) => {
      this.tenants.set(t.id, t);
      if (MOCK_TENANT_DATA[t.id]) {
        this.snapshots.set(t.id, { ...MOCK_TENANT_DATA[t.id] });
      }
    });
  }

  // ---- Secret handling -----------------------------------------------------------
  // Tenants are ALWAYS held in memory and on disk with clientSecret encrypted (or
  // absent). Decryption only ever happens transiently, right before a Graph API call.
  // Anything handed back to an API route/UI goes through sanitizeTenant/sanitizeSnapshot,
  // which mask the secret entirely — it is a write-only field from the client's perspective.

  private encryptTenantSecret(tenant: Tenant): Tenant {
    const secret = tenant.credentials.clientSecret;
    if (!secret || isEncrypted(secret)) return tenant;
    return { ...tenant, credentials: { ...tenant.credentials, clientSecret: encryptSecret(secret) } };
  }

  private sanitizeTenant(tenant: Tenant): Tenant {
    return {
      ...tenant,
      credentials: {
        ...tenant.credentials,
        clientSecret: tenant.credentials.clientSecret ? SECRET_MASK : undefined,
      },
    };
  }

  private sanitizeSnapshot(snapshot: TenantSecuritySnapshot): TenantSecuritySnapshot {
    return { ...snapshot, tenant: this.sanitizeTenant(snapshot.tenant) };
  }

  /** @internal Raw lookup, used only right before a Microsoft Graph call. */
  private getTenantWithDecryptedSecret(id: string): Tenant | undefined {
    const tenant = this.tenants.get(id);
    if (!tenant) return undefined;
    const secret = tenant.credentials.clientSecret;
    if (!secret || !isEncrypted(secret)) return tenant;
    return { ...tenant, credentials: { ...tenant.credentials, clientSecret: decryptSecret(secret) } };
  }

  /** @internal Raw (encrypted-secret) snapshot lookup/creation, safe to mutate by reference. */
  private ensureSnapshot(tenantId: string): TenantSecuritySnapshot | undefined {
    let snapshot = this.snapshots.get(tenantId);
    if (!snapshot && this.tenants.has(tenantId)) {
      const tenant = this.tenants.get(tenantId)!;
      snapshot = this.generateBlankSnapshot(tenant);
      this.snapshots.set(tenantId, snapshot);
      this.saveToDisk();
    }
    return snapshot;
  }

  // ---- Public API -----------------------------------------------------------------

  public getAllTenants(): Tenant[] {
    return Array.from(this.tenants.values()).map((t) => this.sanitizeTenant(t));
  }

  public getTenant(id: string): Tenant | undefined {
    const tenant = this.tenants.get(id);
    return tenant ? this.sanitizeTenant(tenant) : undefined;
  }

  public getSnapshot(tenantId: string): TenantSecuritySnapshot | undefined {
    const snapshot = this.ensureSnapshot(tenantId);
    return snapshot ? this.sanitizeSnapshot(snapshot) : undefined;
  }

  public async syncTenant(tenantId: string): Promise<TenantSecuritySnapshot | undefined> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return undefined;
    const existing = this.snapshots.get(tenantId);
    const { snapshot } = await fetchLiveTenantSnapshot(tenant, existing);
    if (snapshot) {
      // Never let a decrypted secret end up cached in the snapshot's embedded tenant.
      snapshot.tenant = this.encryptTenantSecret(snapshot.tenant);
      this.snapshots.set(tenantId, snapshot);
      this.saveToDisk();
      return this.sanitizeSnapshot(snapshot);
    }
    return existing ? this.sanitizeSnapshot(existing) : undefined;
  }

  public async testPermissions(tenantId: string): Promise<TenantPermissionReport | null> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return null;
    return await testAppRegistrationPermissions(tenant);
  }

  public async deployBaselinePolicy(
    tenantId: string,
    baselineCode: string
  ): Promise<{ success: boolean; policy?: any; snapshot?: TenantSecuritySnapshot; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    const deployResult = await deployConditionalAccessPolicy(tenant, baselineCode);
    if (!deployResult.success) {
      return { success: false, error: deployResult.error };
    }

    // Resync immediately to update live snapshot
    const updatedSnapshot = await this.syncTenant(tenantId);
    return {
      success: true,
      policy: deployResult.policy,
      snapshot: updatedSnapshot,
    };
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

    const stored = this.encryptTenantSecret(newTenant);
    this.tenants.set(id, stored);
    const snapshot = this.generateBlankSnapshot(stored);
    this.snapshots.set(id, snapshot);
    this.saveToDisk();
    return this.sanitizeTenant(stored);
  }

  public updateTenant(id: string, updates: Partial<Tenant>): Tenant | undefined {
    const existing = this.tenants.get(id);
    if (!existing) return undefined;

    let mergedCredentials = existing.credentials;
    if (updates.credentials) {
      const incomingSecret = updates.credentials.clientSecret;
      // A masked value coming back from the UI (or no value at all) means "leave the
      // existing secret alone" — the client never has the real value to send back.
      const keepExistingSecret = !incomingSecret || incomingSecret === SECRET_MASK;
      mergedCredentials = {
        ...existing.credentials,
        ...updates.credentials,
        clientSecret: keepExistingSecret ? existing.credentials.clientSecret : encryptSecret(incomingSecret!),
      };
    }

    const updated: Tenant = {
      ...existing,
      ...updates,
      credentials: mergedCredentials,
      lastSyncTimestamp: new Date().toISOString(),
    };
    this.tenants.set(id, updated);
    const snap = this.snapshots.get(id);
    if (snap) {
      snap.tenant = updated;
    }
    this.saveToDisk();
    return this.sanitizeTenant(updated);
  }

  public removeTenant(id: string): boolean {
    const exists = this.tenants.has(id);
    if (exists) {
      this.tenants.delete(id);
      this.snapshots.delete(id);
      this.saveToDisk();
    }
    return exists;
  }

  public addTablEntry(tenantId: string, entry: Omit<TenantSecuritySnapshot["mdoThreat"]["tabl"][0], "id" | "dateAdded">) {
    const snap = this.ensureSnapshot(tenantId);
    if (!snap) return null;
    const newEntry = {
      ...entry,
      id: `tabl-${Date.now().toString(36)}`,
      dateAdded: new Date().toISOString(),
    };
    snap.mdoThreat.tabl.unshift(newEntry);
    this.saveToDisk();
    return newEntry;
  }

  public removeTablEntry(tenantId: string, entryId: string): boolean {
    const snap = this.ensureSnapshot(tenantId);
    if (!snap) return false;
    const initialLen = snap.mdoThreat.tabl.length;
    snap.mdoThreat.tabl = snap.mdoThreat.tabl.filter((e) => e.id !== entryId);
    const removed = snap.mdoThreat.tabl.length < initialLen;
    if (removed) this.saveToDisk();
    return removed;
  }

  public addGroup(tenantId: string, group: Omit<TenantSecuritySnapshot["groups"][0], "id" | "createdDateTime">) {
    const snap = this.ensureSnapshot(tenantId);
    if (!snap) return null;
    const newGroup = {
      ...group,
      id: `grp-${Date.now().toString(36)}`,
      createdDateTime: new Date().toISOString(),
    };
    snap.groups.unshift(newGroup);
    this.saveToDisk();
    return newGroup;
  }

  public updateSharePointPolicy(
    tenantId: string,
    updates: Partial<Pick<TenantSecuritySnapshot["sharePoint"], "tenantSharingLevel" | "defaultLinkType" | "anonymousLinkExpirationDays">>
  ) {
    const snap = this.ensureSnapshot(tenantId);
    if (!snap) return null;
    snap.sharePoint = { ...snap.sharePoint, ...updates };
    this.saveToDisk();
    return snap.sharePoint;
  }

  public isPasswordConfigured(): boolean {
    return !!this.authConfig;
  }

  public getPasswordHash(): string | null {
    return this.authConfig?.passwordHash ?? null;
  }

  public setPasswordHash(passwordHash: string): void {
    this.authConfig = { passwordHash, updatedAt: new Date().toISOString() };
    this.saveToDisk();
  }

  public getSettings(): SystemSettings {
    return this.settings;
  }

  public updateSettings(updates: Partial<SystemSettings>): SystemSettings {
    this.settings = { ...this.settings, ...updates };
    this.saveToDisk();
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
