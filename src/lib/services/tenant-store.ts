import fs from "fs";
import path from "path";
import Database from "better-sqlite3";
import { Tenant, TenantSecuritySnapshot, SystemSettings, AuditLogEntry, SyncResult, SyncOutcome } from "../types";
import { INITIAL_TENANTS, MOCK_TENANT_DATA } from "../data/mock-tenants";
import { createBlankSnapshot } from "../data/default-snapshot";
import { encryptSecret, decryptSecret, isEncrypted, SECRET_MASK } from "./crypto";
import {
  fetchLiveTenantSnapshot,
  testAppRegistrationPermissions,
  deployConditionalAccessPolicy,
  TenantPermissionReport,
} from "./graph-client";
import {
  testExoConnectivity,
  ExoConnectivityResult,
  startExoDeviceCodeFlow,
  pollExoDeviceCodeFlow,
  DeviceCodeStart,
  DeviceCodePollStatus,
} from "./exo-client";

interface AuthConfigRow {
  passwordHash: string;
  updatedAt: string;
}

const DEFAULT_SETTINGS: SystemSettings = {
  enableMcpServer: true,
  allowToolExecution: true,
  autoSyncIntervalMinutes: 30,
  auditLogRetentionDays: 90,
};

// SQLite-backed store for multi-tenant configurations and snapshots. Each entity is
// still just a JSON blob (same shape the app already used), but as its own row with
// real transactional writes instead of a full-file rewrite on every mutation.
class TenantStore {
  private db: Database.Database;

  constructor() {
    const dataDir = path.join(process.cwd(), "data");
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    this.db = new Database(path.join(dataDir, "clarity365.db"));
    this.db.pragma("journal_mode = WAL");
    this.initSchema();
    this.migrateFromLegacyJsonIfNeeded();
    this.migrateLegacyPlaintextSecrets();
  }

  // Flushes and closes the underlying SQLite connection. Called on graceful
  // process shutdown (see instrumentation.ts) so WAL contents get a clean
  // checkpoint instead of relying on the next open to replay them.
  public close(): void {
    this.db.close();
  }

  private initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS snapshots (
        tenant_id TEXT PRIMARY KEY,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS auth_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        password_hash TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        category TEXT NOT NULL,
        action TEXT NOT NULL,
        tenant_id TEXT,
        tenant_name TEXT,
        success INTEGER NOT NULL,
        detail TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp DESC);
    `);
  }

  // One-time migration from the old data/clarity-store.json flat file. Only runs
  // when the tenants table is empty (fresh DB). On success, the legacy file is
  // renamed (never deleted) so it's obviously retired but still recoverable. On
  // failure, the store is deliberately left empty rather than silently reseeded
  // with demo tenants — that would paper over a real problem with fake data while
  // the original file sits untouched.
  private migrateFromLegacyJsonIfNeeded() {
    const { c } = this.db.prepare("SELECT COUNT(*) as c FROM tenants").get() as { c: number };
    if (c > 0) return;

    const legacyPath = path.join(process.cwd(), "data", "clarity-store.json");
    if (!fs.existsSync(legacyPath)) {
      this.seedDefaults();
      return;
    }

    try {
      const raw = fs.readFileSync(legacyPath, "utf-8");
      const parsed = JSON.parse(raw);

      const migrate = this.db.transaction(() => {
        if (Array.isArray(parsed.tenants)) {
          for (const t of parsed.tenants as Tenant[]) this.putTenantRow(t);
        }
        if (parsed.snapshots && typeof parsed.snapshots === "object") {
          for (const [id, snap] of Object.entries(parsed.snapshots)) {
            this.putSnapshotRow(id, snap as TenantSecuritySnapshot);
          }
        }
        if (parsed.settings) {
          this.putSettingsRow({ ...DEFAULT_SETTINGS, ...parsed.settings });
        }
        if (parsed.authConfig) {
          this.putAuthConfigRow(parsed.authConfig as AuthConfigRow);
        }
      });
      migrate();

      fs.renameSync(legacyPath, `${legacyPath}.migrated-backup`);
      console.log(`[Clarity365 Store] Migrated ${legacyPath} to SQLite (data/clarity365.db).`);
    } catch (err) {
      console.error(
        `[Clarity365 Store] Found ${legacyPath} but failed to migrate it to SQLite. ` +
          `Starting with an empty store rather than risking your data — the original file is untouched. ` +
          `Fix the underlying issue and restart.`,
        err
      );
    }
  }

  private migrateLegacyPlaintextSecrets() {
    let migrated = false;
    for (const tenant of this.getAllTenantRows()) {
      const secret = tenant.credentials.clientSecret;
      if (!secret || isEncrypted(secret)) continue;
      try {
        this.putTenantRow(this.encryptTenantSecret(tenant));
        const snap = this.getSnapshotRow(tenant.id);
        if (snap) {
          snap.tenant = this.encryptTenantSecret(tenant);
          this.putSnapshotRow(tenant.id, snap);
        }
        migrated = true;
      } catch (err) {
        console.error(
          `[Clarity365 Store] Could not encrypt legacy plaintext client secret for tenant '${tenant.id}'. ` +
            `Set CLARITY365_ENCRYPTION_KEY and restart to migrate it.`,
          err
        );
      }
    }
    if (migrated) {
      console.log("[Clarity365 Store] Migrated legacy plaintext client secret(s) to encrypted storage.");
    }
  }

  private seedDefaults() {
    const seed = this.db.transaction(() => {
      for (const t of INITIAL_TENANTS) {
        this.putTenantRow(t);
        if (MOCK_TENANT_DATA[t.id]) {
          this.putSnapshotRow(t.id, { ...MOCK_TENANT_DATA[t.id] });
        }
      }
    });
    seed();
  }

  // ---- Row access (raw, encrypted-secret, no sanitization) ------------------------

  private getAllTenantRows(): Tenant[] {
    const rows = this.db.prepare("SELECT data FROM tenants").all() as { data: string }[];
    return rows.map((r) => JSON.parse(r.data));
  }

  private getTenantRow(id: string): Tenant | undefined {
    const row = this.db.prepare("SELECT data FROM tenants WHERE id = ?").get(id) as { data: string } | undefined;
    return row ? JSON.parse(row.data) : undefined;
  }

  private putTenantRow(tenant: Tenant) {
    this.db
      .prepare("INSERT INTO tenants (id, data) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data")
      .run(tenant.id, JSON.stringify(tenant));
  }

  private deleteTenantRow(id: string) {
    this.db.prepare("DELETE FROM tenants WHERE id = ?").run(id);
  }

  private getSnapshotRow(tenantId: string): TenantSecuritySnapshot | undefined {
    const row = this.db.prepare("SELECT data FROM snapshots WHERE tenant_id = ?").get(tenantId) as
      | { data: string }
      | undefined;
    return row ? JSON.parse(row.data) : undefined;
  }

  private putSnapshotRow(tenantId: string, snapshot: TenantSecuritySnapshot) {
    this.db
      .prepare(
        "INSERT INTO snapshots (tenant_id, data) VALUES (?, ?) ON CONFLICT(tenant_id) DO UPDATE SET data = excluded.data"
      )
      .run(tenantId, JSON.stringify(snapshot));
  }

  private deleteSnapshotRow(tenantId: string) {
    this.db.prepare("DELETE FROM snapshots WHERE tenant_id = ?").run(tenantId);
  }

  private getSettingsRow(): SystemSettings {
    const row = this.db.prepare("SELECT data FROM settings WHERE id = 1").get() as { data: string } | undefined;
    return row ? { ...DEFAULT_SETTINGS, ...JSON.parse(row.data) } : { ...DEFAULT_SETTINGS };
  }

  private putSettingsRow(settings: SystemSettings) {
    this.db
      .prepare("INSERT INTO settings (id, data) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data")
      .run(JSON.stringify(settings));
  }

  private getAuthConfigRow(): AuthConfigRow | undefined {
    const row = this.db.prepare("SELECT password_hash, updated_at FROM auth_config WHERE id = 1").get() as
      | { password_hash: string; updated_at: string }
      | undefined;
    return row ? { passwordHash: row.password_hash, updatedAt: row.updated_at } : undefined;
  }

  private putAuthConfigRow(config: AuthConfigRow) {
    this.db
      .prepare(
        `INSERT INTO auth_config (id, password_hash, updated_at) VALUES (1, ?, ?)
         ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash, updated_at = excluded.updated_at`
      )
      .run(config.passwordHash, config.updatedAt);
  }

  // ---- Secret handling -----------------------------------------------------------
  // Tenants are ALWAYS held on disk with clientSecret and exoRefreshToken
  // encrypted (or absent). Decryption only ever happens transiently, right before a
  // Graph/Exchange Online API call. Anything handed back to an API route/UI goes
  // through sanitizeTenant/sanitizeSnapshot, which mask both entirely — they are
  // write-only fields from the client's perspective.

  private encryptTenantSecret(tenant: Tenant): Tenant {
    const secret = tenant.credentials.clientSecret;
    const refreshToken = tenant.credentials.exoRefreshToken;
    const needsSecretEncryption = secret && !isEncrypted(secret);
    const needsTokenEncryption = refreshToken && !isEncrypted(refreshToken);
    if (!needsSecretEncryption && !needsTokenEncryption) return tenant;
    return {
      ...tenant,
      credentials: {
        ...tenant.credentials,
        clientSecret: needsSecretEncryption ? encryptSecret(secret!) : secret,
        exoRefreshToken: needsTokenEncryption ? encryptSecret(refreshToken!) : refreshToken,
      },
    };
  }

  private sanitizeTenant(tenant: Tenant): Tenant {
    return {
      ...tenant,
      credentials: {
        ...tenant.credentials,
        clientSecret: tenant.credentials.clientSecret ? SECRET_MASK : undefined,
        exoRefreshToken: tenant.credentials.exoRefreshToken ? SECRET_MASK : undefined,
      },
    };
  }

  private sanitizeSnapshot(snapshot: TenantSecuritySnapshot): TenantSecuritySnapshot {
    return { ...snapshot, tenant: this.sanitizeTenant(snapshot.tenant) };
  }

  /** @internal Raw lookup, used only right before a Microsoft Graph/Exchange Online call. */
  private getTenantWithDecryptedSecret(id: string): Tenant | undefined {
    const tenant = this.getTenantRow(id);
    if (!tenant) return undefined;
    const secret = tenant.credentials.clientSecret;
    const refreshToken = tenant.credentials.exoRefreshToken;
    return {
      ...tenant,
      credentials: {
        ...tenant.credentials,
        clientSecret: secret && isEncrypted(secret) ? decryptSecret(secret) : secret,
        exoRefreshToken: refreshToken && isEncrypted(refreshToken) ? decryptSecret(refreshToken) : refreshToken,
      },
    };
  }

  // Exchange Online refresh tokens rotate on every use (single-use, public-
  // client tokens) — this is called as the rotation callback threaded through
  // exo-client.ts's calls so the new token is saved immediately, not just
  // whatever token was current when the sync started.
  private persistExoRefreshToken(tenantId: string, newRefreshToken: string): void {
    const row = this.getTenantRow(tenantId);
    if (!row) return;
    this.putTenantRow({
      ...row,
      credentials: { ...row.credentials, exoRefreshToken: encryptSecret(newRefreshToken) },
    });
  }

  /** @internal Raw (encrypted-secret) snapshot lookup/creation. */
  private ensureSnapshot(tenantId: string): TenantSecuritySnapshot | undefined {
    let snapshot = this.getSnapshotRow(tenantId);
    if (!snapshot && this.getTenantRow(tenantId)) {
      const tenant = this.getTenantRow(tenantId)!;
      snapshot = createBlankSnapshot(tenant);
      this.putSnapshotRow(tenantId, snapshot);
    }
    return snapshot;
  }

  // ---- Public API -----------------------------------------------------------------

  public getAllTenants(): Tenant[] {
    return this.getAllTenantRows().map((t) => this.sanitizeTenant(t));
  }

  public getTenant(id: string): Tenant | undefined {
    const tenant = this.getTenantRow(id);
    return tenant ? this.sanitizeTenant(tenant) : undefined;
  }

  public getSnapshot(tenantId: string): TenantSecuritySnapshot | undefined {
    const snapshot = this.ensureSnapshot(tenantId);
    return snapshot ? this.sanitizeSnapshot(snapshot) : undefined;
  }

  public async syncTenant(
    tenantId: string,
    source: "manual" | "scheduled" = "manual"
  ): Promise<SyncResult | undefined> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return undefined;
    const existing = this.getSnapshotRow(tenantId);
    const { snapshot, error } = await fetchLiveTenantSnapshot(tenant, existing, (newToken) =>
      this.persistExoRefreshToken(tenantId, newToken)
    );
    if (snapshot) {
      // Never let a decrypted secret end up persisted in the snapshot's embedded tenant.
      snapshot.tenant = this.encryptTenantSecret(snapshot.tenant);
      this.putSnapshotRow(tenantId, snapshot);
      return { snapshot: this.sanitizeSnapshot(snapshot), outcome: "synced" };
    }

    // Live fetch failed entirely (e.g. bad credentials) — don't let this look
    // like a success just because a stale cached snapshot exists to fall back on.
    const outcome: SyncOutcome = existing ? "stale_fallback" : "no_data";
    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "tenant_sync_failure",
      action: `${source === "scheduled" ? "Scheduled" : "Manual"} sync failed`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: false,
      detail:
        outcome === "stale_fallback"
          ? `Live Graph sync failed; served cached data from ${existing!.tenant.lastSyncTimestamp}. ${error || ""}`.trim()
          : `Live Graph sync failed; no cached data available. ${error || ""}`.trim(),
    });

    return {
      snapshot: existing ? this.sanitizeSnapshot(existing) : undefined,
      outcome,
      error,
    };
  }

  public async testPermissions(tenantId: string): Promise<TenantPermissionReport | null> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return null;
    return await testAppRegistrationPermissions(tenant);
  }

  public async testExoConnectivity(tenantId: string): Promise<ExoConnectivityResult | null> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return null;
    return await testExoConnectivity(tenant, (newToken) => this.persistExoRefreshToken(tenantId, newToken));
  }

  public async startExoConnect(tenantId: string): Promise<{ result?: DeviceCodeStart; error?: string } | null> {
    const tenant = this.getTenantRow(tenantId);
    if (!tenant) return null;
    return await startExoDeviceCodeFlow(tenant.credentials.tenantId);
  }

  public async pollExoConnect(tenantId: string, deviceCode: string): Promise<{ status: DeviceCodePollStatus; error?: string } | null> {
    const tenant = this.getTenantRow(tenantId);
    if (!tenant) return null;
    const result = await pollExoDeviceCodeFlow(tenant.credentials.tenantId, deviceCode);
    if (result.status === "success" && result.refreshToken) {
      this.persistExoRefreshToken(tenantId, result.refreshToken);
    }
    return { status: result.status, error: result.error };
  }

  public async deployBaselinePolicy(
    tenantId: string,
    baselineCode: string
  ): Promise<{ success: boolean; policy?: any; snapshot?: TenantSecuritySnapshot; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    const deployResult = await deployConditionalAccessPolicy(tenant, baselineCode);
    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "ca_policy_deploy",
      action: `Deploy baseline policy ${baselineCode}`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: deployResult.success,
      detail: deployResult.success
        ? `Created '${deployResult.policy?.displayName || baselineCode}' in Report-Only mode.`
        : deployResult.error,
    });

    if (!deployResult.success) {
      return { success: false, error: deployResult.error };
    }

    // Resync immediately to update live snapshot
    const syncResult = await this.syncTenant(tenantId);
    return {
      success: true,
      policy: deployResult.policy,
      snapshot: syncResult?.snapshot,
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
      // Demo tenants have nothing to validate, so they're immediately "healthy".
      // A newly-added live tenant hasn't had its credentials verified against
      // Microsoft Graph yet — show it as disconnected until the first sync
      // (or permissions check) actually succeeds, rather than a misleading
      // green "healthy" badge for credentials that were never tested.
      connectionStatus: tenantData.isDemo ? "healthy" : "disconnected",
      credentials: tenantData.credentials || {
        tenantId: tenantData.organizationId || crypto.randomUUID(),
        authMode: "mock",
        status: "connected",
      },
      isDemo: tenantData.isDemo ?? false,
    };

    const stored = this.encryptTenantSecret(newTenant);
    const add = this.db.transaction(() => {
      this.putTenantRow(stored);
      this.putSnapshotRow(id, createBlankSnapshot(stored));
    });
    add();
    return this.sanitizeTenant(stored);
  }

  public updateTenant(id: string, updates: Partial<Tenant>): Tenant | undefined {
    const existing = this.getTenantRow(id);
    if (!existing) return undefined;

    let mergedCredentials = existing.credentials;
    if (updates.credentials) {
      const incomingSecret = updates.credentials.clientSecret;
      // A masked value coming back from the UI (or no value at all) means "leave the
      // existing secret alone" — the client never has the real value to send back.
      // exoRefreshToken is deliberately NOT handled here — it's exclusively written by
      // persistExoRefreshToken() as part of the device-code connect/rotation flow, never
      // through this generic update path, so the spread below naturally leaves it alone
      // whenever a caller's update payload doesn't mention it.
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

    const write = this.db.transaction(() => {
      this.putTenantRow(updated);
      const snap = this.getSnapshotRow(id);
      if (snap) {
        snap.tenant = updated;
        this.putSnapshotRow(id, snap);
      }
    });
    write();
    return this.sanitizeTenant(updated);
  }

  public removeTenant(id: string): boolean {
    const exists = !!this.getTenantRow(id);
    if (exists) {
      const remove = this.db.transaction(() => {
        this.deleteTenantRow(id);
        this.deleteSnapshotRow(id);
      });
      remove();
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
    this.putSnapshotRow(tenantId, snap);
    return newEntry;
  }

  public removeTablEntry(tenantId: string, entryId: string): boolean {
    const snap = this.ensureSnapshot(tenantId);
    if (!snap) return false;
    const initialLen = snap.mdoThreat.tabl.length;
    snap.mdoThreat.tabl = snap.mdoThreat.tabl.filter((e) => e.id !== entryId);
    const removed = snap.mdoThreat.tabl.length < initialLen;
    if (removed) this.putSnapshotRow(tenantId, snap);
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
    this.putSnapshotRow(tenantId, snap);
    return newGroup;
  }

  public updateSharePointPolicy(
    tenantId: string,
    updates: Partial<Pick<TenantSecuritySnapshot["sharePoint"], "tenantSharingLevel" | "defaultLinkType" | "anonymousLinkExpirationDays">>
  ) {
    const snap = this.ensureSnapshot(tenantId);
    if (!snap) return null;
    snap.sharePoint = { ...snap.sharePoint, ...updates };
    this.putSnapshotRow(tenantId, snap);
    return snap.sharePoint;
  }

  public isPasswordConfigured(): boolean {
    return !!this.getAuthConfigRow();
  }

  public getPasswordHash(): string | null {
    return this.getAuthConfigRow()?.passwordHash ?? null;
  }

  public setPasswordHash(passwordHash: string): void {
    this.putAuthConfigRow({ passwordHash, updatedAt: new Date().toISOString() });
  }

  public getSettings(): SystemSettings {
    return this.getSettingsRow();
  }

  public updateSettings(updates: Partial<SystemSettings>): SystemSettings {
    const merged = { ...this.getSettingsRow(), ...updates };
    this.putSettingsRow(merged);
    return merged;
  }

  public addAuditLogEntry(entry: Omit<AuditLogEntry, "id">): void {
    this.db
      .prepare(
        `INSERT INTO audit_log (timestamp, category, action, tenant_id, tenant_name, success, detail)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        entry.timestamp,
        entry.category,
        entry.action,
        entry.tenantId ?? null,
        entry.tenantName ?? null,
        entry.success ? 1 : 0,
        entry.detail ?? null
      );

    // Prune on write rather than on a schedule — audit log volume here is low
    // (deploys + MCP tool calls only), so an occasional extra DELETE is cheap and
    // avoids needing a separate timer alongside the sync scheduler.
    const retentionDays = this.getSettingsRow().auditLogRetentionDays;
    if (retentionDays > 0) {
      const cutoff = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
      this.db.prepare("DELETE FROM audit_log WHERE timestamp < ?").run(cutoff);
    }
  }

  public getAuditLog(filters: { tenantId?: string; category?: string; limit?: number } = {}): AuditLogEntry[] {
    const conditions: string[] = [];
    const params: any[] = [];

    if (filters.tenantId) {
      conditions.push("tenant_id = ?");
      params.push(filters.tenantId);
    }
    if (filters.category) {
      conditions.push("category = ?");
      params.push(filters.category);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const limit = Math.min(Math.max(filters.limit ?? 200, 1), 1000);
    params.push(limit);

    const rows = this.db
      .prepare(`SELECT * FROM audit_log ${whereClause} ORDER BY timestamp DESC, id DESC LIMIT ?`)
      .all(...params) as any[];

    return rows.map((r) => ({
      id: r.id,
      timestamp: r.timestamp,
      category: r.category,
      action: r.action,
      tenantId: r.tenant_id ?? undefined,
      tenantName: r.tenant_name ?? undefined,
      success: !!r.success,
      detail: r.detail ?? undefined,
    }));
  }
}

// Global singleton instance
const globalForTenantStore = globalThis as unknown as { tenantStore: TenantStore };
export const tenantStore = globalForTenantStore.tenantStore || new TenantStore();
if (process.env.NODE_ENV !== "production") globalForTenantStore.tenantStore = tenantStore;
