import fs from "fs";
import path from "path";
import Database from "better-sqlite3";
import { Tenant, TenantSecuritySnapshot, SystemSettings, AuditLogEntry, SyncResult, SyncOutcome, SecurityIncidentItem, IncidentStatus } from "../types";
import { INITIAL_TENANTS, MOCK_TENANT_DATA } from "../data/mock-tenants";
import { createBlankSnapshot } from "../data/default-snapshot";
import { encryptSecret, decryptSecret, isEncrypted, SECRET_MASK } from "./crypto";
import {
  fetchLiveTenantSnapshot,
  testAppRegistrationPermissions,
  deployConditionalAccessPolicy,
  TenantPermissionReport,
  getGraphAccessToken,
} from "./graph-client";
import { graphFetch } from "./graph-fetch";

import {
  testExoConnectivity,
  ExoConnectivityResult,
  startExoDeviceCodeFlow,
  pollExoDeviceCodeFlow,
  DeviceCodeStart,
  DeviceCodePollStatus,
  addTenantAllowBlockListItem,
  removeTenantAllowBlockListItem,
  applyMdoRemediation,
  disableForwardingRule as disableForwardingRuleExo,
  removeMailboxDelegation as removeMailboxDelegationExo,
  setMailboxAuditingEnabled as setMailboxAuditingEnabledExo,
  DelegationAccessRight,
} from "./exo-client";
import { mapEntryTypeToListType } from "./mdo-mapper";
import { MDO_BASELINE_STANDARDS } from "../data/mdo-baseline-definitions";
import { MAILFLOW_BASELINE_STANDARDS } from "../data/mailflow-baseline-definitions";

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

// Server-side guard for TABL entries - the Add modal's `required`/`minLength`
// form rules only stop the human UI, not a direct API call or an MCP agent,
// and a write-enabled tenant would otherwise forward garbage straight to a
// live Exchange Online Tenant Allow/Block List write. Both addTablEntry
// callers (the /tabl API route and the manage_tabl MCP tool) funnel through
// this one function, so validating here covers both.
const TABL_DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const TABL_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TABL_SHA256_RE = /^[a-f0-9]{64}$/i;

function validateTablEntryInput(entry: {
  listType?: string;
  entryType?: string;
  value?: string;
  notes?: string;
}): string | null {
  if (entry.listType !== "allow" && entry.listType !== "block") {
    return "listType must be 'allow' or 'block'.";
  }
  if (!["domain", "sender", "url", "file_hash"].includes(entry.entryType || "")) {
    return "entryType must be one of 'domain', 'sender', 'url', 'file_hash'.";
  }
  const value = (entry.value || "").trim();
  if (!value) return "A value is required.";
  if (entry.entryType === "domain" && !TABL_DOMAIN_RE.test(value)) {
    return "Value doesn't look like a valid domain (e.g. contoso.com).";
  }
  if (entry.entryType === "sender" && !TABL_EMAIL_RE.test(value)) {
    return "Value doesn't look like a valid sender email address.";
  }
  if (entry.entryType === "url") {
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return "URL must use http:// or https://.";
      }
    } catch {
      return "Value isn't a valid URL.";
    }
  }
  if (entry.entryType === "file_hash" && !TABL_SHA256_RE.test(value)) {
    return "Value must be a 64-character SHA-256 hex hash.";
  }
  if ((entry.notes || "").trim().length < 10) {
    return "A security/audit reason of at least 10 characters is required.";
  }
  return null;
}

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
  // with demo tenants - that would paper over a real problem with fake data while
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
          `Starting with an empty store rather than risking your data - the original file is untouched. ` +
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
    return row ? this.backfillSnapshot(JSON.parse(row.data)) : undefined;
  }

  // Snapshots are long-lived JSON blobs - a row written before a field existed
  // in TenantSecuritySnapshot (e.g. mdoThreat.alerts) stays missing that field
  // forever, since nothing else ever rewrites it wholesale. Every reader (UI
  // components, this store) relies on the type's fields always being present,
  // so backfill any gaps against createBlankSnapshot's defaults right where the
  // row is deserialized, rather than defending against `undefined` everywhere
  // the snapshot is consumed.
  private backfillSnapshot(snapshot: TenantSecuritySnapshot): TenantSecuritySnapshot {
    const blank = createBlankSnapshot(snapshot.tenant);
    const mockSnap = MOCK_TENANT_DATA[snapshot.tenant.id];
    const incidents =
      Array.isArray(snapshot.incidents) && snapshot.incidents.length > 0
        ? snapshot.incidents
        : (mockSnap?.incidents || []);

    const devices =
      snapshot.intune?.devices && snapshot.intune.devices.length >= (mockSnap?.intune?.devices?.length || 0)
        ? snapshot.intune.devices
        : (mockSnap?.intune?.devices || snapshot.intune?.devices || []);

    return {
      ...blank,
      ...snapshot,
      conditionalAccess: { ...blank.conditionalAccess, ...snapshot.conditionalAccess },
      accountClassification: { ...blank.accountClassification, ...snapshot.accountClassification },
      mdoThreat: { ...blank.mdoThreat, ...snapshot.mdoThreat },
      intune: {
        ...blank.intune,
        ...snapshot.intune,
        devices,
      },
      sharePoint: { ...blank.sharePoint, ...snapshot.sharePoint },
      incidents,
      highRiskThreatIndicators: { ...blank.highRiskThreatIndicators, ...snapshot.highRiskThreatIndicators },
    };
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
  // through sanitizeTenant/sanitizeSnapshot, which mask both entirely - they are
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
  // client tokens) - this is called as the rotation callback threaded through
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

    // Live fetch failed entirely (e.g. bad credentials) - don't let this look
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
      // Microsoft Graph yet - show it as disconnected until the first sync
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
      // existing secret alone" - the client never has the real value to send back.
      // exoRefreshToken is deliberately NOT handled here - it's exclusively written by
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

  // Real Exchange Online writes only happen when BOTH exoRefreshToken and
  // exoWriteEnabled are set - the latter is an explicit, off-by-default admin
  // opt-in (see types/index.ts), since EXO's delegated device-code auth can't
  // be scoped to read-only the way Graph app permissions can. Everything else
  // (no EXO connection, or connected with writes left disabled) keeps the
  // original local-only tracking behavior, flagged via isLocalOnly below -
  // syncTenant() merges those back in after every resync rather than
  // overwriting them (see graph-client.ts's mdoThreat.tabl assignment).
  public async addTablEntry(
    tenantId: string,
    entry: Omit<TenantSecuritySnapshot["mdoThreat"]["tabl"][0], "id" | "dateAdded">
  ): Promise<{ success: boolean; error?: string; entry?: TenantSecuritySnapshot["mdoThreat"]["tabl"][0] }> {
    const validationError = validateTablEntryInput(entry);
    if (validationError) return { success: false, error: validationError };

    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    const value = entry.value.trim();
    const existingSnap = this.getSnapshotRow(tenantId);
    const isDuplicate = existingSnap?.mdoThreat.tabl.some(
      (e) => e.listType === entry.listType && e.entryType === entry.entryType && e.value.toLowerCase() === value.toLowerCase()
    );
    if (isDuplicate) return { success: false, error: `A ${entry.listType} entry for '${value}' already exists.` };

    if (tenant.credentials.exoRefreshToken && tenant.credentials.exoWriteEnabled) {
      const listType = mapEntryTypeToListType(entry.entryType);
      const result = await addTenantAllowBlockListItem(
        tenant,
        {
          listType,
          action: entry.listType === "allow" ? "Allow" : "Block",
          value: entry.value,
          notes: entry.notes,
          expirationDate: entry.expirationDate !== "Never" ? entry.expirationDate : undefined,
        },
        (newToken) => this.persistExoRefreshToken(tenantId, newToken)
      );
      this.addAuditLogEntry({
        timestamp: new Date().toISOString(),
        category: "exo_write",
        action: `Add TABL entry (${entry.listType}/${entry.entryType})`,
        tenantId: tenant.id,
        tenantName: tenant.displayName,
        success: result.success,
        detail: result.success
          ? `Added '${entry.value}' to the live Exchange Online Tenant Allow/Block List.`
          : result.error,
      });
      if (!result.success) return { success: false, error: result.error };

      const syncResult = await this.syncTenant(tenantId);
      const created = syncResult?.snapshot?.mdoThreat.tabl.find((e) => e.value === entry.value);
      return { success: true, entry: created };
    }

    const snap = this.ensureSnapshot(tenantId);
    if (!snap) return { success: false, error: "Tenant not found" };
    const newEntry = {
      ...entry,
      id: `tabl-${Date.now().toString(36)}`,
      dateAdded: new Date().toISOString(),
      isLocalOnly: true,
    };
    snap.mdoThreat.tabl.unshift(newEntry);
    this.putSnapshotRow(tenantId, snap);
    return { success: true, entry: newEntry };
  }

  public async removeTablEntry(tenantId: string, entryId: string): Promise<{ success: boolean; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    if (tenant.credentials.exoRefreshToken && tenant.credentials.exoWriteEnabled) {
      const snap = this.getSnapshotRow(tenantId);
      const target = snap?.mdoThreat.tabl.find((e) => e.id === entryId);
      if (!target) return { success: false, error: "Entry not found." };

      const listType = mapEntryTypeToListType(target.entryType);
      const result = await removeTenantAllowBlockListItem(
        tenant,
        { listType, identity: target.id },
        (newToken) => this.persistExoRefreshToken(tenantId, newToken)
      );
      this.addAuditLogEntry({
        timestamp: new Date().toISOString(),
        category: "exo_write",
        action: `Remove TABL entry (${target.entryType})`,
        tenantId: tenant.id,
        tenantName: tenant.displayName,
        success: result.success,
        detail: result.success
          ? `Removed '${target.value}' from the live Exchange Online Tenant Allow/Block List.`
          : result.error,
      });
      if (!result.success) return { success: false, error: result.error };

      await this.syncTenant(tenantId);
      return { success: true };
    }

    const snap = this.ensureSnapshot(tenantId);
    if (!snap) return { success: false, error: "Tenant not found" };
    const initialLen = snap.mdoThreat.tabl.length;
    snap.mdoThreat.tabl = snap.mdoThreat.tabl.filter((e) => e.id !== entryId);
    const removed = snap.mdoThreat.tabl.length < initialLen;
    if (removed) this.putSnapshotRow(tenantId, snap);
    return removed ? { success: true } : { success: false, error: "Entry not found." };
  }

  // Runs the one-setting EXO fix for a single MDO baseline gap (see
  // MDO_BASELINE_STANDARDS' remediation descriptors) - same
  // exoRefreshToken/exoWriteEnabled gate, audit logging, and post-write resync
  // pattern as addTablEntry/removeTablEntry above, just targeting a Set-*Policy
  // cmdlet instead of a TABL cmdlet.
  public async applyMdoBaselineFix(
    tenantId: string,
    code: string,
    extra?: Record<string, string>
  ): Promise<{ success: boolean; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };
    if (!tenant.credentials.exoRefreshToken || !tenant.credentials.exoWriteEnabled) {
      return { success: false, error: "Exchange Online writes are not enabled for this tenant." };
    }

    const standard = MDO_BASELINE_STANDARDS.find((s) => s.code === code);
    if (!standard || !standard.remediation) {
      return { success: false, error: "No automated fix is available for this check." };
    }

    const snap = this.getSnapshotRow(tenantId);
    const matchingPolicies = (snap?.mdoThreat.policies || []).filter((p) => p.policyType === standard.policyType);
    if (matchingPolicies.length === 0) {
      return { success: false, error: `No ${standard.policyType} policy found to remediate.` };
    }
    // The UI hides the one-click fix whenever more than one policy of this
    // type exists (see MdoPoliciesModule.tsx) since auto-remediating one
    // arbitrary policy while others stay non-compliant would be misleading -
    // this is a defense-in-depth guard for any caller that bypasses the UI
    // (a direct API call, or a future MCP tool).
    if (matchingPolicies.length > 1) {
      return {
        success: false,
        error: `Multiple ${standard.policyType} policies exist - apply this fix manually in Exchange Online.`,
      };
    }
    const policy = matchingPolicies[0];

    const inputField = standard.remediation.requiresInputField;
    if (inputField && !extra?.[inputField.key]?.trim()) {
      return { success: false, error: `${inputField.label} is required to apply this fix.` };
    }

    const parameters = standard.remediation.buildParameters(policy, extra);
    const result = await applyMdoRemediation(tenant, standard.remediation.cmdlet, parameters, (newToken) =>
      this.persistExoRefreshToken(tenantId, newToken)
    );

    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "exo_write",
      action: `Apply MDO baseline fix ${code} (${standard.remediation.cmdlet})`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: result.success,
      detail: result.success ? standard.remediation.summary : result.error,
    });

    if (!result.success) return { success: false, error: result.error };

    await this.syncTenant(tenantId);
    return { success: true };
  }

  // Disables a detected forwarding vector (inbox rule, transport rule, or
  // mailbox-level auto-forward) - same exoRefreshToken/exoWriteEnabled gate,
  // audit logging, and post-write resync pattern as applyMdoBaselineFix above.
  public async disableForwardingRule(tenantId: string, ruleId: string): Promise<{ success: boolean; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };
    if (!tenant.credentials.exoRefreshToken || !tenant.credentials.exoWriteEnabled) {
      return { success: false, error: "Exchange Online writes are not enabled for this tenant." };
    }

    const snap = this.getSnapshotRow(tenantId);
    const rule = snap?.emailForwarding.find((r) => r.id === ruleId);
    if (!rule) return { success: false, error: "Forwarding rule not found." };

    const result = await disableForwardingRuleExo(
      tenant,
      { scope: rule.scope, name: rule.name, mailboxOwner: rule.mailboxOwner },
      (newToken) => this.persistExoRefreshToken(tenantId, newToken)
    );

    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "exo_write",
      action: `Disable forwarding rule (${rule.scope}): ${rule.name}`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: result.success,
      detail: result.success ? `Disabled '${rule.name}' (was forwarding to ${rule.forwardingAddress}).` : result.error,
    });

    if (!result.success) return { success: false, error: result.error };
    await this.syncTenant(tenantId);
    return { success: true };
  }

  // Revokes one FullAccess/SendAs/SendOnBehalf delegation from a mailbox -
  // same gate/audit/resync pattern as the methods above.
  public async revokeMailboxDelegation(
    tenantId: string,
    mailboxId: string,
    principalUserPrincipalName: string,
    accessRight: DelegationAccessRight
  ): Promise<{ success: boolean; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };
    if (!tenant.credentials.exoRefreshToken || !tenant.credentials.exoWriteEnabled) {
      return { success: false, error: "Exchange Online writes are not enabled for this tenant." };
    }

    const snap = this.getSnapshotRow(tenantId);
    const mailbox = snap?.mailboxes.find((m) => m.id === mailboxId);
    if (!mailbox) return { success: false, error: "Mailbox not found." };
    const delegation = mailbox.delegations.find(
      (d) => d.principalUserPrincipalName === principalUserPrincipalName && d.accessRight === accessRight
    );
    if (!delegation) return { success: false, error: "Delegation not found." };

    const remainingSendOnBehalf =
      accessRight === "SendOnBehalf"
        ? mailbox.delegations
            .filter((d) => d.accessRight === "SendOnBehalf" && d.principalUserPrincipalName !== principalUserPrincipalName)
            .map((d) => d.principalUserPrincipalName)
        : undefined;

    const result = await removeMailboxDelegationExo(
      tenant,
      { mailboxUpn: mailbox.userPrincipalName, principalUpn: principalUserPrincipalName, accessRight, remainingSendOnBehalf },
      (newToken) => this.persistExoRefreshToken(tenantId, newToken)
    );

    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "exo_write",
      action: `Revoke ${accessRight} delegation on ${mailbox.userPrincipalName}`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: result.success,
      detail: result.success
        ? `Removed ${principalUserPrincipalName}'s ${accessRight} access to ${mailbox.userPrincipalName}.`
        : result.error,
    });

    if (!result.success) return { success: false, error: result.error };
    await this.syncTenant(tenantId);
    return { success: true };
  }

  // Enables tenant-wide mailbox audit logging - the prerequisite for every
  // delegation/forwarding finding above being investigable after the fact
  // (see the mailboxAuditingEnabled comment in types/index.ts).
  public async setMailboxAuditingEnabled(tenantId: string): Promise<{ success: boolean; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };
    if (!tenant.credentials.exoRefreshToken || !tenant.credentials.exoWriteEnabled) {
      return { success: false, error: "Exchange Online writes are not enabled for this tenant." };
    }

    const result = await setMailboxAuditingEnabledExo(tenant, (newToken) => this.persistExoRefreshToken(tenantId, newToken));

    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "exo_write",
      action: "Enable tenant-wide mailbox audit logging",
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: result.success,
      detail: result.success ? "Set-OrganizationConfig -AuditDisabled $false" : result.error,
    });

    if (!result.success) return { success: false, error: result.error };
    await this.syncTenant(tenantId);
    return { success: true };
  }

  // Runs the remediation for one Mail Flow Rules baseline check (MF01/02/04
  // have one; MF03 is judgment-call-only, same "no auto-fix" convention as
  // MDO09). MF01/02 target a specific transport rule (ruleId required);
  // MF04 targets the tenant-wide outbound spam policy (ruleId ignored).
  // Same gate/audit/resync pattern as applyMdoBaselineFix.
  public async applyMailflowBaselineFix(
    tenantId: string,
    code: string,
    ruleId?: string
  ): Promise<{ success: boolean; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };
    if (!tenant.credentials.exoRefreshToken || !tenant.credentials.exoWriteEnabled) {
      return { success: false, error: "Exchange Online writes are not enabled for this tenant." };
    }

    const standard = MAILFLOW_BASELINE_STANDARDS.find((s) => s.code === code);
    if (!standard || !standard.remediation) {
      return { success: false, error: "No automated fix is available for this check." };
    }

    const snap = this.getSnapshotRow(tenantId);
    let parameters: Record<string, any>;
    let detailName: string;

    if (code === "MF04") {
      const outboundPolicy = snap?.mdoThreat.policies.find((p) => p.policyType === "AntiSpamOutbound");
      parameters = standard.remediation.buildParameters(outboundPolicy?.displayName || "Default");
      detailName = "tenant-wide auto-forwarding (outbound spam policy)";
    } else if (code === "MF07") {
      parameters = standard.remediation.buildParameters("Default");
      detailName = "tenant-wide auto-forwarding (remote domain)";
    } else if (code === "MF08") {
      parameters = standard.remediation.buildParameters("");
      detailName = "external sender warning tag";
    } else {
      // MF01/MF02 target a specific transport rule. MF05/MF06 (connectors)
      // have no remediation defined at all - the !standard.remediation
      // guard above already returned before reaching here for those codes.
      if (!ruleId) return { success: false, error: "Missing ruleId for this fix." };
      const rule = snap?.mailflowTransportRules.find((r) => r.id === ruleId);
      if (!rule) return { success: false, error: "Transport rule not found." };
      parameters = standard.remediation.buildParameters(rule.name);
      detailName = rule.name;
    }

    const result = await applyMdoRemediation(tenant, standard.remediation.cmdlet, parameters, (newToken) =>
      this.persistExoRefreshToken(tenantId, newToken)
    );

    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "exo_write",
      action: `Apply Mail Flow Rules baseline fix ${code} (${standard.remediation.cmdlet})`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: result.success,
      detail: result.success ? `${standard.remediation.summary} (${detailName})` : result.error,
    });

    if (!result.success) return { success: false, error: result.error };
    await this.syncTenant(tenantId);
    return { success: true };
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

    // Prune on write rather than on a schedule - audit log volume here is low
    // (deploys + MCP tool calls only), so an occasional extra DELETE is cheap and
    // avoids needing a separate timer alongside the sync scheduler.
    const retentionDays = this.getSettingsRow().auditLogRetentionDays;
    if (retentionDays > 0) {
      const cutoff = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
      this.db.prepare("DELETE FROM audit_log WHERE timestamp < ?").run(cutoff);
    }
  }

  public async containUserAccount(
    tenantId: string,
    options: {
      userId?: string;
      userPrincipalName: string;
      revokeTokens: boolean;
      disableAccount: boolean;
      resetPassword: boolean;
      purgeForwardingRules: boolean;
      reason?: string;
    }
  ): Promise<{
    success: boolean;
    actionsExecuted: string[];
    errors: string[];
    snapshot?: TenantSecuritySnapshot;
  }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, actionsExecuted: [], errors: ["Tenant not found"] };

    const actionsExecuted: string[] = [];
    const errors: string[] = [];
    const target = options.userId || options.userPrincipalName;

    // 1. Live Microsoft Graph actions if credentials configured and not demo
    if (!tenant.isDemo && tenant.credentials?.clientId && tenant.credentials?.clientSecret) {
      const { token, error: tokenError } = await getGraphAccessToken(tenant.credentials);
      if (token) {
        const headers = {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        };

        if (options.revokeTokens) {
          try {
            const res = await graphFetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(target)}/revokeSignInSessions`, {
              method: "POST",
              headers,
            });
            if (res.ok) {
              actionsExecuted.push("Revoked active sign-in sessions and refresh tokens.");
            } else {
              const data = await res.json().catch(() => ({}));
              errors.push(`Token revocation: ${data.error?.message || res.statusText}`);
            }
          } catch (e: any) {
            errors.push(`Token revocation: ${e.message}`);
          }
        }

        if (options.disableAccount) {
          try {
            const res = await graphFetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(target)}`, {
              method: "PATCH",
              headers,
              body: JSON.stringify({ accountEnabled: false }),
            });
            if (res.ok) {
              actionsExecuted.push("Disabled account in Microsoft Entra ID.");
            } else {
              const data = await res.json().catch(() => ({}));
              errors.push(`Account disablement: ${data.error?.message || res.statusText}`);
            }
          } catch (e: any) {
            errors.push(`Account disablement: ${e.message}`);
          }
        }

        if (options.resetPassword) {
          try {
            const res = await graphFetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(target)}`, {
              method: "PATCH",
              headers,
              body: JSON.stringify({
                passwordProfile: {
                  forceChangePasswordNextSignIn: true,
                },
              }),
            });
            if (res.ok) {
              actionsExecuted.push("Enforced password change on next sign-in.");
            } else {
              const data = await res.json().catch(() => ({}));
              errors.push(`Password reset flag: ${data.error?.message || res.statusText}`);
            }
          } catch (e: any) {
            errors.push(`Password reset flag: ${e.message}`);
          }
        }
      } else if (tokenError) {
        errors.push(`Graph authentication: ${tokenError}`);
      }
    } else {
      // Simulation mode for demo / offline
      if (options.revokeTokens) actionsExecuted.push("Revoked active sign-in sessions (Simulated).");
      if (options.disableAccount) actionsExecuted.push("Disabled user account (Simulated).");
      if (options.resetPassword) actionsExecuted.push("Enforced password change on next sign-in (Simulated).");
    }

    // 2. Exchange Online forwarding rule purge if requested
    if (options.purgeForwardingRules) {
      const snap = this.ensureSnapshot(tenantId);
      if (snap) {
        const userRules = snap.emailForwarding.filter(
          (r) =>
            r.mailboxOwner?.toLowerCase() === options.userPrincipalName.toLowerCase() ||
            r.mailboxOwner?.toLowerCase() === options.userId?.toLowerCase()
        );
        for (const rule of userRules) {
          if (tenant.credentials?.exoRefreshToken && tenant.credentials?.exoWriteEnabled) {
            await disableForwardingRuleExo(
              tenant,
              { scope: rule.scope, name: rule.name, mailboxOwner: rule.mailboxOwner },
              () => {}
            );
          }
          rule.state = "Disabled";
          actionsExecuted.push(`Disabled forwarding rule: '${rule.name}'`);
        }
      }
    }

    // 3. Update local snapshot state
    const snap = this.ensureSnapshot(tenantId);
    if (snap) {
      const user = snap.accountClassification.users.find(
        (u) => u.userPrincipalName.toLowerCase() === options.userPrincipalName.toLowerCase() || u.id === options.userId
      );
      if (user && options.disableAccount) {
        user.accountEnabled = false;
        user.classification = "disabled";
      }

      const mfaUser = snap.mfaAudit.find(
        (u) => u.userPrincipalName.toLowerCase() === options.userPrincipalName.toLowerCase() || u.id === options.userId
      );
      if (mfaUser && options.disableAccount) {
        mfaUser.accountEnabled = false;
      }

      this.putSnapshotRow(tenantId, snap);
    }

    // 4. Log to Audit Log
    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "incident_containment",
      action: `Contain user account: ${options.userPrincipalName}`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: errors.length === 0,
      detail:
        actionsExecuted.join(" | ") +
        (errors.length > 0 ? ` (Errors: ${errors.join(", ")})` : "") +
        (options.reason ? ` - Reason: ${options.reason}` : ""),
    });

    return {
      success: errors.length === 0 || actionsExecuted.length > 0,
      actionsExecuted,
      errors,
      snapshot: this.ensureSnapshot(tenantId) || undefined,
    };
  }

  public async isolateEndpointDevice(
    tenantId: string,
    deviceId: string,
    deviceName: string,
    comment?: string
  ): Promise<{ success: boolean; error?: string; snapshot?: TenantSecuritySnapshot }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    let success = true;
    let errorDetail: string | undefined;

    if (!tenant.isDemo && tenant.credentials?.clientId && tenant.credentials?.clientSecret) {
      const { token, error: tokenError } = await getGraphAccessToken(tenant.credentials);
      if (token) {
        try {
          const res = await graphFetch(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${encodeURIComponent(deviceId)}/isolateDevice`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ comment: comment || "Isolated by Clarity365 Incident Response" }),
          });
          if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            success = false;
            errorDetail = data.error?.message || `Device isolation returned HTTP ${res.status}`;
          }
        } catch (e: any) {
          success = false;
          errorDetail = e.message;
        }
      } else {
        success = false;
        errorDetail = tokenError || "Failed to obtain Graph access token";
      }
    }

    const snap = this.ensureSnapshot(tenantId);
    if (snap) {
      const dev = snap.intune.devices.find((d) => d.id === deviceId || d.deviceName.toLowerCase() === deviceName.toLowerCase());
      if (dev) {
        (dev as any).isIsolated = true;
      }
      if (Array.isArray(snap.incidents)) {
        snap.incidents.forEach((inc) => {
          inc.impactedDevices.forEach((d) => {
            if (d.id === deviceId || d.deviceName.toLowerCase() === deviceName.toLowerCase()) {
              d.isIsolated = true;
            }
          });
        });
      }
      this.putSnapshotRow(tenantId, snap);
    }

    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "device_isolation",
      action: `Isolate Endpoint Device: ${deviceName}`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success,
      detail: success ? `Device '${deviceName}' successfully isolated from network.` : errorDetail,
    });

    return { success, error: errorDetail, snapshot: this.ensureSnapshot(tenantId) || undefined };
  }

  public async scanEndpointDevice(
    tenantId: string,
    deviceId: string,
    deviceName: string,
    scanType: "quickScan" | "fullScan" = "quickScan"
  ): Promise<{ success: boolean; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    let success = true;
    let errorDetail: string | undefined;

    if (!tenant.isDemo && tenant.credentials?.clientId && tenant.credentials?.clientSecret) {
      const { token, error: tokenError } = await getGraphAccessToken(tenant.credentials);
      if (token) {
        try {
          const res = await graphFetch(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${encodeURIComponent(deviceId)}/windowsDefenderScan`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ quickScan: scanType === "quickScan" }),
          });
          if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            success = false;
            errorDetail = data.error?.message || `Defender scan returned HTTP ${res.status}`;
          }
        } catch (e: any) {
          success = false;
          errorDetail = e.message;
        }
      } else {
        success = false;
        errorDetail = tokenError || "Failed to obtain Graph access token";
      }
    }

    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "device_scan",
      action: `Trigger Defender Scan: ${deviceName} (${scanType})`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success,
      detail: success ? `Triggered ${scanType} on '${deviceName}'.` : errorDetail,
    });

    return { success, error: errorDetail };
  }

  public updateSecurityIncident(
    tenantId: string,
    incidentId: string,
    updates: Partial<SecurityIncidentItem>
  ): { success: boolean; snapshot?: TenantSecuritySnapshot } {
    const snap = this.ensureSnapshot(tenantId);
    if (!snap || !Array.isArray(snap.incidents)) return { success: false };

    const incident = snap.incidents.find((i) => i.id === incidentId || i.incidentId === incidentId);
    if (!incident) return { success: false };

    Object.assign(incident, updates);
    incident.lastUpdateDateTime = new Date().toISOString();
    this.putSnapshotRow(tenantId, snap);

    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "incident_containment",
      action: `Update Incident ${incident.incidentId}: ${updates.status || "Updated"}`,
      tenantId,
      tenantName: snap.tenant.displayName,
      success: true,
      detail: `Status updated to '${updates.status || incident.status}' for '${incident.displayName}'.`,
    });

    return { success: true, snapshot: snap };
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
