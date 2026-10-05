import fs from "fs";
import path from "path";
import crypto from "crypto";
import { Readable } from "stream";
import Database from "better-sqlite3";
import Papa from "papaparse";
import {
  Tenant,
  ScenarioConfirmationKey,
  TenantSecuritySnapshot,
  SystemSettings,
  AuditLogEntry,
  SyncResult,
  SyncOutcome,
  SecurityIncidentItem,
  IncidentStatus,
  FleetPostureSummary,
  FleetLicenseOptimizationSummary,
  FleetSearchResultItem,
  AsrRuleActivitySummary,
  AsrDetectionEvent,
  AsrDetectionTimeRange,
  UnifiedAuditLogImport,
  UnifiedAuditLogRecord,
  UnifiedAuditLogSearchFilters,
  UnifiedAuditLogSearchResult,
  UnifiedAuditLogImportProgress,
  AuditLogFlagsResult,
  DefenderAvPolicySettings,
  EdrPolicySettings,
  BitLockerPolicySettings,
  IntuneAssignmentTarget,
  AsrRuleMode,
  MdeConnectorSettings,
} from "../types";
import { mapCsvRowToRecord, getExportCapWarning, RawCsvRow } from "./audit-log-parser";
import { AUDIT_INVESTIGATION_TEMPLATES } from "../data/audit-investigation-templates";
import { flagMassDeletionBursts, flagPossibleBec } from "./audit-log-heuristics";
import {
  computeFleetPosture,
  computeFleetLicenseWaste,
  searchAcrossFleet,
} from "./fleet-analyzer";
import { INITIAL_TENANTS, MOCK_TENANT_DATA } from "../data/mock-tenants";
import { mergeDemoCaPolicies } from "../utils/demo-ca-policy-merge";
import { canWriteToExchange } from "../utils/exchange-access";
import { SNAPSHOT_SYNC_SCHEMA_VERSION, shouldRefuseSnapshotOverwrite, storedSchemaVersion } from "../utils/sync-schema-version";
import { createBlankSnapshot } from "../data/default-snapshot";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { encryptSecret, decryptSecret, isEncrypted, SECRET_MASK } from "./crypto";
import {
  fetchLiveTenantSnapshot,
  testAppRegistrationPermissions,
  deployConditionalAccessPolicy,
  TenantPermissionReport,
  getGraphAccessToken,
  invalidateGraphTokenCache,
  hasLifetimeValidationError,
  fetchAsrDetectionSummaries,
  fetchAsrDetectionEvents,
  TOTAL_SYNC_STEPS,
  fetchDefenderAvPolicy as fetchDefenderAvPolicyGraph,
  deployDefenderAvPolicy,
  fetchEdrPolicy as fetchEdrPolicyGraph,
  deployEdrPolicy as deployEdrPolicyGraph,
  fetchBitLockerPolicy as fetchBitLockerPolicyGraph,
  deployBitLockerPolicy as deployBitLockerPolicyGraph,
  deployAsrRulePolicy,
  updateMdeConnectorSettings as updateMdeConnectorSettingsGraph,
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
  invalidateExoAppAccessCache,
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
// Shown when an Exchange write is attempted but not allowed: either the
// tenant's write switch is off, or its Exchange access can't write (for
// example the app only has Global Reader).
const EXCHANGE_WRITES_UNAVAILABLE =
  "Exchange changes aren't available for this tenant. Turn on Exchange writes in the Permissions check, and make sure the app has the Exchange Administrator role.";

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

export interface SyncProgressState {
  step: string;
  stepIndex: number;
  totalSteps: number;
  startedAt: number;
}

interface SyncProgressCacheGlobal {
  clarity365SyncProgress?: Map<string, SyncProgressState>;
}

// In-memory only, keyed by tenant id - a live sync's step-by-step progress
// isn't data worth persisting to SQLite, just a transient status the UI
// polls while a sync is actually running. Same globalThis pattern as
// graph-client.ts's tokenCache, so a Next.js dev-mode hot-reload doesn't
// spawn a second map and lose track of an in-flight sync's progress.
const syncProgressCacheGlobal = globalThis as unknown as SyncProgressCacheGlobal;
if (!syncProgressCacheGlobal.clarity365SyncProgress) {
  syncProgressCacheGlobal.clarity365SyncProgress = new Map<string, SyncProgressState>();
}
const syncProgressCache = syncProgressCacheGlobal.clarity365SyncProgress;

// Exported so the sync-progress API route can read it without needing a
// TenantStore instance method for what is, deliberately, not persisted
// state.
export function getSyncProgress(tenantId: string): SyncProgressState | undefined {
  return syncProgressCache.get(tenantId);
}

interface AuditImportProgressCacheGlobal {
  clarity365AuditImportProgress?: Map<string, UnifiedAuditLogImportProgress>;
}

// Same globalThis-cached-Map pattern as syncProgressCache above, for CSV
// import progress instead of a live Graph sync. Unlike a tenant sync, an
// import is a genuine streaming parse of a file whose total row count isn't
// known upfront (no second pass just to count lines first) - so this reports
// a live rows-processed counter rather than a step index/percentage.
const auditImportProgressCacheGlobal = globalThis as unknown as AuditImportProgressCacheGlobal;
if (!auditImportProgressCacheGlobal.clarity365AuditImportProgress) {
  auditImportProgressCacheGlobal.clarity365AuditImportProgress = new Map<string, UnifiedAuditLogImportProgress>();
}
const auditImportProgressCache = auditImportProgressCacheGlobal.clarity365AuditImportProgress;

export function getAuditImportProgress(tenantId: string): UnifiedAuditLogImportProgress | undefined {
  return auditImportProgressCache.get(tenantId);
}

interface TenantStoreDbGlobal {
  clarity365TenantStoreDb?: Database.Database;
}
const globalForDb = globalThis as unknown as TenantStoreDbGlobal;

// SQLite-backed store for multi-tenant configurations and snapshots. Each entity is
// still just a JSON blob (same shape the app already used), but as its own row with
// real transactional writes instead of a full-file rewrite on every mutation.
class TenantStore {
  private db: Database.Database;

  constructor() {
    // Dev-mode only: reuse the already-open SQLite connection across a
    // Next.js hot-reload instead of opening a second one. This is
    // deliberately scoped to just the raw connection, not the whole
    // TenantStore instance (see the exported `tenantStore` below for why
    // caching the instance itself caused edited methods to silently keep
    // running pre-edit code until a full server restart).
    if (process.env.NODE_ENV !== "production" && globalForDb.clarity365TenantStoreDb) {
      this.db = globalForDb.clarity365TenantStoreDb;
    } else {
      const dataDir = path.join(process.cwd(), "data");
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }
      this.db = new Database(path.join(dataDir, "clarity365.db"));
      this.db.pragma("journal_mode = WAL");
      if (process.env.NODE_ENV !== "production") globalForDb.clarity365TenantStoreDb = this.db;
    }
    // initSchema is CREATE TABLE IF NOT EXISTS (idempotent); both migration
    // methods already check "is this already done?" before acting - safe
    // and cheap to re-run every time a fresh instance is constructed below.
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
      CREATE TABLE IF NOT EXISTS ual_imports (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        uploaded_at TEXT NOT NULL,
        row_count INTEGER NOT NULL,
        skipped_row_count INTEGER NOT NULL,
        earliest_event TEXT,
        latest_event TEXT,
        possibly_capped INTEGER NOT NULL DEFAULT 0,
        export_cap_warning TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_ual_imports_tenant ON ual_imports (tenant_id, uploaded_at DESC);
      CREATE TABLE IF NOT EXISTS ual_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        import_id TEXT NOT NULL,
        creation_date TEXT NOT NULL,
        record_type TEXT,
        operation TEXT,
        user_id TEXT,
        client_ip TEXT,
        session_id TEXT,
        client_info TEXT,
        result_status TEXT,
        workload TEXT,
        raw_data TEXT NOT NULL,
        parse_error INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_ual_records_tenant_session ON ual_records (tenant_id, session_id);
      CREATE INDEX IF NOT EXISTS idx_ual_records_tenant_user ON ual_records (tenant_id, user_id);
      CREATE INDEX IF NOT EXISTS idx_ual_records_tenant_operation ON ual_records (tenant_id, operation);
      CREATE INDEX IF NOT EXISTS idx_ual_records_tenant_date ON ual_records (tenant_id, creation_date);
      CREATE INDEX IF NOT EXISTS idx_ual_records_import ON ual_records (import_id);
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

    // Same "demo tenants always reflect current mock-tenants.ts" rule as
    // users/mailboxes/signIns below - the old length-comparison heuristic
    // (keep whichever side had more devices) looked reasonable but silently
    // preserved a stale already-persisted demo device list whenever a
    // mock-tenants.ts edit only changed fields on existing devices (adding
    // nonComplianceReasons, say) without changing the device count - the
    // exact same staleness class signIns hit, caught here before it shipped
    // by remembering that precedent rather than rediscovering it live.
    const devices =
      snapshot.tenant.isDemo && mockSnap?.intune?.devices && mockSnap.intune.devices.length > 0
        ? mockSnap.intune.devices
        : (snapshot.intune?.devices || mockSnap?.intune?.devices || []);

    const users =
      snapshot.tenant.isDemo && mockSnap?.accountClassification?.users && mockSnap.accountClassification.users.length > 0
        ? mockSnap.accountClassification.users
        : (snapshot.accountClassification?.users || mockSnap?.accountClassification?.users || []);

    const mailboxes =
      snapshot.tenant.isDemo && mockSnap?.mailboxes && mockSnap.mailboxes.length > 0
        ? mockSnap.mailboxes
        : (snapshot.mailboxes || mockSnap?.mailboxes || []);

    // Same "demo tenants always reflect current mock-tenants.ts" rule as
    // users/mailboxes above - without this, a demo tenant seeded before a
    // mock-tenants.ts edit keeps serving its old, already-persisted signIns
    // forever, since nothing else ever rewrites a mock tenant's snapshot
    // (fetchLiveTenantSnapshot short-circuits unchanged for authMode ===
    // "mock"). Found via exactly that: normalizing mock signIns' country
    // values to ISO-2 codes had no visible effect until this was added.
    const signIns =
      snapshot.tenant.isDemo && mockSnap?.signIns && mockSnap.signIns.length > 0
        ? mockSnap.signIns
        : (snapshot.signIns || mockSnap?.signIns || []);

    return {
      ...blank,
      ...snapshot,
      conditionalAccess: {
        ...blank.conditionalAccess,
        ...snapshot.conditionalAccess,
        // Demo tenants: refresh policy shapes and named locations from
        // mock-tenants.ts (never re-synced otherwise), merging rather than
        // replacing policies so local demo deploys survive - see
        // mergeDemoCaPolicies. Added for Security Simulations Stage 1.
        ...(snapshot.tenant.isDemo && mockSnap?.conditionalAccess
          ? {
              policies: mergeDemoCaPolicies(snapshot.conditionalAccess?.policies || [], mockSnap.conditionalAccess.policies),
              namedLocations: mockSnap.conditionalAccess.namedLocations ?? snapshot.conditionalAccess?.namedLocations,
            }
          : {}),
      },
      identitySettings:
        snapshot.tenant.isDemo && mockSnap?.identitySettings ? mockSnap.identitySettings : snapshot.identitySettings,
      // Security Simulations Stage 5: same demo refresh rule. These are never
      // written locally, so the mock value simply wins for demo tenants.
      exchangeSecurity: snapshot.tenant.isDemo && mockSnap ? mockSnap.exchangeSecurity : snapshot.exchangeSecurity,
      privilegedRoleAssignments: snapshot.tenant.isDemo && mockSnap ? mockSnap.privilegedRoleAssignments : snapshot.privilegedRoleAssignments,
      oauthConsentGrants: snapshot.tenant.isDemo && mockSnap ? mockSnap.oauthConsentGrants : snapshot.oauthConsentGrants,
      alertPolicies: snapshot.tenant.isDemo && mockSnap ? mockSnap.alertPolicies : snapshot.alertPolicies,
      accountClassification: {
        ...blank.accountClassification,
        ...snapshot.accountClassification,
        users,
      },
      mailboxes,
      signIns,
      mdoThreat: { ...blank.mdoThreat, ...snapshot.mdoThreat },
      intune: {
        ...blank.intune,
        ...snapshot.intune,
        devices,
      },
      sharePoint: {
        ...blank.sharePoint,
        ...snapshot.sharePoint,
        // Demo tenants: only the Security Simulations Stage 5 setting fields
        // come from mock-tenants.ts - sites stay as stored, since the
        // SharePoint module can change them locally.
        ...(snapshot.tenant.isDemo && mockSnap?.sharePoint
          ? {
              linkDefaultsReported: mockSnap.sharePoint.linkDefaultsReported,
              resharingByExternalUsersEnabled: mockSnap.sharePoint.resharingByExternalUsersEnabled,
              unmanagedSyncAppRestricted: mockSnap.sharePoint.unmanagedSyncAppRestricted,
              syncAllowedDomainCount: mockSnap.sharePoint.syncAllowedDomainCount,
              sharingDomainRestrictionMode: mockSnap.sharePoint.sharingDomainRestrictionMode,
              legacyAuthProtocolsEnabled: mockSnap.sharePoint.legacyAuthProtocolsEnabled,
              idleSessionSignOutEnabled: mockSnap.sharePoint.idleSessionSignOutEnabled,
              requireAcceptingUserToMatchInvitedUser: mockSnap.sharePoint.requireAcceptingUserToMatchInvitedUser,
            }
          : {}),
      },
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
    const startedAt = Date.now();
    syncProgressCache.set(tenantId, { step: "Starting sync...", stepIndex: 0, totalSteps: TOTAL_SYNC_STEPS, startedAt });
    try {
      return await this.runSync(tenantId, tenant, existing, source, startedAt);
    } finally {
      // Always clear, success or failure, so a stale "in progress" state can
      // never outlive the sync that created it.
      syncProgressCache.delete(tenantId);
    }
  }

  private async runSync(
    tenantId: string,
    tenant: Tenant,
    existing: TenantSecuritySnapshot | undefined,
    source: "manual" | "scheduled",
    startedAt: number
  ): Promise<SyncResult | undefined> {
    // Read before fetching: fetchLiveTenantSnapshot builds on `existing`
    // and mutates it in place, including its syncSchemaVersion.
    const storedVersion = storedSchemaVersion(existing);
    const runFetch = () =>
      fetchLiveTenantSnapshot(
        tenant,
        existing,
        (newToken) => this.persistExoRefreshToken(tenantId, newToken),
        (step, stepIndex, totalSteps) => syncProgressCache.set(tenantId, { step, stepIndex, totalSteps, startedAt })
      );

    let { snapshot, error } = await runFetch();

    // fetchLiveTenantSnapshot fetches ONE token at the top and reuses it
    // across ~20 sequential sync sections, so it can't use
    // withFreshTokenOnLifetimeError's per-call retry itself - see that
    // function's comment in graph-client.ts for the full live diagnosis of
    // why a cached token that's still "valid" by our own bookkeeping can be
    // genuinely rejected by one specific Graph resource mid-sync, while
    // every other resource keeps accepting it. Detected here, not inside
    // that function, because it almost always returns a snapshot even on
    // partial failure - the per-section errors land in
    // snapshot.syncHealth.errors, not this call's own {error}. Confirmed
    // safe to retry the whole sync: fetchLiveTenantSnapshot is read-only
    // (no write calls anywhere in it), and its one side effect - EXO
    // refresh-token rotation - is self-idempotent by design.
    if (hasLifetimeValidationError(snapshot?.syncHealth?.errors)) {
      invalidateGraphTokenCache(tenant.credentials);
      const retry = await runFetch();
      if (retry.snapshot) {
        snapshot = retry.snapshot;
        error = retry.error;
      }
    }

    if (snapshot && shouldRefuseSnapshotOverwrite(storedVersion)) {
      // This build is older than the one that wrote the stored snapshot
      // (typically a long-running dev server that predates a sync change).
      // Saving would silently drop the newer build's data - see
      // src/lib/utils/sync-schema-version.ts. Keep what's stored.
      const detail = `Sync skipped: stored data was written by a newer version of Clarity365 (sync schema ${storedVersion}, this server runs ${SNAPSHOT_SYNC_SCHEMA_VERSION}). Restart the server to load the current code.`;
      this.addAuditLogEntry({
        timestamp: new Date().toISOString(),
        category: "tenant_sync_failure",
        action: `${source === "scheduled" ? "Scheduled" : "Manual"} sync skipped`,
        tenantId: tenant.id,
        tenantName: tenant.displayName,
        success: false,
        detail,
      });
      const stored = this.getSnapshotRow(tenantId);
      return { snapshot: stored ? this.sanitizeSnapshot(stored) : undefined, outcome: "stale_fallback", error: detail };
    }

    if (snapshot) {
      // Never let a decrypted secret end up persisted in the snapshot's embedded tenant.
      snapshot.tenant = this.encryptTenantSecret(snapshot.tenant);
      // A confirmation saved while this sync was running must not be lost:
      // the sync started from a copy of the tenant row taken before it.
      const latestRow = this.getTenantRow(tenantId);
      if (latestRow) snapshot.tenant.scenarioConfirmations = latestRow.scenarioConfirmations;
      this.putSnapshotRow(tenantId, snapshot);
      // The snapshot's embedded tenant carries the freshly-computed connectionStatus/
      // lastSyncTimestamp (see graph-client.ts), but that's a copy living inside the
      // snapshot blob - the canonical `tenants` row (what getAllTenants()/getTenant()
      // return, i.e. what the Header badge and Fleet Posture Matrix actually read) was
      // never being updated here, so a tenant could sync successfully forever and still
      // show whatever status it had at creation.
      this.putTenantRow(snapshot.tenant);
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

    // Persist the failure onto the tenant record itself - otherwise
    // connectionStatus silently stays whatever it was from the last
    // successful sync (e.g. "healthy") even while every subsequent attempt
    // keeps failing. Patch the raw row (never the decrypted `tenant` local)
    // so the encrypted clientSecret/exoRefreshToken are never re-persisted
    // in plaintext, same pattern as persistExoRefreshToken().
    const rawRow = this.getTenantRow(tenantId);
    if (rawRow && rawRow.connectionStatus !== "error") {
      this.putTenantRow({ ...rawRow, connectionStatus: "error" });
    }

    const sanitizedExisting = existing ? this.sanitizeSnapshot(existing) : undefined;
    return {
      snapshot: sanitizedExisting
        ? { ...sanitizedExisting, tenant: { ...sanitizedExisting.tenant, connectionStatus: "error" } }
        : undefined,
      outcome,
      error,
    };
  }

  public async testPermissions(tenantId: string): Promise<TenantPermissionReport | null> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return null;
    // Force a fresh access token rather than reusing getGraphAccessToken's
    // cached one (keyed by tenantId:clientId, good for up to ~55 minutes -
    // see invalidateGraphTokenCache's own comment). Granting a new API
    // permission's admin consent in Entra never invalidates tokens already
    // issued before that grant, only tokens requested after it - so without
    // this, clicking "Re-Test Permissions" right after granting consent kept
    // silently re-testing the same stale token and showing the exact same
    // (now-wrong) result until the cache happened to expire on its own.
    // Live report: PermissionsModal.tsx's Re-Test button appeared to do
    // nothing (or "instantly" pass through the write-permission check, which
    // decodeAppRolesFromToken() now does synchronously from that cached
    // token instead of a live network probe) until a full page reload
    // eventually outlasted the cache. This is the one deliberate exception
    // to reusing the token cache - every other call site still benefits from
    // it for performance.
    invalidateGraphTokenCache(tenant.credentials);
    return await testAppRegistrationPermissions(tenant);
  }

  // On-demand only (Advanced Hunting) - not part of syncTenant, see
  // graph-client.fetchAsrDetectionSummaries for why.
  public async getAsrDetectionSummaries(
    tenantId: string,
    timeRange: AsrDetectionTimeRange = "30d"
  ): Promise<{ summaries?: AsrRuleActivitySummary[]; error?: string } | null> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return null;
    const currentRuleStates = this.getSnapshot(tenantId)?.asrRules || [];
    return await fetchAsrDetectionSummaries(tenant, currentRuleStates, timeRange);
  }

  public async getAsrDetectionEvents(
    tenantId: string,
    ruleId: string,
    timeRange: AsrDetectionTimeRange = "30d"
  ): Promise<{ events?: AsrDetectionEvent[]; error?: string } | null> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return null;
    return await fetchAsrDetectionEvents(tenant, ruleId, timeRange);
  }

  public async testExoConnectivity(tenantId: string): Promise<ExoConnectivityResult | null> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return null;
    const result = await testExoConnectivity(tenant, (newToken) => this.persistExoRefreshToken(tenantId, newToken));
    // Save the app-only status so modules and the Permissions check reflect
    // it straight away, without waiting for the next sync. Patches the raw
    // row (never the decrypted tenant), like persistExoRefreshToken.
    if (result.appAccess) {
      const row = this.getTenantRow(tenantId);
      if (row) this.putTenantRow({ ...row, credentials: { ...row.credentials, exoAppAccess: result.appAccess } });
    }
    return result;
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

    // Update snapshot in store
    const snap = this.getSnapshot(tenantId);
    if (snap) {
      const existingPolicies = snap.conditionalAccess?.policies || [];
      const updatedPolicies = [...existingPolicies];
      const idx = updatedPolicies.findIndex(
        (p) =>
          p.baselineCode?.toUpperCase() === baselineCode.toUpperCase() ||
          p.name.toUpperCase().startsWith(`${baselineCode.toUpperCase()}:`) ||
          p.name.toUpperCase().startsWith(`${baselineCode.toUpperCase()} `)
      );

      if (idx >= 0) {
        updatedPolicies[idx] = {
          ...updatedPolicies[idx],
          state: "enabledForReportingButNotEnforced",
          modifiedDateTime: new Date().toISOString(),
        };
      } else {
        const baselineDef = CA_BASELINE_STANDARDS.find((b) => b.code === baselineCode);
        updatedPolicies.push({
          id: `pol-ca-${Date.now()}-${baselineCode.toLowerCase()}`,
          name: `${baselineCode}: ${baselineDef?.name || "Baseline Policy"}`,
          state: "enabledForReportingButNotEnforced",
          baselineCode,
          createdDateTime: new Date().toISOString(),
          modifiedDateTime: new Date().toISOString(),
          grantControls:
            baselineCode === "CA07"
              ? ["mfa", "passwordChange"]
              : baselineCode === "CA01" || baselineCode === "CA08"
              ? ["block"]
              : baselineCode === "CA09"
              ? ["compliantDevice", "domainJoinedDevice"]
              : baselineCode === "CA10"
              ? ["authenticationStrength:PhishingResistantMFA"]
              : ["mfa"],
          conditions: {
            users: {
              include:
                baselineCode === "CA03" || baselineCode === "CA10"
                  ? ["DirectoryRole:GlobalAdmin", "DirectoryRole:SecurityAdmin"]
                  : ["All"],
              exclude: [],
            },
            applications: {
              include: baselineCode === "CA05" ? ["797f4846-ba00-4fd7-ba43-dac1f8f63013"] : ["All"],
              exclude: [],
            },
            clientAppTypes: baselineCode === "CA01" ? ["exchangeActiveSync", "other"] : ["all"],
            ...(baselineCode === "CA06" ? { signInRiskLevels: ["medium", "high"] } : {}),
            ...(baselineCode === "CA07" ? { userRiskLevels: ["high"] } : {}),
            ...(baselineCode === "CA08" ? { locations: { include: ["All"], exclude: ["AllTrusted"] } } : {}),
            ...(baselineCode === "CA09" ? { platforms: { include: ["windows", "macOS", "iOS", "android"], exclude: [] } } : {}),
          },
          matchesBaseline: true,
        });
      }

      snap.conditionalAccess = {
        ...snap.conditionalAccess,
        policies: updatedPolicies,
      };
      this.saveSnapshot(tenantId, snap);
    }

    const updatedSnap = this.getSnapshot(tenantId);
    return {
      success: true,
      policy: deployResult.policy,
      snapshot: updatedSnap || undefined,
    };
  }

  // Phase 2 Endpoint Security write path - each of the three methods below
  // mirrors deployBaselinePolicy's exact shape (decrypt secret -> call the
  // matching graph-client function -> audit log -> patch snap.intune in
  // place -> save -> return updated snapshot). Callers (the API routes) are
  // responsible for checking Tenant.endpointSecurityWriteMode ===
  // "write_enabled" before calling any of these - these methods don't
  // re-check it themselves, same convention as deployBaselinePolicy not
  // re-checking the CA write permission.

  // Read-only, on-demand (not part of the main sync - see plan/vault notes
  // on why this differs from mdeConnectorSettings/onboardingStates, which
  // are cheap enough to ride along in every sync). Also refreshes the
  // stored snapshot's intune.defenderAvPolicy so the module doesn't need to
  // refetch on every render, just on first mount / after a deploy.
  public async getDefenderAvPolicy(
    tenantId: string
  ): Promise<{ deployedPolicyId?: string; settings: DefenderAvPolicySettings; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { settings: {}, error: "Tenant not found" };

    const result = await fetchDefenderAvPolicyGraph(tenant);
    if (!result.error) {
      const snap = this.getSnapshot(tenantId);
      if (snap) {
        snap.intune = {
          ...snap.intune,
          defenderAvPolicy: { deployedPolicyId: result.deployedPolicyId, settings: result.settings },
        };
        this.saveSnapshot(tenantId, snap);
      }
    }
    return result;
  }

  public async deployDefenderAvPolicy(
    tenantId: string,
    settings: DefenderAvPolicySettings,
    assignment: IntuneAssignmentTarget
  ): Promise<{ success: boolean; policyId?: string; snapshot?: TenantSecuritySnapshot; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    // If a Clarity365-deployed AV policy already exists (its id was cached
    // the last time getDefenderAvPolicy or this method ran), update it in
    // place instead of creating a duplicate - see deployDefenderAvPolicy's
    // own comment for why this matters.
    const existingPolicyId = this.getSnapshot(tenantId)?.intune?.defenderAvPolicy?.deployedPolicyId;

    const deployResult = await deployDefenderAvPolicy(tenant, settings, assignment, existingPolicyId);
    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "defender_av_deploy",
      action: existingPolicyId ? "Update Defender Antivirus policy" : "Deploy Defender Antivirus policy",
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: deployResult.success,
      detail: deployResult.success
        ? `${existingPolicyId ? "Updated" : "Deployed"} Defender Antivirus policy (assignment: ${assignment.mode}).`
        : deployResult.error,
    });

    if (!deployResult.success) {
      return { success: false, error: deployResult.error };
    }

    const snap = this.getSnapshot(tenantId);
    if (snap) {
      snap.intune = {
        ...snap.intune,
        defenderAvPolicy: { deployedPolicyId: deployResult.policyId, settings },
      };
      this.saveSnapshot(tenantId, snap);
    }

    return { success: true, policyId: deployResult.policyId, snapshot: this.getSnapshot(tenantId) || undefined };
  }

  // Mirrors getDefenderAvPolicy/deployDefenderAvPolicy exactly.
  public async getEdrPolicy(
    tenantId: string
  ): Promise<{ deployedPolicyId?: string; settings: EdrPolicySettings; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { settings: {}, error: "Tenant not found" };

    const result = await fetchEdrPolicyGraph(tenant);
    if (!result.error) {
      const snap = this.getSnapshot(tenantId);
      if (snap) {
        snap.intune = {
          ...snap.intune,
          edrPolicy: { deployedPolicyId: result.deployedPolicyId, settings: result.settings },
        };
        this.saveSnapshot(tenantId, snap);
      }
    }
    return result;
  }

  public async deployEdrPolicy(
    tenantId: string,
    settings: EdrPolicySettings,
    assignment: IntuneAssignmentTarget
  ): Promise<{ success: boolean; policyId?: string; snapshot?: TenantSecuritySnapshot; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    // If a Clarity365-deployed EDR policy already exists (its id was cached
    // the last time getEdrPolicy or this method ran), update it in place
    // instead of creating a duplicate - see deployEdrPolicy's own comment
    // for why this matters.
    const existingPolicyId = this.getSnapshot(tenantId)?.intune?.edrPolicy?.deployedPolicyId;

    const deployResult = await deployEdrPolicyGraph(tenant, settings, assignment, existingPolicyId);
    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "edr_policy_deploy",
      action: existingPolicyId ? "Update EDR policy" : "Deploy EDR policy",
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: deployResult.success,
      detail: deployResult.success
        ? `${existingPolicyId ? "Updated" : "Deployed"} EDR policy (assignment: ${assignment.mode}).`
        : deployResult.error,
    });

    if (!deployResult.success) {
      return { success: false, error: deployResult.error };
    }

    const snap = this.getSnapshot(tenantId);
    if (snap) {
      snap.intune = {
        ...snap.intune,
        edrPolicy: { deployedPolicyId: deployResult.policyId, settings },
      };
      this.saveSnapshot(tenantId, snap);
    }

    return { success: true, policyId: deployResult.policyId, snapshot: this.getSnapshot(tenantId) || undefined };
  }

  // Mirrors getDefenderAvPolicy/deployDefenderAvPolicy exactly.
  public async getBitLockerPolicy(
    tenantId: string
  ): Promise<{ deployedPolicyId?: string; settings: BitLockerPolicySettings; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { settings: {}, error: "Tenant not found" };

    const result = await fetchBitLockerPolicyGraph(tenant);
    if (!result.error) {
      const snap = this.getSnapshot(tenantId);
      if (snap) {
        snap.intune = {
          ...snap.intune,
          bitLockerPolicy: { deployedPolicyId: result.deployedPolicyId, settings: result.settings },
        };
        this.saveSnapshot(tenantId, snap);
      }
    }
    return result;
  }

  public async deployBitLockerPolicy(
    tenantId: string,
    settings: BitLockerPolicySettings,
    assignment: IntuneAssignmentTarget
  ): Promise<{ success: boolean; policyId?: string; snapshot?: TenantSecuritySnapshot; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    // If a Clarity365-deployed BitLocker policy already exists (its id was
    // cached the last time getBitLockerPolicy or this method ran), update
    // it in place instead of creating a duplicate - see deployEdrPolicy's
    // comment for why this matters.
    const existingPolicyId = this.getSnapshot(tenantId)?.intune?.bitLockerPolicy?.deployedPolicyId;

    const deployResult = await deployBitLockerPolicyGraph(tenant, settings, assignment, existingPolicyId);
    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "bitlocker_policy_deploy",
      action: existingPolicyId ? "Update BitLocker policy" : "Deploy BitLocker policy",
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: deployResult.success,
      detail: deployResult.success
        ? `${existingPolicyId ? "Updated" : "Deployed"} BitLocker policy (assignment: ${assignment.mode}).`
        : deployResult.error,
    });

    if (!deployResult.success) {
      return { success: false, error: deployResult.error };
    }

    const snap = this.getSnapshot(tenantId);
    if (snap) {
      snap.intune = {
        ...snap.intune,
        bitLockerPolicy: { deployedPolicyId: deployResult.policyId, settings },
      };
      this.saveSnapshot(tenantId, snap);
    }

    return { success: true, policyId: deployResult.policyId, snapshot: this.getSnapshot(tenantId) || undefined };
  }

  public async deployAsrRules(
    tenantId: string,
    desiredModes: Record<string, Exclude<AsrRuleMode, "not_configured">>,
    assignment: IntuneAssignmentTarget
  ): Promise<{ success: boolean; policyId?: string; snapshot?: TenantSecuritySnapshot; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    // Only update in place if *this app* created the existing policy (see
    // clarity365AsrPolicyId's own comment) - never inferred from the
    // general multi-surface ASR read.
    const existingPolicyId = this.getSnapshot(tenantId)?.intune?.clarity365AsrPolicyId;

    const deployResult = await deployAsrRulePolicy(tenant, desiredModes, assignment, existingPolicyId);
    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "asr_rule_deploy",
      action: `${existingPolicyId ? "Update" : "Deploy"} ASR rules (${Object.keys(desiredModes).length} rule(s))`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: deployResult.success,
      detail: deployResult.success
        ? `${existingPolicyId ? "Updated" : "Deployed"} ASR rules policy (assignment: ${assignment.mode}).${deployResult.error ? " " + deployResult.error : ""}`
        : deployResult.error,
    });

    if (!deployResult.success) {
      return { success: false, error: deployResult.error };
    }

    const snap = this.getSnapshot(tenantId);
    if (snap) {
      snap.intune = { ...snap.intune, clarity365AsrPolicyId: deployResult.policyId };
      this.saveSnapshot(tenantId, snap);
    }

    return { success: true, policyId: deployResult.policyId, snapshot: this.getSnapshot(tenantId) || undefined };
  }

  public async updateMdeConnectorSettings(
    tenantId: string,
    connectorId: string,
    patch: Partial<MdeConnectorSettings>
  ): Promise<{ success: boolean; snapshot?: TenantSecuritySnapshot; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };

    const result = await updateMdeConnectorSettingsGraph(tenant, connectorId, patch);
    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "mde_connector_update",
      action: `Update MDE connector settings (${Object.keys(patch).join(", ")})`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: result.success,
      detail: result.success ? "Updated MDE connector settings - takes effect immediately, tenant-wide." : result.error,
    });

    if (!result.success) {
      return { success: false, error: result.error };
    }

    const snap = this.getSnapshot(tenantId);
    if (snap && snap.intune.mdeConnectorSettings) {
      snap.intune = {
        ...snap.intune,
        mdeConnectorSettings: { ...snap.intune.mdeConnectorSettings, ...patch },
      };
      this.saveSnapshot(tenantId, snap);
    }

    return { success: true, snapshot: this.getSnapshot(tenantId) || undefined };
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

      // A cached Graph token is keyed by tenantId:clientId, not by secret -
      // rotating just the secret (the common case, e.g. fixing a bad/expired
      // one) would otherwise keep serving a token acquired under the OLD
      // secret until it happened to expire on its own, up to ~55 minutes
      // later, making a credential fix look like it silently didn't work.
      // Clear both the old and new key in case tenantId/clientId changed too.
      invalidateGraphTokenCache(existing.credentials);
      invalidateGraphTokenCache(mergedCredentials);
      // Same for the cached app-only Exchange check - new credentials must be re-checked.
      invalidateExoAppAccessCache(existing.credentials);
      invalidateExoAppAccessCache(mergedCredentials);
      // A new secret has its own expiry date; forget the old one until the next sync reads it.
      if (!keepExistingSecret) delete mergedCredentials.secretExpiry;
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

  // "Confirmed once" answer for one Security Scenarios check on one tenant
  // (see scenario-confirmations.ts). Local to Clarity365: nothing is sent to
  // Microsoft 365. Pass null to clear. Unlike updateTenant(), this leaves
  // lastSyncTimestamp alone.
  public setScenarioConfirmation(id: string, key: ScenarioConfirmationKey, value: { status: "inPlace" | "notInPlace"; note?: string } | null): Tenant | undefined {
    const existing = this.getTenantRow(id);
    if (!existing) return undefined;
    const confirmations = { ...(existing.scenarioConfirmations || {}) };
    if (value === null) delete confirmations[key];
    else confirmations[key] = { status: value.status, note: value.note, confirmedAt: new Date().toISOString() };
    const updated: Tenant = { ...existing, scenarioConfirmations: confirmations };
    const write = this.db.transaction(() => {
      this.putTenantRow(updated);
      const snap = this.getSnapshotRow(id);
      if (snap) {
        snap.tenant = { ...snap.tenant, scenarioConfirmations: confirmations };
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

    if (canWriteToExchange(tenant.credentials)) {
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

    if (canWriteToExchange(tenant.credentials)) {
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
  // canWriteToExchange gate, audit logging, and post-write resync
  // pattern as addTablEntry/removeTablEntry above, just targeting a Set-*Policy
  // cmdlet instead of a TABL cmdlet.
  public async applyMdoBaselineFix(
    tenantId: string,
    code: string,
    extra?: Record<string, string>
  ): Promise<{ success: boolean; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };
    if (!canWriteToExchange(tenant.credentials)) {
      return { success: false, error: EXCHANGE_WRITES_UNAVAILABLE };
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
  // mailbox-level auto-forward) - same canWriteToExchange gate,
  // audit logging, and post-write resync pattern as applyMdoBaselineFix above.
  public async disableForwardingRule(tenantId: string, ruleId: string): Promise<{ success: boolean; error?: string }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, error: "Tenant not found" };
    if (!canWriteToExchange(tenant.credentials)) {
      return { success: false, error: EXCHANGE_WRITES_UNAVAILABLE };
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
    if (!canWriteToExchange(tenant.credentials)) {
      return { success: false, error: EXCHANGE_WRITES_UNAVAILABLE };
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
    if (!canWriteToExchange(tenant.credentials)) {
      return { success: false, error: EXCHANGE_WRITES_UNAVAILABLE };
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
    if (!canWriteToExchange(tenant.credentials)) {
      return { success: false, error: EXCHANGE_WRITES_UNAVAILABLE };
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

  public saveSnapshot(tenantId: string, snapshot: TenantSecuritySnapshot): void {
    this.putSnapshotRow(tenantId, snapshot);
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
    temporaryPassword?: string;
    actionsExecuted: string[];
    errors: string[];
    snapshot?: TenantSecuritySnapshot;
  }> {
    const tenant = this.getTenantWithDecryptedSecret(tenantId);
    if (!tenant) return { success: false, actionsExecuted: [], errors: ["Tenant not found"] };

    const actionsExecuted: string[] = [];
    const errors: string[] = [];
    const target = options.userId || options.userPrincipalName;
    let temporaryPassword: string | undefined;

    if (options.resetPassword) {
      const charsUpper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
      const charsLower = "abcdefghijkmnopqrstuvwxyz";
      const charsDigits = "23456789";
      const charsSpecial = "!@#$%^&*";
      let pwd = "Clt!";
      for (let i = 0; i < 3; i++) pwd += charsUpper[Math.floor(Math.random() * charsUpper.length)];
      for (let i = 0; i < 4; i++) pwd += charsLower[Math.floor(Math.random() * charsLower.length)];
      for (let i = 0; i < 3; i++) pwd += charsDigits[Math.floor(Math.random() * charsDigits.length)];
      pwd += charsSpecial[Math.floor(Math.random() * charsSpecial.length)];
      temporaryPassword = pwd;
    }

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

        if (options.resetPassword && temporaryPassword) {
          try {
            const res = await graphFetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(target)}`, {
              method: "PATCH",
              headers,
              body: JSON.stringify({
                passwordProfile: {
                  password: temporaryPassword,
                  forceChangePasswordNextSignIn: true,
                },
              }),
            });
            if (res.ok) {
              actionsExecuted.push(`Set temporary password & enforced reset on next sign-in.`);
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
      if (options.disableAccount) actionsExecuted.push("Disabled user account in Entra ID (Simulated).");
      if (options.resetPassword && temporaryPassword) {
        actionsExecuted.push(`Generated Temporary One-Time Password: ${temporaryPassword} (Simulated).`);
      }
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
          if (canWriteToExchange(tenant.credentials)) {
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
      temporaryPassword,
      actionsExecuted,
      errors,
      snapshot: this.ensureSnapshot(tenantId) || undefined,
    };
  }

  public async restoreUserAccount(
    tenantId: string,
    options: {
      userId?: string;
      userPrincipalName: string;
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

    if (!tenant.isDemo && tenant.credentials?.clientId && tenant.credentials?.clientSecret) {
      const { token, error: tokenError } = await getGraphAccessToken(tenant.credentials);
      if (token) {
        try {
          const res = await graphFetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(target)}`, {
            method: "PATCH",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ accountEnabled: true }),
          });
          if (res.ok) {
            actionsExecuted.push("Re-enabled user account in Microsoft Entra ID.");
          } else {
            const data = await res.json().catch(() => ({}));
            errors.push(`Account re-enablement: ${data.error?.message || res.statusText}`);
          }
        } catch (e: any) {
          errors.push(`Account re-enablement: ${e.message}`);
        }
      } else {
        errors.push(`Graph authentication: ${tokenError}`);
      }
    } else {
      actionsExecuted.push("Re-enabled user account in Microsoft Entra ID (Simulated).");
    }

    const snap = this.ensureSnapshot(tenantId);
    if (snap) {
      const user = snap.accountClassification.users.find(
        (u) => u.userPrincipalName.toLowerCase() === options.userPrincipalName.toLowerCase() || u.id === options.userId
      );
      if (user) {
        user.accountEnabled = true;
        user.classification = "licensed";
      }

      const mfaUser = snap.mfaAudit.find(
        (u) => u.userPrincipalName.toLowerCase() === options.userPrincipalName.toLowerCase() || u.id === options.userId
      );
      if (mfaUser) {
        mfaUser.accountEnabled = true;
      }

      this.putSnapshotRow(tenantId, snap);
    }

    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "incident_containment",
      action: `Restore / Re-enable User Account: ${options.userPrincipalName}`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success: errors.length === 0,
      detail: actionsExecuted.join(" | ") + (options.reason ? ` - Reason: ${options.reason}` : ""),
    });

    return {
      success: errors.length === 0 || actionsExecuted.length > 0,
      actionsExecuted,
      errors,
      snapshot: this.ensureSnapshot(tenantId) || undefined,
    };
  }

  public async releaseEndpointDevice(
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
          const res = await graphFetch(`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${encodeURIComponent(deviceId)}/unisolateDevice`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ comment: comment || "Released from isolation by Clarity365 IR" }),
          });
          if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            success = false;
            errorDetail = data.error?.message || `Device release returned HTTP ${res.status}`;
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
        (dev as any).isIsolated = false;
      }
      if (Array.isArray(snap.incidents)) {
        snap.incidents.forEach((inc) => {
          inc.impactedDevices.forEach((d) => {
            if (d.id === deviceId || d.deviceName.toLowerCase() === deviceName.toLowerCase()) {
              d.isIsolated = false;
            }
          });
        });
      }
      this.putSnapshotRow(tenantId, snap);
    }

    this.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      category: "device_isolation",
      action: `Release Endpoint Device: ${deviceName}`,
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      success,
      detail: success ? `Device '${deviceName}' successfully released from network isolation.` : errorDetail,
    });

    return { success, error: errorDetail, snapshot: this.ensureSnapshot(tenantId) || undefined };
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

  // ---- Phase 2.1: Fleet Management & Cross-Tenant Analytics API -------------------

  public getAllSnapshots(): TenantSecuritySnapshot[] {
    const tenants = this.getAllTenantRows();
    const snapshots: TenantSecuritySnapshot[] = [];
    for (const t of tenants) {
      const snap = this.getSnapshot(t.id);
      if (snap) snapshots.push(snap);
    }
    return snapshots;
  }

  public getFleetPosture(): FleetPostureSummary {
    const tenants = this.getAllTenants();
    const snapshots = this.getAllSnapshots();
    return computeFleetPosture(tenants, snapshots);
  }

  public getFleetLicenseWaste(): FleetLicenseOptimizationSummary {
    const snapshots = this.getAllSnapshots();
    return computeFleetLicenseWaste(snapshots);
  }

  public searchFleet(query: string, category?: string): FleetSearchResultItem[] {
    const snapshots = this.getAllSnapshots();
    return searchAcrossFleet(snapshots, query, category);
  }

  // ---- Audit Log Investigator (ingested Purview unified audit log CSV exports) ----

  private rowToUalImport(r: any): UnifiedAuditLogImport {
    return {
      id: r.id,
      tenantId: r.tenant_id,
      filename: r.filename,
      uploadedAt: r.uploaded_at,
      rowCount: r.row_count,
      skippedRowCount: r.skipped_row_count,
      earliestEvent: r.earliest_event ?? undefined,
      latestEvent: r.latest_event ?? undefined,
      possiblyCapped: !!r.possibly_capped,
      exportCapWarning: r.export_cap_warning ?? undefined,
    };
  }

  private rowToUalRecord(r: any): UnifiedAuditLogRecord {
    return {
      id: r.id,
      tenantId: r.tenant_id,
      importId: r.import_id,
      creationDate: r.creation_date,
      recordType: r.record_type ?? undefined,
      operation: r.operation ?? undefined,
      userId: r.user_id ?? undefined,
      clientIp: r.client_ip ?? undefined,
      sessionId: r.session_id ?? undefined,
      clientInfo: r.client_info ?? undefined,
      resultStatus: r.result_status ?? undefined,
      workload: r.workload ?? undefined,
      rawData: r.raw_data,
      parseError: !!r.parse_error,
    };
  }

  // Marks an import as starting before the (potentially long) streaming
  // parse begins, so the very first progress poll already sees something
  // instead of a brief "not in progress" window at the start of a big file.
  public startAuditImportProgress(tenantId: string, importId: string, filename: string) {
    auditImportProgressCache.set(tenantId, {
      importId,
      filename,
      rowsProcessed: 0,
      insertedCount: 0,
      skippedCount: 0,
      startedAt: Date.now(),
      done: false,
    });
  }

  public clearAuditImportProgress(tenantId: string) {
    auditImportProgressCache.delete(tenantId);
  }

  // Streams a Purview unified audit log CSV export straight from the
  // upload's own request stream into SQLite, batching inserts so a
  // 1,000,000-row Audit Premium export never needs its rows materialized
  // into one JS array. One malformed AuditData row is recorded with
  // parseError: true (see audit-log-parser.ts), never aborts the import.
  public async ingestAuditLogCsv(
    tenantId: string,
    importId: string,
    filename: string,
    fileStream: ReadableStream<Uint8Array>
  ): Promise<UnifiedAuditLogImport> {
    const nodeStream = Readable.fromWeb(fileStream as any);

    const insertStmt = this.db.prepare(`
      INSERT INTO ual_records
        (tenant_id, import_id, creation_date, record_type, operation, user_id, client_ip, session_id, client_info, result_status, workload, raw_data, parse_error)
      VALUES
        (@tenantId, @importId, @creationDate, @recordType, @operation, @userId, @clientIp, @sessionId, @clientInfo, @resultStatus, @workload, @rawData, @parseError)
    `);
    const insertBatch = this.db.transaction((rows: any[]) => {
      for (const row of rows) insertStmt.run(row);
    });

    const startedAt = Date.now();
    let rowsProcessed = 0;
    let insertedCount = 0;
    let skippedCount = 0;
    let earliestEvent: string | undefined;
    let latestEvent: string | undefined;
    let batch: any[] = [];
    const BATCH_SIZE = 500;

    const flush = () => {
      if (batch.length === 0) return;
      insertBatch(batch);
      insertedCount += batch.length;
      batch = [];
    };

    const reportProgress = () => {
      auditImportProgressCache.set(tenantId, {
        importId,
        filename,
        rowsProcessed,
        insertedCount: insertedCount + batch.length,
        skippedCount,
        startedAt,
        done: false,
      });
    };

    await new Promise<void>((resolve, reject) => {
      Papa.parse<RawCsvRow>(nodeStream as any, {
        header: true,
        skipEmptyLines: true,
        step: (results) => {
          const row = results.data;
          if (!row || Object.keys(row).length === 0) return;
          rowsProcessed++;

          if (!row.AuditData && !row.CreationDate) {
            skippedCount++;
          } else {
            const { record } = mapCsvRowToRecord(row, { tenantId, importId });
            if (!earliestEvent || record.creationDate < earliestEvent) earliestEvent = record.creationDate;
            if (!latestEvent || record.creationDate > latestEvent) latestEvent = record.creationDate;
            batch.push({
              tenantId: record.tenantId,
              importId: record.importId,
              creationDate: record.creationDate,
              recordType: record.recordType ?? null,
              operation: record.operation ?? null,
              userId: record.userId ?? null,
              clientIp: record.clientIp ?? null,
              sessionId: record.sessionId ?? null,
              clientInfo: record.clientInfo ?? null,
              resultStatus: record.resultStatus ?? null,
              workload: record.workload ?? null,
              rawData: record.rawData,
              parseError: record.parseError ? 1 : 0,
            });
            if (batch.length >= BATCH_SIZE) flush();
          }

          if (rowsProcessed % 200 === 0) reportProgress();
        },
        complete: () => resolve(),
        error: (err: Error) => reject(err),
      });
    });

    flush();

    const exportCapWarning = getExportCapWarning(rowsProcessed);
    const importRecord: UnifiedAuditLogImport = {
      id: importId,
      tenantId,
      filename,
      uploadedAt: new Date().toISOString(),
      rowCount: insertedCount,
      skippedRowCount: skippedCount,
      earliestEvent,
      latestEvent,
      possiblyCapped: !!exportCapWarning,
      exportCapWarning,
    };

    this.db
      .prepare(
        `INSERT INTO ual_imports (id, tenant_id, filename, uploaded_at, row_count, skipped_row_count, earliest_event, latest_event, possibly_capped, export_cap_warning)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        importRecord.id,
        importRecord.tenantId,
        importRecord.filename,
        importRecord.uploadedAt,
        importRecord.rowCount,
        importRecord.skippedRowCount,
        importRecord.earliestEvent ?? null,
        importRecord.latestEvent ?? null,
        importRecord.possiblyCapped ? 1 : 0,
        importRecord.exportCapWarning ?? null
      );

    return importRecord;
  }

  public getAuditLogImports(tenantId: string): UnifiedAuditLogImport[] {
    const rows = this.db
      .prepare("SELECT * FROM ual_imports WHERE tenant_id = ? ORDER BY uploaded_at DESC")
      .all(tenantId) as any[];
    return rows.map((r) => this.rowToUalImport(r));
  }

  // Removes an import and every record it produced - the only supported way
  // to undo an upload (e.g. wrong file, wrong tenant) short of a raw DB edit.
  public deleteAuditLogImport(tenantId: string, importId: string): boolean {
    const remove = this.db.transaction(() => {
      const result = this.db
        .prepare("DELETE FROM ual_imports WHERE tenant_id = ? AND id = ?")
        .run(tenantId, importId);
      this.db.prepare("DELETE FROM ual_records WHERE tenant_id = ? AND import_id = ?").run(tenantId, importId);
      return result.changes > 0;
    });
    return remove();
  }

  public searchAuditLogRecords(tenantId: string, filters: UnifiedAuditLogSearchFilters = {}): UnifiedAuditLogSearchResult {
    const conditions: string[] = ["tenant_id = ?"];
    const params: any[] = [tenantId];

    if (filters.importId) {
      conditions.push("import_id = ?");
      params.push(filters.importId);
    }
    if (filters.operation) {
      conditions.push("operation = ?");
      params.push(filters.operation);
    }
    if (filters.operations && filters.operations.length > 0) {
      // Investigation Template filter - "operation is one of N values,"
      // independent of the single-value dropdown filter above.
      conditions.push(`operation IN (${filters.operations.map(() => "?").join(", ")})`);
      params.push(...filters.operations);
    }
    if (filters.recordType) {
      conditions.push("record_type = ?");
      params.push(filters.recordType);
    }
    if (filters.workload) {
      conditions.push("workload = ?");
      params.push(filters.workload);
    }
    if (filters.userId) {
      // Partial match, not exact - lets you type "alice" instead of the full
      // alice@contoso.com UPN. sessionId below stays exact: it's normally
      // clicked through or typeahead-selected rather than hand-typed.
      conditions.push("user_id LIKE ?");
      params.push(`%${filters.userId}%`);
    }
    if (filters.sessionId) {
      conditions.push("session_id = ?");
      params.push(filters.sessionId);
    }
    if (filters.clientInfo) {
      conditions.push("client_info LIKE ?");
      params.push(`%${filters.clientInfo}%`);
    }
    if (filters.startDate) {
      conditions.push("creation_date >= ?");
      params.push(filters.startDate);
    }
    if (filters.endDate) {
      conditions.push("creation_date <= ?");
      params.push(filters.endDate);
    }
    if (filters.search) {
      conditions.push("(operation LIKE ? OR user_id LIKE ? OR client_ip LIKE ? OR session_id LIKE ? OR client_info LIKE ? OR raw_data LIKE ?)");
      const like = `%${filters.search}%`;
      params.push(like, like, like, like, like, like);
    }

    const whereClause = `WHERE ${conditions.join(" AND ")}`;
    const sortDirection = filters.sortDirection === "asc" ? "ASC" : "DESC";
    const pageSize = Math.min(Math.max(filters.pageSize ?? 50, 1), 500);
    const page = Math.max(filters.page ?? 1, 1);
    const offset = (page - 1) * pageSize;

    const { c: total } = this.db.prepare(`SELECT COUNT(*) as c FROM ual_records ${whereClause}`).get(...params) as {
      c: number;
    };

    const rows = this.db
      .prepare(`SELECT * FROM ual_records ${whereClause} ORDER BY creation_date ${sortDirection}, id ${sortDirection} LIMIT ? OFFSET ?`)
      .all(...params, pageSize, offset) as any[];

    // Facets are scoped to the tenant (and import, if one is selected) but
    // deliberately NOT to the rest of the active filters - otherwise picking
    // one Operation would immediately empty out every other Operation option
    // in its own dropdown.
    const facetConditions = ["tenant_id = ?"];
    const facetParams: any[] = [tenantId];
    if (filters.importId) {
      facetConditions.push("import_id = ?");
      facetParams.push(filters.importId);
    }
    const facetWhere = `WHERE ${facetConditions.join(" AND ")}`;
    const distinctValues = (column: string): string[] =>
      (
        this.db
          .prepare(`SELECT DISTINCT ${column} as v FROM ual_records ${facetWhere} AND ${column} IS NOT NULL ORDER BY v LIMIT 500`)
          .all(...facetParams) as { v: string }[]
      ).map((r) => r.v);

    return {
      records: rows.map((r) => this.rowToUalRecord(r)),
      total,
      facets: {
        operations: distinctValues("operation"),
        recordTypes: distinctValues("record_type"),
        workloads: distinctValues("workload"),
      },
    };
  }

  // Every record sharing a Session ID, chronological - the direct
  // implementation of Microsoft's own documented technique (grouping by
  // SessionId + ClientIPAddress + ClientInfoString) for telling attacker
  // activity apart from the legitimate user's own activity in one session.
  public getAuditLogSessionTimeline(tenantId: string, sessionId: string): UnifiedAuditLogRecord[] {
    const rows = this.db
      .prepare("SELECT * FROM ual_records WHERE tenant_id = ? AND session_id = ? ORDER BY creation_date ASC, id ASC")
      .all(tenantId, sessionId) as any[];
    return rows.map((r) => this.rowToUalRecord(r));
  }

  // Lightweight typeahead for the Session ID / User / Client search fields -
  // capped and prefix-matched so it stays fast even over a million-row import.
  public getAuditLogTypeahead(tenantId: string, field: "sessionId" | "userId" | "clientInfo", query: string): string[] {
    const column = field === "sessionId" ? "session_id" : field === "userId" ? "user_id" : "client_info";
    if (!query || query.length < 2) return [];
    const rows = this.db
      .prepare(
        `SELECT DISTINCT ${column} as v FROM ual_records WHERE tenant_id = ? AND ${column} LIKE ? ORDER BY v LIMIT 20`
      )
      .all(tenantId, `%${query}%`) as { v: string }[];
    return rows.map((r) => r.v).filter(Boolean);
  }

  // One COUNT(*) per Investigation Template, scoped to the tenant (and
  // import, if one is selected) - cheap since operation is indexed. Lets
  // each template button show a real count instead of guessing.
  public getAuditLogTemplateCounts(tenantId: string, importId?: string): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const template of AUDIT_INVESTIGATION_TEMPLATES) {
      const conditions = ["tenant_id = ?", `operation IN (${template.operations.map(() => "?").join(", ")})`];
      const params: any[] = [tenantId, ...template.operations];
      if (importId) {
        conditions.push("import_id = ?");
        params.push(importId);
      }
      const { c } = this.db
        .prepare(`SELECT COUNT(*) as c FROM ual_records WHERE ${conditions.join(" AND ")}`)
        .get(...params) as { c: number };
      counts[template.id] = c;
    }
    return counts;
  }

  // Phase 3 heuristic flags - each aggregation is done in SQL (never a raw
  // per-record JS scan over up to 1,000,000 rows), then handed to the pure,
  // tested scoring functions in audit-log-heuristics.ts.
  public getAuditLogFlags(tenantId: string, importId?: string): AuditLogFlagsResult {
    const scopeConditions = ["tenant_id = ?"];
    const scopeParams: any[] = [tenantId];
    if (importId) {
      scopeConditions.push("import_id = ?");
      scopeParams.push(importId);
    }
    const scopeWhere = scopeConditions.join(" AND ");

    // 1. Session hijack / AiTM - a session touching 2+ distinct client IPs.
    const sessionRows = this.db
      .prepare(
        `SELECT session_id, GROUP_CONCAT(DISTINCT client_ip) as ips_concat, COUNT(DISTINCT client_ip) as ip_count,
                MIN(creation_date) as first_seen, MAX(creation_date) as last_seen, COUNT(*) as record_count
         FROM ual_records
         WHERE ${scopeWhere} AND session_id IS NOT NULL
         GROUP BY session_id
         HAVING ip_count >= 2`
      )
      .all(...scopeParams) as any[];
    const sessionHijack = sessionRows.map((r) => ({
      sessionId: r.session_id,
      distinctIpCount: r.ip_count,
      distinctIps: (r.ips_concat || "").split(",").filter(Boolean),
      recordCount: r.record_count,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
    }));

    // 2. Mass deletion - reuses the Mass Deletion template's own operation
    // list, so the flag and the one-click filter always agree on what
    // counts as a "delete."
    const massDeletionOps = AUDIT_INVESTIGATION_TEMPLATES.find((t) => t.id === "mass_deletion")!.operations;
    const deleteBuckets = this.db
      .prepare(
        `SELECT user_id, strftime('%Y-%m-%dT%H', creation_date) as hour_bucket, COUNT(*) as delete_count
         FROM ual_records
         WHERE ${scopeWhere} AND user_id IS NOT NULL AND operation IN (${massDeletionOps.map(() => "?").join(", ")})
         GROUP BY user_id, hour_bucket`
      )
      .all(...scopeParams, ...massDeletionOps) as any[];
    const massDeletion = flagMassDeletionBursts(
      deleteBuckets.map((r) => ({ userId: r.user_id, hourBucket: r.hour_bucket, deleteCount: r.delete_count }))
    );

    // 3. Possible BEC - inbox-rule/forwarding changes (the BEC template's
    // operation list minus the mail-volume operations, which are the
    // second, independent signal below) joined against MailItemsAccessed
    // volume in the same hour bucket.
    const becTemplateOps = AUDIT_INVESTIGATION_TEMPLATES.find((t) => t.id === "bec")!.operations;
    const mailVolumeOps = ["MailItemsAccessed", "Send", "SendAs", "SendOnBehalf"];
    const inboxRuleOps = becTemplateOps.filter((op) => !mailVolumeOps.includes(op));
    const inboxRuleChangeRows = this.db
      .prepare(
        `SELECT user_id, strftime('%Y-%m-%dT%H', creation_date) as hour_bucket, COUNT(*) as change_count
         FROM ual_records
         WHERE ${scopeWhere} AND user_id IS NOT NULL AND operation IN (${inboxRuleOps.map(() => "?").join(", ")})
         GROUP BY user_id, hour_bucket`
      )
      .all(...scopeParams, ...inboxRuleOps) as any[];
    const mailAccessRows = this.db
      .prepare(
        `SELECT user_id, strftime('%Y-%m-%dT%H', creation_date) as hour_bucket, COUNT(*) as access_count
         FROM ual_records
         WHERE ${scopeWhere} AND user_id IS NOT NULL AND operation = 'MailItemsAccessed'
         GROUP BY user_id, hour_bucket`
      )
      .all(...scopeParams) as any[];
    const possibleBec = flagPossibleBec(
      inboxRuleChangeRows.map((r) => ({ userId: r.user_id, hourBucket: r.hour_bucket, inboxRuleChangeCount: r.change_count })),
      mailAccessRows.map((r) => ({ userId: r.user_id, hourBucket: r.hour_bucket, mailItemsAccessedCount: r.access_count }))
    );

    return { sessionHijack, massDeletion, possibleBec };
  }
}

// Always construct fresh - in production this only ever runs once anyway
// (no hot-reloading), and in dev this is what makes an edit to any method on
// this class take effect on the very next request instead of needing a full
// server restart. The constructor above reuses the underlying SQLite
// connection via its own globalThis cache, so this doesn't open a second
// database handle or re-run migrations against a fresh one - only the class
// instance (and therefore its method bodies) is ever rebuilt.
export const tenantStore = new TenantStore();
