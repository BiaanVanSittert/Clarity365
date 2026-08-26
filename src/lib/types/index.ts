// ==========================================
// Clarity365 Core Multi-Tenant Domain Types
// ==========================================

export type TrafficStatus = "pass" | "warn" | "fail" | "info";

export type TenantLicenseType = "M365_E5" | "M365_E3" | "M365_BP" | "M365_F3" | "A5_EDU";

export interface TenantCapability {
  id: string;
  name: string;
  category: "Identity" | "Endpoint" | "Threat" | "Compliance" | "Collaboration";
  licensed: boolean;
  tier: string;
  description: string;
}

export interface TenantCredentials {
  tenantId: string;
  clientId?: string;
  clientSecret?: string;
  // Optional Exchange Online delegated-auth connection, used only for MDO
  // policy & TABL sync (see exo-client.ts) — Exchange admin APIs don't accept
  // the client-secret flow used for everything else in this app. Established
  // via a one-time device-code sign-in (Microsoft's own first-party EXO
  // PowerShell client, no custom app registration changes needed) rather than
  // a certificate; the refresh token rotates on every use and is re-persisted
  // each time, encrypted, exactly like clientSecret. Independent of
  // authMode/clientSecret: a tenant can have Graph secret auth configured
  // with or without this connection also being set up.
  exoRefreshToken?: string;
  exoConnectedAt?: string;
  // Off by default, even once Exchange Online is connected. EXO's delegated
  // device-code auth can't be scoped to "read-only" the way Graph app
  // permissions can — whatever Exchange role the connecting admin holds is
  // what Clarity365 can do via EXO — so this flag is the explicit,
  // admin-controlled substitute for the missing narrower consent: it gates
  // whether TABL Add/Remove actually calls New-/Remove-TenantAllowBlockListItems
  // against the live tenant, versus staying purely local-only tracking.
  exoWriteEnabled?: boolean;
  authMode: "mock" | "secret" | "certificate";
  verifiedAt?: string;
  status: "connected" | "syncing" | "error" | "offline";
}

export interface Tenant {
  id: string;
  displayName: string;
  defaultDomainName: string;
  organizationId: string;
  primaryContact: string;
  tier: TenantLicenseType;
  createdDate: string;
  lastSyncTimestamp: string;
  connectionStatus: "healthy" | "sync_in_progress" | "degraded" | "disconnected";
  credentials: TenantCredentials;
  isDemo?: boolean;
}

// Module 1: Conditional Access Policies
export type CAPolicyState = "enabled" | "disabled" | "enabledForReportingButNotEnforced";

export interface CAPolicyRule {
  id: string;
  name: string;
  baselineCode: string | null; // e.g., 'CA01', 'CA02'... 'CA10' or null for custom
  baselineTitle?: string;
  state: CAPolicyState;
  modifiedDateTime: string;
  createdDateTime: string;
  grantControls: string[];
  conditions: {
    users: { include: string[]; exclude: string[] };
    applications: { include: string[]; exclude: string[] };
    clientAppTypes: string[];
    platforms?: { include: string[]; exclude: string[] };
    locations?: { include: string[]; exclude: string[] };
    userRiskLevels?: string[];
    signInRiskLevels?: string[];
  };
  matchesBaseline: boolean;
  recommendation?: string;
}

export interface CABaselineItem {
  code: string;
  name: string;
  description: string;
  recommendedState: CAPolicyState;
  targetScope: string;
  riskMitigated: string;
}

export type SignInStatus = "success" | "failed" | "ca_blocked" | "report_only_failed";

export interface SignInEvent {
  id: string;
  createdDateTime: string;
  userPrincipalName: string;
  userDisplayName: string;
  userId: string;
  ipAddress: string;
  location: {
    city: string;
    state: string;
    country: string;
  };
  clientApp: string;
  appDisplayName: string;
  status: SignInStatus;
  errorCode: number;
  failureReason?: string;
  isRisky: boolean;
  riskLevel: "none" | "low" | "medium" | "high";
  deviceDetail: {
    deviceId?: string;
    displayName?: string;
    operatingSystem: string;
    browser: string;
    isCompliant: boolean;
    isManaged: boolean;
    trustType?: string;
  };
  appliedConditionalAccessPolicies: {
    id: string;
    displayName: string;
    result:
      | "success"
      | "failure"
      | "notApplied"
      | "notEnabled"
      | "reportOnlySuccess"
      | "reportOnlyFailure"
      | "reportOnlyNotApplied"
      | "reportOnlyInterrupted"
      | "unknown";
    enforcedGrantControls: string[];
    enforcedSessionControls?: string[];
  }[];
  hasReportOnlyFailure?: boolean;
  reportOnlyFailedPolicies?: string[];
}

// Module 3: Microsoft Secure Score & Recommendations
export interface SecureScoreHistoryPoint {
  date: string;
  score: number;
  maxScore: number;
  percentage: number;
}

export interface SecureScoreControl {
  id: string;
  title: string;
  category: "Identity" | "Device" | "Apps" | "Data" | "Infrastructure";
  scoreCurrent: number;
  scoreMax: number;
  implementationCost: "Low" | "Moderate" | "High";
  userImpact: "Low" | "Moderate" | "High";
  status: "Completed" | "Partial" | "Unresolved" | "Ignored";
  actionType: "Requirement" | "Configuration" | "Policy";
  remediationSummary: string;
  powershellCommand?: string;
}

export interface TenantSecureScore {
  currentScore: number;
  maxScore: number;
  percentage: number;
  delta30Days: number;
  delta90Days: number;
  industryBenchmark: number;
  history: SecureScoreHistoryPoint[];
  controls: SecureScoreControl[];
}

// Module 4: MFA Audit & Methods
export type AuthMethodType =
  | "passkey_fido2"
  | "ms_authenticator_push"
  | "ms_authenticator_totp"
  | "sms"
  | "voice_call"
  | "email_otp"
  | "app_password"
  | "none";

export interface UserMfaProfile {
  id: string;
  userPrincipalName: string;
  displayName: string;
  jobTitle: string;
  department: string;
  accountEnabled: boolean;
  isAdmin: boolean;
  adminRoles?: string[];
  mfaRegistered: boolean;
  mfaEnforcedByPolicy: boolean;
  defaultMethod: AuthMethodType;
  registeredMethods: AuthMethodType[];
  isWeakAuth: boolean;
  passwordLastSetDateTime: string;
  lastSignInDateTime: string;
  isSsprRegistered?: boolean;
  isPasswordlessCapable?: boolean;
  methodsCount?: number;
  authStrength?: "phishing_resistant" | "strong" | "weak" | "none";
}


// Module 5: User & Account Classification
export interface TenantAccountSummary {
  totalAccounts: number;
  licensedUsersCount: number;
  unlicensedActiveCount: number; // accountEnabled = true, licenses = 0 -> ORPHAN RISK
  disabledAccountsCount: number;
  guestAccountsCount: number;
  users: {
    id: string;
    userPrincipalName: string;
    displayName: string;
    classification: "licensed" | "unlicensed_active" | "disabled" | "guest";
    licenses: string[];
    accountEnabled: boolean;
    department: string;
    createdDateTime: string;
    lastSignInDateTime?: string;
    riskFlag?: string;
  }[];
}

// Module 6: Exchange Mailbox Permissions & Delegation
export interface MailboxDelegation {
  principalDisplayName: string;
  principalUserPrincipalName: string;
  accessRight: "FullAccess" | "SendAs" | "SendOnBehalf";
  isInherited: boolean;
}

export interface MailboxItem {
  id: string;
  userPrincipalName: string;
  displayName: string;
  recipientType: "UserMailbox" | "SharedMailbox" | "RoomMailbox" | "EquipmentMailbox";
  totalItemSizeMB: number;
  itemCount: number;
  archiveStatus: "Enabled" | "Disabled" | "None";
  hasDirectLicense: boolean; // Flag for shared mailbox cost waste
  delegations: MailboxDelegation[];
  warningNote?: string;
}

// Module 7: Email Forwarding Rules
export interface EmailForwardingRule {
  id: string;
  scope: "transport_rule" | "inbox_rule" | "smtp_forward";
  name: string;
  mailboxOwner?: string;
  forwardingAddress: string;
  isExternal: boolean;
  ruleAction: "ForwardTo" | "ForwardAsAttachmentTo" | "RedirectTo" | "Bcc";
  state: "Enabled" | "Disabled";
  dateCreated: string;
  alertLevel: "critical" | "warning" | "info";
}

// Module 8: Defender for Office 365 (MDO) & TABL
export interface MdoThreatPolicy {
  id: string;
  policyType: "AntiSpamInbound" | "AntiSpamOutbound" | "AntiPhishing" | "AntiMalware" | "SafeLinks" | "SafeAttachments";
  displayName: string;
  state: "Enabled" | "Disabled" | "StrictPreset" | "StandardPreset";
  assignedScope: string;
  impersonationProtection: boolean;
  spoofIntelligence: boolean;
  zapEnabled: boolean; // Zero-hour auto purge
  complianceRating: "compliant" | "substandard" | "critical";
  // Baseline-scoring fields (see mdo-baseline-definitions.ts) — each backs one
  // specific MDO0x check rather than a generic "is it configured" boolean.
  realTimeScanning: boolean; // SafeLinks: URLs are actually scanned in real time, not just rewritten
  blockingAction: boolean; // SafeAttachments: action is Block/DynamicDelivery, not Allow/Monitor
  commonAttachmentFilter: boolean; // AntiMalware: common attachment type filter enabled
  outboundNotify: boolean; // AntiSpamOutbound: admin is notified of suspected outbound spam
  // AntiSpamOutbound: AutoForwardingMode is "Off" — the tenant-wide kill
  // switch controlling whether ANY auto-forward to an external address is
  // even possible. Scored by the Mail Flow Rules baseline (MF04), not the
  // MDO0x baseline — a separate concern from outboundNotify/MDO08.
  autoForwardingBlocked?: boolean;
}

// Full-fidelity org-wide transport rule shape used by the Transport & Mail
// Flow Rules baseline (mailflow-baseline-*.ts) — distinct from
// EmailForwardingRule, which only represents the forwarding-shaped subset of
// transport rules surfaced in the Email Forwarding Audit module (Module 7).
// A rule can be flagged here (e.g. an SCL override) without ever appearing
// in EmailForwardingRule at all.
export interface MailflowTransportRule {
  id: string;
  name: string;
  state: "Enabled" | "Disabled";
  redirectsExternally: boolean;
  externalRedirectAddress?: string;
  overridesSpamConfidence: boolean; // SetSCL action present — bypasses spam/phish filtering for matching mail
  hasNoScopingConditions: boolean; // applies to all mail, not a specific sender/domain/recipient
  hasExpiry: boolean;
}

export interface MailflowConnector {
  id: string;
  name: string;
  direction: "Inbound" | "Outbound";
  enabled: boolean;
  // Inbound only: treats all mail claiming to be from a configured domain as
  // pre-authenticated regardless of sending IP — a common way spam/phish
  // filtering gets silently bypassed for an entire domain.
  trustsAnonymousSenders: boolean;
  requiresTls: boolean;
}

export interface MailflowBaselineResult {
  code: string;
  met: boolean;
  offendingRuleNames?: string[];
  offendingRuleIds?: string[];
}

// Domain Authentication (SPF/DKIM/DMARC) — the primary defense against the
// tenant's own domain being spoofed to phish its customers/partners. DKIM
// comes from the Exchange Online connection; SPF/DMARC are public DNS TXT
// lookups, so — unlike everything else in this app — remediation here is
// exact DNS record text to publish at the domain registrar, not a button,
// since neither Microsoft 365 nor this app can write to a domain's DNS.
export type DomainAuthCheckStatus = "pass" | "warn" | "fail" | "unknown";

export interface DomainAuthCheck {
  status: DomainAuthCheckStatus;
  detail: string;
  // Exact remediation text (e.g. the literal DNS record to add), present
  // whenever status isn't "pass".
  recommendation?: string;
}

export interface DomainAuthStatus {
  domain: string;
  isDefaultDomain: boolean;
  dkim: DomainAuthCheck;
  spf: DomainAuthCheck;
  dmarc: DomainAuthCheck;
}

export interface TablEntry {
  id: string;
  listType: "allow" | "block";
  entryType: "domain" | "sender" | "url" | "file_hash";
  value: string;
  addedBy: string;
  dateAdded: string;
  expirationDate: string | "Never";
  notes: string;
  // Set when this entry was added while Exchange Online writes were
  // disabled (or EXO wasn't connected yet) — see tenant-store.addTablEntry.
  // A live resync merges these back in rather than dropping them, since
  // they were never pushed to the real Tenant Allow/Block List and so never
  // come back from a Get-TenantAllowBlockListItems fetch.
  isLocalOnly?: boolean;
}

// Static definition of one MDO0x baseline check (mirrors CABaselineItem) —
// see mdo-baseline-definitions.ts for the actual MDO_BASELINE_STANDARDS list.
export interface MdoBaselineItem {
  code: string;
  name: string;
  description: string;
  policyType: MdoThreatPolicy["policyType"];
  riskMitigated: string;
}

// Per-check result of scoring live MdoThreatPolicy data against
// MDO_BASELINE_STANDARDS (mdo-baseline-definitions.ts) — the dynamic half of
// the baseline pair; the static check definitions themselves aren't
// duplicated onto the snapshot (unlike conditionalAccess.baselineDefinitions)
// since nothing needs them decoupled from the data file that defines them.
export interface MdoBaselineResult {
  code: string;
  met: boolean;
  policyFound: boolean;
  currentPolicyName?: string;
  // How many policies of this check's policyType actually exist. When this
  // is >1, `met` reflects "every one of them satisfies the check" rather
  // than a single arbitrary policy, and unmetPolicyNames names the ones
  // still failing (see mdo-baseline-matcher.ts).
  policyCount: number;
  unmetPolicyNames?: string[];
}

export interface MdoThreatAlert {
  id: string;
  title: string;
  severity: "informational" | "low" | "medium" | "high";
  status: "new" | "inProgress" | "resolved";
  classification: "truePositive" | "falsePositive" | "benignPositive" | "unknown";
  category: string;
  createdDateTime: string;
  description: string;
  affectedUsers: string[];
  webUrl?: string;
}

// Module 9: Connected Services & App Registrations
export interface AppRegistrationItem {
  id: string;
  appId: string;
  displayName: string;
  publisher: string;
  isMicrosoftApp: boolean;
  isMultiTenant: boolean;
  createdDateTime: string;
  secretsCount: number;
  certificatesCount: number;
  expiringCredentialsCount: number;
  highPrivilegePermissions: string[];
  allPermissions: string[];
  riskCategory: "critical" | "high" | "moderate" | "low";
}

// Module 10: Intune Endpoint Security
export interface IntuneDevice {
  id: string;
  deviceName: string;
  userPrincipalName: string;
  operatingSystem: "Windows" | "macOS" | "iOS" | "Android" | "Linux";
  osVersion: string;
  complianceState: "compliant" | "noncompliant" | "conflict" | "error" | "inGracePeriod";
  isEncrypted: boolean;
  antivirusStatus: "active" | "outOfDate" | "disabled" | "notInstalled";
  edrOnboardingState: "onboarded" | "canBeOnboarded" | "unsupported" | "error";
  lastSyncDateTime: string;
  // Richer per-device detail, populated from the same managedDevices Graph
  // call via an expanded $select (see graph-client.ts) — optional because
  // demo/mock tenants don't set them and older cached snapshots predate them.
  model?: string;
  manufacturer?: string;
  serialNumber?: string;
  imei?: string;
  enrolledDateTime?: string;
  managementAgent?: string;
  ownerType?: "company" | "personal" | "unknown";
  deviceEnrollmentType?: string;
  totalStorageBytes?: number;
  freeStorageBytes?: number;
  deviceCategory?: string;
  azureADDeviceId?: string;
  // Graph reports this as the string "true"/"false"/"unknown", not a boolean.
  jailBroken?: string;
  complianceGracePeriodExpirationDateTime?: string;
  wiFiMacAddress?: string;
}

export interface IntunePolicySummary {
  antivirusPoliciesCount: number;
  edrPoliciesCount: number;
  compliantDevices: number;
  nonCompliantDevices: number;
  totalDevices: number;
  devices: IntuneDevice[];
}

// Module 11: Groups & Distribution
export interface TenantGroup {
  id: string;
  displayName: string;
  mailNickname: string;
  groupType: "Security" | "M365Unified" | "DistributionList" | "MailEnabledSecurity";
  membershipType: "Assigned" | "Dynamic";
  ownersCount: number;
  membersCount: number;
  owners: string[];
  members: string[];
  isPrivileged: boolean;
  syncSource: "Cloud" | "WindowsServerAD";
  createdDateTime: string;
}

// Module 12: SharePoint & Storage Policies
export interface SharePointSiteItem {
  id: string;
  siteName: string;
  siteUrl: string;
  template: "TeamSite" | "CommunicationSite" | "HubSite" | "PersonalOneDrive";
  storageUsedGB: number;
  storageAllocatedGB: number;
  sharingCapability: "Anyone" | "NewAndExistingGuests" | "ExistingGuests" | "OnlyPeopleInOrg";
  isSensitiveDataPresent: boolean;
  ownerUPN: string;
  lastActivityDate: string;
}

export interface SharePointTenantPolicy {
  tenantSharingLevel: "Anyone" | "NewAndExistingGuests" | "ExistingGuests" | "OnlyPeopleInOrg";
  defaultLinkType: "SpecificPeople" | "Internal" | "Anyone";
  anonymousLinkExpirationDays: number;
  totalStorageAllocatedTB: number;
  totalStorageUsedTB: number;
  sites: SharePointSiteItem[];
}

// Per-section result of the most recent live Graph sync. Absent entirely for
// demo/mock tenants and for snapshots that predate this field.
export interface SyncHealth {
  isPartial: boolean;
  errors: string[]; // e.g. "Sign-in logs: Pagination stopped early: Insufficient privileges."
  lastAttemptAt: string;
}

// Whole-sync outcome, distinct from SyncHealth's per-section granularity above.
// "synced" = a fresh snapshot was obtained (it may still itself carry a partial
// SyncHealth). "stale_fallback" = the live fetch failed entirely (e.g. bad
// credentials) but a previously-cached snapshot exists and was served instead.
// "no_data" = the live fetch failed and there was no cache to fall back to.
export type SyncOutcome = "synced" | "stale_fallback" | "no_data";

export interface SyncResult {
  snapshot?: TenantSecuritySnapshot;
  outcome: SyncOutcome;
  error?: string;
}

// Full Tenant Aggregated Snapshot
export interface TenantSecuritySnapshot {
  tenant: Tenant;
  syncHealth?: SyncHealth;
  capabilities: TenantCapability[];
  secureScore: TenantSecureScore;
  conditionalAccess: {
    baselineCoverageScore: number;
    policies: CAPolicyRule[];
    baselineDefinitions: CABaselineItem[];
  };
  signIns: SignInEvent[];
  mfaAudit: UserMfaProfile[];
  accountClassification: TenantAccountSummary;
  mailboxes: MailboxItem[];
  emailForwarding: EmailForwardingRule[];
  // Get-OrganizationConfig's AuditDisabled, inverted — undefined until an EXO
  // sync has actually run (never connected, or the mailflow fetch itself
  // failed). Every mailbox-delegation and forwarding-rule finding in this
  // snapshot is only investigable after the fact if this is true, so it's
  // surfaced as a standalone gating check rather than folded into a generic list.
  mailboxAuditingEnabled?: boolean;
  mailflowTransportRules: MailflowTransportRule[];
  mailflowConnectors: MailflowConnector[];
  // Get-RemoteDomain (Default)'s AutoForwardEnabled === false — a second,
  // more obscure org-wide auto-forward switch distinct from
  // MdoThreatPolicy.autoForwardingBlocked (the outbound-spam one). Optional
  // because it's undefined until an EXO sync has actually populated it.
  remoteDomainAutoForwardBlocked?: boolean;
  // Get-ExternalInOutlook's Enabled — the "this message is from an external
  // sender" Outlook banner.
  externalSenderTagEnabled?: boolean;
  domainAuth: DomainAuthStatus[];
  mdoThreat: {
    policies: MdoThreatPolicy[];
    tabl: TablEntry[];
    alerts: MdoThreatAlert[];
  };
  appRegistrations: AppRegistrationItem[];
  intune: IntunePolicySummary;
  groups: TenantGroup[];
  sharePoint: SharePointTenantPolicy;
  highRiskThreatIndicators: {
    // externalForwardingCount intentionally removed: it was a second, separate
    // mock-only counter that never derived from emailForwarding and was never
    // populated by a live sync — every reader now computes it directly from
    // emailForwarding instead (see e.g. MdoPoliciesModule's own count pattern).
    openSharePointSitesCount: number;
    unprotectedAdminsCount: number;
    highRiskAppRegistrationsCount: number;
  };
}

// Audit Trail — records mutating/sensitive actions (CA policy deployments, MCP
// tool executions, sync failures) for after-the-fact review. Pruned on write
// according to SystemSettings.auditLogRetentionDays.
export interface AuditLogEntry {
  id: number;
  timestamp: string;
  category: "ca_policy_deploy" | "mcp_tool_call" | "tenant_sync_failure" | "exo_write";
  action: string;
  tenantId?: string;
  tenantName?: string;
  success: boolean;
  detail?: string;
}

// System Settings & MCP Config
export interface SystemSettings {
  enableMcpServer: boolean;
  mcpAuthToken?: string;
  // Gates manage_tabl's mutating add/remove actions (see src/lib/mcp/engine.ts) —
  // read-only MCP tools always run regardless of this setting.
  allowToolExecution: boolean;
  autoSyncIntervalMinutes: number;
  auditLogRetentionDays: number;
}

// Time Range & Date Filter Types
export type TimeRangePreset = "all" | "24h" | "7d" | "30d" | "custom";

export interface CustomDateRange {
  startDate: string; // ISO date format YYYY-MM-DD or full ISO
  endDate: string;   // ISO date format YYYY-MM-DD or full ISO
}

// Alert Dismissal / Clearance State
export interface DismissedAlertsState {
  [tenantId: string]: {
    allCleared?: boolean;
    clearedAt?: string;
    modules?: {
      ca_baseline?: boolean;
      signin_logs?: boolean;
      mfa_audit?: boolean;
      user_class?: boolean;
      forwarding?: boolean;
      groups?: boolean;
    };
  };
}

