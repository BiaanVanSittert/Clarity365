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
  certificateThumbprint?: string;
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
  category: "Identity" | "Device" | "Apps" | "Data";
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
  mdoThreat: {
    policies: MdoThreatPolicy[];
    tabl: TablEntry[];
  };
  appRegistrations: AppRegistrationItem[];
  intune: IntunePolicySummary;
  groups: TenantGroup[];
  sharePoint: SharePointTenantPolicy;
  highRiskThreatIndicators: {
    externalForwardingCount: number;
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
  category: "ca_policy_deploy" | "mcp_tool_call" | "tenant_sync_failure";
  action: string;
  tenantId?: string;
  tenantName?: string;
  success: boolean;
  detail?: string;
}

// System Settings & MCP Config
export interface SystemSettings {
  enableMcpServer: boolean;
  mcpServerPort: number;
  mcpAuthToken?: string;
  allowToolExecution: boolean;
  autoSyncIntervalMinutes: number;
  auditLogRetentionDays: number;
  defaultTheme: "light" | "system";
  tableDensity: "compact" | "normal";
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

