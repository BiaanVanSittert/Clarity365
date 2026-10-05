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

export interface ExoAppAccess {
  // ok: token has Exchange.ManageAsApp and a usable role. notSetUp: the
  // permission or the role is missing. error: the check itself failed.
  status: "ok" | "notSetUp" | "error";
  // Entra role found in the token's `wids` claim.
  role?: "exchangeAdministrator" | "globalAdministrator" | "globalReader" | "otherRole";
  // Exchange Administrator / Global Administrator can write; Global Reader can't.
  canWrite: boolean;
  hasPermission: boolean;
  // How the app authenticated. "clientSecret" works but isn't Microsoft's
  // documented method for Exchange (certificates are) - see the plan.
  method: "clientSecret" | "certificate";
  checkedAt: string;
  detail?: string;
}

export interface TenantCredentials {
  tenantId: string;
  clientId?: string;
  clientSecret?: string;
  // Optional Exchange Online delegated-auth connection, used only for MDO
  // policy & TABL sync (see exo-client.ts) - Exchange admin APIs don't accept
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
  // permissions can - whatever Exchange role the connecting admin holds is
  // what Clarity365 can do via EXO - so this flag is the explicit,
  // admin-controlled substitute for the missing narrower consent: it gates
  // whether TABL Add/Remove actually calls New-/Remove-TenantAllowBlockListItems
  // against the live tenant, versus staying purely local-only tracking.
  exoWriteEnabled?: boolean;
  // App-only Exchange Online access through this app registration: the
  // Office 365 Exchange Online "Exchange.ManageAsApp" permission plus an
  // Entra role assigned to the app. No sign-in involved - this replaces the
  // device-code connection above whenever it's set up (see ai-context-vault/
  // Optimization/Exchange App-Only Access Plan.md). Recorded by the sync and
  // the Permissions check; undefined = never checked. Not a secret.
  exoAppAccess?: ExoAppAccess;
  // When the client secret in use expires, read by the sync from the app's
  // own registration (credential-expiry.ts). Undefined = not known. Not a secret.
  secretExpiry?: SecretExpiry;
  authMode: "mock" | "secret" | "certificate";
  verifiedAt?: string;
}

// Microsoft 365 alert policies, read by the sync through Security &
// Compliance PowerShell (scc-client.ts).
export interface AlertPolicySummary {
  name: string;
  // The audit-log activities the policy watches. Empty for Microsoft's malware-type policies.
  operations: string[];
  disabled: boolean;
  // True for Microsoft's built-in policies.
  isSystemRule: boolean;
  // How many addresses are emailed (the addresses themselves aren't stored).
  notifyRecipients: number;
  notificationEnabled?: boolean;
  aggregation?: string;
  threshold?: number;
  timeWindowMinutes?: number;
  severity?: string;
  category?: string;
}

export interface AlertPolicyInventory {
  policies: AlertPolicySummary[];
  // Set when the policies couldn't be read; `policies` is then empty and
  // must not be read as "no alert policies".
  unavailable?: "notSetUp" | "error";
  detail?: string;
  checkedAt: string;
}

// Security Scenarios checks an operator can confirm once per tenant because
// Microsoft doesn't expose the setting (see scenario-confirmations.ts).
export type ScenarioConfirmationKey = "alert-audit-config" | "alert-user-deletion" | "sharepoint-anyone-link-expiry" | "sharepoint-default-link";

export interface ScenarioConfirmation {
  status: "inPlace" | "notInPlace";
  confirmedAt: string;
  note?: string;
}

export interface SecretExpiry {
  expiresAt: string;
  // True when the secret in use was identified exactly; false when this is
  // the soonest-expiring secret on the app registration (a safe estimate).
  exact: boolean;
  checkedAt: string;
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
  connectionStatus: "healthy" | "degraded" | "disconnected" | "error";
  credentials: TenantCredentials;
  // "Confirmed once" answers for Security Scenarios checks. Local to
  // Clarity365; lapse after a year.
  scenarioConfirmations?: Partial<Record<ScenarioConfirmationKey, ScenarioConfirmation>>;
  isDemo?: boolean;
  // Deliberate per-tenant opt-in for endpoint-security deploy features
  // (MDE connector toggles, Defender AV policy, ASR rule deployment) -
  // defaults to "read_only" wherever undefined (older tenants, mock data)
  // rather than requiring a migration. See EndpointSecurityWriteMode.
  endpointSecurityWriteMode?: "read_only" | "write_enabled";
  // Manual attestation state for the organizational/legal half of the
  // Compliance Readiness controls (see compliance-evaluator.ts's POPIA/
  // GDPR/HIPAA control sets - ai-context-vault/Optimization/Compliance
  // Readiness Checklist Plan.md). Keyed by ControlDefinition.attestationKey.
  // Set ONLY by a human via the Compliance Matrix UI - never inferred or
  // auto-set, since nothing in this app can verify a contract was actually
  // signed or a registration actually filed. Persisted through the existing
  // generic PUT /api/tenants/{id} route (updateTenant's partial merge does a
  // SHALLOW merge, so a write must always send the full map, not one key).
  complianceAttestations?: Record<
    string,
    { attested: boolean; attestedAt?: string; attestedBy?: string; note?: string }
  >;
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
    // exclude here is Graph's excludeUsers only; excludeGroupIds is the
    // separate excludeGroups field - Graph models "exclude this group of
    // people" and "exclude this specific group" as distinct properties, and
    // this app previously only captured the former (see the Groups baseline's
    // G03 check, which is the first thing that actually needs the latter).
    // includeRoles preserves Graph's directory-role targeting (conditions.users.includeRoles)
    // distinctly from includeUsers - collapsing the two into `include` loses the signal
    // ca-baseline-matcher.ts's targetsAdminRoles() needs to recognize admin-scoped policies.
    //
    // Everything marked "Security Simulations" below was previously dropped
    // by mapConditionalAccessPolicy() - see ai-context-vault/Optimization/
    // Security Simulations Plan.md, Stage 1. All optional: snapshots
    // persisted before these existed simply don't have them (no migration
    // system - see Optimization Plan's tenth bug-class variant), and
    // undefined must be read as "not synced yet", never as "not configured".
    users: {
      include: string[];
      exclude: string[];
      excludeGroupIds?: string[];
      includeRoles?: string[];
      // Security Simulations: Graph's includeGroups (only excludeGroups was
      // kept before, so a group-scoped policy looked like it targeted nobody).
      includeGroupIds?: string[];
      excludeRoles?: string[];
      // guestOrExternalUserTypes, split from Graph's comma-separated string -
      // which guest kinds the include/exclude "GuestsOrExternalUsers" marker covers.
      includeGuestTypes?: string[];
      excludeGuestTypes?: string[];
    };
    applications: {
      include: string[];
      exclude: string[];
      // includeUserActions, e.g. "urn:user:registersecurityinfo" / "urn:user:registerdevice"
      userActions?: string[];
      // includeAuthenticationContextClassReferences, e.g. ["c1"]
      authenticationContexts?: string[];
    };
    clientAppTypes: string[];
    platforms?: { include: string[]; exclude: string[] };
    locations?: { include: string[]; exclude: string[] };
    userRiskLevels?: string[];
    signInRiskLevels?: string[];
    // authenticationFlows.transferMethods, split: "deviceCodeFlow" / "authenticationTransfer"
    authenticationFlows?: string[];
    // Graph returns a comma-separated flags string ("minor,moderate,elevated")
    insiderRiskLevels?: string[];
    // Stored as-is and never parsed - the rule is its own expression
    // language, so anything evaluating it must report "indeterminate".
    deviceFilter?: { mode: "include" | "exclude"; rule: string };
    // Workload-identity targeting (conditions.clientApplications)
    clientApplications?: { includeServicePrincipals: string[]; excludeServicePrincipals: string[] };
    servicePrincipalRiskLevels?: string[];
  };
  // grantControls.operator - "OR" means any one listed control satisfies the
  // policy, "AND" means all of them are required. Undefined on old snapshots.
  grantOperator?: "AND" | "OR";
  sessionControls?: CaSessionControls;
  matchesBaseline: boolean;
  recommendation?: string;
}

// conditionalAccessPolicy.sessionControls. tokenProtection and
// continuousAccessEvaluation exist only on the beta endpoint (confirmed
// against Microsoft Learn 2026-09-29: v1.0's conditionalAccessSessionControls
// has only the other five), so they're filled from a separate best-effort
// beta read - undefined means that read didn't happen or failed, not "off".
export interface CaSessionControls {
  signInFrequency?: {
    isEnabled: boolean;
    value?: number;
    type?: "hours" | "days";
    frequencyInterval?: "timeBased" | "everyTime";
    authenticationType?: string;
  };
  persistentBrowser?: { isEnabled: boolean; mode?: "always" | "never" };
  applicationEnforcedRestrictions?: boolean;
  cloudAppSecurity?: { isEnabled: boolean; type?: string };
  disableResilienceDefaults?: boolean;
  // beta: secureSignInSession (token protection)
  tokenProtection?: boolean;
  // beta: continuousAccessEvaluation.mode
  continuousAccessEvaluation?: "disabled" | "strictEnforcement" | "strictLocation";
}

// Exchange Online settings the Security Simulations scenarios need (Stage 5).
// Every field optional: undefined = that EXO read didn't happen or failed.
export interface ExchangeSecuritySettings {
  // Get-AdminAuditLogConfig UnifiedAuditLogIngestionEnabled. Only accurate
  // when read through Exchange Online (it's always False in Security &
  // Compliance PowerShell) - Clarity365 reads it through EXO.
  unifiedAuditLogIngestionEnabled?: boolean;
  // Get-TransportConfig SmtpClientAuthenticationDisabled (org-wide default).
  smtpClientAuthDisabledOrgWide?: boolean;
  // Get-CASMailbox, capped like the mailbox scan.
  casMailboxes?: CasMailboxProtocols[];
  casMailboxesTruncated?: boolean;
}

export interface CasMailboxProtocols {
  primarySmtpAddress: string;
  popEnabled: boolean;
  imapEnabled: boolean;
  activeSyncEnabled: boolean;
  // Per-mailbox override; null = follows the org-wide setting.
  smtpClientAuthDisabled: boolean | null;
}

// Directory role assignments with their PIM state (Stage 5).
export interface PrivilegedRoleAssignments {
  // "pim": roleEligibility/roleAssignmentScheduleInstances (needs Entra ID
  // P2). "roleAssignments": the non-PIM fallback, which only lists active
  // assignments and can't tell permanent from time-bound.
  source: "pim" | "roleAssignments";
  assignments: PrivilegedRoleAssignment[];
  // Why PIM data wasn't used when source is "roleAssignments" (Graph's error).
  pimUnavailableReason?: string;
}

export interface PrivilegedRoleAssignment {
  principalId: string;
  principalType: "user" | "group" | "servicePrincipal" | "unknown";
  principalDisplayName?: string;
  principalUserPrincipalName?: string;
  // Lower-case role template id (roleDefinitionId for built-in roles).
  roleTemplateId: string;
  // eligible: must activate through PIM. activated: a PIM activation in
  // progress. activePermanent / activeTimeBound: standing assignments.
  kind: "eligible" | "activated" | "activePermanent" | "activeTimeBound";
  endDateTime?: string;
}

// Delegated permission grants (oauth2PermissionGrants), aggregated per app
// and consent type (Stage 5).
export interface OAuthConsentGrantSummary {
  grants: OAuthConsentGrant[];
  // True when the grant list hit the page cap.
  truncated: boolean;
  // Set when grants couldn't be read at all (grants is then empty and means
  // "unknown", not "none"). "missingPermission": the app registration lacks
  // DelegatedPermissionGrant.Read.All / Directory.Read.All - found on every
  // live tenant at first sync, so it's reported here rather than as a sync
  // error that would mark every tenant "degraded".
  unavailable?: "missingPermission" | "error";
  unavailableDetail?: string;
}

export interface OAuthConsentGrant {
  servicePrincipalId: string;
  appDisplayName?: string;
  publisherName?: string;
  publisherVerified?: boolean;
  // Published by Microsoft itself.
  isMicrosoftApp?: boolean;
  // AllPrincipals = admin consented for everyone; Principal = user consent.
  consentType: "AllPrincipals" | "Principal";
  scopes: string[];
  highRiskScopes: string[];
  // Users who consented (Principal grants only).
  userCount: number;
}

// identity/conditionalAccess/namedLocations - resolves the location GUIDs a
// CAPolicyRule references into countries or IP ranges.
export interface CaNamedLocation {
  id: string;
  displayName: string;
  kind: "country" | "ip";
  // kind === "country": ISO 3166-1 alpha-2, uppercase (same convention as SignInEvent.location.country)
  countries?: string[];
  includeUnknownCountries?: boolean;
  countryLookupMethod?: "clientIpAddress" | "authenticatorAppGps";
  // kind === "ip"
  ipRanges?: string[];
  isTrusted?: boolean;
}

// Tenant-wide identity settings the Security Simulations scenarios need that
// live outside Conditional Access itself. Every field optional - undefined
// means "not synced", never "off".
export interface TenantIdentitySettings {
  // policies/identitySecurityDefaultsEnforcementPolicy.isEnabled - when true,
  // Conditional Access can't be used at all.
  securityDefaultsEnabled?: boolean;
  // policies/authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
  userConsentPolicies?: string[];
  // Derived from userConsentPolicies (ManagePermissionGrantsForSelf.* entries only):
  // "disabled" (none), "verifiedPublishersLowRisk" (microsoft-user-default-low),
  // "microsoftRecommended" (microsoft-user-default-recommended),
  // "allApps" (microsoft-user-default-legacy), "custom" (anything else)
  userConsentMode?: "disabled" | "verifiedPublishersLowRisk" | "microsoftRecommended" | "allApps" | "custom";
  // authorizationPolicy.guestUserRoleId, resolved to a readable level
  guestAccessLevel?: "sameAsMember" | "limited" | "restricted" | "unknown";
  // authorizationPolicy.allowInvitesFrom
  guestInviteSetting?: "none" | "adminsAndGuestInviters" | "adminsGuestInvitersAndAllMembers" | "everyone" | "unknown";
  // policies/adminConsentRequestPolicy.isEnabled
  adminConsentWorkflowEnabled?: boolean;
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

// How a sign-in was authenticated. Only Microsoft's beta sign-in log reports
// this; see sign-in-authentication.ts.
export interface SignInAuthentication {
  // What Entra required for this sign-in. "singleFactor" means MFA was not
  // required - not necessarily that the account has no MFA.
  requirement: "singleFactor" | "multiFactor";
  // Methods presented in this sign-in ("Password", "Mobile app notification", ...).
  methods: string[];
  // True when no method was presented because an existing session already satisfied it.
  fromExistingSession: boolean;
}

export interface SignInEvent {
  id: string;
  createdDateTime: string;
  // Optional: undefined on demo data, on snapshots synced before 2026-10-01
  // and when the beta sign-in log wasn't available.
  authentication?: SignInAuthentication;
  userType?: "member" | "guest";
  // Autonomous System Number of the network the sign-in came from.
  asn?: number;
  userPrincipalName: string;
  userDisplayName: string;
  userId: string;
  ipAddress: string;
  location: {
    city: string;
    state: string;
    // Always an ISO 3166-1 alpha-2 code (e.g. "US", "BG"), uppercase - this
    // is what Graph's real signInLocation.countryOrRegion field actually
    // returns ("the country code info (two letter code)", per Microsoft's
    // own resource reference), and graph-client.ts stores it unmodified.
    // Never a full country name - mock data used to disagree with this
    // (e.g. "United States") until that was normalized to match live data,
    // exactly the kind of two-representations-of-one-fact drift this
    // project has hit before. Resolve to a display name via
    // sign-in-country.ts's getCountryDisplayName(), never re-derived ad hoc.
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

// What Clarity365 can actually do about a control, distinct from Microsoft's
// own userImpact/implementationCost fields: "auto" means this app already has
// a live Graph write path for it (set via clarity365Action, e.g. a CA baseline
// code or an Endpoint Security policy key) and can offer a one-click deploy;
// "guided" means there's a documented fix (actionUrl and/or a PowerShell
// script) but no in-app write path yet; "manual_only" covers anything that
// isn't scriptable at all (purchasing a license, an org-wide behavior change).
export interface SecureScoreControlDeployment {
  type: "auto" | "guided" | "manual_only";
  clarity365Action?: string;
}

export interface SecureScoreControl {
  id: string;
  title: string;
  category: "Identity" | "Device" | "Apps" | "Data" | "Infrastructure";
  scoreCurrent: number;
  scoreMax: number;
  // Live Graph data - see secure-score-mapper.ts's mapSecureScoreControl -
  // shows "Unknown" for the majority of controls (confirmed live: ~70% of a
  // real tenant's catalog) and "Medium" as well as "Moderate" for the same
  // concept depending on the control. Never silently collapse "Unknown" into
  // a real severity - that misrepresents "Microsoft didn't classify this" as
  // an actual moderate rating.
  implementationCost: "Low" | "Moderate" | "High" | "Unknown";
  userImpact: "Low" | "Moderate" | "High" | "Unknown";
  status: "Completed" | "Partial" | "Unresolved" | "Ignored";
  actionType: "Requirement" | "Configuration" | "Policy";
  // Tenant-specific "why this matters" text, from the secureScores
  // controlScores[] entry - distinct from remediationSummary's "how to fix"
  // steps, which come from the separate secureScoreControlProfiles catalog.
  description: string;
  remediationSummary: string;
  // Direct deep link to the exact admin portal blade for this control
  // (Graph's controlProfile.actionUrl) - real and live, not authored by this
  // app. Absent for some controls (third-party/AATP-sourced ones especially).
  actionUrl?: string;
  // Graph's controlProfile.remediationImpact - the effect on end users of
  // actually applying the fix (e.g. "users must re-authenticate"), a
  // different axis from the userImpact severity enum above.
  remediationImpact?: string;
  threats?: string[];
  // Graph's controlScores[].implementationStatus free-text (e.g. "current
  // status: On") - supplementary to the derived status enum, not a
  // replacement for it.
  implementationStatus?: string;
  powershellCommand?: string;
  deployment: SecureScoreControlDeployment;
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
  // Role template GUIDs (lower-case) from real directoryRoles membership -
  // what Conditional Access includeRoles/excludeRoles compare against.
  // Undefined on snapshots synced before Security Simulations Stage 2, and
  // never set for the "Global Administrator" placeholder adminRoles gets when
  // only the registration report says isAdmin. Note directoryRoles lists
  // active assignments only: PIM-eligible (not activated) roles and roles
  // held via a role-assignable group are not included here.
  adminRoleTemplateIds?: string[];
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

// Cross-reference of mfaAudit (admin role membership) against accountClassification
// (per-user license assignment) - a privileged admin account also provisioned with a
// daily-use Exchange/Teams license, see admin-hygiene-matcher.ts
export interface LicensedGlobalAdminRisk {
  userId: string;
  userPrincipalName: string;
  displayName: string;
  adminRoles: string[];
  licenses: string[];
}

// The general superset of LicensedGlobalAdminRisk above - every admin account
// (licensed or not), with full role lists and precomputed status flags, so
// consumers (Privileged Access Review, User Classification) don't re-join.
export interface PrivilegedAccountRecord {
  userId: string;
  userPrincipalName: string;
  displayName: string;
  adminRoles: string[];
  accountEnabled: boolean;
  lastSignInDateTime: string;
  mfaRegistered: boolean;
  isWeakAuth: boolean;
  defaultMethod: AuthMethodType;
  isUnprotected: boolean;
  licenses: string[];
  isLicensedForDailyUse: boolean;
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
  // Baseline-scoring fields (see mdo-baseline-definitions.ts) - each backs one
  // specific MDO0x check rather than a generic "is it configured" boolean.
  realTimeScanning: boolean; // SafeLinks: URLs are actually scanned in real time, not just rewritten
  blockingAction: boolean; // SafeAttachments: action is Block/DynamicDelivery, not Allow/Monitor
  commonAttachmentFilter: boolean; // AntiMalware: common attachment type filter enabled
  outboundNotify: boolean; // AntiSpamOutbound: admin is notified of suspected outbound spam
  // AntiSpamOutbound: AutoForwardingMode is "Off" - the tenant-wide kill
  // switch controlling whether ANY auto-forward to an external address is
  // even possible. Scored by the Mail Flow Rules baseline (MF04), not the
  // MDO0x baseline - a separate concern from outboundNotify/MDO08.
  autoForwardingBlocked?: boolean;
}

// Full-fidelity org-wide transport rule shape used by the Transport & Mail
// Flow Rules baseline (mailflow-baseline-*.ts) - distinct from
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
  overridesSpamConfidence: boolean; // SetSCL action present - bypasses spam/phish filtering for matching mail
  hasNoScopingConditions: boolean; // applies to all mail, not a specific sender/domain/recipient
  hasExpiry: boolean;
}

export interface MailflowConnector {
  id: string;
  name: string;
  direction: "Inbound" | "Outbound";
  enabled: boolean;
  // Inbound only: treats all mail claiming to be from a configured domain as
  // pre-authenticated regardless of sending IP - a common way spam/phish
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

// Domain Authentication (SPF/DKIM/DMARC) - the primary defense against the
// tenant's own domain being spoofed to phish its customers/partners. DKIM
// comes from the Exchange Online connection; SPF/DMARC are public DNS TXT
// lookups, so - unlike everything else in this app - remediation here is
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
  // disabled (or EXO wasn't connected yet) - see tenant-store.addTablEntry.
  // A live resync merges these back in rather than dropping them, since
  // they were never pushed to the real Tenant Allow/Block List and so never
  // come back from a Get-TenantAllowBlockListItems fetch.
  isLocalOnly?: boolean;
}

// Static definition of one MDO0x baseline check (mirrors CABaselineItem) -
// see mdo-baseline-definitions.ts for the actual MDO_BASELINE_STANDARDS list.
export interface MdoBaselineItem {
  code: string;
  name: string;
  description: string;
  policyType: MdoThreatPolicy["policyType"];
  riskMitigated: string;
}

// Per-check result of scoring live MdoThreatPolicy data against
// MDO_BASELINE_STANDARDS (mdo-baseline-definitions.ts) - the dynamic half of
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

// Module 8.6: Security Operations & Incident Response Center
export type IncidentSeverity = "critical" | "high" | "medium" | "low" | "informational";
export type IncidentStatus = "active" | "inProgress" | "resolved" | "redirected";

export interface IncidentImpactedUser {
  id?: string;
  userPrincipalName: string;
  displayName: string;
}

export interface IncidentImpactedDevice {
  id?: string;
  deviceName: string;
  operatingSystem?: string;
  isIsolated?: boolean;
}

export interface SecurityIncidentItem {
  id: string;
  incidentId: string;
  displayName: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  classification?: "truePositive" | "falsePositive" | "benignPositive" | "unknown";
  determination?: string;
  createdDateTime: string;
  lastUpdateDateTime: string;
  assignedTo?: string;
  mitreTechniques: string[];
  alertsCount: number;
  impactedUsers: IncidentImpactedUser[];
  impactedDevices: IncidentImpactedDevice[];
  description: string;
  recommendedActions: string[];
  commentsCount?: number;
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
  // call via an expanded $select (see graph-client.ts) - optional because
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
  // Per-setting reasons this device is failing compliance (e.g. "Require
  // BitLocker", "Require Threat scan" i.e. Defender Antimalware, "Minimum OS
  // version") - only populated for devices with at least one non-compliant/
  // error/conflict setting. Sourced from
  // deviceCompliancePolicySettingStateSummaries, a fleet-wide (not
  // per-device) Graph resource - see
  // ai-context-vault/Optimization/Intune Non-Compliance Reasons Plan.md.
  // Optional/additive - undefined just means "not yet re-synced since this
  // field was added" or "no specific setting failures reported by
  // Microsoft," not "compliant."
  nonComplianceReasons?: DeviceComplianceReason[];
}

export interface DeviceComplianceReason {
  settingName: string; // Graph's own human-readable name, e.g. "Require BitLocker"
  // "unknown"/"compliant"/"remediated"/"notApplicable" rows are deliberately
  // never turned into a DeviceComplianceReason - they aren't an actionable
  // finding, so a device with only those has zero reasons, not a confusing
  // "unknown" chip (see the UI's "no specific reasons reported" fallback).
  state: "nonCompliant" | "error" | "conflict";
}

// Microsoft Defender for Endpoint connector settings (the "Defender and MEM
// Reporting" blade in Intune) - deviceManagement/mobileThreatDefenseConnectors,
// v1.0 fields plus a handful only exposed in beta (noted per-field below).
// Verified property-by-property against Microsoft's own Graph API reference
// before implementation - a few settings from that blade (Android COBO/COPE
// MTD role grant, EDR auto-connect-package, EDR sample sharing) genuinely
// aren't exposed via Graph at all and are deliberately not modeled here.
export interface MdeConnectorSettings {
  id: string;
  lastHeartbeatDateTime?: string;
  partnerState: "unavailable" | "available" | "enabled" | "unresponsive" | "notSetUp" | "error" | "unknownFutureValue";
  microsoftDefenderForEndpointAttachEnabled: boolean;
  partnerUnsupportedOsVersionBlocked: boolean;
  androidEnabled: boolean;
  androidMobileApplicationManagementEnabled: boolean;
  androidDeviceBlockedOnMissingPartnerData: boolean;
  iosEnabled: boolean;
  iosMobileApplicationManagementEnabled: boolean;
  iosDeviceBlockedOnMissingPartnerData: boolean;
  allowPartnerToCollectIOSApplicationMetadata: boolean;
  allowPartnerToCollectIOSPersonalApplicationMetadata: boolean;
  // beta-only
  allowPartnerToCollectIosCertificateMetadata?: boolean;
  allowPartnerToCollectIosPersonalCertificateMetadata?: boolean;
  windowsEnabled: boolean;
  windowsMobileApplicationManagementEnabled?: boolean; // beta-only
  windowsDeviceBlockedOnMissingPartnerData: boolean;
  macEnabled?: boolean; // beta-only
  macDeviceBlockedOnMissingPartnerData?: boolean; // beta-only
}

// Per-device Microsoft Defender for Endpoint onboarding status -
// deviceManagement/advancedThreatProtectionOnboardingStateSummary's
// advancedThreatProtectionOnboardingDeviceSettingStates relationship (beta).
// This is the real telemetry intune-mapper.ts's own comment says would be
// needed to replace the compliance-state-derived edrOnboardingState
// approximation with actual Defender data - see applyRealEdrOnboardingStates.
export interface AtpOnboardingDeviceState {
  deviceName: string;
  userPrincipalName?: string;
  platformType?: string;
  state: "unknown" | "notApplicable" | "compliant" | "remediated" | "nonCompliant" | "error" | "conflict" | "notAssigned";
}

export interface IntunePolicySummary {
  antivirusPoliciesCount: number;
  edrPoliciesCount: number;
  compliantDevices: number;
  nonCompliantDevices: number;
  totalDevices: number;
  devices: IntuneDevice[];
  // Undefined until a live sync fetches these (mock/blank snapshots don't
  // populate them) - both optional for the same reason licenseSkus is.
  mdeConnectorSettings?: MdeConnectorSettings;
  onboardingStates?: AtpOnboardingDeviceState[];
  // Phase 2 write path - the Clarity365-deployed Defender AV Settings
  // Catalog policy, if any. Populated on-demand (endpoint-security module
  // fetch), not part of the main sync - see DefenderAvPolicySettings below.
  defenderAvPolicy?: {
    deployedPolicyId?: string;
    settings: DefenderAvPolicySettings;
  };
  // Same on-demand, deploy-on-request shape as defenderAvPolicy above.
  edrPolicy?: {
    deployedPolicyId?: string;
    settings: EdrPolicySettings;
  };
  // Same on-demand, deploy-on-request shape as defenderAvPolicy above.
  bitLockerPolicy?: {
    deployedPolicyId?: string;
    settings: BitLockerPolicySettings;
  };
  // Deliberately NOT the same shape as defenderAvPolicy/edrPolicy above: ASR
  // rule state (asrRules on TenantSecuritySnapshot) is merged from up to
  // three independent Intune surfaces, and a tenant can genuinely have
  // multiple pre-existing Settings Catalog ASR policies that Clarity365
  // didn't create (another admin's, another tool's). This field tracks only
  // the id of the one policy *this app itself* created via deployAsrRules,
  // set the moment that create call succeeds - never inferred from the
  // general multi-surface sync - so a later "Deploy ASR Rules" click updates
  // that specific policy in place instead of guessing at (and potentially
  // overwriting) some other policy it never made.
  clarity365AsrPolicyId?: string;
}

// Microsoft Defender Antivirus Settings Catalog policy toggles. Field names,
// grouping, and the settingDefinitionId map in graph-client.ts's
// DEFENDER_AV_SETTING_DEFINITION_IDS were all confirmed live against a real
// tenant's own Settings Catalog category/setting metadata
// (deviceManagement/configurationCategories + configurationSettings, the
// same tenant-agnostic catalog the ASR slug-map already reads) - not just
// Microsoft's docs. That live check caught two wrong IDs this file's own
// comments had previously asserted with false confidence (allowFullScanOnRemovableDrives,
// allowUpdatesOnMeteredNetwork) and one field (allowCloudProtection) that
// was missing entirely - see graph-client.ts for the corrected map.
export interface DefenderAvPolicySettings {
  // Real-time protection
  allowRealtimeMonitoring?: boolean; // "Allow Realtime Monitoring"
  allowBehaviorMonitoring?: boolean; // "Allow Behavior Monitoring"
  allowCloudProtection?: boolean; // "Allow Cloud Protection"
  allowIOAVProtection?: boolean; // "Allow scanning of all downloaded files and attachments"
  allowScriptScanning?: boolean; // "Allow Script Scanning"
  allowScanningNetworkFiles?: boolean; // "Allow Scanning Network Files"
  allowEmailScanning?: boolean; // "Allow Email Scanning"
  // Scan
  allowArchiveScanning?: boolean; // "Allow Archive Scanning"
  allowFullScanOnMappedNetworkDrives?: boolean; // "Allow Full Scan On Mapped Network Drives"
  allowFullScanOnRemovableDrives?: boolean; // "Allow Full Scan Removable Drive Scanning"
  enableLowCpuPriority?: boolean; // "Enable Low CPU Priority"
  disableCatchupFullScan?: boolean; // "Disable Catchup Full Scan"
  disableCatchupQuickScan?: boolean; // "Disable Catchup Quick Scan"
  checkForSignaturesBeforeRunningScan?: boolean; // "Check For Signatures Before Running Scan"
  // Updates
  allowUpdatesOnMeteredNetwork?: boolean; // "Metered Connection Updates" (no "Allow" prefix - confirmed live)
  // Exclusions / admin merge
  disableLocalAdminMerge?: boolean; // "Disable Local Admin Merge"
  // User experience
  allowUserUIAccess?: boolean; // "Allow User UI Access"
}

// Endpoint Detection and Response policy (a real, assignable Settings
// Catalog policy, category "Microsoft Defender for Endpoint" -
// device_vendor_msft_windowsadvancedthreatprotection_* setting root,
// confirmed live the same way as DefenderAvPolicySettings). Deliberately
// narrower than every EDR profile option Microsoft exposes: "Onboard"/
// "Offboard" configuration-package-type values require pasting a signed
// blob file downloaded from the Defender portal, which isn't modeled here -
// only the "Auto from connector" path (recommended by Microsoft, and the
// only one that needs no manual file) is exposed as a plain toggle.
export interface EdrPolicySettings {
  // "Microsoft Defender for Endpoint client configuration package type" set
  // to "Auto from connector" when true, left not-configured when false/unset.
  autoFromConnector?: boolean;
  // "Sample Sharing": "All" when true, "None" when false, not-configured when unset.
  sampleSharingAll?: boolean;
}

// BitLocker Settings Catalog policy toggles (Device/Vendor/MSFT/BitLocker
// CSP - the direct CSP category Microsoft's Intune "Endpoint Security >
// Disk encryption > BitLocker" profile uses, confirmed live against a real
// tenant's own Settings Catalog category/setting metadata, not guessed -
// distinct from the separate "BitLocker Drive Encryption" Administrative
// Templates/GPO category, which this app doesn't use, matching the same
// direct-CSP convention DefenderAvPolicySettings/EdrPolicySettings already
// use). Deliberately narrower than every BitLocker CSP setting Microsoft
// exposes: RemovableDrivesExcludedFromEncryption takes a free-form
// comma-separated hardware-id list, not a simple toggle, and is out of
// scope for a plain checkbox form (same reasoning EDR uses to exclude
// Onboard/Offboard).
export interface BitLockerPolicySettings {
  // "Require Device Encryption" - the actual on/off switch.
  requireDeviceEncryption?: boolean;
  // "Allow Standard User Encryption" - lets Require Device Encryption
  // succeed even when the currently signed-in user is a standard
  // (non-admin) user. Per Microsoft's own setting description, this is
  // functionally paired with allowWarningForOtherDiskEncryption below: it
  // only takes effect once that setting is also explicitly set to false
  // (silent encryption) - Graph's schema doesn't enforce this as a hard
  // dependency, but the setting is a no-op without it.
  allowStandardUserEncryption?: boolean;
  // "Allow Warning For Other Disk Encryption" - true (Microsoft's own
  // default when unset) shows the encryption notification/warning prompt;
  // false suppresses it and encrypts silently. Must be false for
  // allowStandardUserEncryption above to actually work - see its comment.
  allowWarningForOtherDiskEncryption?: boolean;
  // "Configure Recovery Password Rotation" - a real three-way choice
  // confirmed live, not a boolean: rotation off, on for Entra ID-joined
  // devices only (Microsoft's own default when this is left unset), or on
  // for both Entra ID-joined and hybrid-joined devices.
  recoveryPasswordRotation?: "off" | "entraIdOnly" | "entraIdAndHybrid";
}

// Recommended baseline, surfaced by the UI as a one-click "Use Recommended"
// preset rather than a silent default - never applied without an explicit
// admin action. Lives here (not graph-client.ts, which is server-only) so
// the client-side UI can import it directly without pulling in any
// server-side module. Require Device Encryption is the actual switch; the
// other three exist specifically to make that succeed cleanly in a real
// fleet: Allow Standard User Encryption ON + Allow Warning For Other Disk
// Encryption OFF together enable silent encryption even when the signed-in
// user isn't a local admin (per Microsoft's own docs, these two are
// functionally paired - see BitLockerPolicySettings' own comment above),
// and Recovery Password Rotation ON for both Entra ID and hybrid-joined
// devices is Microsoft's own stronger-than-default option (their unset
// default only covers Entra ID-joined devices).
export const RECOMMENDED_BITLOCKER_POLICY: BitLockerPolicySettings = {
  requireDeviceEncryption: true,
  allowStandardUserEncryption: true,
  allowWarningForOtherDiskEncryption: false,
  recoveryPasswordRotation: "entraIdAndHybrid",
};

// Standard Intune assignment-target shapes any Settings Catalog policy
// accepts, per Microsoft's documented assignments array. "none" = create
// the policy with an empty assignments call ("Do Not Assign") - it exists
// but affects nothing until assigned, the deliberate default for a fresh
// Phase 2 deploy so nothing is ever silently applied fleet-wide.
export interface IntuneAssignmentTarget {
  mode: "none" | "allDevices" | "allUsers" | "allUsersAndDevices" | "group";
  groupId?: string;
  excludeGroupId?: string;
}

// Read-only vs write-enabled gate for the endpoint-security deploy features
// (MDE connector toggles, Defender AV policy, ASR rule deployment) - a
// deliberate per-tenant choice (see Tenant.endpointSecurityWriteMode), not
// inferred from whatever Graph permission happens to be granted. Both this
// AND the actual DeviceManagementConfiguration.ReadWrite.All permission must
// be satisfied before any Deploy action is offered.
export type EndpointSecurityWriteMode = "read_only" | "write_enabled";

export interface IntuneCoverageGapUser {
  userId: string;
  userPrincipalName: string;
  displayName: string;
  department: string;
}

export interface IntuneCoverageGaps {
  usersWithoutIntuneDevice: IntuneCoverageGapUser[];
  devicesWithoutEdr: IntuneDevice[];
}

// Attack Surface Reduction rule state, per tenant. "warn" behaves like Block
// but the end user can click through it; both are treated as "in progress"
// rather than fully protected - see asr-rule-matcher.ts.
export type AsrRuleMode = "not_configured" | "audit" | "warn" | "block";

export interface AsrRuleState {
  ruleId: string; // GUID, matches AsrRuleDefinition.id in asr-rule-definitions.ts
  mode: AsrRuleMode;
  // Every source (Settings Catalog policy / legacy Device Configuration
  // profile / Endpoint Security Template) that contributed a non-"not
  // configured" opinion for this rule, deduped - see asr-configuration-mapper.ts.
  sourcePolicyNames?: string[];
  // True when 2+ sources set DIFFERENT modes for this rule. Intune's real
  // merge behavior drops a conflicting setting entirely rather than picking
  // a winner, so `mode` above is already "not_configured" in this case -
  // this flag is what keeps that distinguishable from a rule nobody has
  // ever touched, since a self-canceling policy pair is a real, actionable
  // misconfiguration.
  hasConflict?: boolean;
}

// Selectable lookback window for ASR detection activity (both the per-rule
// drawer and the module-wide summary). "all" doesn't literally mean
// unlimited - Advanced Hunting's DeviceEvents table only retains what the
// tenant's own retention policy keeps (30 days by default, longer if a
// tenant has configured extended retention) - it requests the longest
// window Graph will accept and lets Graph naturally return whatever is
// actually still retained, rather than this app guessing a tenant's real
// retention setting.
export type AsrDetectionTimeRange = "7d" | "30d" | "all";

// On-demand only (Advanced Hunting) - never stored on TenantSecuritySnapshot,
// see asr-detection-mapper.ts and Core Graph Layer notes for why.
export interface AsrRuleActivitySummary {
  ruleId: string;
  auditHitCount: number;
  blockHitCount: number;
  warnBypassedCount: number; // only nonzero for the 2 rules with a WarnBypassed action type
}

export interface AsrDetectionEvent {
  timestamp: string;
  deviceName: string;
  actionType: string; // raw Advanced Hunting ActionType, e.g. "AsrRansomwareBlocked"
  fileName?: string;
  folderPath?: string;
  initiatingProcessFileName?: string;
  initiatingProcessCommandLine?: string;
  additionalFields?: Record<string, unknown>;
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
  // Baseline-scoring fields (see groups-baseline-definitions.ts) - each backs
  // one specific G0x check, so unlike isPrivileged (a static demo-data flag)
  // these are populated from real Graph fields once live sync exists.
  isAssignableToRole: boolean; // membership in this group IS an admin role grant
  membershipRule?: string; // raw dynamic-membership rule text, for Dynamic groups
  guestMemberCount: number;
}

// Per-check result of scoring live TenantGroup/tenant-settings data against
// GROUPS_BASELINE_STANDARDS (groups-baseline-definitions.ts) - same shape as
// MailflowBaselineResult, since most checks here are also "does any group
// violate this" rather than a single per-type lookup like MDO's.
export interface GroupsBaselineResult {
  code: string;
  met: boolean;
  offendingGroupNames?: string[];
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
  // False when Graph didn't report the two fields above. v1.0's
  // sharepointSettings has neither a default link type nor an Anyone-link
  // expiry (confirmed on Microsoft Learn 2026-09-30), so on live tenants
  // they have always been placeholders ("Internal" / 0). Undefined on
  // snapshots from before Security Simulations Stage 5.
  linkDefaultsReported?: boolean;
  // Security Simulations Stage 5 - the rest of admin/sharepoint/settings.
  // Undefined = not synced.
  resharingByExternalUsersEnabled?: boolean;
  unmanagedSyncAppRestricted?: boolean;
  syncAllowedDomainCount?: number;
  sharingDomainRestrictionMode?: "none" | "allowList" | "blockList";
  legacyAuthProtocolsEnabled?: boolean;
  idleSessionSignOutEnabled?: boolean;
  requireAcceptingUserToMatchInvitedUser?: boolean;
  totalStorageAllocatedTB: number;
  totalStorageUsedTB: number;
  sites: SharePointSiteItem[];
}

// Per-check result of scoring live SharePointTenantPolicy data against
// SHAREPOINT_BASELINE_STANDARDS (sharepoint-baseline-definitions.ts) - same
// shape as GroupsBaselineResult/MailflowBaselineResult.
export interface SharePointBaselineResult {
  code: string;
  met: boolean;
  offendingSiteNames?: string[];
}

// Per-section result of the most recent live Graph sync. Absent entirely for
// demo/mock tenants and for snapshots that predate this field.
export interface SignInCoverage {
  // How far back the sync asks Microsoft for sign-ins.
  windowDays: number;
  count: number;
  // Oldest / newest sign-in loaded. Absent when none were.
  from?: string;
  to?: string;
  // False when older sign-ins inside the window weren't loaded.
  complete: boolean;
  // "limit": stopped at the sync's page limit (newest records only).
  // "error": Microsoft timed out or refused part-way.
  incompleteReason?: "limit" | "error";
  // Whether the sign-ins carry authentication details (MFA requirement and
  // method) - only when the beta sign-in log answered.
  hasAuthDetails?: boolean;
}

export interface SyncHealth {
  isPartial: boolean;
  errors: string[]; // e.g. "Sign-in logs: Pagination stopped early: Insufficient privileges."
  // Required Graph permissions the app registration didn't have at this sync
  // (read from the access token). Undefined on snapshots synced before 2026-10-01.
  missingPermissions?: string[];
  // Deliberate limits that were hit (e.g. "capped at the first 250 groups").
  // Not errors: they don't make a tenant degraded. Undefined before 2026-10-05.
  notices?: string[];
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
// GET /subscribedSkus - a tenant's purchased license pools. consumedUnits is
// how many are assigned; enabledUnits is how many were paid for; the gap is
// paid-for seats sitting unassigned (see calculateTenantMonthlyWaste's
// "unassigned_license_sku" category, which prices this out).
export interface TenantLicenseSku {
  skuId: string;
  skuPartNumber: string;
  consumedUnits: number;
  enabledUnits: number;
  availableUnits: number;
}

export interface TenantSecuritySnapshot {
  tenant: Tenant;
  // Shape version of the build that last live-synced this snapshot - see
  // src/lib/utils/sync-schema-version.ts. Absent on older snapshots.
  syncSchemaVersion?: number;
  syncHealth?: SyncHealth;
  capabilities: TenantCapability[];
  // Undefined until a live Graph sync has fetched /subscribedSkus (mock/blank
  // snapshots have no purchased-seat data to report).
  licenseSkus?: TenantLicenseSku[];
  secureScore: TenantSecureScore;
  conditionalAccess: {
    baselineCoverageScore: number;
    policies: CAPolicyRule[];
    baselineDefinitions: CABaselineItem[];
    // Undefined until a sync has fetched named locations (Security Simulations Stage 1).
    namedLocations?: CaNamedLocation[];
  };
  // Undefined until a sync has fetched them (Security Simulations Stage 1).
  identitySettings?: TenantIdentitySettings;
  // Security Simulations Stage 5. Each undefined until a sync fetched it.
  exchangeSecurity?: ExchangeSecuritySettings;
  privilegedRoleAssignments?: PrivilegedRoleAssignments;
  oauthConsentGrants?: OAuthConsentGrantSummary;
  signIns: SignInEvent[];
  // The period the synced sign-ins actually cover. Undefined on demo tenants
  // and snapshots synced before 2026-10-01 - read it through
  // getSignInCoverage() (sign-in-coverage.ts), which fills that gap.
  signInCoverage?: SignInCoverage;
  // Undefined until a sync has tried to read alert policies.
  alertPolicies?: AlertPolicyInventory;
  mfaAudit: UserMfaProfile[];
  accountClassification: TenantAccountSummary;
  mailboxes: MailboxItem[];
  emailForwarding: EmailForwardingRule[];
  // Get-OrganizationConfig's AuditDisabled, inverted - undefined until an EXO
  // sync has actually run (never connected, or the mailflow fetch itself
  // failed). Every mailbox-delegation and forwarding-rule finding in this
  // snapshot is only investigable after the fact if this is true, so it's
  // surfaced as a standalone gating check rather than folded into a generic list.
  mailboxAuditingEnabled?: boolean;
  mailflowTransportRules: MailflowTransportRule[];
  mailflowConnectors: MailflowConnector[];
  // Get-RemoteDomain (Default)'s AutoForwardEnabled === false - a second,
  // more obscure org-wide auto-forward switch distinct from
  // MdoThreatPolicy.autoForwardingBlocked (the outbound-spam one). Optional
  // because it's undefined until an EXO sync has actually populated it.
  remoteDomainAutoForwardBlocked?: boolean;
  // Get-ExternalInOutlook's Enabled - the "this message is from an external
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
  // Undefined until a live sync has resolved the tenant's Intune Attack
  // Surface Reduction intent(s) - see Core Graph Layer notes. A rule with no
  // entry here (or when this whole array is undefined) is treated as
  // "not_configured", not as "unknown", since that's the true default state
  // of any ASR rule nobody has ever touched.
  asrRules?: AsrRuleState[];
  groups: TenantGroup[];
  // Tenant-wide Entra ID group settings (GET /groupSettings) - undefined
  // until a live sync has actually populated them. Each backs one specific
  // G0x check (see groups-baseline-definitions.ts) rather than a per-group
  // field, since these are single tenant-wide switches, not per-group facts.
  groupExpirationPolicyEnabled?: boolean;
  groupSelfServiceCreationRestricted?: boolean;
  groupNamingPolicyEnabled?: boolean;
  sharePoint: SharePointTenantPolicy;
  incidents: SecurityIncidentItem[];
  highRiskThreatIndicators: {
    unprotectedAdminsCount: number;
    highRiskAppRegistrationsCount: number;
  };
}

// Audit Trail - records mutating/sensitive actions (CA policy deployments, MCP
// tool executions, sync failures, incident containment) for after-the-fact review.
export interface AuditLogEntry {
  id: number;
  timestamp: string;
  category:
    | "ca_policy_deploy"
    | "mcp_tool_call"
    | "tenant_sync_failure"
    | "exo_write"
    | "incident_containment"
    | "device_isolation"
    | "device_scan"
    | "defender_av_deploy"
    | "edr_policy_deploy"
    | "bitlocker_policy_deploy"
    | "asr_rule_deploy"
    | "mde_connector_update";
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
  // Gates manage_tabl's mutating add/remove actions (see src/lib/mcp/engine.ts) -
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

// ==========================================
// Phase 2.1: Fleet Management & Cross-Tenant Analytics
// ==========================================

export interface FleetTenantPosture {
  tenantId: string;
  displayName: string;
  defaultDomainName: string;
  tier: TenantLicenseType;
  connectionStatus: "healthy" | "degraded" | "disconnected" | "error";
  // Read-only visibility of when the tenant's client secret expires.
  secretExpiry?: SecretExpiry;
  isDemo?: boolean;
  lastSyncTimestamp: string;
  secureScore: {
    current: number;
    max: number;
    percentage: number;
  };
  totalUsers: number;
  licensedUsers: number;
  unlicensedActiveUsers: number;
  totalDevices: number;
  nonCompliantDevices: number;
  isolatedDevices: number;
  missingCABaselinesCount: number;
  weakMfaCount: number;
  externalForwardingCount: number;
  activeIncidentsCount: number;
  criticalHighIncidentsCount: number;
  compositeRiskScore: number; // 0-100 (100 = highest risk)
  riskLevel: "critical" | "high" | "medium" | "low";
  monthlyEstimatedWasteUsd: number;
}

export interface FleetTopFailingBaseline {
  code: string;
  name: string;
  category: "Identity" | "Exchange" | "Defender" | "Groups" | "SharePoint";
  failingTenantsCount: number;
  totalTenantsCount: number;
  failingTenantNames: string[];
}

export interface FleetPostureSummary {
  totalTenants: number;
  healthyTenantsCount: number;
  totalManagedUsers: number;
  totalManagedDevices: number;
  averageSecureScore: number;
  totalActiveIncidents: number;
  totalCriticalHighIncidents: number;
  tenantsAtCriticalRisk: number;
  totalMonthlyEstimatedWasteUsd: number;
  tenants: FleetTenantPosture[];
  topFailingBaselines: FleetTopFailingBaseline[];
  recentCrossTenantIncidents: (SecurityIncidentItem & { tenantId: string; tenantName: string })[];
}

export interface FleetLicenseOptimizationItem {
  id: string;
  tenantId: string;
  tenantName: string;
  category:
    | "active_licensed_user"
    | "inactive_licensed_user"
    | "licensed_shared_mailbox"
    | "disabled_licensed_user"
    | "orphaned_account"
    | "unassigned_license_sku";
  title: string;
  description: string;
  impactedIdentity: string;
  displayName?: string;
  department?: string;
  licenseSku?: string;
  estimatedMonthlyCostUsd: number;
  lastSignInDateTime?: string;
  daysInactive?: number;
  accountState?: "active" | "dormant" | "disabled" | "unlicensed" | "shared_mailbox";
  remediationAction: string;
  remediationModule: string;
}

export interface FleetLicenseOptimizationSummary {
  totalMonthlyWasteUsd: number;
  totalAnnualWasteUsd: number;
  totalMonthlyLicensedCostUsd: number;
  wasteByCategory: {
    licensedSharedMailboxes: number;
    orphanedAccounts: number;
    inactiveLicensedUsers: number;
    disabledLicensedUsers: number;
    unassignedSkus: number;
  };
  items: FleetLicenseOptimizationItem[];
}

export interface FleetSearchResultItem {
  id: string;
  tenantId: string;
  tenantName: string;
  category: "user" | "incident" | "ip_address" | "file_hash" | "device" | "app_registration" | "forwarding_rule" | "tabl";
  title: string;
  subtitle: string;
  matchField: string;
  matchValue: string;
  statusPill?: {
    status: TrafficStatus;
    label: string;
  };
  metadata?: Record<string, string | number | boolean>;
  targetModule: string;
}

// ---------------------------------------------------------------------------
// Phase 2.2: Golden Baseline Drift & Multi-Tenant Bulk Operations
// ---------------------------------------------------------------------------

export interface GoldenBaselineTemplate {
  id: string;
  name: string;
  description: string;
  version: string;
  updatedAt: string;
  caPolicies: {
    code: string;
    name: string;
    requiredState: "enabled" | "reportOnly";
    requiresEntraP2?: boolean;
  }[];
  requireExternalForwardingBlocked: boolean;
  requireMailboxAuditLogging: boolean;
  requireDkimSigning: boolean;
  requireModernAuthOnly: boolean;
  requireNoLicensedGlobalAdmins: boolean;
  minimumSecureScore: number;
}

export interface TenantDriftFinding {
  id: string;
  tenantId: string;
  tenantName: string;
  component: "conditional_access" | "mailflow" | "mailboxes" | "identity" | "storage";
  ruleCode: string;
  ruleName: string;
  severity: "critical" | "high" | "medium" | "low";
  expectedState: string;
  actualState: string;
  driftDescription: string;
  detectedTimestamp: string;
  remediationAction: string;
  remediationSupported: boolean;
  remediationPayload?: Record<string, any>;
}

export interface TenantDriftAssessment {
  tenantId: string;
  tenantName: string;
  defaultDomainName: string;
  alignmentScore: number; // 0 - 100%, higher = better (flat pass/total ratio)
  weightedDriftScore: number; // 0 - 100, higher = worse (severity-weighted deviation from the Golden Standard)
  weightedDriftFactors: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  status: "in_sync" | "minor_drift" | "critical_drift";
  totalEvaluatedRules: number;
  passingRulesCount: number;
  driftedRulesCount: number;
  criticalFindingsCount: number;
  highFindingsCount: number;
  mediumFindingsCount: number;
  lowFindingsCount: number;
  findings: TenantDriftFinding[];
}

export interface FleetDriftSummary {
  totalTenantsEvaluated: number;
  inSyncCount: number;
  minorDriftCount: number;
  criticalDriftCount: number;
  overallFleetAlignmentPercentage: number;
  overallFleetWeightedDriftScore: number;
  tenantAssessments: TenantDriftAssessment[];
  allFindings: TenantDriftFinding[];
}

export interface FleetTablEntry {
  id: string;
  type: "domain" | "sender" | "url" | "fileHash" | "ip";
  value: string;
  action: "block" | "allow";
  reason: string;
  addedBy: string;
  createdAt: string;
  syncedTenants: {
    tenantId: string;
    tenantName: string;
    status: "synced" | "pending" | "failed";
    syncedAt?: string;
    error?: string;
  }[];
}

export interface FleetBulkDeployRequest {
  baselineCodes: string[];
  targetTenantIds: string[];
  mode?: "reportOnly" | "enabled";
}

export interface FleetBulkDeployTenantResult {
  tenantId: string;
  tenantName: string;
  baselineCode: string;
  policyName: string;
  status: "success" | "skipped" | "failed";
  message: string;
  error?: string;
}

export interface FleetBulkDeployResult {
  totalRequested: number;
  successCount: number;
  skippedCount: number;
  failedCount: number;
  results: FleetBulkDeployTenantResult[];
}

// ---------------------------------------------------------------------------
// Phase 2.3: Executive & Compliance Reporting Engine (QBR Generator & Compliance Matrix)
// ---------------------------------------------------------------------------

export interface ReportBrandingConfig {
  mspName: string;
  mspLogoUrl?: string;
  preparedBy: string;
  accentColor?: string;
  clientContact?: string;
}

export interface ExecutiveQbrReport {
  id: string;
  generatedAt: string;
  period: string; // e.g., "Q3 2026" or "August 2026"
  tenant: {
    id: string;
    displayName: string;
    defaultDomain: string;
    tier: string;
  };
  branding: ReportBrandingConfig;
  executiveSummary: {
    overallHealthScore: number; // 0-100
    secureScorePercent: number;
    baselineAdoptionScore: number;
    activeThreatsCount: number;
    totalMonthlyCostSavingsIdentified: number;
    totalMonthlyCostSavingsReclaimed: number;
    headlineStatus: "optimal" | "acceptable" | "needs_attention" | "critical_risk";
    keyAchievements: string[];
    topActionItems: string[];
  };
  identityMfaSection: {
    totalUsers: number;
    mfaEnforcedPercent: number;
    adminCount: number;
    adminsWithPhishingResistantMfa: number;
    riskyUsersCount: number;
    guestUsersCount: number;
  };
  goldenBaselineSection: {
    totalPoliciesEvaluated: number;
    enforcedCount: number;
    reportOnlyCount: number;
    missingCount: number;
    policies: {
      code: string;
      name: string;
      state: "enforced" | "report_only" | "missing" | "misconfigured";
      impact: string;
    }[];
  };
  threatsAndHygieneSection: {
    externalForwardingRulesBlocked: number;
    quarantineAlertsRemediated: number;
    threatIndicatorsActive: number;
    unmanagedDevicesCount: number;
    anonymousSharePointLinksCount: number;
  };
  costOptimizationSection: {
    inactiveLicensedUsersCount: number;
    wastedSharedMailboxLicensesCount: number;
    totalEstimatedAnnualWaste: number;
    reclaimableSeats: {
      upn: string;
      license: string;
      estimatedMonthlyCost: number;
      reason: string;
    }[];
  };
  // Guidance-only, tier-eligibility view over the DLP/sensitivity-label
  // recommendation catalog (src/lib/data/data-protection-recommendations.ts)
  // - not a live posture check, since there is no live DLP sync (see
  // ai-context-vault/Optimization/DLP & Sensitivity Labels Plan.md). Reuses
  // the same getTierEligibility() the Fleet Data Protection Visibility
  // matrix uses, applied to this one tenant.
  dataProtectionSection: {
    tenantTier: string;
    totalRecommendationsCount: number;
    eligibleRecommendationsCount: number;
    needsE5Count: number;
    unconfirmedTierCount: number;
    eligibleRecommendations: { id: string; title: string; regulations: string[] }[];
  };
}

// popia/gdpr_uk_gdpr/hipaa added 2026-09-22 - unlike the three technical
// frameworks above, these three are hybrid: partly auto-computed from this
// snapshot, partly manual attestation (see ComplianceControlItem.attestationKey
// and Tenant.complianceAttestations). See Compliance Readiness Checklist Plan
// in the vault for why they're deliberately folded into this same type rather
// than kept as a separate concept - the user asked for it to "live inside the
// existing Compliance Matrix," so it reuses this exact machinery end to end.
export type ComplianceFramework =
  | "cis_m365_v3"
  | "nist_csf_v2"
  | "essential_eight"
  | "popia"
  | "gdpr_uk_gdpr"
  | "hipaa";

export interface ComplianceControlItem {
  id: string;
  framework: ComplianceFramework;
  section: string; // e.g. "1. Account & Authentication"
  controlNumber: string; // e.g. "1.1.1"
  title: string;
  description: string;
  level?: "Level 1" | "Level 2";
  status: "compliant" | "non_compliant" | "partially_compliant" | "not_applicable";
  relevance: "critical" | "high" | "medium";
  evidence: string;
  remediationGuide: string;
  relatedBaselineCode?: string;
  // Present only on POPIA/GDPR/HIPAA's organizational/legal items - this is
  // what tells the UI to render an "Attest" control instead of read-only
  // evidence, and is the key into Tenant.complianceAttestations. Absent for
  // every auto-computed control (all of CIS/NIST/Essential Eight, and the
  // technical half of POPIA/GDPR/HIPAA).
  attestationKey?: string;
  // A real citation URL backing this control's regulationRef, where the
  // content was grounded against a public source rather than asserted from
  // memory - see the DLP catalog's same non-legal-advice convention.
  sourceUrl?: string;
}

export interface TenantComplianceAssessment {
  tenantId: string;
  tenantName: string;
  defaultDomainName: string;
  evaluatedAt: string;
  framework: ComplianceFramework;
  frameworkTitle: string;
  totalControls: number;
  compliantCount: number;
  nonCompliantCount: number;
  partiallyCompliantCount: number;
  scorePercentage: number;
  level1ScorePercentage?: number;
  level2ScorePercentage?: number;
  controls: ComplianceControlItem[];
}

export interface FleetComplianceSummary {
  framework: ComplianceFramework;
  frameworkTitle: string;
  evaluatedAt: string;
  totalTenantsEvaluated: number;
  overallFleetCompliancePercentage: number;
  tenantAssessments: TenantComplianceAssessment[];
  topFailingControls: {
    controlNumber: string;
    title: string;
    failingTenantsCount: number;
  }[];
}

// Audit Log Investigator - ingested Microsoft Purview unified audit log CSV
// exports, stored/searched independently of AuditLogEntry above (this app's
// own operator activity log - an unrelated, pre-existing concept that just
// happens to share the word "audit"). See audit-log-parser.ts.
export interface UnifiedAuditLogImport {
  id: string;
  tenantId: string;
  filename: string;
  uploadedAt: string;
  rowCount: number;
  skippedRowCount: number;
  earliestEvent?: string;
  latestEvent?: string;
  // True when rowCount lands at or past Purview's own export caps (50,000 for
  // Audit Standard, 1,000,000 for Audit Premium) - a nudge that the uploaded
  // window may be an incomplete slice of the real investigation timeframe,
  // not a claim about which license actually produced this file.
  possiblyCapped: boolean;
  exportCapWarning?: string;
}

export interface UnifiedAuditLogRecord {
  id: number;
  tenantId: string;
  importId: string;
  creationDate: string;
  recordType?: string;
  operation?: string;
  userId?: string;
  clientIp?: string;
  sessionId?: string;
  clientInfo?: string;
  resultStatus?: string;
  workload?: string;
  // The full source row (CreationDate/UserIds/Operations/RecordType columns
  // plus the parsed - or, on a malformed row, raw-string - AuditData JSON),
  // so the detail drawer can show everything even though only a handful of
  // fields are hoisted into indexed columns above.
  rawData: string;
  parseError?: boolean;
}

export interface UnifiedAuditLogSearchFilters {
  search?: string;
  operation?: string;
  // Distinct from `operation` above (single-value, dropdown-driven) - set by
  // an Investigation Template's operation list ("is one of N values"). The
  // UI treats the two as mutually exclusive since combining them has no
  // sensible meaning, but the store accepts either independently.
  operations?: string[];
  recordType?: string;
  workload?: string;
  userId?: string;
  sessionId?: string;
  clientInfo?: string;
  startDate?: string;
  endDate?: string;
  importId?: string;
  page?: number;
  pageSize?: number;
  sortDirection?: "asc" | "desc";
}

export interface UnifiedAuditLogSearchResult {
  records: UnifiedAuditLogRecord[];
  total: number;
  facets: {
    operations: string[];
    recordTypes: string[];
    workloads: string[];
  };
}

export interface UnifiedAuditLogImportProgress {
  importId: string;
  filename: string;
  rowsProcessed: number;
  insertedCount: number;
  skippedCount: number;
  startedAt: number;
  done: boolean;
  error?: string;
}

// Phase 2 - Investigation Templates (see audit-investigation-templates.ts)
export interface AuditInvestigationTemplate {
  id: string;
  name: string;
  description: string;
  operations: string[];
}

// Phase 3 - Heuristic flags (see audit-log-heuristics.ts). All three are
// framed in the UI as "worth investigating," never a verdict.
export interface SessionHijackFlag {
  sessionId: string;
  distinctIpCount: number;
  distinctIps: string[];
  recordCount: number;
  firstSeen: string;
  lastSeen: string;
}

export interface MassDeletionFlag {
  userId: string;
  hourBucket: string;
  deleteCount: number;
}

export interface PossibleBecFlag {
  userId: string;
  hourBucket: string;
  inboxRuleChangeCount: number;
  mailItemsAccessedCount: number;
}

export interface AuditLogFlagsResult {
  sessionHijack: SessionHijackFlag[];
  massDeletion: MassDeletionFlag[];
  possibleBec: PossibleBecFlag[];
}

