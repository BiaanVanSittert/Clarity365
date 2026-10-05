import { ScenarioConfirmation, ScenarioConfirmationKey, TenantSecuritySnapshot } from "../types";
import { AUDIT_CONFIG_OPERATIONS, USER_DELETION_OPERATIONS, describeAlertTrigger, findAlertCoverage } from "./alert-policy-mapper";
import { CONFIRMATION_VALID_DAYS, ConfirmationState, getConfirmationState } from "../utils/scenario-confirmations";
import { CA_DOCS, CaGapAnalysis, CaGapCellState, CaGapControl, CaGapPersona, analyzeCaGaps } from "./ca-gap-analyzer";
import { CaEnvironment, CaEvaluationResult, SignInContext, evaluateSignIn } from "./ca-policy-evaluator";
import { BreakGlassCandidate, SimAccountLists, buildCaEnvironment, buildSyntheticSimUser, detectLikelyBreakGlassAccounts, isLikelyBreakGlassRef, listSimAccounts } from "./ca-sim-context";
import { SituationRunResult, detectHomeCountry, runSituation } from "./signin-situation-runner";
import { SIGNIN_SITUATIONS, SituationPersona } from "../data/signin-situation-definitions";
import { smtpAuthEnabledFor } from "./security-posture-mapper";
import { GLOBAL_ADMIN_TEMPLATE_ID, DIRECTORY_ROLE_TEMPLATES, getRoleTemplateById } from "../utils/directory-role-templates";
import { hasIntuneCapability } from "../utils/intune-capability";

// Security Simulations Stage 6: attack scenarios, each broken into the
// defensive layers ("checks") that would stop it (ai-context-vault/
// Optimization/Security Simulations Plan.md). Checks that are really
// sign-in questions reuse the Sign-in Situations runner or the CA Gap
// Analysis matrix, so the three views can never disagree.
//
// Colours (user decisions): green = prevented, red = not prevented, orange
// = partial and "not assessed" (data missing, permission missing, or a
// manual check). Missing data is never green.

// ------------------------------------------------------------------ types

export type ScenarioCheckStatus = "prevented" | "partial" | "notPrevented" | "notAssessed";
export type ScenarioSection = "identity" | "audit" | "exchange" | "sharepoint";

export interface ScenarioCheckResult {
  id: string;
  label: string;
  status: ScenarioCheckStatus;
  detail: string;
  // Specific offending accounts, apps, mailboxes... (capped for display).
  items?: string[];
  fix?: string;
  docsUrl?: string;
  // Offers "simulate in Sign-in Situations" for this persona.
  simulatePersona?: SituationPersona;
  // A command that puts the fix in place, shown in a copyable box.
  command?: string;
  // Set when Clarity365 can't see this for itself and the operator may
  // confirm it once for the tenant (scenario-confirmations.ts).
  confirmKey?: ScenarioConfirmationKey;
  // The operator's confirmation for this check, if there is one.
  confirmation?: ConfirmationState;
  // "How to fix" guide for this check (scenario-fix-guides.ts); set only while it isn't green.
  guideId?: string;
}

export interface ScenarioResult {
  id: string;
  section: ScenarioSection;
  title: string;
  description: string;
  // Scenario-wide caveat shown above its checks.
  warning?: string;
  checks: ScenarioCheckResult[];
  counts: Record<ScenarioCheckStatus, number>;
  verdict: ScenarioCheckStatus;
  // Checks that are partial or not prevented.
  gaps: number;
}

export const SCENARIO_SECTIONS: { id: ScenarioSection; label: string }[] = [
  { id: "identity", label: "Identity & Conditional Access" },
  { id: "audit", label: "Audit & Detection" },
  { id: "exchange", label: "Exchange & Email" },
  { id: "sharepoint", label: "SharePoint & Data" },
];

// Microsoft Learn pages beyond CA_DOCS, each verified to exist on 2026-09-30.
export const SCENARIO_DOCS = {
  smtpAuth: "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission",
  auditLog: "https://learn.microsoft.com/en-us/purview/audit-log-enable-disable",
  unmanagedDevices: "https://learn.microsoft.com/en-us/sharepoint/control-access-from-unmanaged-devices",
  userConsent: "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent",
  externalForwarding: "https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding",
  pim: "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure",
} as const;

// ---------------------------------------------------------------- context

interface ScenarioContext {
  snapshot: TenantSecuritySnapshot;
  env: CaEnvironment;
  gap: CaGapAnalysis;
  accounts: SimAccountLists;
  breakGlass: BreakGlassCandidate[];
  homeCountry: string;
  foreignCountry: string;
  situation: (id: string) => SituationRunResult;
  probe: (persona: SituationPersona, overrides: Partial<SignInContext>) => CaEvaluationResult;
}

const MAX_ITEMS = 12;
const cap = (items: string[]) => (items.length > MAX_ITEMS ? [...items.slice(0, MAX_ITEMS), `and ${items.length - MAX_ITEMS} more`] : items);

const EXO_NOT_CONNECTED =
  "Exchange Online isn't connected for this tenant (or its settings haven't been synced yet), so this can't be checked. Connect it from the Permissions check, then re-sync.";

// ---------------------------------------------------------------- helpers

function fromSituation(ctx: ScenarioContext, situationId: string, label: string, fix?: string): Omit<ScenarioCheckResult, "id"> {
  const r = ctx.situation(situationId);
  const status: ScenarioCheckStatus =
    r.verdict === "prevented" ? "prevented" : r.verdict === "partial" ? "partial" : r.verdict === "notPrevented" ? "notPrevented" : "notAssessed";
  return {
    label,
    status,
    detail: r.outcomeText,
    fix: status === "prevented" ? undefined : fix || r.fixes[0]?.title,
    simulatePersona: r.situation.persona,
  };
}

const CELL_STATUS: Record<CaGapCellState, ScenarioCheckStatus> = {
  enforced: "prevented",
  reportOnly: "partial",
  noPolicy: "notPrevented",
  unlicensed: "notPrevented",
  notApplicable: "notAssessed",
  unknown: "notAssessed",
};

function fromCell(ctx: ScenarioContext, persona: CaGapPersona, control: CaGapControl, label: string, fix: string, docsUrl?: string): Omit<ScenarioCheckResult, "id"> {
  const cell = ctx.gap.matrix.find((c) => c.persona === persona && c.control === control)!;
  const names = cell.policies.map((p) => `"${p.name}"`).join(", ");
  const detail =
    cell.state === "enforced"
      ? `Enforced by ${names || "security defaults"}.`
      : cell.state === "reportOnly"
      ? `Only in report-only mode (${names}), so nothing is enforced yet.`
      : cell.state === "unlicensed"
      ? cell.note || "Needs a licence this tenant doesn't have."
      : cell.state === "unknown"
      ? `Can't confirm: ${(cell.note || "a policy might provide this").replace(/\.$/, "")}.`
      : "No enforced Conditional Access policy provides this.";
  const personaSim: Partial<Record<CaGapPersona, SituationPersona>> = { admins: "globalAdmin", users: "user", guests: "guest" };
  return { label, status: CELL_STATUS[cell.state], detail, fix: CELL_STATUS[cell.state] === "prevented" ? undefined : fix, docsUrl, simulatePersona: personaSim[persona] };
}

function boolCheck(
  value: boolean | undefined,
  good: boolean,
  label: string,
  texts: { good: string; bad: string; unknown: string },
  fix: string,
  docsUrl?: string
): Omit<ScenarioCheckResult, "id"> {
  if (value === undefined) return { label, status: "notAssessed", detail: texts.unknown, fix, docsUrl };
  return value === good ? { label, status: "prevented", detail: texts.good } : { label, status: "notPrevented", detail: texts.bad, fix, docsUrl };
}

function isGuestUpn(upn: string | undefined): boolean {
  return !!upn && upn.toLowerCase().includes("#ext#");
}

// Distinct user principals holding a role, from PIM data when available,
// otherwise from directory-role membership on the MFA profiles.
function holdersOf(ctx: ScenarioContext, roleIds: Set<string>, kinds?: Set<string>): { id: string; upn: string; kind: string }[] {
  const pr = ctx.snapshot.privilegedRoleAssignments;
  const out = new Map<string, { id: string; upn: string; kind: string }>();
  if (pr) {
    for (const a of pr.assignments) {
      if (!roleIds.has(a.roleTemplateId) || a.principalType === "servicePrincipal") continue;
      if (kinds && !kinds.has(a.kind)) continue;
      out.set(a.principalId, { id: a.principalId, upn: a.principalUserPrincipalName || a.principalDisplayName || a.principalId, kind: a.kind });
    }
    return [...out.values()];
  }
  if (kinds && !kinds.has("activePermanent")) return [];
  for (const u of ctx.snapshot.mfaAudit || []) {
    const ids = (u.adminRoleTemplateIds || []).map((x) => x.toLowerCase());
    if (ids.some((id) => roleIds.has(id))) out.set(u.id, { id: u.id, upn: u.userPrincipalName, kind: "activePermanent" });
  }
  return [...out.values()];
}

const isBreakGlass = (ctx: ScenarioContext, h: { id: string; upn: string }) =>
  !!(isLikelyBreakGlassRef(h.id, ctx.breakGlass) || isLikelyBreakGlassRef(h.upn, ctx.breakGlass));

const PRIVILEGED_ROLE_IDS = new Set(DIRECTORY_ROLE_TEMPLATES.filter((r) => r.isPrivileged).map((r) => r.templateId));
const USER_ADMIN = "fe930be7-5e62-47db-91af-98c3a49a38b1";
const PRIV_AUTH_ADMIN = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13";
const EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de";

// --------------------------------------------------------------- scenarios

interface CheckDef {
  id: string;
  // The "How to fix" guide (scenario-fix-guides.ts), offered while the check isn't green.
  guideId?: string;
  evaluate: (ctx: ScenarioContext) => Omit<ScenarioCheckResult, "id">;
}

interface ScenarioDef {
  id: string;
  section: ScenarioSection;
  title: string;
  description: string;
  warning?: (ctx: ScenarioContext) => string | undefined;
  checks: CheckDef[];
}

export const SCENARIO_DEFINITIONS: ScenarioDef[] = [
  // ================================================ Identity & Conditional Access
  {
    id: "foreign-country",
    section: "identity",
    title: "Sign-in from outside allowed countries",
    description: "An attacker with a stolen password signs in from a country the organisation doesn't operate in.",
    checks: [
      { id: "users", guideId: "block-foreign-countries", evaluate: (c) => fromSituation(c, "user-foreign", "Standard users are blocked from foreign countries") },
      { id: "admins", guideId: "block-foreign-countries", evaluate: (c) => fromSituation(c, "ga-foreign", "Admins are blocked from foreign countries") },
      { id: "guests", guideId: "block-foreign-countries", evaluate: (c) => fromSituation(c, "guest-foreign", "Guests are blocked from foreign countries") },
      {
        id: "unknown-country", guideId: "include-unknown-countries",
        evaluate: (c) => {
          const r = c.probe("user", { location: { country: null, ipNamedLocationIds: [] } });
          const status: ScenarioCheckStatus = r.enforced.outcome === "blocked" ? "prevented" : r.enforced.outcome === "indeterminate" ? "notAssessed" : "notPrevented";
          return {
            label: "Addresses that don't map to any country are covered",
            status,
            detail:
              status === "prevented"
                ? "A sign-in from an address with no known country is blocked too."
                : status === "notAssessed"
                ? "Can't confirm: location conditions couldn't be evaluated."
                : "A sign-in from an address that doesn't map to a country (common with anonymisers) isn't blocked.",
            fix: status === "prevented" ? undefined : "Tick \"Include unknown countries/regions\" on the blocked-countries named location (or leave it off the allowed list).",
            docsUrl: CA_DOCS.blockByLocation,
            simulatePersona: "user",
          };
        },
      },
      {
        id: "device-registration", guideId: "require-mfa-device-registration",
        evaluate: (c) => {
          const r = c.probe("user", { target: { kind: "userAction", action: "urn:user:registerdevice" }, location: { country: c.foreignCountry, ipNamedLocationIds: [] } });
          const status: ScenarioCheckStatus = r.enforced.outcome === "blocked" || r.enforced.outcome === "challenged" ? "prevented" : r.enforced.outcome === "indeterminate" ? "notAssessed" : "notPrevented";
          return {
            label: "Registering a device from abroad needs MFA",
            status,
            detail:
              status === "prevented"
                ? "A policy covers the \"Register or join devices\" action."
                : "Location policies don't apply to device registration, and no policy requires MFA for it, so a foreign sign-in can still register a device that may later count as trusted.",
            fix: status === "prevented" ? undefined : "Add a \"Register or join devices\" user-action policy requiring MFA, and set the tenant's device setting \"Require MFA to register or join devices\" to No so the policy is enforced.",
            docsUrl: CA_DOCS.deviceRegistration,
          };
        },
      },
    ],
  },
  {
    id: "token-replay",
    section: "identity",
    title: "Stolen session token replay",
    description:
      "An attacker steals a signed-in session token (for example through an adversary-in-the-middle phishing page or malware) and replays it from their own device. MFA was already satisfied inside the token.",
    checks: [
      {
        id: "token-protection", guideId: "require-token-protection",
        evaluate: (c) => {
          const policies = c.env.policies.filter((p) => p.state === "enabled");
          const anyRead = c.env.policies.some((p) => p.sessionControls?.tokenProtection !== undefined);
          const withTp = policies.filter((p) => p.sessionControls?.tokenProtection === true);
          if (!anyRead && c.env.policies.length > 0 && !c.snapshot.tenant.isDemo) {
            return {
              label: "Token protection binds sessions to the device",
              status: "notAssessed",
              detail: "Token protection is only reported by Microsoft's beta API, and that read didn't return data for this tenant.",
              fix: "Re-sync; if this persists, check token protection in the Entra admin center.",
            };
          }
          return withTp.length > 0
            ? { label: "Token protection binds sessions to the device", status: "prevented", detail: `Enforced by ${withTp.map((p) => `"${p.name}"`).join(", ")}.` }
            : {
                label: "Token protection binds sessions to the device",
                status: "notPrevented",
                detail: "No enforced policy requires token protection, so a stolen token works from any device.",
                fix: "Require token protection for Windows desktop sign-ins to Exchange Online and SharePoint Online (start with admins and report-only).",
                docsUrl: CA_DOCS.sessionLifetime,
              };
        },
      },
      { id: "admin-device", guideId: "require-compliant-device-admins", evaluate: (c) => fromCell(c, "admins", "managedDevice", "Admins must use a compliant or hybrid-joined device", "Require a compliant or hybrid-joined device for admin roles.", CA_DOCS.deviceCompliance) },
      { id: "admin-frequency", guideId: "admin-session-limits", evaluate: (c) => fromCell(c, "admins", "sessionLimits", "Admin sessions are time-limited", "Set a sign-in frequency (for example 4 hours) and disable persistent browser sessions for admin roles.", CA_DOCS.sessionLifetime) },
      { id: "admin-phishing-resistant", guideId: "require-phishing-resistant-admins", evaluate: (c) => fromCell(c, "admins", "phishingResistant", "Admins use phishing-resistant MFA", "Require the phishing-resistant MFA authentication strength for admin roles.", CA_DOCS.adminPhishingResistant) },
      {
        id: "cae", guideId: "keep-cae-on",
        evaluate: (c) => {
          const disabled = c.env.policies.filter((p) => p.state === "enabled" && p.sessionControls?.continuousAccessEvaluation === "disabled");
          const strict = c.env.policies.filter((p) => p.state === "enabled" && (p.sessionControls?.continuousAccessEvaluation === "strictEnforcement" || p.sessionControls?.continuousAccessEvaluation === "strictLocation"));
          if (disabled.length > 0) {
            return { label: "Continuous access evaluation revokes sessions quickly", status: "notPrevented", detail: `Disabled by ${disabled.map((p) => `"${p.name}"`).join(", ")}.`, fix: "Remove the policy that disables continuous access evaluation." };
          }
          return strict.length > 0
            ? { label: "Continuous access evaluation revokes sessions quickly", status: "prevented", detail: `Strict enforcement via ${strict.map((p) => `"${p.name}"`).join(", ")}.` }
            : { label: "Continuous access evaluation revokes sessions quickly", status: "prevented", detail: "On (Microsoft's default); nothing disables it." };
        },
      },
    ],
  },
  {
    id: "guest-role",
    section: "identity",
    title: "Guest account holding a directory role",
    description: "An external account is given an admin role, so a compromise at a partner becomes admin access to this tenant.",
    checks: [
      {
        id: "no-guest-admins",
        guideId: "remove-guest-admin-roles",
        evaluate: (c) => {
          const fromProfiles = (c.snapshot.mfaAudit || []).filter((u) => u.isAdmin && isGuestUpn(u.userPrincipalName)).map((u) => `${u.userPrincipalName} (${(u.adminRoles || []).join(", ")})`);
          const fromPim = (c.snapshot.privilegedRoleAssignments?.assignments || [])
            .filter((a) => isGuestUpn(a.principalUserPrincipalName))
            .map((a) => `${a.principalUserPrincipalName} (${getRoleTemplateById(a.roleTemplateId)?.displayName || "role"}, ${a.kind})`);
          const all = [...new Set([...fromProfiles, ...fromPim])];
          return all.length === 0
            ? { label: "No guest holds an admin role", status: "prevented", detail: "No guest account holds a directory role." }
            : { label: "No guest holds an admin role", status: "notPrevented", detail: `${all.length} guest account(s) hold directory roles.`, items: cap(all), fix: "Remove directory roles from guest accounts; give partners a member account in this tenant if they genuinely need admin access, with PIM and MFA." };
        },
      },
      {
        id: "guest-access-level", guideId: "restrict-guest-directory-access",
        evaluate: (c) => {
          const lvl = c.snapshot.identitySettings?.guestAccessLevel;
          const label = "Guest access to directory data is restricted";
          if (!lvl || lvl === "unknown") return { label, status: "notAssessed", detail: "Guest access level wasn't synced.", fix: "Re-sync this tenant." };
          if (lvl === "restricted") return { label, status: "prevented", detail: "Guests can only see their own directory objects." };
          if (lvl === "limited") return { label, status: "partial", detail: "Guests have limited access (Microsoft's default); they can still see some directory data.", fix: "Set guest user access to \"most restrictive\" in External collaboration settings." };
          return { label, status: "notPrevented", detail: "Guests have the same directory access as members.", fix: "Set guest user access to \"most restrictive\" in External collaboration settings." };
        },
      },
      {
        id: "guest-invites", guideId: "restrict-guest-invites",
        evaluate: (c) => {
          const s = c.snapshot.identitySettings?.guestInviteSetting;
          const label = "Only admins and guest inviters can invite guests";
          if (!s || s === "unknown") return { label, status: "notAssessed", detail: "Guest invite setting wasn't synced.", fix: "Re-sync this tenant." };
          if (s === "none" || s === "adminsAndGuestInviters") return { label, status: "prevented", detail: "Invitations are limited to admins and the Guest Inviter role." };
          if (s === "adminsGuestInvitersAndAllMembers") return { label, status: "partial", detail: "Every member can invite guests.", fix: "Limit invitations to admins and users in the Guest Inviter role." };
          return { label, status: "notPrevented", detail: "Anyone, including guests, can invite guests.", fix: "Limit invitations to admins and users in the Guest Inviter role." };
        },
      },
      { id: "guest-mfa", guideId: "require-mfa-guests", evaluate: (c) => fromCell(c, "guests", "mfa", "Guests must complete MFA", "Require MFA for guests and external users (CA04).", CA_DOCS.guestsMfa) },
    ],
  },
  {
    id: "password-spray",
    section: "identity",
    title: "Password spray on an account without MFA",
    description: "An attacker tries common passwords against many accounts; any account without MFA that uses a weak password falls.",
    checks: [
      {
        id: "mfa-registered", guideId: "mfa-registration-drive",
        evaluate: (c) => {
          const missing = (c.snapshot.mfaAudit || []).filter((u) => u.accountEnabled && !u.mfaRegistered && !isGuestUpn(u.userPrincipalName));
          return missing.length === 0
            ? { label: "Every enabled user has MFA registered", status: "prevented", detail: "All enabled member accounts have an MFA method registered." }
            : {
                label: "Every enabled user has MFA registered",
                status: "notPrevented",
                detail: `${missing.length} enabled account(s) have no MFA method registered; if MFA is required they'll be prompted to register, which an attacker holding the password can do first.`,
                items: cap(missing.map((u) => u.userPrincipalName)),
                fix: "Run a registration campaign, protect security info registration, and issue Temporary Access Passes for new users.",
              };
        },
      },
      { id: "mfa-enforced", guideId: "require-mfa-all-users", evaluate: (c) => fromCell(c, "users", "mfa", "MFA is enforced for all users", "Require MFA for all users on all resources (CA02).", CA_DOCS.mfaAllUsers) },
      { id: "legacy-blocked", guideId: "block-legacy-auth", evaluate: (c) => fromCell(c, "users", "legacyBlocked", "Legacy authentication is blocked", "Block the Exchange ActiveSync and Other clients client app types (CA01).", CA_DOCS.legacyAuth) },
      {
        id: "no-individual-exclusions", guideId: "remove-individual-exclusions",
        evaluate: (c) => {
          const all = [...c.accounts.globalAdmins, ...c.accounts.otherAdmins, ...c.accounts.standardUsers];
          const excluded = all.filter((a) => a.excludedFrom && !a.breakGlassReasons);
          return excluded.length === 0
            ? { label: "No account is individually excluded from policies", status: "prevented", detail: "No non-break-glass account is excluded by name." }
            : {
                label: "No account is individually excluded from policies",
                status: "notPrevented",
                detail: `${excluded.length} account(s) are excluded by name, so the policies above don't protect them.`,
                items: cap(excluded.map((a) => `${a.userPrincipalName}: ${a.excludedFrom!.join(", ")}`)),
                fix: "Remove exclusions that are no longer needed; move service accounts to managed identities or workload-identity policies.",
                simulatePersona: "user",
              };
        },
      },
    ],
  },
  {
    id: "legacy-mailbox",
    section: "identity",
    title: "Legacy authentication mailbox access",
    description: "An attacker uses an old mail protocol (SMTP AUTH, POP, IMAP, ActiveSync) that can't do MFA, to read or send mail with just a password.",
    checks: [
      { id: "ca-legacy", guideId: "block-legacy-auth", evaluate: (c) => fromCell(c, "users", "legacyBlocked", "Conditional Access blocks legacy authentication", "Block the Exchange ActiveSync and Other clients client app types (CA01).", CA_DOCS.legacyAuth) },
      {
        id: "smtp-auth-org",
        guideId: "disable-smtp-auth-org",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.exchangeSecurity?.smtpClientAuthDisabledOrgWide,
            true,
            "SMTP AUTH is turned off organisation-wide",
            { good: "SMTP AUTH is off for the organisation.", bad: "SMTP AUTH is on for the organisation - every mailbox can use it unless overridden.", unknown: EXO_NOT_CONNECTED },
            "Run Set-TransportConfig -SmtpClientAuthenticationDisabled $true and enable SMTP AUTH only on the mailboxes that need it.",
            SCENARIO_DOCS.smtpAuth
          ),
      },
      {
        id: "smtp-auth-mailboxes", guideId: "restrict-smtp-auth-mailboxes",
        evaluate: (c) => {
          const ex = c.snapshot.exchangeSecurity;
          const label = "Only mailboxes that need SMTP AUTH have it";
          if (!ex?.casMailboxes) return { label, status: "notAssessed", detail: EXO_NOT_CONNECTED };
          const enabled = ex.casMailboxes.filter((m) => smtpAuthEnabledFor(m, ex.smtpClientAuthDisabledOrgWide) === true);
          if (enabled.length === 0) return { label, status: "prevented", detail: "No mailbox can use SMTP AUTH." };
          return {
            label,
            status: ex.smtpClientAuthDisabledOrgWide ? "partial" : "notPrevented",
            detail: `${enabled.length} mailbox(es) can use SMTP AUTH${ex.casMailboxesTruncated ? " (first 250 mailboxes checked)" : ""}.`,
            items: cap(enabled.map((m) => m.primarySmtpAddress)),
            fix: "Keep SMTP AUTH only on mailboxes for printers or apps that genuinely need it, ideally moved to OAuth or a relay connector.",
            docsUrl: SCENARIO_DOCS.smtpAuth,
          };
        },
      },
      {
        id: "pop-imap", guideId: "disable-pop-imap",
        evaluate: (c) => {
          const ex = c.snapshot.exchangeSecurity;
          const label = "POP and IMAP are off where they aren't used";
          if (!ex?.casMailboxes) return { label, status: "notAssessed", detail: EXO_NOT_CONNECTED };
          const open = ex.casMailboxes.filter((m) => m.popEnabled || m.imapEnabled);
          if (open.length === 0) return { label, status: "prevented", detail: "POP and IMAP are off on every mailbox checked." };
          return {
            label,
            status: "partial",
            detail: `POP or IMAP is on for ${open.length} of ${ex.casMailboxes.length} mailbox(es). Microsoft has retired basic authentication for these, so they now go through modern sign-in and Conditional Access, but every enabled protocol is extra surface (Microsoft leaves them on by default).`,
            items: cap(open.map((m) => m.primarySmtpAddress)),
            fix: "Turn POP and IMAP off with Set-CASMailbox (and in the CAS mailbox plans for new mailboxes) except where a client needs them.",
          };
        },
      },
      {
        id: "sharepoint-legacy", guideId: "sharepoint-block-legacy-auth",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.sharePoint?.legacyAuthProtocolsEnabled,
            false,
            "SharePoint blocks apps that don't use modern authentication",
            { good: "SharePoint's legacy authentication protocols are off.", bad: "SharePoint still accepts apps that don't use modern authentication, which can bypass Conditional Access.", unknown: "SharePoint settings haven't been synced yet." },
            "In the SharePoint admin center, Access control > Apps that don't use modern authentication > Block access.",
            SCENARIO_DOCS.unmanagedDevices
          ),
      },
    ],
  },
  {
    id: "ga-noncompliant",
    section: "identity",
    title: "Global admin on a non-compliant device",
    description: "An admin signs in from a personal or infected computer, exposing admin sessions to whatever is running on it.",
    checks: [
      { id: "admin-device", guideId: "require-compliant-device-admins", evaluate: (c) => fromCell(c, "admins", "managedDevice", "Admins must use a compliant or hybrid-joined device", "Require a compliant or hybrid-joined device for admin roles (CA09 scoped to admins).", CA_DOCS.deviceCompliance) },
      { id: "desktop", guideId: "require-compliant-device-admins", evaluate: (c) => fromSituation(c, "ga-desktop-unmanaged", "Desktop apps on an unmanaged PC are blocked for admins") },
      { id: "macos", guideId: "require-compliant-device-admins", evaluate: (c) => fromSituation(c, "ga-macos-unmanaged", "Unmanaged Macs are blocked for admins") },
      {
        id: "no-excluded-ga", guideId: "remove-individual-exclusions",
        evaluate: (c) => {
          const excluded = c.accounts.globalAdmins.filter((a) => a.excludedFrom && !a.breakGlassReasons);
          return excluded.length === 0
            ? { label: "No Global Admin is individually excluded", status: "prevented", detail: "Only likely break-glass accounts are excluded by name." }
            : { label: "No Global Admin is individually excluded", status: "notPrevented", detail: `${excluded.length} Global Admin(s) are excluded by name.`, items: cap(excluded.map((a) => `${a.userPrincipalName}: ${a.excludedFrom!.join(", ")}`)), fix: "Remove the exclusions, or confirm these are monitored emergency-access accounts.", simulatePersona: "globalAdmin" };
        },
      },
      {
        id: "intune",
        evaluate: (c) =>
          hasIntuneCapability(c.snapshot)
            ? { label: "Intune is licensed, so device compliance can be enforced", status: "prevented", detail: "Microsoft Intune is licensed." }
            : { label: "Intune is licensed, so device compliance can be enforced", status: "notPrevented", detail: "Intune isn't licensed, so \"require a compliant device\" can't be satisfied by any device.", fix: "License Intune (included in Microsoft 365 Business Premium, E3 and E5)." },
      },
    ],
  },
  {
    id: "oauth-consent",
    section: "identity",
    title: "Malicious OAuth app consent",
    description: "A user is tricked into approving an app that asks for access to their mail or files. The app keeps that access even after a password reset.",
    checks: [
      {
        id: "user-consent", guideId: "restrict-user-consent",
        evaluate: (c) => {
          const mode = c.snapshot.identitySettings?.userConsentMode;
          const label = "User consent is restricted";
          if (!mode) return { label, status: "notAssessed", detail: "Consent settings weren't synced.", fix: "Re-sync this tenant." };
          if (mode === "disabled") return { label, status: "prevented", detail: "Users can't consent to apps; an admin must approve." };
          if (mode === "verifiedPublishersLowRisk" || mode === "microsoftRecommended") return { label, status: "prevented", detail: "Users can only consent to verified publishers for low-impact permissions (Microsoft's recommendation)." };
          if (mode === "custom") return { label, status: "partial", detail: "A custom consent policy is in use; check what it allows.", fix: "Review the custom app consent policy.", docsUrl: SCENARIO_DOCS.userConsent };
          return { label, status: "notPrevented", detail: "Users can consent to any app for any permission that doesn't need admin approval, including reading their mail and files.", fix: "Allow user consent only for verified publishers and low-impact permissions, or disable it.", docsUrl: SCENARIO_DOCS.userConsent };
        },
      },
      {
        id: "admin-workflow", guideId: "enable-admin-consent-workflow",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.identitySettings?.adminConsentWorkflowEnabled,
            true,
            "Users can request admin approval for apps",
            { good: "The admin consent workflow is on.", bad: "The admin consent workflow is off, so blocked users look for workarounds instead of asking.", unknown: "Admin consent workflow setting wasn't synced." },
            "Turn on the admin consent workflow so users can request approval.",
            SCENARIO_DOCS.userConsent
          ),
      },
      {
        id: "risky-grants", guideId: "revoke-risky-app-consent",
        evaluate: (c) => {
          const o = c.snapshot.oauthConsentGrants;
          const label = "No user has consented to a risky unverified app";
          if (!o) return { label, status: "notAssessed", detail: "Consent grants haven't been synced yet.", fix: "Re-sync this tenant." };
          if (o.unavailable === "missingPermission") {
            return { label, status: "notAssessed", detail: "The app registration can't read consent grants.", fix: "Grant DelegatedPermissionGrant.Read.All (or Directory.Read.All) to the Clarity365 app registration, then re-sync. It's listed as optional in the Permissions check." };
          }
          if (o.unavailable) return { label, status: "notAssessed", detail: `Consent grants couldn't be read: ${o.unavailableDetail || "unknown error"}.` };
          const risky = o.grants.filter((g) => g.consentType === "Principal" && g.highRiskScopes.length > 0 && !g.isMicrosoftApp && g.publisherVerified !== true);
          return risky.length === 0
            ? { label, status: "prevented", detail: `${o.grants.length} consented app(s) reviewed; none unverified with access to mail, files or the directory.` }
            : {
                label,
                status: "notPrevented",
                detail: `${risky.length} unverified app(s) hold user-consented access to mail, files or the directory.`,
                items: cap(risky.map((g) => `${g.appDisplayName || g.servicePrincipalId} (${g.userCount} user(s)): ${g.highRiskScopes.join(", ")}`)),
                fix: "Review each app in Enterprise applications > Permissions; revoke and disable any you don't recognise.",
              };
        },
      },
      {
        id: "app-registrations", guideId: "review-app-permissions",
        evaluate: (c) => {
          const risky = (c.snapshot.appRegistrations || []).filter((a) => a.riskCategory === "critical" || a.riskCategory === "high");
          return risky.length === 0
            ? { label: "No app registration holds critical permissions", status: "prevented", detail: "No app registration is rated high or critical." }
            : { label: "No app registration holds critical permissions", status: "partial", detail: `${risky.length} app registration(s) hold high-privilege permissions.`, items: cap(risky.map((a) => `${a.displayName}: ${a.highPrivilegePermissions.join(", ")}`)), fix: "Review these in App Registrations and remove permissions they don't need." };
        },
      },
    ],
  },
  {
    id: "device-code",
    section: "identity",
    title: "Device-code phishing",
    description: "An attacker sends a device code and asks the victim to enter it at microsoft.com/devicelogin, receiving a token that already satisfies MFA.",
    checks: [
      { id: "users", guideId: "block-device-code-flow", evaluate: (c) => fromSituation(c, "user-devicecode", "Device code flow is blocked for users") },
      { id: "admins", guideId: "block-device-code-flow", evaluate: (c) => fromSituation(c, "ga-devicecode", "Device code flow is blocked for admins") },
      { id: "guests", guideId: "block-device-code-flow", evaluate: (c) => fromSituation(c, "guest-devicecode", "Device code flow is blocked for guests") },
      {
        id: "auth-transfer", guideId: "block-authentication-transfer",
        evaluate: (c) => {
          const r = c.probe("user", { authenticationFlow: "authenticationTransfer" });
          const status: ScenarioCheckStatus = r.enforced.outcome === "blocked" ? "prevented" : r.enforced.outcome === "indeterminate" ? "notAssessed" : "notPrevented";
          return {
            label: "Authentication transfer is blocked",
            status,
            detail:
              status === "prevented"
                ? `Blocked by ${r.enforced.blockedBy.map((b) => `"${b.policyName}"`).join(", ")}.`
                : status === "notAssessed"
                ? `Can't confirm: ${r.enforced.uncertainPolicies.map((u) => `"${u.policyName}" (${u.reason})`).join("; ")}.`
                : "Moving a session to another device by QR code isn't blocked.",
            fix: status === "prevented" ? undefined : "Add authentication transfer to the authentication flows policy that blocks device code flow.",
            simulatePersona: "user",
          };
        },
      },
    ],
  },
  {
    id: "role-escalation",
    section: "identity",
    title: "Privilege escalation by role assignment",
    description: "An attacker who controls one admin, an app or a group owner assigns themselves a more powerful role.",
    checks: [
      {
        id: "ga-count", guideId: "right-size-global-admins",
        evaluate: (c) => {
          const all = holdersOf(c, new Set([GLOBAL_ADMIN_TEMPLATE_ID]));
          const count = all.length;
          const label = "Between two and five Global Admins";
          if (count === 0) return { label, status: "notAssessed", detail: "Role assignments haven't been synced." };
          const items = cap(all.map((h) => `${h.upn} (${h.kind})`));
          if (count > 5) return { label, status: "notPrevented", detail: `${count} accounts hold Global Administrator. Microsoft recommends fewer than five.`, items, fix: "Move admins to least-privileged roles (Exchange, SharePoint, User, Helpdesk Administrator...) and keep Global Administrator for a few people plus break-glass accounts." };
          if (count < 2) return { label, status: "partial", detail: "Only one Global Administrator - a single lost account locks the tenant.", items, fix: "Add a second Global Administrator (an emergency-access account)." };
          return { label, status: "prevented", detail: `${count} Global Administrator(s).`, items };
        },
      },
      {
        id: "standing-access", guideId: "make-admin-roles-eligible",
        evaluate: (c) => {
          const pr = c.snapshot.privilegedRoleAssignments;
          const label = "Admin roles are just-in-time (PIM), not standing";
          if (!pr) return { label, status: "notAssessed", detail: "Role assignments haven't been synced." };
          if (pr.source !== "pim") {
            return {
              label,
              status: c.env.entraP2Licensed ? "notAssessed" : "notPrevented",
              detail: c.env.entraP2Licensed
                ? `PIM data couldn't be read${pr.pimUnavailableReason ? ` (${pr.pimUnavailableReason})` : ""}, so every assignment shows as standing.`
                : "Without Entra ID P2 there's no PIM, so every admin role is standing access.",
              fix: c.env.entraP2Licensed ? "Re-sync; if it persists, check PIM in the Entra admin center." : "License Entra ID P2 and make admin roles eligible in PIM.",
              docsUrl: SCENARIO_DOCS.pim,
            };
          }
          const standing = pr.assignments.filter(
            (a) => PRIVILEGED_ROLE_IDS.has(a.roleTemplateId) && a.kind === "activePermanent" && a.principalType === "user" && !isBreakGlass(c, { id: a.principalId, upn: a.principalUserPrincipalName || "" })
          );
          if (standing.length === 0) return { label, status: "prevented", detail: "Every privileged role is eligible or time-bound, apart from break-glass accounts." };
          return { label, status: "notPrevented", detail: `${standing.length} permanent privileged role assignment(s) outside break-glass accounts.`, items: cap(standing.map((a) => `${a.principalUserPrincipalName || a.principalDisplayName || a.principalId}: ${getRoleTemplateById(a.roleTemplateId)?.displayName}`)), fix: "Convert these to eligible assignments in PIM, with MFA and approval on activation.", docsUrl: SCENARIO_DOCS.pim };
        },
      },
      {
        id: "role-assignable-groups", guideId: "remove-role-group-owners",
        evaluate: (c) => {
          const adminUpns = new Set((c.snapshot.mfaAudit || []).filter((u) => u.isAdmin).map((u) => u.userPrincipalName.toLowerCase()));
          const risky = (c.snapshot.groups || []).filter((g) => g.isAssignableToRole && (g.owners || []).some((o) => !adminUpns.has(o.toLowerCase())));
          return risky.length === 0
            ? { label: "Role-assignable groups are owned by admins only", status: "prevented", detail: "No role-assignable group has a non-admin owner." }
            : { label: "Role-assignable groups are owned by admins only", status: "notPrevented", detail: "Owners of these groups can add members - and so grant the group's admin role.", items: cap(risky.map((g) => `${g.displayName}: ${(g.owners || []).filter((o) => !adminUpns.has(o.toLowerCase())).join(", ")}`)), fix: "Remove non-admin owners from role-assignable groups." };
        },
      },
      {
        id: "apps-grant-roles", guideId: "review-app-permissions",
        evaluate: (c) => {
          const risky = (c.snapshot.appRegistrations || []).filter((a) =>
            a.highPrivilegePermissions.some((p) => /RoleManagement\.ReadWrite\.Directory|AppRoleAssignment\.ReadWrite\.All|Directory\.ReadWrite\.All/i.test(p))
          );
          return risky.length === 0
            ? { label: "No app can assign roles or permissions", status: "prevented", detail: "No app registration holds role- or permission-granting permissions." }
            : { label: "No app can assign roles or permissions", status: "notPrevented", detail: "A stolen secret for these apps is enough to make anyone an admin.", items: cap(risky.map((a) => `${a.displayName}: ${a.highPrivilegePermissions.join(", ")}`)), fix: "Remove these permissions unless essential; rotate secrets to certificates and restrict who owns the apps." };
        },
      },
      { id: "admin-phishing-resistant", guideId: "require-phishing-resistant-admins", evaluate: (c) => fromCell(c, "admins", "phishingResistant", "Admins use phishing-resistant MFA", "Require the phishing-resistant MFA authentication strength for admin roles.", CA_DOCS.adminPhishingResistant) },
    ],
  },

  // ====================================================== Audit & Detection
  {
    id: "mfa-tampering",
    section: "audit",
    title: "MFA tampering after compromise",
    description: "After stealing a password, an attacker registers their own authenticator app so they keep access even after being noticed.",
    checks: [
      {
        id: "registration-protected", guideId: "protect-security-info-registration",
        evaluate: (c) => {
          const r = c.probe("user", { target: { kind: "userAction", action: "urn:user:registersecurityinfo" }, device: "unmanaged", location: { country: c.foreignCountry, ipNamedLocationIds: [] } });
          const label = "Registering security info is protected";
          if (r.enforced.outcome === "blocked" || r.enforced.outcome === "challenged") return { label, status: "prevented", detail: "A policy covers the \"Register security information\" action." };
          if (r.withReportOnly.outcome === "blocked" || r.withReportOnly.outcome === "challenged") return { label, status: "partial", detail: "A policy covers it, but only in report-only mode.", fix: "Switch the security-info registration policy on.", docsUrl: CA_DOCS.securityInfoRegistration };
          return { label, status: "notPrevented", detail: "No policy targets the \"Register security information\" action, so a password alone can add an MFA method.", fix: "Require MFA or a trusted location to register security info, and use Temporary Access Passes for new users.", docsUrl: CA_DOCS.securityInfoRegistration };
        },
      },
      { id: "user-risk", guideId: "require-risk-remediation", evaluate: (c) => fromCell(c, "users", "userRisk", "High user risk forces remediation", "Require risk remediation when user risk is high (CA07).", CA_DOCS.userRisk) },
      {
        id: "ual", guideId: "enable-unified-audit-log",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.exchangeSecurity?.unifiedAuditLogIngestionEnabled,
            true,
            "Registration changes are recorded in the audit log",
            { good: "The Microsoft 365 audit log is on.", bad: "The Microsoft 365 audit log is off, so the change would leave no trace.", unknown: EXO_NOT_CONNECTED },
            "Turn on auditing in the Microsoft Purview portal (Audit > Start recording user and admin activity).",
            SCENARIO_DOCS.auditLog
          ),
      },
    ],
  },
  {
    id: "silent-tenant",
    section: "audit",
    title: "Silent tenant: auditing turned off",
    description: "Auditing is off (Microsoft doesn't turn it on by default for Business plans), or an attacker turns it off, so nothing they do can be investigated later.",
    checks: [
      {
        id: "ual", guideId: "enable-unified-audit-log",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.exchangeSecurity?.unifiedAuditLogIngestionEnabled,
            true,
            "The Microsoft 365 audit log is on",
            { good: "Audit log ingestion is on.", bad: "Audit log ingestion is off: sign-in-independent activity (mail access, file downloads, admin changes) isn't recorded.", unknown: EXO_NOT_CONNECTED },
            "Turn on auditing in the Microsoft Purview portal, or run Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true.",
            SCENARIO_DOCS.auditLog
          ),
      },
      {
        id: "mailbox-auditing", guideId: "enable-mailbox-auditing",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.mailboxAuditingEnabled,
            true,
            "Mailbox auditing is on",
            { good: "Mailbox auditing is on for the organisation.", bad: "Mailbox auditing is off, so mailbox access by attackers or delegates isn't recorded.", unknown: EXO_NOT_CONNECTED },
            "Run Set-OrganizationConfig -AuditDisabled $false."
          ),
      },
      {
        id: "signin-logs",
        evaluate: (c) => {
          const errs = (c.snapshot.syncHealth?.errors || []).filter((e) => /^Sign-in logs/i.test(e));
          const label = "Sign-in logs are available";
          if (errs.some((e) => /premium|license|licence|forbidden|insufficient/i.test(e))) return { label, status: "notPrevented", detail: "Sign-in logs couldn't be read (they need Entra ID P1 or the AuditLog.Read.All permission).", fix: "License Entra ID P1 and grant AuditLog.Read.All." };
          if ((c.snapshot.signIns || []).length > 0) return { label, status: "prevented", detail: `${c.snapshot.signIns.length} sign-in event(s) synced.` };
          return { label, status: "notAssessed", detail: "No sign-in events were synced, so availability can't be confirmed." };
        },
      },
      {
        id: "alerting", guideId: "alert-audit-config-changes",
        evaluate: (c) =>
          alertPolicyCheck(c, {
            label: "Someone is alerted if auditing is changed",
            operations: AUDIT_CONFIG_OPERATIONS,
            confirmKey: "alert-audit-config",
            watched: "the audit log configuration is changed (Set-AdminAuditLogConfig)",
            fix: "Create an alert policy for audit-configuration changes (see How to fix), or a Sentinel rule and confirm it here.",
            docsUrl: SCENARIO_DOCS.auditLog,
          }),
      },
    ],
  },
  {
    id: "mass-deletion",
    section: "audit",
    title: "Mass user deletion",
    description: "A compromised admin deletes many users (or disables them) to disrupt the business. Deleted users can be restored for 30 days.",
    checks: [
      {
        id: "standing-deleters", guideId: "make-admin-roles-eligible",
        evaluate: (c) => {
          const holders = holdersOf(c, new Set([GLOBAL_ADMIN_TEMPLATE_ID, USER_ADMIN, PRIV_AUTH_ADMIN]), new Set(["activePermanent"])).filter((h) => !isBreakGlass(c, h));
          const label = "Few accounts can delete users at any moment";
          if (!c.snapshot.privilegedRoleAssignments && holders.length === 0) return { label, status: "notAssessed", detail: "Role assignments haven't been synced." };
          const items = cap(holders.map((h) => h.upn));
          if (holders.length <= 2) return { label, status: "prevented", detail: `${holders.length} standing account(s) (outside break-glass) hold Global, User or Privileged Authentication Administrator.`, items };
          return { label, status: holders.length <= 5 ? "partial" : "notPrevented", detail: `${holders.length} accounts can delete users at any moment.`, items, fix: "Make these roles eligible in PIM so deletion needs an activation with MFA and a reason.", docsUrl: SCENARIO_DOCS.pim };
        },
      },
      {
        id: "pim", guideId: "make-admin-roles-eligible",
        evaluate: (c) => {
          const pr = c.snapshot.privilegedRoleAssignments;
          const label = "Admin roles need activation (PIM)";
          if (!pr) return { label, status: "notAssessed", detail: "Role assignments haven't been synced." };
          if (pr.source !== "pim") return { label, status: c.env.entraP2Licensed ? "notAssessed" : "notPrevented", detail: c.env.entraP2Licensed ? "PIM data couldn't be read." : "PIM needs Entra ID P2.", docsUrl: SCENARIO_DOCS.pim };
          const eligible = pr.assignments.filter((a) => a.kind === "eligible" && PRIVILEGED_ROLE_IDS.has(a.roleTemplateId));
          return eligible.length > 0
            ? { label, status: "prevented", detail: `${eligible.length} privileged role assignment(s) are eligible and need activation.` }
            : { label, status: "notPrevented", detail: "PIM is available but no privileged role is eligible - every admin has standing access.", fix: "Convert admin role assignments to eligible in PIM.", docsUrl: SCENARIO_DOCS.pim };
        },
      },
      {
        id: "protected-actions", guideId: "protect-sensitive-admin-actions",
        evaluate: (c) => {
          const withContext = c.env.policies.filter((p) => p.state === "enabled" && (p.conditions.applications.authenticationContexts || []).length > 0);
          return withContext.length > 0
            ? { label: "Sensitive admin actions need step-up authentication", status: "partial", detail: `Authentication contexts are used by ${withContext.map((p) => `"${p.name}"`).join(", ")}. Confirm they're attached to the protected actions for deleting users and policies.`, fix: "In Entra roles > Protected actions, attach an authentication context to the deletion permissions." }
            : { label: "Sensitive admin actions need step-up authentication", status: "notPrevented", detail: "No policy uses an authentication context, so protected actions (such as deleting Conditional Access policies) aren't gated.", fix: "Create an authentication context, a policy requiring phishing-resistant MFA for it, and attach it to protected actions." };
        },
      },
      {
        id: "alerting", guideId: "alert-user-deletion",
        evaluate: (c) =>
          alertPolicyCheck(c, {
            label: "User deletion raises an alert",
            operations: USER_DELETION_OPERATIONS,
            confirmKey: "alert-user-deletion",
            watched: "a user is deleted",
            fix: "Create an alert policy for user deletion (see How to fix), or a Sentinel rule and confirm it here.",
          }),
      },
    ],
  },

  // ========================================================== Exchange & Email
  {
    id: "mailbox-rule-exfil",
    section: "exchange",
    title: "Mailbox rule exfiltration",
    description: "After compromising a mailbox, an attacker adds an inbox rule (or mailbox forwarding) that quietly sends copies of mail outside.",
    checks: [
      {
        id: "no-external-rules", guideId: "stop-external-mailbox-forwarding",
        evaluate: (c) => {
          if (!c.snapshot.tenant.isDemo && c.snapshot.mailboxAuditingEnabled === undefined && (c.snapshot.emailForwarding || []).length === 0) {
            return { label: "No mailbox forwards mail outside", status: "notAssessed", detail: EXO_NOT_CONNECTED };
          }
          const external = (c.snapshot.emailForwarding || []).filter((r) => r.isExternal && r.state === "Enabled" && r.scope !== "transport_rule");
          return external.length === 0
            ? { label: "No mailbox forwards mail outside", status: "prevented", detail: "No enabled inbox rule or mailbox forwarding sends mail to an external address." }
            : { label: "No mailbox forwards mail outside", status: "notPrevented", detail: `${external.length} inbox rule(s) or mailbox forward(s) send mail externally.`, items: cap(external.map((r) => `${r.mailboxOwner || r.name} → ${r.forwardingAddress}`)), fix: "Review each in Email Forwarding Audit and remove any that aren't approved." };
        },
      },
      {
        id: "outbound-policy", guideId: "block-external-autoforward-outbound",
        evaluate: (c) => {
          const outbound = (c.snapshot.mdoThreat?.policies || []).filter((p) => p.policyType === "AntiSpamOutbound");
          const label = "Outbound spam policy blocks automatic external forwarding";
          if (outbound.length === 0) return { label, status: "notAssessed", detail: EXO_NOT_CONNECTED };
          if (outbound.every((p) => p.autoForwardingBlocked === undefined)) {
            return { label, status: "notAssessed", detail: "The outbound spam policies were synced but didn't report their automatic-forwarding setting.", fix: "Check Automatic forwarding in the outbound spam policies (Defender portal).", docsUrl: SCENARIO_DOCS.externalForwarding };
          }
          const open = outbound.filter((p) => p.autoForwardingBlocked === false);
          return open.length === 0
            ? { label, status: "prevented", detail: "Automatic forwarding to external recipients is off." }
            : { label, status: "notPrevented", detail: `${open.map((p) => `"${p.displayName}"`).join(", ")} ${open.length === 1 ? "doesn't" : "don't"} set automatic forwarding to Off. Microsoft recommends an explicit Off rather than \"Automatic\".`, fix: "Set automatic forwarding to \"Off - Forwarding is disabled\" in the outbound spam policies, with a separate policy for approved forwarders.", docsUrl: SCENARIO_DOCS.externalForwarding };
        },
      },
      {
        id: "remote-domain", guideId: "block-autoforward-remote-domain",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.remoteDomainAutoForwardBlocked,
            true,
            "The default remote domain blocks auto-forwarding",
            { good: "The default remote domain doesn't allow automatic forwarding.", bad: "The default remote domain allows automatic forwarding.", unknown: EXO_NOT_CONNECTED },
            "Run Set-RemoteDomain Default -AutoForwardEnabled $false.",
            SCENARIO_DOCS.externalForwarding
          ),
      },
      {
        id: "mailbox-auditing", guideId: "enable-mailbox-auditing",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.mailboxAuditingEnabled,
            true,
            "New inbox rules are recorded",
            { good: "Mailbox auditing is on, so rule creation is logged.", bad: "Mailbox auditing is off, so rule creation isn't logged.", unknown: EXO_NOT_CONNECTED },
            "Run Set-OrganizationConfig -AuditDisabled $false."
          ),
      },
    ],
  },
  {
    id: "transport-rule-exfil",
    section: "exchange",
    title: "Transport-rule exfiltration",
    description: "A compromised Exchange admin adds an organisation-wide mail flow rule that copies (BCC) or redirects mail outside.",
    checks: [
      {
        id: "no-external-rules", guideId: "disable-external-transport-rules",
        evaluate: (c) => {
          const rules = c.snapshot.mailflowTransportRules || [];
          if (!c.snapshot.tenant.isDemo && rules.length === 0 && c.snapshot.mailboxAuditingEnabled === undefined) return { label: "No mail flow rule sends mail outside", status: "notAssessed", detail: EXO_NOT_CONNECTED };
          const external = rules.filter((r) => r.state === "Enabled" && r.redirectsExternally);
          return external.length === 0
            ? { label: "No mail flow rule sends mail outside", status: "prevented", detail: `${rules.length} mail flow rule(s) checked; none copy or redirect mail externally.` }
            : { label: "No mail flow rule sends mail outside", status: "notPrevented", detail: `${external.length} enabled rule(s) copy or redirect mail externally.`, items: cap(external.map((r) => `${r.name} → ${r.externalRedirectAddress || "external address"}`)), fix: "Review each rule in Mailflow Rules and remove any that aren't approved." };
        },
      },
      {
        id: "exchange-admins", guideId: "make-admin-roles-eligible",
        evaluate: (c) => {
          const holders = holdersOf(c, new Set([GLOBAL_ADMIN_TEMPLATE_ID, EXCHANGE_ADMIN]), new Set(["activePermanent"])).filter((h) => !isBreakGlass(c, h));
          const label = "Few accounts can change mail flow rules";
          if (!c.snapshot.privilegedRoleAssignments && holders.length === 0) return { label, status: "notAssessed", detail: "Role assignments haven't been synced." };
          const items = cap(holders.map((h) => h.upn));
          return holders.length <= 3
            ? { label, status: "prevented", detail: `${holders.length} standing Global or Exchange Administrator(s) outside break-glass.`, items }
            : { label, status: "partial", detail: `${holders.length} accounts can create mail flow rules at any moment.`, items, fix: "Reduce standing Exchange and Global Administrators; use PIM for the rest.", docsUrl: SCENARIO_DOCS.pim };
        },
      },
      {
        id: "ual", guideId: "enable-unified-audit-log",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.exchangeSecurity?.unifiedAuditLogIngestionEnabled,
            true,
            "Rule changes are recorded in the audit log",
            { good: "The Microsoft 365 audit log is on.", bad: "The Microsoft 365 audit log is off, so rule changes aren't recorded.", unknown: EXO_NOT_CONNECTED },
            "Turn on auditing in the Microsoft Purview portal.",
            SCENARIO_DOCS.auditLog
          ),
      },
    ],
  },

  // ========================================================== SharePoint & Data
  {
    id: "bulk-sync",
    section: "sharepoint",
    title: "Bulk sync to an unmanaged device",
    description: "A departing employee or an attacker syncs whole document libraries to a personal computer with the OneDrive app.",
    checks: [
      {
        id: "sync-restricted", guideId: "sharepoint-sync-domain-joined",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.sharePoint?.unmanagedSyncAppRestricted,
            true,
            "OneDrive sync only works on domain-joined PCs",
            { good: `OneDrive sync is restricted to ${c.snapshot.sharePoint?.syncAllowedDomainCount ?? "approved"} domain(s).`, bad: "OneDrive sync works on any PC.", unknown: "SharePoint settings haven't been synced yet." },
            "In the SharePoint admin center, Settings > OneDrive sync > allow syncing only on computers joined to specific domains.",
            SCENARIO_DOCS.unmanagedDevices
          ),
      },
      { id: "desktop-blocked", guideId: "require-compliant-device-desktop", evaluate: (c) => fromSituation(c, "user-desktop-unmanaged", "Desktop apps on unmanaged devices are blocked") },
      {
        id: "browser-limited", guideId: "sharepoint-limit-unmanaged-devices",
        evaluate: (c) => {
          const r = c.probe("user", { device: "unmanaged", clientAppType: "browser" });
          const limited = r.enforced.sessionControls.some((s) => s.controls.some((x) => /App-enforced restrictions|Defender for Cloud Apps/.test(x)));
          const label = "Browsers on unmanaged devices get web-only access";
          if (r.enforced.outcome === "blocked") return { label, status: "prevented", detail: "Unmanaged devices are blocked outright." };
          return limited
            ? { label, status: "prevented", detail: "App-enforced restrictions (or a Defender for Cloud Apps session) limit downloads in the browser." }
            : { label, status: "notPrevented", detail: "Browser sessions on unmanaged devices can download files freely.", fix: "Set SharePoint's unmanaged device access to \"Allow limited, web-only access\" (it creates the Conditional Access policy for you).", docsUrl: SCENARIO_DOCS.unmanagedDevices, simulatePersona: "user" };
        },
      },
    ],
  },
  {
    id: "anyone-link",
    section: "sharepoint",
    title: "Anyone link on a sensitive site",
    description: "Someone shares a file from a sensitive site with an \"Anyone\" link; the link gets forwarded and the file is open to the internet with no sign-in.",
    warning: () =>
      "Sensitivity labels aren't synced yet, so Clarity365 can't tell which sites are sensitive. These checks cover every site.",
    checks: [
      {
        id: "tenant-level", guideId: "sharepoint-restrict-anyone-org",
        evaluate: (c) => {
          const lvl = c.snapshot.sharePoint?.tenantSharingLevel;
          return lvl === "Anyone"
            ? { label: "Anyone links are off for the organisation", status: "notPrevented", detail: "The organisation-wide sharing level allows Anyone links.", fix: "Lower the organisation sharing level to \"New and existing guests\", and enable Anyone links only on sites that need them.", docsUrl: SCENARIO_DOCS.unmanagedDevices }
            : { label: "Anyone links are off for the organisation", status: "prevented", detail: "Anyone links aren't allowed anywhere (the organisation-wide level is stricter)." };
        },
      },
      {
        id: "sites", guideId: "sharepoint-restrict-anyone-sites",
        evaluate: (c) => {
          const sites = (c.snapshot.sharePoint?.sites || []).filter((s) => s.sharingCapability === "Anyone");
          return sites.length === 0
            ? { label: "No site allows Anyone links", status: "prevented", detail: `${(c.snapshot.sharePoint?.sites || []).length} site(s) checked.` }
            : { label: "No site allows Anyone links", status: "notPrevented", detail: `${sites.length} site(s) allow Anyone links.`, items: cap(sites.map((s) => s.siteName || s.siteUrl)), fix: "Restrict sharing on these sites unless they're genuinely public." };
        },
      },
      {
        id: "expiry", guideId: "sharepoint-anyone-link-expiry",
        evaluate: (c) => {
          const sp = c.snapshot.sharePoint;
          const label = "Anyone links expire";
          if (!sp || sp.tenantSharingLevel !== "Anyone") return { label, status: "prevented", detail: "Not needed: Anyone links are off." };
          if (sp.linkDefaultsReported === false) return { label, status: "notAssessed", detail: "Microsoft's API doesn't report the Anyone-link expiry, so it can't be checked from here.", fix: "Check it in the SharePoint admin center > Sharing > Advanced settings for Anyone links (30 days or fewer), then confirm it here.", confirmKey: "sharepoint-anyone-link-expiry" };
          return sp.anonymousLinkExpirationDays > 0 && sp.anonymousLinkExpirationDays <= 30
            ? { label, status: "prevented", detail: `Anyone links expire after ${sp.anonymousLinkExpirationDays} day(s).` }
            : { label, status: "notPrevented", detail: sp.anonymousLinkExpirationDays > 0 ? `Anyone links last ${sp.anonymousLinkExpirationDays} days.` : "Anyone links never expire.", fix: "Set Anyone links to expire within 30 days." };
        },
      },
      {
        id: "default-link", guideId: "sharepoint-default-link-type",
        evaluate: (c) => {
          const sp = c.snapshot.sharePoint;
          const label = "The default link isn't an Anyone link";
          if (!sp || sp.tenantSharingLevel !== "Anyone") return { label, status: "prevented", detail: "Not needed: Anyone links are off." };
          if (sp.linkDefaultsReported === false) return { label, status: "notAssessed", detail: "Microsoft's API doesn't report the default link type, so it can't be checked from here.", fix: "Check it in the SharePoint admin center > Sharing > File and folder links (the default should not be Anyone), then confirm it here.", confirmKey: "sharepoint-default-link" };
          return sp.defaultLinkType === "Anyone"
            ? { label, status: "notPrevented", detail: "New links default to Anyone links.", fix: "Set the default link to \"Specific people\" or \"Only people in your organization\"." }
            : { label, status: "prevented", detail: `New links default to ${sp.defaultLinkType === "SpecificPeople" ? "specific people" : "people in the organisation"}.` };
        },
      },
    ],
  },
  {
    id: "guest-reshare",
    section: "sharepoint",
    title: "Guest re-share sprawl",
    description: "A guest re-shares files they were given with more people outside, until nobody knows who can see them.",
    checks: [
      {
        id: "reshare", guideId: "sharepoint-prevent-guest-reshare",
        evaluate: (c) =>
          boolCheck(
            c.snapshot.sharePoint?.resharingByExternalUsersEnabled,
            false,
            "Guests can't re-share files they don't own",
            { good: "Guests can't re-share.", bad: "Guests can re-share files, folders and sites they don't own.", unknown: "SharePoint settings haven't been synced yet." },
            "Run Set-SPOTenant -PreventExternalUsersFromResharing $true (or untick it in the SharePoint admin center > Sharing)."
          ),
      },
      {
        id: "domains", guideId: "sharepoint-domain-allowlist",
        evaluate: (c) => {
          const mode = c.snapshot.sharePoint?.sharingDomainRestrictionMode;
          const label = "Sharing is limited to approved domains";
          if (!mode) return { label, status: "notAssessed", detail: "SharePoint settings haven't been synced yet." };
          if (mode === "allowList") return { label, status: "prevented", detail: "External sharing is limited to an allow list of domains." };
          if (mode === "blockList") return { label, status: "partial", detail: "Some domains are blocked; everything else is allowed.", fix: "Consider an allow list of partner domains instead." };
          return { label, status: "notPrevented", detail: "Files can be shared with any external domain.", fix: "Limit external sharing to partner domains (SharePoint admin center > Sharing > Limit external sharing by domain)." };
        },
      },
      {
        id: "invites", guideId: "restrict-guest-invites",
        evaluate: (c) => {
          const s = c.snapshot.identitySettings?.guestInviteSetting;
          const label = "Guests can't invite other guests";
          if (!s || s === "unknown") return { label, status: "notAssessed", detail: "Guest invite setting wasn't synced." };
          return s === "everyone"
            ? { label, status: "notPrevented", detail: "Guests can invite other guests.", fix: "Limit invitations to admins and users in the Guest Inviter role." }
            : { label, status: "prevented", detail: "Guests can't invite other guests." };
        },
      },
    ],
  },
];

// --------------------------------------------------------------- evaluation

// Red if any layer lets the attack through (a single open path is enough),
// green only when every check is prevented, orange otherwise (partial
// checks, or checks that couldn't be assessed). Green and red lead, per the
// user's colour decision.
// "Someone is alerted when X happens": answered from the tenant's Microsoft
// 365 alert policies when they could be read. Only a policy that is enabled,
// watches the activity and emails someone counts as prevented. When no
// policy is found the check is red, with the option to confirm that the
// alert lives somewhere Clarity365 can't see (Sentinel, another SIEM).
function alertPolicyCheck(
  c: ScenarioContext,
  spec: { label: string; operations: string[]; confirmKey: ScenarioConfirmationKey; watched: string; fix: string; docsUrl?: string }
): Omit<ScenarioCheckResult, "id"> {
  const { label, confirmKey, docsUrl } = spec;
  const inventory = c.snapshot.alertPolicies;
  const coverage = findAlertCoverage(inventory, spec.operations);
  const names = coverage.policies.map((p) => `"${p.name}"`).join(", ");
  switch (coverage.state) {
    case "alerting": {
      const p = coverage.policies[0];
      const trigger = describeAlertTrigger(p);
      return { label, status: "prevented", detail: `Alert policy ${names} emails ${p.notifyRecipients} recipient(s) when ${spec.watched}${trigger ? ` (${trigger})` : ""}.` };
    }
    case "raisedNotEmailed":
      return { label, status: "partial", detail: `Alert policy ${names} raises an alert when ${spec.watched}, but emails nobody, so it is only seen if someone opens the Defender portal.`, fix: "Add an email recipient to the alert policy.", docsUrl };
    case "disabledOnly":
      return { label, status: "notPrevented", detail: `Alert policy ${names} watches this but is turned off.`, fix: "Turn the alert policy on (Defender portal > Policies & rules > Alert policy).", docsUrl };
    case "none":
      return {
        label,
        status: "notPrevented",
        detail: `None of this tenant's ${inventory!.policies.length} Microsoft 365 alert policies fires when ${spec.watched}. If you alert on it elsewhere (Sentinel or another monitoring tool), confirm that here.`,
        fix: spec.fix,
        docsUrl,
        confirmKey,
      };
    default: {
      const reason = !inventory
        ? "Alert policies haven't been synced yet. Re-sync this tenant."
        : inventory.unavailable === "notSetUp"
          ? "Alert policies can't be read until Exchange app access is set up for this tenant (see the Permissions check)."
          : `Alert policies couldn't be read: ${inventory.detail || "unknown error"}.`;
      return { label, status: "notAssessed", detail: reason, fix: "Until they can be read, check it in the Defender portal (Policies & rules > Alert policy) and confirm it here.", docsUrl, confirmKey };
    }
  }
}

const shortDate = (iso: string) => iso.slice(0, 10);

// A valid confirmation settles a check Clarity365 can't see for itself:
// "in place" turns it green, "not in place" red. A lapsed one no longer
// counts and the check says so. Checks without a confirmKey are never touched.
export function applyManualConfirmation(check: ScenarioCheckResult, confirmations: Partial<Record<ScenarioConfirmationKey, ScenarioConfirmation>> | undefined, now: Date): ScenarioCheckResult {
  if (!check.confirmKey) return check;
  const state = getConfirmationState(confirmations?.[check.confirmKey], now);
  if (!state) return check;
  if (state.expired) {
    return { ...check, confirmation: state, detail: `${check.detail} Your confirmation from ${shortDate(state.confirmedAt)} is more than ${CONFIRMATION_VALID_DAYS} days old and no longer counts; please check again.` };
  }
  const note = state.note ? ` Note: ${state.note}` : "";
  if (state.status === "inPlace") {
    return { ...check, confirmation: state, status: "prevented", detail: `Confirmed manually on ${shortDate(state.confirmedAt)} (valid until ${shortDate(state.expiresAt)}).${note}`, fix: undefined, command: undefined };
  }
  return { ...check, confirmation: state, status: "notPrevented", detail: `Marked as not in place on ${shortDate(state.confirmedAt)}.${note}` };
}

export function rollUpVerdict(checks: { status: ScenarioCheckStatus }[]): ScenarioCheckStatus {
  if (checks.some((c) => c.status === "notPrevented")) return "notPrevented";
  if (checks.length > 0 && checks.every((c) => c.status === "prevented")) return "prevented";
  if (checks.every((c) => c.status === "notAssessed")) return "notAssessed";
  return "partial";
}

export function evaluateScenarios(snapshot: TenantSecuritySnapshot, options: { foreignCountry?: string; now?: Date } = {}): ScenarioResult[] {
  const now = options.now || new Date();
  const env = buildCaEnvironment(snapshot);
  const homeCountry = detectHomeCountry(snapshot);
  const foreignCountry = options.foreignCountry || (homeCountry === "RU" ? "CN" : "RU");
  const breakGlass = detectLikelyBreakGlassAccounts(snapshot);
  const situationCache = new Map<string, SituationRunResult>();
  const ctx: ScenarioContext = {
    snapshot,
    env,
    gap: analyzeCaGaps(snapshot, options.now || new Date(), homeCountry),
    accounts: listSimAccounts(snapshot),
    breakGlass,
    homeCountry,
    foreignCountry,
    situation: (id) => {
      if (!situationCache.has(id)) {
        const def = SIGNIN_SITUATIONS.find((s) => s.id === id)!;
        situationCache.set(id, runSituation(def, buildSyntheticSimUser(def.persona), env, { homeCountry, foreignCountry }, breakGlass));
      }
      return situationCache.get(id)!;
    },
    probe: (persona, overrides) =>
      evaluateSignIn(
        {
          user: buildSyntheticSimUser(persona),
          target: { kind: "resource", resource: "Office365" },
          clientAppType: "browser",
          platform: "windows",
          device: persona === "guest" ? "unmanaged" : "compliant",
          location: { country: homeCountry, ipNamedLocationIds: [] },
          signInRisk: "none",
          userRisk: "none",
          insiderRisk: "none",
          ...overrides,
        },
        env
      ),
  };

  return SCENARIO_DEFINITIONS.map((def) => {
    const checks = def.checks.map((check) => {
      const result = applyManualConfirmation({ id: check.id, ...check.evaluate(ctx) }, snapshot.tenant?.scenarioConfirmations, now);
      return check.guideId && result.status !== "prevented" ? { ...result, guideId: check.guideId } : result;
    });
    const counts: Record<ScenarioCheckStatus, number> = { prevented: 0, partial: 0, notPrevented: 0, notAssessed: 0 };
    for (const c of checks) counts[c.status] += 1;
    return {
      id: def.id,
      section: def.section,
      title: def.title,
      description: def.description,
      warning: def.warning?.(ctx),
      checks,
      counts,
      verdict: rollUpVerdict(checks),
      gaps: counts.partial + counts.notPrevented,
    };
  });
}
