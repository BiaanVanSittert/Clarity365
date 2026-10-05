import { CAPolicyRule, CaNamedLocation, SignInEvent, TenantSecuritySnapshot } from "../types";
import { CaEnvironment, CaRequirementKind, CaSimClientAppType, CaSimDeviceState, CaSimPlatform, CaSimUser, SignInContext, evaluateSignIn } from "./ca-policy-evaluator";
import { buildSimUser } from "./ca-sim-context";
import { hasEntraP2Capability } from "../utils/entra-p2";
import { isIpInCidr } from "../utils/ip-range";
import { normalizeCountryCode, UNKNOWN_COUNTRY } from "../utils/sign-in-country";
import { formatDay } from "../utils/sign-in-coverage";

// "What would this new Conditional Access policy have done to the sign-ins
// we already have?" Replays the tenant's synced sign-ins through the What If
// engine (ca-policy-evaluator.ts) against the proposed policy on its own, as
// if it were switched on. Used by the fix guides so a lockout shows up before
// the policy is created, not after.
//
// Approximations, stated on the preview itself:
//  - every sign-in is treated as a sign-in to Office 365 (the synced record
//    has the app's name, not the resource the policy would target);
//  - device-code use, user risk and user actions aren't in the synced data,
//    so policies that depend only on those can't be previewed (the guide
//    says so instead of showing "no impact");
//  - only successful sign-ins count: one that already failed isn't "broken"
//    by a new policy.

export interface PolicyImpactPreview {
  // Successful sign-ins replayed.
  checked: number;
  from?: string;
  to?: string;
  blocked: number;
  blockedUsers: string[];
  // Would have been asked for something more (MFA, a compliant device...).
  challenged: number;
  challengedUsers: string[];
  challengeKinds: CaRequirementKind[];
  // Would have been asked for MFA (or phishing-resistant MFA) but the sign-in
  // already did it, so nothing changes for the user. Not in `challenged`.
  alreadyMet: number;
  // Of `challenged`: sign-ins whose log doesn't say how the user signed in
  // (synced before the beta sign-in log was read), so they may already have
  // done MFA.
  challengedWithoutMethodDetail: number;
  // Couldn't be decided from the data (for example group membership not synced).
  undetermined: number;
  // Sign-ins the policy wouldn't have touched.
  unaffected: number;
}

const USER_LIMIT = 15;

export function clientAppTypeOf(clientApp: string | undefined): CaSimClientAppType {
  const c = (clientApp || "").toLowerCase();
  if (c === "browser") return "browser";
  if (c.includes("mobile apps and desktop")) return "mobileAppsAndDesktopClients";
  if (c.includes("activesync")) return "exchangeActiveSync";
  return c === "" || c === "unknown" ? "browser" : "other";
}

export function platformOf(operatingSystem: string | undefined): CaSimPlatform {
  const os = (operatingSystem || "").toLowerCase();
  if (os.includes("windows")) return "windows";
  if (os.includes("mac")) return "macOS";
  if (os.includes("ios") || os.includes("iphone") || os.includes("ipad")) return "iOS";
  if (os.includes("android")) return "android";
  if (os.includes("linux")) return "linux";
  return "unknown";
}

export function deviceStateOf(device: SignInEvent["deviceDetail"] | undefined): CaSimDeviceState {
  if (device?.isCompliant) return "compliant";
  if (/hybrid/i.test(device?.trustType || "")) return "hybridJoined";
  return "unmanaged";
}

function userFor(snapshot: TenantSecuritySnapshot, event: SignInEvent): CaSimUser {
  const known = event.userId ? buildSimUser(snapshot, event.userId) : undefined;
  if (known) return known;
  const upn = event.userPrincipalName || "unknown";
  return {
    id: event.userId || undefined,
    userPrincipalName: upn,
    isGuest: event.userType === "guest" || upn.toLowerCase().includes("#ext#"),
    roleTemplateIds: [],
    // Roles and groups unknown for an account that isn't in the synced user list.
    roleTemplateIdsComplete: false,
    groupIds: [],
  };
}

export function signInToContext(snapshot: TenantSecuritySnapshot, event: SignInEvent, namedLocations: CaNamedLocation[]): SignInContext {
  const country = normalizeCountryCode(event.location?.country);
  const ipNamedLocationIds = namedLocations
    .filter((l) => l.kind === "ip" && (l.ipRanges || []).some((r) => isIpInCidr(event.ipAddress, r)))
    .map((l) => l.id);
  const risk = event.riskLevel === "low" || event.riskLevel === "medium" || event.riskLevel === "high" ? event.riskLevel : "none";
  return {
    user: userFor(snapshot, event),
    target: { kind: "resource", resource: "Office365" },
    clientAppType: clientAppTypeOf(event.clientApp),
    platform: platformOf(event.deviceDetail?.operatingSystem),
    device: deviceStateOf(event.deviceDetail),
    location: { country: country === UNKNOWN_COUNTRY ? null : country, ipNamedLocationIds },
    signInRisk: risk,
    userRisk: "none",
    insiderRisk: "none",
  };
}

const KIND_LABELS: Record<CaRequirementKind, string> = {
  mfa: "MFA",
  phishingResistantMfa: "phishing-resistant MFA",
  authenticationStrength: "a stronger sign-in method",
  appProtection: "an app protection policy",
  passwordChange: "a password change",
  other: "a compliant or joined device, or another control",
};

const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

// The preview as plain sentences, for the guide and reports.
export function describePolicyImpact(p: PolicyImpactPreview): { headline: string; lines: string[] } {
  const period = p.from && p.to ? ` from ${formatDay(p.from)} to ${formatDay(p.to)}` : "";
  const headline = `Replayed ${plural(p.checked, "successful sign-in")}${period} against this policy, as if it were on.`;
  const lines: string[] = [];
  if (p.blocked > 0) lines.push(`${plural(p.blocked, "sign-in")} would have been blocked (${p.blockedUsers.join(", ")}${p.blockedUsers.length >= USER_LIMIT ? ", ..." : ""}).`);
  if (p.challenged > 0) {
    const kinds = p.challengeKinds.map((k) => KIND_LABELS[k]).join(" or ");
    lines.push(`${plural(p.challenged, "sign-in")} would have needed ${kinds || "something more"} (${p.challengedUsers.join(", ")}${p.challengedUsers.length >= USER_LIMIT ? ", ..." : ""}).`);
  }
  if (p.challengedWithoutMethodDetail > 0) {
    const which = p.challengedWithoutMethodDetail === p.challenged ? "None of these record" : `${p.challengedWithoutMethodDetail.toLocaleString("en-US")} of these ${p.challengedWithoutMethodDetail === 1 ? "doesn't" : "don't"} record`;
    lines.push(`${which} how the user signed in (they were synced before Clarity365 read that), so some may already have done it. Re-sync for exact numbers.`);
  }
  if (p.alreadyMet > 0) lines.push(`${plural(p.alreadyMet, "sign-in")} already met what the policy asks for.`);
  if (p.undetermined > 0) lines.push(`${plural(p.undetermined, "sign-in")} couldn't be decided from the synced data.`);
  if (p.blocked + p.challenged === 0) lines.push("Nobody would have been blocked or asked for more.");
  else if (p.unaffected > 0) lines.push(`${plural(p.unaffected, "sign-in")} wouldn't have been affected.`);
  return { headline, lines };
}

const succeeded =(e: SignInEvent) => e.status === "success" || e.status === "report_only_failed";

const PHISHING_RESISTANT_METHOD = /fido|passkey|windows hello|certificate/i;

// True when the sign-in already satisfied every requirement the policy adds
// (only MFA and phishing-resistant MFA can be told from the sign-in log).
function alreadySatisfied(e: SignInEvent, kinds: CaRequirementKind[]): boolean {
  const auth = e.authentication;
  if (!auth || auth.requirement !== "multiFactor" || kinds.length === 0) return false;
  return kinds.every((k) => k === "mfa" || (k === "phishingResistantMfa" && auth.methods.some((m) => PHISHING_RESISTANT_METHOD.test(m))));
}

// Replays successful synced sign-ins against `policy` alone, switched on.
// `extraNamedLocations` are locations the guide would create first.
export function previewPolicyImpact(snapshot: TenantSecuritySnapshot, policy: CAPolicyRule, extraNamedLocations: CaNamedLocation[] = []): PolicyImpactPreview {
  const namedLocations = [...(snapshot.conditionalAccess?.namedLocations || []), ...extraNamedLocations];
  const env: CaEnvironment = {
    policies: [{ ...policy, state: "enabled" }],
    namedLocations,
    groups: snapshot.groups || [],
    entraP2Licensed: hasEntraP2Capability(snapshot),
    securityDefaultsEnabled: false,
  };
  const events = (snapshot.signIns || []).filter(succeeded);
  const blockedUsers = new Set<string>();
  const challengedUsers = new Set<string>();
  const kinds = new Set<CaRequirementKind>();
  let blocked = 0;
  let challenged = 0;
  let undetermined = 0;
  let alreadyMet = 0;
  let challengedWithoutMethodDetail = 0;
  for (const e of events) {
    const outcome = evaluateSignIn(signInToContext(snapshot, e, namedLocations), env).enforced;
    if (outcome.outcome === "blocked") {
      blocked++;
      blockedUsers.add(e.userPrincipalName);
    } else if (outcome.outcome === "challenged" && alreadySatisfied(e, outcome.requirementKinds)) {
      alreadyMet++;
    } else if (outcome.outcome === "challenged") {
      challenged++;
      if (!e.authentication) challengedWithoutMethodDetail++;
      challengedUsers.add(e.userPrincipalName);
      outcome.requirementKinds.forEach((k) => kinds.add(k));
    } else if (outcome.outcome === "indeterminate") {
      undetermined++;
    }
  }
  const times = events.map((e) => e.createdDateTime).sort();
  return {
    checked: events.length,
    from: times[0],
    to: times[times.length - 1],
    blocked,
    blockedUsers: [...blockedUsers].slice(0, USER_LIMIT),
    challenged,
    challengedUsers: [...challengedUsers].slice(0, USER_LIMIT),
    challengeKinds: [...kinds],
    alreadyMet,
    challengedWithoutMethodDetail,
    undetermined,
    unaffected: events.length - blocked - challenged - alreadyMet - undetermined,
  };
}
