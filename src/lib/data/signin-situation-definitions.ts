import { SignInEvent } from "../types";
import type { CaDesiredOutcome } from "../services/ca-fix-recommender";
import type { SignInContext } from "../services/ca-policy-evaluator";

// The 26 "sign in as" situations of the Sign-in Situations view (ai-context-
// vault/Optimization/Security Simulations Plan.md, Stage 3). Data only - the
// runner (signin-situation-runner.ts) turns each into a SignInContext,
// evaluates it with ca-policy-evaluator.ts, and applies the colour rules.
//
// Design rule: each situation changes ONE risky thing from its persona's
// normal sign-in (PERSONA_NORMAL below), and `normal` is that same sign-in
// with the risky part removed. Found live: when every situation also used
// an unmanaged device, "require a compliant device for everyone" became the
// answer to foreign-country, device-code and risk situations alike.

export type SituationPersona = "globalAdmin" | "user" | "guest";

// Sign-in context fields a situation can override (the user is chosen in the UI).
export type SituationContext = Partial<Omit<SignInContext, "user" | "location">> & {
  // "home": the tenant's home country. "foreign": the country picked in the
  // UI. "trusted": home country, inside the tenant's trusted IP named
  // locations. "untrustedIp": home country, outside every IP named location.
  location?: "home" | "foreign" | "trusted" | "untrustedIp";
};

export interface SigninSituation {
  id: string;
  persona: SituationPersona;
  label: string;
  // Why this situation matters - shown under the title.
  description: string;
  context: SituationContext;
  // The same sign-in without the risky part, used to rank fixes.
  normal: SituationContext;
  desired: CaDesiredOutcome;
  // A good-path control case: the EXPECTED result is "allowed after MFA",
  // so a block is itself a finding (guests can't collaborate).
  goodPath?: boolean;
  baselineCode?: string;
  newPolicyDescription: string;
  // Extra caveat shown with the result.
  caveat?: string;
  // Matches real sign-in log events that look like this situation.
  evidence?: (event: SignInEvent, homeCountry: string) => boolean;
}

// What a normal, low-risk sign-in looks like for each persona.
export const PERSONA_NORMAL: Record<SituationPersona, Omit<SignInContext, "user" | "location"> & { location: SituationContext["location"] }> = {
  globalAdmin: {
    target: { kind: "resource", resource: "Office365" },
    clientAppType: "browser",
    platform: "windows",
    device: "compliant",
    location: "home",
    signInRisk: "none",
    userRisk: "none",
    insiderRisk: "none",
  },
  user: {
    target: { kind: "resource", resource: "Office365" },
    clientAppType: "browser",
    platform: "windows",
    device: "compliant",
    location: "home",
    signInRisk: "none",
    userRisk: "none",
    insiderRisk: "none",
  },
  // A guest's device is never managed by this tenant.
  guest: {
    target: { kind: "resource", resource: "Office365" },
    clientAppType: "browser",
    platform: "windows",
    device: "unmanaged",
    location: "home",
    signInRisk: "none",
    userRisk: "none",
    insiderRisk: "none",
  },
};

const MODERN_CLIENTS = new Set(["browser", "mobile apps and desktop clients", "unknown", ""]);
const isLegacyClient = (e: SignInEvent) => !MODERN_CLIENTS.has((e.clientApp || "").toLowerCase());
const isForeign = (e: SignInEvent, home: string) => !!e.location?.country && e.location.country.toUpperCase() !== home.toUpperCase();
const isUnmanaged = (e: SignInEvent) => !e.deviceDetail?.isManaged && !e.deviceDetail?.isCompliant;
const isHighRisk = (e: SignInEvent) => e.riskLevel === "high";

const BLOCK_DEVICE_CODE =
  "Block the device code flow (and authentication transfer) for all users, excluding only accounts that genuinely need it (for example meeting-room devices). Microsoft's own \"Block device code flow\" policy template does this.";
const COMPLIANT_DEVICE_ADMINS = "Require a compliant or Microsoft Entra hybrid joined device for every administrator role, on all platforms.";

export const SIGNIN_SITUATIONS: SigninSituation[] = [
  // ------------------------------------------------------- Global Admin
  {
    id: "ga-unmanaged-known",
    persona: "globalAdmin",
    label: "Unmanaged device, known location",
    description: "An admin signs in from a personal or shared computer on the office network. A stolen admin password is enough if only location is trusted.",
    context: { device: "unmanaged", location: "trusted" },
    normal: { device: "compliant", location: "trusted" },
    desired: "block",
    baselineCode: "CA09",
    newPolicyDescription: COMPLIANT_DEVICE_ADMINS,
    evidence: (e) => isUnmanaged(e),
  },
  {
    id: "ga-foreign",
    persona: "globalAdmin",
    label: "Sign-in from a foreign country",
    description: "An admin account signs in from a country the organisation doesn't operate in - a classic sign of a stolen credential.",
    context: { location: "foreign" },
    normal: { location: "home" },
    desired: "block",
    baselineCode: "CA08",
    newPolicyDescription: "Block sign-ins from every country except the ones you operate in (a country named location excluded from an \"All locations\" block).",
    evidence: (e, home) => isForeign(e, home),
  },
  {
    id: "ga-hosting",
    persona: "globalAdmin",
    label: "Sign-in from a hosting-provider address",
    description: "An admin signs in from a cloud or VPS address in your own country - the way attackers blend in with local traffic.",
    context: { location: "untrustedIp" },
    normal: { location: "trusted" },
    desired: "phishingResistant",
    baselineCode: "CA10",
    newPolicyDescription: "Require phishing-resistant MFA for admin roles whenever they sign in from outside your trusted named locations.",
    caveat: "Conditional Access has no \"hosting provider\" condition. This is modelled as an address outside every trusted named location; Microsoft's anonymous-IP risk detection may also raise the sign-in risk, but the simulation doesn't assume it.",
  },
  {
    id: "ga-devicecode",
    persona: "globalAdmin",
    label: "Device-code flow",
    description: "An admin is tricked into entering a device code on microsoft.com/devicelogin, handing the attacker a token (device-code phishing).",
    context: { authenticationFlow: "deviceCodeFlow" },
    normal: {},
    desired: "block",
    newPolicyDescription: BLOCK_DEVICE_CODE,
  },
  {
    id: "ga-legacy",
    persona: "globalAdmin",
    label: "Legacy authentication client",
    description: "An admin account is used from an old protocol (IMAP, POP, SMTP AUTH) that can't do MFA - the main target of password spray.",
    context: { clientAppType: "other" },
    normal: {},
    desired: "block",
    baselineCode: "CA01",
    newPolicyDescription: "Block the \"Exchange ActiveSync\" and \"Other clients\" client app types for all users.",
    evidence: isLegacyClient,
  },
  {
    id: "ga-high-signin-risk",
    persona: "globalAdmin",
    label: "High sign-in risk",
    description: "Microsoft flags an admin sign-in as high risk (for example an unfamiliar location, a token anomaly or a password-spray pattern).",
    context: { signInRisk: "high" },
    normal: {},
    desired: "phishingResistant",
    baselineCode: "CA06",
    newPolicyDescription: "Require phishing-resistant MFA (or block) for admin roles when sign-in risk is medium or high.",
    evidence: isHighRisk,
  },
  {
    id: "ga-macos-unmanaged",
    persona: "globalAdmin",
    label: "Unmanaged macOS device",
    description: "An admin signs in from a Mac that isn't enrolled in Intune. Device policies are often scoped to Windows only.",
    context: { platform: "macOS", device: "unmanaged" },
    normal: { platform: "macOS", device: "compliant" },
    desired: "block",
    baselineCode: "CA09",
    newPolicyDescription: COMPLIANT_DEVICE_ADMINS,
  },
  {
    id: "ga-desktop-unmanaged",
    persona: "globalAdmin",
    label: "Desktop client, unmanaged device",
    description: "An admin uses Outlook or PowerShell on an unmanaged PC. Browser-only policies miss desktop and mobile apps.",
    context: { clientAppType: "mobileAppsAndDesktopClients", device: "unmanaged" },
    normal: { clientAppType: "mobileAppsAndDesktopClients", device: "compliant" },
    desired: "block",
    baselineCode: "CA09",
    newPolicyDescription: COMPLIANT_DEVICE_ADMINS,
  },

  // ------------------------------------------------------ Standard user
  {
    id: "user-unmanaged-browser",
    persona: "user",
    label: "Unmanaged device, browser",
    description: "A user opens Outlook on the web from a home or kiosk computer. MFA is the minimum; limited web access keeps files off the device.",
    context: { device: "unmanaged" },
    normal: { device: "compliant" },
    desired: "strongAuth",
    baselineCode: "CA02",
    newPolicyDescription: "Require MFA for all users on all resources, and consider app-enforced restrictions for browser sessions on unmanaged devices.",
    evidence: (e) => isUnmanaged(e) && (e.clientApp || "").toLowerCase() === "browser",
  },
  {
    id: "user-foreign",
    persona: "user",
    label: "Sign-in from a foreign country",
    description: "A user account signs in from a country the organisation doesn't operate in.",
    context: { location: "foreign" },
    normal: { location: "home" },
    desired: "block",
    baselineCode: "CA08",
    newPolicyDescription: "Block sign-ins from every country except the ones you operate in, with a separate exception group for approved travellers.",
    evidence: (e, home) => isForeign(e, home),
  },
  {
    id: "user-devicecode",
    persona: "user",
    label: "Device-code flow",
    description: "A user is phished into entering a device code, giving the attacker a token that already satisfies MFA.",
    context: { authenticationFlow: "deviceCodeFlow" },
    normal: {},
    desired: "block",
    newPolicyDescription: BLOCK_DEVICE_CODE,
  },
  {
    id: "user-eas",
    persona: "user",
    label: "Legacy Exchange ActiveSync",
    description: "A phone mail app connects with basic Exchange ActiveSync, bypassing MFA.",
    context: { clientAppType: "exchangeActiveSync", platform: "iOS" },
    normal: { platform: "iOS", clientAppType: "mobileAppsAndDesktopClients" },
    desired: "block",
    baselineCode: "CA01",
    newPolicyDescription: "Block the \"Exchange ActiveSync\" and \"Other clients\" client app types for all users.",
    evidence: (e) => /activesync/i.test(e.clientApp || ""),
  },
  {
    id: "user-other-legacy",
    persona: "user",
    label: "Other legacy client",
    description: "IMAP, POP or authenticated SMTP with a password only - the standard password-spray path.",
    context: { clientAppType: "other" },
    normal: {},
    desired: "block",
    baselineCode: "CA01",
    newPolicyDescription: "Block the \"Exchange ActiveSync\" and \"Other clients\" client app types for all users.",
    evidence: (e) => isLegacyClient(e) && !/activesync/i.test(e.clientApp || ""),
  },
  {
    id: "user-high-signin-risk",
    persona: "user",
    label: "High sign-in risk",
    description: "Microsoft flags the sign-in itself as high risk.",
    context: { signInRisk: "high" },
    normal: {},
    desired: "strongAuth",
    baselineCode: "CA06",
    newPolicyDescription: "Require MFA for all users when sign-in risk is medium or high.",
    evidence: isHighRisk,
  },
  {
    id: "user-high-user-risk",
    persona: "user",
    label: "High user risk",
    description: "Microsoft believes the account itself is compromised (for example leaked credentials).",
    context: { userRisk: "high" },
    normal: {},
    desired: "passwordChange",
    baselineCode: "CA07",
    newPolicyDescription: "Require MFA and a secure password change when user risk is high.",
  },
  {
    id: "user-insider-elevated",
    persona: "user",
    label: "Elevated insider risk",
    description: "Purview Insider Risk Management rates the user as elevated risk (for example mass downloads before resigning).",
    context: { insiderRisk: "elevated" },
    normal: {},
    desired: "block",
    newPolicyDescription: "Block access (or require terms of use) for users with elevated insider risk. Needs Microsoft Purview Insider Risk Management with Adaptive Protection.",
  },
  {
    id: "user-android-unmanaged",
    persona: "user",
    label: "Unmanaged Android device",
    description: "A user signs in from a personal Android phone. Company data should only open in app-protected apps.",
    context: { platform: "android", clientAppType: "mobileAppsAndDesktopClients", device: "unmanaged" },
    normal: { platform: "android", clientAppType: "mobileAppsAndDesktopClients", device: "compliant" },
    desired: "appProtection",
    baselineCode: "CA09",
    newPolicyDescription: "Require an approved client app with an app protection policy on iOS and Android.",
  },
  {
    id: "user-ios-unmanaged",
    persona: "user",
    label: "Unmanaged iOS device",
    description: "A user signs in from a personal iPhone or iPad.",
    context: { platform: "iOS", clientAppType: "mobileAppsAndDesktopClients", device: "unmanaged" },
    normal: { platform: "iOS", clientAppType: "mobileAppsAndDesktopClients", device: "compliant" },
    desired: "appProtection",
    baselineCode: "CA09",
    newPolicyDescription: "Require an approved client app with an app protection policy on iOS and Android.",
  },
  {
    id: "user-desktop-unmanaged",
    persona: "user",
    label: "Desktop client, unmanaged device",
    description: "A user syncs mail and files with desktop apps on a personal PC, copying company data to an unmanaged device.",
    context: { clientAppType: "mobileAppsAndDesktopClients", device: "unmanaged" },
    normal: { clientAppType: "mobileAppsAndDesktopClients", device: "compliant" },
    desired: "block",
    baselineCode: "CA09",
    newPolicyDescription: "Require a compliant or hybrid joined device for desktop and mobile apps (browser access can stay MFA-only).",
  },

  // -------------------------------------------------------------- Guest
  {
    id: "guest-browser-known",
    persona: "guest",
    label: "Browser access, known location",
    description: "A normal guest collaboration sign-in. This is a control case: it should be allowed, but only after MFA.",
    context: {},
    normal: {},
    desired: "strongAuth",
    goodPath: true,
    baselineCode: "CA04",
    newPolicyDescription: "Require MFA for guests and external users on all resources.",
  },
  {
    id: "guest-foreign",
    persona: "guest",
    label: "Sign-in from a foreign country",
    description: "A guest account signs in from a country none of your partners operate in.",
    context: { location: "foreign" },
    normal: { location: "home" },
    desired: "block",
    baselineCode: "CA08",
    newPolicyDescription: "Include guests in your country block, or block guests from countries you don't work with.",
    caveat: "Guests legitimately sign in from their own organisation's countries - check the allowed-country list covers your partners before blocking.",
  },
  {
    id: "guest-legacy",
    persona: "guest",
    label: "Legacy authentication client",
    description: "A guest account is used over a legacy protocol that can't do MFA.",
    context: { clientAppType: "other" },
    normal: {},
    desired: "block",
    baselineCode: "CA01",
    newPolicyDescription: "Block the \"Exchange ActiveSync\" and \"Other clients\" client app types for all users, including guests.",
  },
  {
    id: "guest-unmanaged-browser",
    persona: "guest",
    label: "Unmanaged device, browser",
    description: "A guest opens shared files in a browser on their own device.",
    context: {},
    normal: {},
    desired: "strongAuth",
    baselineCode: "CA04",
    newPolicyDescription: "Require MFA for guests and external users on all resources.",
  },
  {
    id: "guest-devicecode",
    persona: "guest",
    label: "Device-code flow",
    description: "A guest account is phished with a device code.",
    context: { authenticationFlow: "deviceCodeFlow" },
    normal: {},
    desired: "block",
    newPolicyDescription: BLOCK_DEVICE_CODE,
  },
  {
    id: "guest-high-signin-risk",
    persona: "guest",
    label: "High sign-in risk",
    description: "A guest's sign-in is risky in their own organisation.",
    context: { signInRisk: "high" },
    normal: {},
    desired: "strongAuth",
    baselineCode: "CA04",
    newPolicyDescription: "Require MFA for all guest access, since this tenant can't react to guest risk.",
    caveat: "Microsoft evaluates a guest's risk in the guest's home organisation, so this tenant's risk-based policies never apply to guests. Requiring MFA for every guest sign-in is the dependable control.",
  },
  {
    id: "guest-auth-transfer",
    persona: "guest",
    label: "Authentication transfer",
    description: "A guest session is transferred from a PC to a phone via QR code, which can move a session to an attacker's device.",
    context: { authenticationFlow: "authenticationTransfer" },
    normal: {},
    desired: "block",
    newPolicyDescription: "Block authentication transfer (in the same authentication flows policy that blocks device code flow).",
  },
];
