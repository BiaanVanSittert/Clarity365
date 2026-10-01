import { SignInAuthentication } from "../types";

// How a sign-in was authenticated, from Microsoft Graph's BETA sign-in
// resource (authenticationRequirement + authenticationDetails; v1.0 has
// neither - confirmed on Microsoft Learn and live, 2026-10-01). Returns
// undefined when the fields aren't there, so "not reported" is never read as
// "single factor".
//
// Real values seen live: authenticationMethod is "Password", "Mobile app
// notification", ... or "Previously satisfied" (the factor came from an
// existing session - "... satisfied by claim in the token"). Most sign-ins are
// the latter. authenticationMethodDetail (phone numbers, device names) is
// deliberately not kept.

const FROM_SESSION_METHODS = new Set(["previously satisfied", "satisfied by token"]);

export function mapSignInAuthentication(raw: any): SignInAuthentication | undefined {
  const requirement = raw?.authenticationRequirement;
  if (requirement !== "singleFactorAuthentication" && requirement !== "multiFactorAuthentication") return undefined;

  const steps: any[] = Array.isArray(raw.authenticationDetails) ? raw.authenticationDetails : [];
  const methods: string[] = [];
  let sessionSteps = 0;
  for (const step of steps) {
    const method = typeof step?.authenticationMethod === "string" ? step.authenticationMethod.trim() : "";
    if (!method || step.succeeded === false) continue;
    if (FROM_SESSION_METHODS.has(method.toLowerCase())) sessionSteps++;
    else if (!methods.includes(method)) methods.push(method);
  }
  return {
    requirement: requirement === "multiFactorAuthentication" ? "multiFactor" : "singleFactor",
    methods,
    fromExistingSession: methods.length === 0 && sessionSteps > 0,
  };
}

// The second factor actually presented, if any (everything except the password).
export function mfaMethodsOf(auth: SignInAuthentication | undefined): string[] {
  return (auth?.methods || []).filter((m) => m.toLowerCase() !== "password");
}

// One label per sign-in for grouping and display.
export function describeSignInAuthentication(auth: SignInAuthentication | undefined): string {
  if (!auth) return "Not reported";
  const second = mfaMethodsOf(auth);
  if (auth.requirement === "multiFactor") {
    if (second.length > 0) return `MFA: ${second.join(" + ")}`;
    return auth.fromExistingSession ? "MFA (already done in this session)" : "MFA (method not reported)";
  }
  if (auth.methods.length > 0) return `No MFA required: ${auth.methods.join(" + ")}`;
  return auth.fromExistingSession ? "No MFA required (existing session)" : "No MFA required";
}
