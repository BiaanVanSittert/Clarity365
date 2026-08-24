import { AuthMethodType } from "../types";

// Classifies a user's MFA registration into Clarity365's method/strength taxonomy.
// Pulled out of graph-client.ts's inline mapping so the classification rules
// themselves — which method strings count as which method, which methods are
// "weak", how default method and overall strength are picked — are unit-testable
// without needing a live Graph response to drive them.

const METHOD_KEYWORD_RULES: [pattern: (lower: string) => boolean, method: AuthMethodType][] = [
  [(l) => l.includes("fido") || l.includes("passkey") || l.includes("securitykey"), "passkey_fido2"],
  [(l) => l.includes("push") || l.includes("authenticatorpush"), "ms_authenticator_push"],
  [(l) => l.includes("softwareonetime") || l.includes("totp") || l.includes("authenticator"), "ms_authenticator_totp"],
  [(l) => l.includes("phone") || l.includes("sms") || l.includes("mobile"), "sms"],
  [(l) => l.includes("voice"), "voice_call"],
  [(l) => l.includes("email"), "email_otp"],
  [(l) => l.includes("password"), "app_password"],
];

export function classifyRegisteredMethods(methodsRegistered: string[] | undefined | null): AuthMethodType[] {
  const registeredMethods: AuthMethodType[] = [];
  if (methodsRegistered && Array.isArray(methodsRegistered)) {
    methodsRegistered.forEach((m) => {
      const lower = m.toLowerCase();
      const match = METHOD_KEYWORD_RULES.find(([pattern]) => pattern(lower));
      if (match) registeredMethods.push(match[1]);
    });
  }
  return registeredMethods;
}

// Best-registered-method wins, in descending order of authentication strength.
const METHOD_PRIORITY: AuthMethodType[] = [
  "passkey_fido2",
  "ms_authenticator_push",
  "ms_authenticator_totp",
  "sms",
  "voice_call",
  "email_otp",
  "app_password",
];

export function pickDefaultMethod(registeredMethods: AuthMethodType[]): AuthMethodType {
  return METHOD_PRIORITY.find((m) => registeredMethods.includes(m)) || "none";
}

export type AuthStrength = "phishing_resistant" | "strong" | "weak" | "none";

const WEAK_METHODS = new Set<AuthMethodType>(["sms", "voice_call", "email_otp", "app_password", "none"]);

export interface ClassifiedMfaProfile {
  registeredMethods: AuthMethodType[];
  defaultMethod: AuthMethodType;
  mfaRegistered: boolean;
  isWeakAuth: boolean;
  authStrength: AuthStrength;
}

/**
 * `methodsRegistered` is the raw `methodsRegistered` array from Graph's
 * userRegistrationDetails; `isMfaRegisteredFlag` is that same record's
 * `isMfaRegistered` boolean (Graph can report a user as MFA-registered via a
 * method that doesn't appear in `methodsRegistered`, so both signals matter).
 */
export function classifyUserAuthMethods(
  methodsRegistered: string[] | undefined | null,
  isMfaRegisteredFlag: boolean
): ClassifiedMfaProfile {
  const registeredMethods = classifyRegisteredMethods(methodsRegistered);
  const defaultMethod = pickDefaultMethod(registeredMethods);
  const mfaRegistered = isMfaRegisteredFlag || registeredMethods.length > 0;
  const isWeakAuth = !mfaRegistered || WEAK_METHODS.has(defaultMethod);

  let authStrength: AuthStrength = "none";
  if (defaultMethod === "passkey_fido2") authStrength = "phishing_resistant";
  else if (defaultMethod === "ms_authenticator_push" || defaultMethod === "ms_authenticator_totp") authStrength = "strong";
  else if (mfaRegistered) authStrength = "weak";

  return { registeredMethods, defaultMethod, mfaRegistered, isWeakAuth, authStrength };
}
