import { describe, it, expect } from "vitest";
import { classifyRegisteredMethods, pickDefaultMethod, classifyUserAuthMethods } from "./mfa-classifier";

describe("classifyRegisteredMethods", () => {
  it("maps known Graph method strings to their AuthMethodType bucket", () => {
    expect(classifyRegisteredMethods(["fido2SecurityKey"])).toEqual(["passkey_fido2"]);
    expect(classifyRegisteredMethods(["microsoftAuthenticatorPush"])).toEqual(["ms_authenticator_push"]);
    expect(classifyRegisteredMethods(["softwareOneTimePasscode"])).toEqual(["ms_authenticator_totp"]);
    expect(classifyRegisteredMethods(["mobilePhone"])).toEqual(["sms"]);
    expect(classifyRegisteredMethods(["alternateVoiceCall"])).toEqual(["voice_call"]);
    expect(classifyRegisteredMethods(["email"])).toEqual(["email_otp"]);
    expect(classifyRegisteredMethods(["temporaryAppPassword"])).toEqual(["app_password"]);
  });

  it("is case-insensitive", () => {
    expect(classifyRegisteredMethods(["FIDO2SecurityKey"])).toEqual(["passkey_fido2"]);
  });

  it("drops unrecognized method strings rather than misclassifying them", () => {
    // e.g. Windows Hello for Business isn't part of Clarity365's taxonomy yet —
    // it's silently excluded rather than being guessed into the wrong bucket.
    expect(classifyRegisteredMethods(["windowsHelloForBusiness", "temporaryAccessPass"])).toEqual([]);
  });

  it("returns an empty array for missing/empty input", () => {
    expect(classifyRegisteredMethods(undefined)).toEqual([]);
    expect(classifyRegisteredMethods(null)).toEqual([]);
    expect(classifyRegisteredMethods([])).toEqual([]);
  });

  it("preserves multiple distinct registered methods", () => {
    expect(classifyRegisteredMethods(["fido2SecurityKey", "mobilePhone"])).toEqual(["passkey_fido2", "sms"]);
  });
});

describe("pickDefaultMethod", () => {
  it("picks the strongest method regardless of array order", () => {
    expect(pickDefaultMethod(["sms", "passkey_fido2", "ms_authenticator_push"])).toBe("passkey_fido2");
    expect(pickDefaultMethod(["app_password", "ms_authenticator_totp"])).toBe("ms_authenticator_totp");
  });

  it("returns 'none' for an empty method list", () => {
    expect(pickDefaultMethod([])).toBe("none");
  });

  it("returns the only method when just one is registered", () => {
    expect(pickDefaultMethod(["app_password"])).toBe("app_password");
  });
});

describe("classifyUserAuthMethods", () => {
  it("classifies a user with no MFA registration at all as none/weak", () => {
    const result = classifyUserAuthMethods([], false);
    expect(result).toEqual({
      registeredMethods: [],
      defaultMethod: "none",
      mfaRegistered: false,
      isWeakAuth: true,
      authStrength: "none",
    });
  });

  it("classifies a passkey user as phishing-resistant and not weak", () => {
    const result = classifyUserAuthMethods(["fido2SecurityKey"], true);
    expect(result.defaultMethod).toBe("passkey_fido2");
    expect(result.mfaRegistered).toBe(true);
    expect(result.isWeakAuth).toBe(false);
    expect(result.authStrength).toBe("phishing_resistant");
  });

  it("classifies a Microsoft Authenticator push user as strong and not weak", () => {
    const result = classifyUserAuthMethods(["microsoftAuthenticatorPush"], true);
    expect(result.isWeakAuth).toBe(false);
    expect(result.authStrength).toBe("strong");
  });

  it("classifies an SMS-only user as weak on both fields", () => {
    const result = classifyUserAuthMethods(["mobilePhone"], true);
    expect(result.mfaRegistered).toBe(true);
    expect(result.isWeakAuth).toBe(true);
    expect(result.authStrength).toBe("weak");
  });

  it("picks the strongest method when a user has both a weak and a strong method registered", () => {
    const result = classifyUserAuthMethods(["mobilePhone", "fido2SecurityKey"], true);
    expect(result.defaultMethod).toBe("passkey_fido2");
    expect(result.isWeakAuth).toBe(false);
    expect(result.authStrength).toBe("phishing_resistant");
  });

  it("trusts Graph's isMfaRegistered flag even when no method string was classified", () => {
    // Graph can report a user as MFA-registered via a method outside Clarity365's
    // taxonomy (e.g. Windows Hello). mfaRegistered follows the flag, but since no
    // concrete method was recognized, defaultMethod stays "none" — which is itself
    // a "weak" bucket, so isWeakAuth is still true despite mfaRegistered being true.
    const result = classifyUserAuthMethods(["windowsHelloForBusiness"], true);
    expect(result.mfaRegistered).toBe(true);
    expect(result.defaultMethod).toBe("none");
    expect(result.isWeakAuth).toBe(true);
    expect(result.authStrength).toBe("weak");
  });
});
