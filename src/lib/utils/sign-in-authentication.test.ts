import { describe, expect, it } from "vitest";
import { describeSignInAuthentication, mapSignInAuthentication, mfaMethodsOf } from "./sign-in-authentication";

// Shapes below are the ones a live beta read returned on 2026-10-01.
const step = (authenticationMethod: string, succeeded = true) => ({ authenticationMethod, succeeded, authenticationMethodDetail: "+27 XXXXXXX12" });

describe("mapSignInAuthentication", () => {
  it("returns undefined for a v1.0 record, which has no authentication fields", () => {
    expect(mapSignInAuthentication({ id: "1", status: { errorCode: 0 } })).toBeUndefined();
    expect(mapSignInAuthentication(undefined)).toBeUndefined();
  });

  it("keeps the methods presented and drops details like phone numbers", () => {
    const auth = mapSignInAuthentication({ authenticationRequirement: "multiFactorAuthentication", authenticationDetails: [step("Password"), step("Mobile app notification")] });
    expect(auth).toEqual({ requirement: "multiFactor", methods: ["Password", "Mobile app notification"], fromExistingSession: false });
    expect(JSON.stringify(auth)).not.toContain("+27");
  });

  it("recognises factors that came from an existing session", () => {
    const auth = mapSignInAuthentication({ authenticationRequirement: "multiFactorAuthentication", authenticationDetails: [step("Previously satisfied"), step("Previously satisfied")] });
    expect(auth).toEqual({ requirement: "multiFactor", methods: [], fromExistingSession: true });
  });

  it("ignores failed steps and handles a record with no steps", () => {
    expect(mapSignInAuthentication({ authenticationRequirement: "singleFactorAuthentication", authenticationDetails: [step("Password", false)] })).toEqual({
      requirement: "singleFactor",
      methods: [],
      fromExistingSession: false,
    });
    expect(mapSignInAuthentication({ authenticationRequirement: "singleFactorAuthentication" })).toEqual({ requirement: "singleFactor", methods: [], fromExistingSession: false });
  });
});

describe("describeSignInAuthentication", () => {
  it("labels each case in plain words", () => {
    expect(describeSignInAuthentication(undefined)).toBe("Not reported");
    expect(describeSignInAuthentication({ requirement: "multiFactor", methods: ["Password", "Mobile app notification"], fromExistingSession: false })).toBe("MFA: Mobile app notification");
    expect(describeSignInAuthentication({ requirement: "multiFactor", methods: [], fromExistingSession: true })).toBe("MFA (already done in this session)");
    expect(describeSignInAuthentication({ requirement: "singleFactor", methods: ["Password"], fromExistingSession: false })).toBe("No MFA required: Password");
    expect(describeSignInAuthentication({ requirement: "singleFactor", methods: [], fromExistingSession: true })).toBe("No MFA required (existing session)");
  });

  it("never counts the password as a second factor", () => {
    expect(mfaMethodsOf({ requirement: "multiFactor", methods: ["Password", "SMS"], fromExistingSession: false })).toEqual(["SMS"]);
  });
});
