import { describe, expect, it } from "vitest";
import { AUDIT_CONFIG_OPERATIONS, USER_DELETION_OPERATIONS, describeAlertTrigger, findAlertCoverage, mapAlertPolicy } from "./alert-policy-mapper";
import { AlertPolicyInventory } from "../types";

// Shapes as Get-ProtectionAlert returned them live (2026-10-02).
const raw = (overrides: object = {}) => ({
  Name: "Audit logging changed",
  Category: "ThreatManagement",
  ThreatType: "Activity",
  Operation: ["Set-AdminAuditLogConfig"],
  Disabled: false,
  IsSystemRule: false,
  Severity: "High",
  NotifyUser: ["secops@contoso.com"],
  NotificationEnabled: true,
  AggregationType: "None",
  Threshold: null,
  TimeWindow: null,
  ...overrides,
});
const inventory = (...policies: object[]): AlertPolicyInventory => ({ policies: policies.map(mapAlertPolicy), checkedAt: "2026-10-02T00:00:00Z" });

describe("mapAlertPolicy", () => {
  it("keeps what the checks need and only counts the recipients", () => {
    const p = mapAlertPolicy(raw());
    expect(p).toEqual({
      name: "Audit logging changed",
      operations: ["Set-AdminAuditLogConfig"],
      disabled: false,
      isSystemRule: false,
      notifyRecipients: 1,
      notificationEnabled: true,
      aggregation: "None",
      threshold: undefined,
      timeWindowMinutes: undefined,
      severity: "High",
      category: "ThreatManagement",
    });
    expect(JSON.stringify(p)).not.toContain("secops@");
  });

  it("handles Microsoft's malware-type policies, which have no Operation", () => {
    expect(mapAlertPolicy(raw({ Operation: null, ThreatType: "Malware", IsSystemRule: true })).operations).toEqual([]);
    expect(mapAlertPolicy({}).name).toBe("Unnamed alert policy");
  });
});

describe("findAlertCoverage", () => {
  it("finds an enabled policy that emails someone", () => {
    const c = findAlertCoverage(inventory(raw()), AUDIT_CONFIG_OPERATIONS);
    expect(c.state).toBe("alerting");
    expect(c.policies.map((p) => p.name)).toEqual(["Audit logging changed"]);
  });

  it("matches on the watched activity, never on the policy's name", () => {
    const misleading = raw({ Name: "Audit logging changed", Operation: ["MailRedirect"] });
    expect(findAlertCoverage(inventory(misleading), AUDIT_CONFIG_OPERATIONS).state).toBe("none");
  });

  it("ignores case, spacing and the trailing full stop Entra activities carry", () => {
    expect(findAlertCoverage(inventory(raw({ Operation: ["Delete user."] })), USER_DELETION_OPERATIONS).state).toBe("alerting");
    expect(findAlertCoverage(inventory(raw({ Operation: [" delete USER "] })), USER_DELETION_OPERATIONS).state).toBe("alerting");
    expect(findAlertCoverage(inventory(raw({ Operation: ["Delete user from group."] })), USER_DELETION_OPERATIONS).state).toBe("none");
  });

  it("says when the alert is raised but nobody is emailed", () => {
    expect(findAlertCoverage(inventory(raw({ NotifyUser: [] })), AUDIT_CONFIG_OPERATIONS).state).toBe("raisedNotEmailed");
    expect(findAlertCoverage(inventory(raw({ NotificationEnabled: false })), AUDIT_CONFIG_OPERATIONS).state).toBe("raisedNotEmailed");
  });

  it("says when the only matching policy is turned off", () => {
    expect(findAlertCoverage(inventory(raw({ Disabled: true })), AUDIT_CONFIG_OPERATIONS).state).toBe("disabledOnly");
    // An enabled one elsewhere wins.
    expect(findAlertCoverage(inventory(raw({ Disabled: true }), raw({ Name: "Second" })), AUDIT_CONFIG_OPERATIONS).policies.map((p) => p.name)).toEqual(["Second"]);
  });

  it("reports none when policies were read and nothing matches", () => {
    const microsoftDefaults = [raw({ Name: "Creation of forwarding/redirect rule", Operation: ["MailRedirect"], IsSystemRule: true }), raw({ Name: "Elevation of Exchange admin privilege", Operation: ["GrantAdminPermission"], IsSystemRule: true })];
    expect(findAlertCoverage(inventory(...microsoftDefaults), AUDIT_CONFIG_OPERATIONS)).toEqual({ state: "none", policies: [] });
  });

  it("is unknown, not none, when alert policies couldn't be read", () => {
    expect(findAlertCoverage(undefined, AUDIT_CONFIG_OPERATIONS).state).toBe("unknown");
    expect(findAlertCoverage({ policies: [], unavailable: "notSetUp", checkedAt: "" }, AUDIT_CONFIG_OPERATIONS).state).toBe("unknown");
    expect(findAlertCoverage({ policies: [], unavailable: "error", checkedAt: "" }, AUDIT_CONFIG_OPERATIONS).state).toBe("unknown");
  });
});

describe("describeAlertTrigger", () => {
  it("describes aggregated policies and stays quiet for per-event ones", () => {
    expect(describeAlertTrigger(mapAlertPolicy(raw({ AggregationType: "SimpleAggregation", Threshold: 5, TimeWindow: 60 })))).toBe("more than 5 in 60 minutes");
    expect(describeAlertTrigger(mapAlertPolicy(raw({ AggregationType: "AnomalousAggregation" })))).toBe("unusual volume");
    expect(describeAlertTrigger(mapAlertPolicy(raw()))).toBe("");
  });
});
