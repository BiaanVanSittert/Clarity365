import { describe, it, expect } from "vitest";
import { applyLicenseAwareStatus } from "./permission-license-check";
import type { PermissionTestResult } from "./graph-client";
import { TenantCapability } from "../types";

function makeResult(overrides: Partial<PermissionTestResult> = {}): PermissionTestResult {
  return {
    permission: "DeviceManagementManagedDevices.Read.All",
    scope: "Application",
    description: "",
    endpoint: "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1",
    status: "missing",
    requiredFor: "",
    ...overrides,
  };
}

function makeCapability(id: string, licensed: boolean): TenantCapability {
  return { id, name: "", category: "Endpoint", licensed, tier: "", description: "" };
}

describe("applyLicenseAwareStatus", () => {
  it("relabels a missing permission as unlicensed when the required capability is confirmed unlicensed", () => {
    const result = applyLicenseAwareStatus(makeResult(), [makeCapability("cap-intune", false)]);
    expect(result.status).toBe("unlicensed");
    expect(result.unlicensed).toBe(true);
    expect(result.errorMessage).toContain("Microsoft Intune");
    expect(result.errorMessage).toContain("will not fix this");
  });

  it("leaves a missing permission unchanged when the required capability IS licensed - a real consent gap, not a license gap", () => {
    const result = applyLicenseAwareStatus(makeResult(), [makeCapability("cap-intune", true)]);
    expect(result.status).toBe("missing");
    expect(result.unlicensed).toBeUndefined();
  });

  it("leaves a missing permission unchanged when the capability list has no matching entry at all (e.g. the SKU fetch itself failed)", () => {
    const result = applyLicenseAwareStatus(makeResult(), []);
    expect(result.status).toBe("missing");
  });

  it("does nothing to a permission with no known license dependency", () => {
    const result = applyLicenseAwareStatus(
      makeResult({ permission: "User.Read.All" }),
      [makeCapability("cap-intune", false)]
    );
    expect(result.status).toBe("missing");
  });

  it("never touches an already-granted result", () => {
    const result = applyLicenseAwareStatus(
      makeResult({ status: "granted" }),
      [makeCapability("cap-intune", false)]
    );
    expect(result.status).toBe("granted");
    expect(result.unlicensed).toBeUndefined();
  });

  it("covers every documented license-gated permission (ThreatHunting.Read.All, SecurityAlert.Read.All)", () => {
    const threatHunting = applyLicenseAwareStatus(
      makeResult({ permission: "ThreatHunting.Read.All" }),
      [makeCapability("cap-mde", false)]
    );
    expect(threatHunting.status).toBe("unlicensed");
    expect(threatHunting.errorMessage).toContain("Defender for Endpoint");

    const securityAlert = applyLicenseAwareStatus(
      makeResult({ permission: "SecurityAlert.Read.All" }),
      [makeCapability("cap-mdo", false)]
    );
    expect(securityAlert.status).toBe("unlicensed");
    expect(securityAlert.errorMessage).toContain("Defender for Office 365");
  });
});
