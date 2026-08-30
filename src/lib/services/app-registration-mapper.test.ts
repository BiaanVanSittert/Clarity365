import { describe, it, expect } from "vitest";
import { mapAppRegistration } from "./app-registration-mapper";

describe("app-registration-mapper", () => {
  it("correctly maps a standard Microsoft Graph application with expiring secrets and high privilege scopes", () => {
    const raw = {
      id: "app-test-1",
      appId: "c1827409-a1b2-4c3d-8e9f-0123456789ab",
      displayName: "Security Automation Daemon",
      publisherDomain: "securitycorp.com",
      signInAudience: "AzureADMultipleOrgs",
      createdDateTime: "2024-01-01T00:00:00Z",
      passwordCredentials: [
        { keyId: "pwd-1", endDateTime: new Date(Date.now() + 5 * 86_400_000).toISOString() },
        { keyId: "pwd-2", endDateTime: new Date(Date.now() + 365 * 86_400_000).toISOString() },
      ],
      keyCredentials: [],
      requiredResourceAccess: [
        {
          resourceAppId: "00000003-0000-0000-c000-000000000000",
          resourceAccess: [
            { id: "19dbc75e-c2e2-444c-a770-ec69d8559fc7", type: "Role" }, // Directory.ReadWrite.All
            { id: "7ab1d382-f21e-4acd-a863-ba3e13f7da61", type: "Role" }, // Directory.Read.All
          ],
        },
      ],
    };

    const item = mapAppRegistration(raw);
    expect(item.displayName).toBe("Security Automation Daemon");
    expect(item.secretsCount).toBe(2);
    expect(item.certificatesCount).toBe(0);
    expect(item.expiringCredentialsCount).toBe(1);
    expect(item.isMultiTenant).toBe(true);
    expect(item.highPrivilegePermissions).toContain("Directory.ReadWrite.All");
    expect(item.riskCategory).toBe("critical");
  });

  it("classifies low risk application with no secrets or high privilege permissions", () => {
    const raw = {
      id: "app-test-2",
      appId: "98271039-4455-6677-8899-001122334455",
      displayName: "Internal Read Only Tool",
      publisherDomain: "contoso.onmicrosoft.com",
      signInAudience: "AzureADMyOrg",
      passwordCredentials: [],
      keyCredentials: [],
      requiredResourceAccess: [
        {
          resourceAppId: "00000003-0000-0000-c000-000000000000",
          resourceAccess: [
            { id: "df021288-bdef-4463-88db-d42042e6e8c4", type: "Scope" }, // User.Read.All
          ],
        },
      ],
    };

    const item = mapAppRegistration(raw);
    expect(item.secretsCount).toBe(0);
    expect(item.expiringCredentialsCount).toBe(0);
    expect(item.highPrivilegePermissions.length).toBe(0);
    expect(item.riskCategory).toBe("low");
  });
});
