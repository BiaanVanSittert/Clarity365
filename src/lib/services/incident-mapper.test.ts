import { describe, it, expect } from "vitest";
import { mapSecurityIncident, synthesizeIncidentsFromMdoAlerts, extractMitreTechniques } from "./incident-mapper";
import { MdoThreatAlert } from "../types";

describe("incident-mapper", () => {
  it("correctly maps a full Defender XDR incident with users, devices, and MITRE techniques", () => {
    const raw = {
      id: "inc-12345",
      incidentId: "12345",
      displayName: "Suspicious inbox forwarding rule and mass email exfiltration",
      severity: "high",
      status: "active",
      classification: "truePositive",
      createdDateTime: "2024-05-10T14:30:00Z",
      alerts: [
        {
          id: "alt-01",
          category: "Phishing",
          mitreTechniques: ["T1566: Phishing"],
          userStates: [
            { aadUserId: "u-01", userPrincipalName: "adele.vance@contoso.com", displayName: "Adele Vance" },
          ],
          deviceStates: [
            { deviceId: "dev-01", netBiosName: "ADELE-LAPTOP", osPlatform: "Windows 11" },
          ],
        },
      ],
      description: "User received phishing email and automated inbox rule created forwarding externally.",
    };

    const incident = mapSecurityIncident(raw);

    expect(incident.incidentId).toBe("12345");
    expect(incident.displayName).toBe("Suspicious inbox forwarding rule and mass email exfiltration");
    expect(incident.severity).toBe("high");
    expect(incident.status).toBe("active");
    expect(incident.impactedUsers.length).toBe(1);
    expect(incident.impactedUsers[0].userPrincipalName).toBe("adele.vance@contoso.com");
    expect(incident.impactedDevices.length).toBe(1);
    expect(incident.impactedDevices[0].deviceName).toBe("ADELE-LAPTOP");
    expect(incident.mitreTechniques).toContain("T1566: Phishing");
    expect(incident.mitreTechniques).toContain("T1114: Email Collection");
    expect(incident.recommendedActions.length).toBeGreaterThan(0);
  });

  it("extracts MITRE techniques using keyword heuristics when explicit techniques are absent", () => {
    const techniques = extractMitreTechniques({
      title: "Malicious PowerShell command execution detected via script interpreter",
      description: "Host ADELE-PC executed encoded PowerShell script",
    });

    expect(techniques).toContain("T1059: Command & Scripting");
  });

  it("synthesizes incidents from MdoThreatAlerts cleanly", () => {
    const alerts: MdoThreatAlert[] = [
      {
        id: "alert-1",
        title: "Malicious URL clicked in inbound email",
        severity: "high",
        status: "new",
        classification: "unknown",
        category: "Phishing",
        createdDateTime: "2024-05-10T12:00:00Z",
        description: "User clicked suspicious link",
        affectedUsers: ["megan.bowen@contoso.com"],
      },
    ];

    const incidents = synthesizeIncidentsFromMdoAlerts(alerts);
    expect(incidents.length).toBe(1);
    expect(incidents[0].displayName).toBe("Malicious URL clicked in inbound email");
    expect(incidents[0].impactedUsers[0].userPrincipalName).toBe("megan.bowen@contoso.com");
    expect(incidents[0].mitreTechniques).toContain("T1566: Phishing");
  });
});
