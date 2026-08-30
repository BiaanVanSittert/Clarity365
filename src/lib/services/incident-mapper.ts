import { SecurityIncidentItem, IncidentSeverity, IncidentStatus, IncidentImpactedUser, IncidentImpactedDevice, MdoThreatAlert } from "../types";

export function mapSeverity(val?: string): IncidentSeverity {
  const s = (val || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "informational";
}

export function mapStatus(val?: string): IncidentStatus {
  const s = (val || "").toLowerCase();
  if (s === "inprogress" || s === "in_progress" || s === "investigating") return "inProgress";
  if (s === "resolved" || s === "closed") return "resolved";
  if (s === "redirected") return "redirected";
  return "active";
}

export function extractMitreTechniques(raw: any): string[] {
  const techniques = new Set<string>();

  if (Array.isArray(raw.mitreTechniques)) {
    raw.mitreTechniques.forEach((t: string) => techniques.add(t));
  }

  if (raw.category && typeof raw.category === "string") {
    const cat = raw.category.toLowerCase();
    if (cat.includes("phish")) techniques.add("T1566: Phishing");
    if (cat.includes("malware")) techniques.add("T1204: User Execution");
    if (cat.includes("credential") || cat.includes("bruteforce")) techniques.add("T1110: Brute Force");
  }

  // Inspect alerts collection if present
  if (Array.isArray(raw.alerts)) {
    raw.alerts.forEach((alert: any) => {
      if (Array.isArray(alert.mitreTechniques)) {
        alert.mitreTechniques.forEach((t: string) => techniques.add(t));
      }
      if (alert.category) {
        if (alert.category.toLowerCase().includes("phish")) techniques.add("T1566: Phishing");
        if (alert.category.toLowerCase().includes("malware")) techniques.add("T1204: User Execution");
        if (alert.category.toLowerCase().includes("credential") || alert.category.toLowerCase().includes("bruteforce")) {
          techniques.add("T1110: Brute Force");
        }
      }
    });
  }

  // Keyword heuristic matching from title/description
  const text = `${raw.displayName || raw.title || ""} ${raw.description || ""}`.toLowerCase();
  if (text.includes("phish")) techniques.add("T1566: Phishing");
  if (text.includes("forwarding") || text.includes("inbox rule") || text.includes("bec")) {
    techniques.add("T1114: Email Collection");
    techniques.add("T1098: Account Manipulation");
  }
  if (text.includes("token") || text.includes("replay") || text.includes("stolen")) {
    techniques.add("T1528: Steal Application Access Token");
  }
  if (text.includes("powershell") || text.includes("script") || text.includes("command")) {
    techniques.add("T1059: Command & Scripting");
  }
  if (text.includes("brute force") || text.includes("spray") || text.includes("credential stuffing")) {
    techniques.add("T1110: Brute Force");
  }
  if (text.includes("oauth") || text.includes("consent") || text.includes("app registration")) {
    techniques.add("T1528: Steal Application Access Token");
  }
  if (text.includes("impossible travel") || text.includes("atypical")) {
    techniques.add("T1078: Valid Accounts");
  }

  return Array.from(techniques);
}

export function extractImpactedEntities(raw: any): { users: IncidentImpactedUser[]; devices: IncidentImpactedDevice[] } {
  const userMap = new Map<string, IncidentImpactedUser>();
  const deviceMap = new Map<string, IncidentImpactedDevice>();

  // Direct fields
  if (Array.isArray(raw.impactedUsers)) {
    raw.impactedUsers.forEach((u: any) => {
      const upn = u.userPrincipalName || u.upn || u.id;
      if (upn) userMap.set(upn.toLowerCase(), { id: u.id, userPrincipalName: upn, displayName: u.displayName || upn });
    });
  }

  if (Array.isArray(raw.impactedDevices)) {
    raw.impactedDevices.forEach((d: any) => {
      const name = d.deviceName || d.name || d.id;
      if (name) deviceMap.set(name.toLowerCase(), { id: d.id, deviceName: name, operatingSystem: d.operatingSystem, isIsolated: !!d.isIsolated });
    });
  }

  // Parse nested alerts
  if (Array.isArray(raw.alerts)) {
    raw.alerts.forEach((alert: any) => {
      if (Array.isArray(alert.userStates)) {
        alert.userStates.forEach((us: any) => {
          const upn = us.userPrincipalName || us.upn;
          if (upn && !userMap.has(upn.toLowerCase())) {
            userMap.set(upn.toLowerCase(), { id: us.aadUserId, userPrincipalName: upn, displayName: us.displayName || upn });
          }
        });
      }
      if (Array.isArray(alert.deviceStates)) {
        alert.deviceStates.forEach((ds: any) => {
          const name = ds.netBiosName || ds.deviceName || ds.id;
          if (name && !deviceMap.has(name.toLowerCase())) {
            deviceMap.set(name.toLowerCase(), { id: ds.deviceId, deviceName: name, operatingSystem: ds.osPlatform });
          }
        });
      }
    });
  }

  return {
    users: Array.from(userMap.values()),
    devices: Array.from(deviceMap.values()),
  };
}

export function generateRecommendedActions(title: string, severity: IncidentSeverity, users: IncidentImpactedUser[], devices: IncidentImpactedDevice[]): string[] {
  const actions: string[] = [];
  const lower = title.toLowerCase();

  if (users.length > 0) {
    if (lower.includes("phish") || lower.includes("forwarding") || lower.includes("bec") || lower.includes("credential") || severity === "critical" || severity === "high") {
      actions.push("Revoke active user session tokens & refresh tokens across all applications.");
      actions.push("Enforce immediate password reset and require MFA re-authentication.");
      actions.push("Audit and remove malicious inbox forwarding rules or delegate permissions.");
    }
  }

  if (devices.length > 0) {
    if (lower.includes("malware") || lower.includes("powershell") || lower.includes("ransomware") || lower.includes("c2") || severity === "critical" || severity === "high") {
      actions.push("Isolate affected endpoints from the network using Defender for Endpoint.");
      actions.push("Trigger an on-demand Defender Antivirus Full Scan on the compromised machines.");
      actions.push("Review active persistence mechanisms and scheduled tasks.");
    }
  }

  if (actions.length === 0) {
    actions.push("Review sign-in logs and user activity for anomalous authentication attempts.");
    actions.push("Investigate related security alerts and mark incident as Resolved once validated.");
  }

  return actions;
}

export function mapSecurityIncident(raw: any): SecurityIncidentItem {
  const { users, devices } = extractImpactedEntities(raw);
  const severity = mapSeverity(raw.severity);
  const status = mapStatus(raw.status);
  const mitreTechniques = extractMitreTechniques(raw);
  const title = raw.displayName || raw.title || "Unclassified Security Incident";

  const recommendedActions =
    Array.isArray(raw.recommendedActions) && raw.recommendedActions.length > 0
      ? raw.recommendedActions
      : generateRecommendedActions(title, severity, users, devices);

  return {
    id: raw.id || raw.incidentId || `inc-${Date.now()}`,
    incidentId: String(raw.incidentId || raw.id || "INC-001"),
    displayName: title,
    severity,
    status,
    classification: raw.classification || "unknown",
    determination: raw.determination,
    createdDateTime: raw.createdDateTime || new Date().toISOString(),
    lastUpdateDateTime: raw.lastUpdateDateTime || raw.createdDateTime || new Date().toISOString(),
    assignedTo: raw.assignedTo,
    mitreTechniques,
    alertsCount: Array.isArray(raw.alerts) ? raw.alerts.length : (raw.alertsCount || 1),
    impactedUsers: users,
    impactedDevices: devices,
    description: raw.description || `Security incident detected with ${users.length} affected user(s) and ${devices.length} endpoint(s).`,
    recommendedActions,
    commentsCount: Array.isArray(raw.comments) ? raw.comments.length : (raw.commentsCount || 0),
  };
}

export function synthesizeIncidentsFromMdoAlerts(alerts: MdoThreatAlert[]): SecurityIncidentItem[] {
  return alerts.map((alert, idx) => {
    const severity = mapSeverity(alert.severity);
    const status = alert.status === "resolved" ? "resolved" : alert.status === "inProgress" ? "inProgress" : "active";
    const users: IncidentImpactedUser[] = (alert.affectedUsers || []).map((u) => ({
      userPrincipalName: u,
      displayName: u.split("@")[0],
    }));

    return {
      id: `syn-${alert.id || idx}`,
      incidentId: `INC-MDO-${1000 + idx}`,
      displayName: alert.title,
      severity,
      status,
      classification: alert.classification,
      createdDateTime: alert.createdDateTime,
      lastUpdateDateTime: alert.createdDateTime,
      mitreTechniques: extractMitreTechniques({ title: alert.title, category: alert.category, description: alert.description }),
      alertsCount: 1,
      impactedUsers: users,
      impactedDevices: [],
      description: alert.description || `Email threat protection alert: ${alert.title}`,
      recommendedActions: generateRecommendedActions(alert.title, severity, users, []),
    };
  });
}
