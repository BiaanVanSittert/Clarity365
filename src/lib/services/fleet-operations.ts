import { tenantStore } from "./tenant-store";
import {
  FleetBulkDeployRequest,
  FleetBulkDeployResult,
  FleetBulkDeployTenantResult,
  FleetTablEntry,
  CAPolicyRule,
} from "../types";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { evaluateTenantDrift, realignFindingLocally } from "./drift-analyzer";

/**
 * In-memory / mock fleet TABL threat blocklist entries.
 * Seeded with standard threat intelligence indicators.
 */
let SEEDED_FLEET_TABL: FleetTablEntry[] = [
  {
    id: "tabl-threat-01",
    type: "domain",
    value: "phish-identity-m365-verify.com",
    action: "block",
    reason: "Active credential harvesting campaign targeting M365 corporate logins.",
    addedBy: "SecOps SOC Lead",
    createdAt: "2026-08-28T14:30:00Z",
    syncedTenants: [
      { tenantId: "tenant-contoso-corp", tenantName: "Contoso Pharmaceuticals Ltd", status: "synced", syncedAt: "2026-08-28T14:31:00Z" },
      { tenantId: "tenant-woodgrove-fsi", tenantName: "Woodgrove Financial Services", status: "synced", syncedAt: "2026-08-28T14:31:00Z" },
      { tenantId: "tenant-fabrikam-logistics", tenantName: "Fabrikam Logistics Global", status: "synced", syncedAt: "2026-08-28T14:31:00Z" },
      { tenantId: "tenant-northwind-health", tenantName: "Northwind Health System", status: "synced", syncedAt: "2026-08-28T14:31:00Z" },
    ],
  },
  {
    id: "tabl-threat-02",
    type: "sender",
    value: "support-update@microsoft-service-auth.net",
    action: "block",
    reason: "Spoofed executive invoice notification with weaponized PDF.",
    addedBy: "Automated Incident Containment",
    createdAt: "2026-08-29T10:15:00Z",
    syncedTenants: [
      { tenantId: "tenant-contoso-corp", tenantName: "Contoso Pharmaceuticals Ltd", status: "synced", syncedAt: "2026-08-29T10:16:00Z" },
      { tenantId: "tenant-woodgrove-fsi", tenantName: "Woodgrove Financial Services", status: "synced", syncedAt: "2026-08-29T10:16:00Z" },
      { tenantId: "tenant-fabrikam-logistics", tenantName: "Fabrikam Logistics Global", status: "synced", syncedAt: "2026-08-29T10:16:00Z" },
      { tenantId: "tenant-northwind-health", tenantName: "Northwind Health System", status: "synced", syncedAt: "2026-08-29T10:16:00Z" },
    ],
  },
  {
    id: "tabl-threat-03",
    type: "fileHash",
    value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    action: "block",
    reason: "DarkGate payload hash identified across cross-tenant phishing campaign.",
    addedBy: "SecOps Threat Analyst",
    createdAt: "2026-08-30T09:00:00Z",
    syncedTenants: [
      { tenantId: "tenant-contoso-corp", tenantName: "Contoso Pharmaceuticals Ltd", status: "synced", syncedAt: "2026-08-30T09:01:00Z" },
      { tenantId: "tenant-woodgrove-fsi", tenantName: "Woodgrove Financial Services", status: "synced", syncedAt: "2026-08-30T09:01:00Z" },
      { tenantId: "tenant-fabrikam-logistics", tenantName: "Fabrikam Logistics Global", status: "synced", syncedAt: "2026-08-30T09:01:00Z" },
      { tenantId: "tenant-northwind-health", tenantName: "Northwind Health System", status: "synced", syncedAt: "2026-08-30T09:01:00Z" },
    ],
  },
];

export function getFleetTablEntries(): FleetTablEntry[] {
  return SEEDED_FLEET_TABL;
}

export function addFleetTablEntry(entry: Omit<FleetTablEntry, "id" | "createdAt" | "syncedTenants">): FleetTablEntry {
  const allTenants = tenantStore.getAllTenants();
  const newEntry: FleetTablEntry = {
    ...entry,
    id: `tabl-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    createdAt: new Date().toISOString(),
    syncedTenants: allTenants.map((t) => ({
      tenantId: t.id,
      tenantName: t.displayName,
      status: "synced",
      syncedAt: new Date().toISOString(),
    })),
  };

  SEEDED_FLEET_TABL = [newEntry, ...SEEDED_FLEET_TABL];

  // Record audit log
  tenantStore.addAuditLogEntry({
    timestamp: new Date().toISOString(),
    tenantId: "fleet",
    tenantName: "Global Fleet",
    category: "exo_write",
    action: `Broadcasted TABL ${entry.action.toUpperCase()} rule for ${entry.type} '${entry.value}' to ${allTenants.length} tenants.`,
    success: true,
  });

  return newEntry;
}

export function removeFleetTablEntry(id: string): boolean {
  const target = SEEDED_FLEET_TABL.find((e) => e.id === id);
  if (!target) return false;

  SEEDED_FLEET_TABL = SEEDED_FLEET_TABL.filter((e) => e.id !== id);

  tenantStore.addAuditLogEntry({
    timestamp: new Date().toISOString(),
    tenantId: "fleet",
    tenantName: "Global Fleet",
    category: "exo_write",
    action: `Removed fleet TABL threat indicator '${target.value}' (${target.type}) across all customer tenants.`,
    success: true,
  });

  return true;
}

/**
 * Executes batch baseline policy deployment across multiple target tenants.
 */
export async function executeBulkCaDeployment(
  req: FleetBulkDeployRequest
): Promise<FleetBulkDeployResult> {
  const results: FleetBulkDeployTenantResult[] = [];
  const mode = req.mode === "enabled" ? "enabled" : "enabledForReportingButNotEnforced";

  for (const tenantId of req.targetTenantIds) {
    const tenant = tenantStore.getTenant(tenantId);
    const snap = tenantStore.getSnapshot(tenantId);

    if (!tenant || !snap) {
      for (const code of req.baselineCodes) {
        results.push({
          tenantId,
          tenantName: tenantId,
          baselineCode: code,
          policyName: code,
          status: "failed",
          message: "Tenant snapshot not found in store.",
          error: "Tenant snapshot missing",
        });
      }
      continue;
    }

    const updatedPolicies = [...(snap.conditionalAccess?.policies || [])];

    for (const code of req.baselineCodes) {
      const baselineDef = CA_BASELINE_STANDARDS.find((b) => b.code === code);
      const policyName = baselineDef ? `${code}: ${baselineDef.name}` : code;

      // Check if already deployed
      const existing = updatedPolicies.find(
        (p) =>
          p.baselineCode?.toUpperCase() === code.toUpperCase() ||
          p.name.toLowerCase().includes(code.toLowerCase())
      );

      if (existing) {
        // Update state if currently disabled
        if (existing.state === "disabled") {
          existing.state = mode;
          existing.modifiedDateTime = new Date().toISOString();
          results.push({
            tenantId,
            tenantName: tenant.displayName,
            baselineCode: code,
            policyName,
            status: "success",
            message: `Updated existing policy from Disabled to ${mode === "enabled" ? "On (Enabled)" : "Report-Only"}.`,
          });
        } else {
          results.push({
            tenantId,
            tenantName: tenant.displayName,
            baselineCode: code,
            policyName,
            status: "skipped",
            message: `Policy is already active (${existing.state === "enabled" ? "Enabled" : "Report-Only"}).`,
          });
        }
      } else {
        // Create new policy in Report-Only mode
        const newPolicy: CAPolicyRule = {
          id: `pol-bulk-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          name: policyName,
          state: mode,
          baselineCode: code,
          createdDateTime: new Date().toISOString(),
          modifiedDateTime: new Date().toISOString(),
          grantControls: ["mfa"],
          conditions: {
            users: { include: ["All"], exclude: [] },
            applications: { include: ["All"], exclude: [] },
            clientAppTypes: ["all"],
          },
          matchesBaseline: true,
        };
        updatedPolicies.push(newPolicy);
        results.push({
          tenantId,
          tenantName: tenant.displayName,
          baselineCode: code,
          policyName,
          status: "success",
          message: `Created policy in ${mode === "enabled" ? "On (Enabled)" : "Report-Only"} mode.`,
        });
      }
    }

    // Save updated snapshot
    snap.conditionalAccess = {
      ...snap.conditionalAccess,
      policies: updatedPolicies,
    };
    tenantStore.saveSnapshot(tenantId, snap);

    // Write to audit log
    tenantStore.addAuditLogEntry({
      timestamp: new Date().toISOString(),
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      category: "ca_policy_deploy",
      action: `Bulk deployed ${req.baselineCodes.join(", ")} in ${mode} mode via Fleet Rollout Engine.`,
      success: true,
    });
  }

  const successCount = results.filter((r) => r.status === "success").length;
  const skippedCount = results.filter((r) => r.status === "skipped").length;
  const failedCount = results.filter((r) => r.status === "failed").length;

  return {
    totalRequested: req.targetTenantIds.length * req.baselineCodes.length,
    successCount,
    skippedCount,
    failedCount,
    results,
  };
}

/**
 * Realigns one or more drift findings on a tenant back to the Golden Baseline.
 */
export async function realignTenantDrift(
  tenantId: string,
  findingIds: string[]
): Promise<{ success: boolean; realignedCount: number; message: string }> {
  const tenant = tenantStore.getTenant(tenantId);
  const snap = tenantStore.getSnapshot(tenantId);

  if (!tenant || !snap) {
    return { success: false, realignedCount: 0, message: "Tenant not found." };
  }

  const currentAssessment = evaluateTenantDrift(snap);
  const targetFindings = currentAssessment.findings.filter((f) => findingIds.includes(f.id));

  if (targetFindings.length === 0) {
    return { success: false, realignedCount: 0, message: "No matching drift findings found to realign." };
  }

  let updatedSnap = snap;
  let realignedCount = 0;

  for (const finding of targetFindings) {
    if (finding.remediationSupported) {
      updatedSnap = realignFindingLocally(updatedSnap, finding);
      realignedCount++;
    }
  }

  tenantStore.saveSnapshot(tenantId, updatedSnap);

  tenantStore.addAuditLogEntry({
    timestamp: new Date().toISOString(),
    tenantId: tenant.id,
    tenantName: tenant.displayName,
    category: "ca_policy_deploy",
    action: `Realigned ${realignedCount} drift findings back to MSP Golden Standard.`,
    success: true,
  });

  return {
    success: true,
    realignedCount,
    message: `Successfully realigned ${realignedCount} security configurations to Golden Baseline.`,
  };
}
