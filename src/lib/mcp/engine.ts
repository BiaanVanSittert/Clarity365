import { tenantStore } from "../services/tenant-store";
import { generateRemediationPlanForTenant } from "../services/remediation-generator";
import { MCP_TOOL_DEFINITIONS, McpToolDefinition } from "./definitions";

export { MCP_TOOL_DEFINITIONS };
export type { McpToolDefinition };

export async function executeMcpTool(name: string, args: Record<string, any>) {
  const { tenantId } = args;

  switch (name) {
    case "list_tenants": {
      const tenants = tenantStore.getAllTenants();
      const results = tenants.map((t) => {
        const snap = tenantStore.getSnapshot(t.id);
        return {
          id: t.id,
          displayName: t.displayName,
          defaultDomain: t.defaultDomainName,
          tier: t.tier,
          status: t.connectionStatus,
          secureScorePercentage: snap?.secureScore.percentage ?? 0,
          licensedUsers: snap?.accountClassification.licensedUsersCount ?? 0,
          criticalAlerts:
            (snap?.highRiskThreatIndicators.externalForwardingCount ?? 0) +
            (snap?.highRiskThreatIndicators.unprotectedAdminsCount ?? 0),
        };
      });
      return { success: true, count: results.length, data: results };
    }

    case "get_tenant_secure_score": {
      const snap = tenantStore.getSnapshot(tenantId);
      if (!snap) return { success: false, error: `Tenant '${tenantId}' not found.` };
      return {
        success: true,
        tenant: snap.tenant.displayName,
        secureScore: snap.secureScore,
      };
    }

    case "audit_conditional_access": {
      const snap = tenantStore.getSnapshot(tenantId);
      if (!snap) return { success: false, error: `Tenant '${tenantId}' not found.` };
      const deployedCodes = new Set(snap.conditionalAccess.policies.map((p) => p.baselineCode).filter(Boolean));
      const baselineAnalysis = snap.conditionalAccess.baselineDefinitions.map((std) => {
        const matchingPolicy = snap.conditionalAccess.policies.find((p) => p.baselineCode === std.code);
        return {
          baselineCode: std.code,
          name: std.name,
          status: matchingPolicy ? (matchingPolicy.state === "enabled" ? "Pass (Enabled)" : "Warning (Report-Only / Disabled)") : "Fail (Missing)",
          matchingPolicyName: matchingPolicy?.name || null,
          policyState: matchingPolicy?.state || null,
          riskMitigated: std.riskMitigated,
        };
      });

      return {
        success: true,
        tenant: snap.tenant.displayName,
        coverageScore: snap.conditionalAccess.baselineCoverageScore,
        totalBaselineStandards: snap.conditionalAccess.baselineDefinitions.length,
        deployedBaselinePoliciesCount: deployedCodes.size,
        policies: snap.conditionalAccess.policies,
        baselineAnalysis,
      };
    }

    case "query_signin_logs": {
      const snap = tenantStore.getSnapshot(tenantId);
      if (!snap) return { success: false, error: `Tenant '${tenantId}' not found.` };
      let events = [...snap.signIns];

      if (args.status && args.status !== "all") {
        events = events.filter((e) => e.status === args.status);
      }
      if (args.userPrincipalName) {
        events = events.filter((e) => e.userPrincipalName.toLowerCase().includes(args.userPrincipalName.toLowerCase()));
      }
      if (args.onlyRisky) {
        events = events.filter((e) => e.isRisky);
      }

      return {
        success: true,
        tenant: snap.tenant.displayName,
        totalEvents: events.length,
        events,
      };
    }

    case "audit_mfa_methods": {
      const snap = tenantStore.getSnapshot(tenantId);
      if (!snap) return { success: false, error: `Tenant '${tenantId}' not found.` };
      let users = [...snap.mfaAudit];
      if (args.onlyWeakAuth) {
        users = users.filter((u) => u.isWeakAuth || !u.mfaRegistered);
      }
      return {
        success: true,
        tenant: snap.tenant.displayName,
        totalAudited: users.length,
        weakAuthCount: snap.mfaAudit.filter((u) => u.isWeakAuth).length,
        missingMfaCount: snap.mfaAudit.filter((u) => !u.mfaRegistered).length,
        users,
      };
    }

    case "audit_email_forwarding": {
      const snap = tenantStore.getSnapshot(tenantId);
      if (!snap) return { success: false, error: `Tenant '${tenantId}' not found.` };
      return {
        success: true,
        tenant: snap.tenant.displayName,
        criticalExternalForwardingCount: snap.emailForwarding.filter((f) => f.isExternal && f.state === "Enabled").length,
        rules: snap.emailForwarding,
      };
    }

    case "manage_tabl": {
      const snap = tenantStore.getSnapshot(tenantId);
      if (!snap) return { success: false, error: `Tenant '${tenantId}' not found.` };

      if (args.action === "list") {
        return { success: true, tenant: snap.tenant.displayName, entries: snap.mdoThreat.tabl };
      } else if (args.action === "add") {
        if (!args.entry || !args.entry.value || !args.entry.listType || !args.entry.entryType) {
          return { success: false, error: "Missing required entry parameters (value, listType, entryType)." };
        }
        const created = tenantStore.addTablEntry(tenantId, {
          listType: args.entry.listType,
          entryType: args.entry.entryType,
          value: args.entry.value,
          addedBy: args.entry.addedBy || "mcp-agent@clarity365.local",
          expirationDate: "Never",
          notes: args.entry.notes || "Added via MCP Agent Tool Call",
        });
        return { success: true, message: `Added ${args.entry.value} to TABL (${args.entry.listType}).`, entry: created };
      } else if (args.action === "remove") {
        if (!args.entryId) return { success: false, error: "Missing entryId to remove." };
        const removed = tenantStore.removeTablEntry(tenantId, args.entryId);
        return { success: removed, message: removed ? `Removed TABL entry ${args.entryId}.` : `Entry ${args.entryId} not found.` };
      }
      return { success: false, error: `Unknown action '${args.action}'.` };
    }

    case "generate_remediation_plan": {
      const snap = tenantStore.getSnapshot(tenantId);
      if (!snap) return { success: false, error: `Tenant '${tenantId}' not found.` };
      const plans = generateRemediationPlanForTenant(snap, args.findingType === "all" ? undefined : args.findingType);
      return {
        success: true,
        tenant: snap.tenant.displayName,
        totalPlansGenerated: plans.length,
        plans,
      };
    }

    default:
      return { success: false, error: `Unrecognized MCP tool '${name}'.` };
  }
}
