import { tenantStore } from "../services/tenant-store";
import { generateRemediationPlanForTenant } from "../services/remediation-generator";
import { MCP_TOOL_DEFINITIONS, McpToolDefinition } from "./definitions";
import { defaultTablExpirationIso } from "../services/mdo-mapper";
import { DATA_PROTECTION_RECOMMENDATIONS } from "../data/data-protection-recommendations";

export { MCP_TOOL_DEFINITIONS };
export type { McpToolDefinition };

// Every MCP tool call is audit-logged - read-only lookups and mutations alike -
// since MCP lets an external AI agent act against real tenants (manage_tabl
// writes directly to a customer's TABL), and a security product needs a record
// of what an agent actually did, not just what a human clicked.
export async function executeMcpTool(name: string, args: Record<string, any>) {
  const startedAt = new Date().toISOString();
  let result: any;
  try {
    result = await runMcpTool(name, args);
  } catch (err: any) {
    result = { success: false, error: err.message || "Tool execution failed." };
  }

  const tenantId = args?.tenantId;
  const tenant = tenantId ? tenantStore.getTenant(tenantId) : undefined;
  const outcomeDetail = result?.error || result?.message;
  tenantStore.addAuditLogEntry({
    timestamp: startedAt,
    category: "mcp_tool_call",
    action: name,
    tenantId,
    tenantName: tenant?.displayName,
    success: result?.success !== false,
    detail: [JSON.stringify(args || {}).slice(0, 300), outcomeDetail].filter(Boolean).join(" | "),
  });

  return result;
}

async function runMcpTool(name: string, args: Record<string, any>) {
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
            (snap?.emailForwarding.filter((f) => f.isExternal && f.state === "Enabled").length ?? 0) +
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
      }

      // "add"/"remove" mutate tenant data - respect the "Allow Autonomous Tool
      // Execution" setting, unlike the read-only actions above/below.
      if (args.action === "add" || args.action === "remove") {
        if (!tenantStore.getSettings().allowToolExecution) {
          return {
            success: false,
            error: "Autonomous tool execution is disabled in Settings - enable 'Allow Autonomous Tool Execution' to let MCP agents modify tenant data.",
          };
        }
      }

      if (args.action === "add") {
        if (!args.entry || !args.entry.value || !args.entry.listType || !args.entry.entryType) {
          return { success: false, error: "Missing required entry parameters (value, listType, entryType)." };
        }
        const result = await tenantStore.addTablEntry(tenantId, {
          listType: args.entry.listType,
          entryType: args.entry.entryType,
          value: args.entry.value,
          addedBy: args.entry.addedBy || "mcp-agent@clarity365.local",
          expirationDate: args.entry.expirationDate || defaultTablExpirationIso(),
          notes: args.entry.notes || "Added via MCP Agent Tool Call",
        });
        return result.success
          ? { success: true, message: `Added ${args.entry.value} to TABL (${args.entry.listType}).`, entry: result.entry }
          : { success: false, error: result.error || "Failed to add TABL entry." };
      } else if (args.action === "remove") {
        if (!args.entryId) return { success: false, error: "Missing entryId to remove." };
        const result = await tenantStore.removeTablEntry(tenantId, args.entryId);
        return result.success
          ? { success: true, message: `Removed TABL entry ${args.entryId}.` }
          : { success: false, error: result.error || `Entry ${args.entryId} not found.` };
      }
      return { success: false, error: `Unknown action '${args.action}'.` };
    }

    case "query_data_protection_recommendations": {
      // The one tool with no tenant to look up - deliberately, this queries
      // the static guidance catalog only. No tenantId check, no snapshot
      // lookup, and (per the "No cross-tenant actions, ever" rule - see
      // ai-context-vault/Optimization/DLP & Sensitivity Labels Plan.md) no
      // path to touch a real tenant's DLP/label config from this tool at all.
      if (args.recommendationId) {
        const rec = DATA_PROTECTION_RECOMMENDATIONS.find((r) => r.id === args.recommendationId);
        if (!rec) return { success: false, error: `Unknown recommendation id '${args.recommendationId}'.` };
        // "kind" only exists on label entries (DLP entries have no kind
        // field at all - see the type's own comment) - branch on it rather
        // than assuming every catalog entry is a DLP rule, now that labels
        // (added 2026-09-22) share this same array.
        const isLabel = "kind" in rec && rec.kind === "label";
        return {
          success: true,
          recommendation: {
            id: rec.id,
            kind: isLabel ? "label" : "dlp",
            title: rec.title,
            regulations: rec.regulations,
            dataCategories: rec.dataCategories,
            minimumLicenseTier: rec.minimumLicenseTier,
            summary: rec.summary,
            ...(isLabel
              ? {
                  labels: (rec as any).labels,
                  labelPolicySettings: (rec as any).labelPolicySettings,
                  autoLabeling: (rec as any).autoLabeling,
                }
              : {
                  sensitiveInfoTypes: (rec as any).sensitiveInfoTypes,
                  recommendedLocations: (rec as any).recommendedLocations,
                  recommendedStartingMode: (rec as any).recommendedStartingMode,
                  ruleLogicSummary: (rec as any).ruleLogicSummary,
                  actions: (rec as any).actions,
                }),
            portalSteps: rec.portalSteps,
            // Materialized with a generic placeholder - this tool call isn't
            // scoped to a real tenant, so there's no real name to substitute.
            powershellTemplate: rec.powershellTemplate("YourTenantName"),
            e5Enhancements: rec.e5Enhancements || [],
            regulationRefs: rec.regulationRefs,
            caveats: rec.caveats,
            relatedRecommendationIds: rec.relatedRecommendationIds || [],
          },
        };
      }

      let results = [...DATA_PROTECTION_RECOMMENDATIONS];
      if (args.regulation) results = results.filter((r) => r.regulations.includes(args.regulation));
      if (args.dataCategory) results = results.filter((r) => r.dataCategories.includes(args.dataCategory));
      if (args.minimumLicenseTier) results = results.filter((r) => r.minimumLicenseTier === args.minimumLicenseTier);

      return {
        success: true,
        count: results.length,
        note: "Guidance-only catalog - every recommendation is applied by hand in the Purview portal or via a generated PowerShell script. This tool never reads or writes a real tenant's DLP/label configuration. Pass recommendationId (from one of the ids below) for full detail on one entry.",
        recommendations: results.map((r) => ({
          id: r.id,
          kind: "kind" in r && r.kind === "label" ? "label" : "dlp",
          title: r.title,
          regulations: r.regulations,
          dataCategories: r.dataCategories,
          minimumLicenseTier: r.minimumLicenseTier,
          summary: r.summary,
        })),
      };
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
