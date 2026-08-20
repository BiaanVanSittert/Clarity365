import { tenantStore } from "../services/tenant-store";
import { generateRemediationPlanForTenant } from "../services/remediation-generator";

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, any>;
    required?: string[];
  };
}

export const MCP_TOOL_DEFINITIONS: McpToolDefinition[] = [
  {
    name: "list_tenants",
    description: "List all connected and demo Microsoft 365 customer tenants managed by Clarity365 with license tier, sync status, and secure score summaries.",
    inputSchema: {
      type: "object",
      properties: {
        filterTier: {
          type: "string",
          description: "Optional filter by license tier (M365_E5, M365_E3, M365_BP, etc.)",
        },
      },
    },
  },
  {
    name: "get_tenant_secure_score",
    description: "Fetch real-time Microsoft Defender Secure Score, category breakdown (Identity, Device, Apps, Data), 30/90-day deltas, and unresolved improvement actions for a specific tenant.",
    inputSchema: {
      type: "object",
      properties: {
        tenantId: {
          type: "string",
          description: "Unique tenant identifier (e.g., 'tenant-contoso-corp')",
        },
      },
      required: ["tenantId"],
    },
  },
  {
    name: "audit_conditional_access",
    description: "Scan all deployed Conditional Access policies in a tenant and benchmark against the industry CA01 through CA10 standard baseline. Highlights missing policies and report-only configurations.",
    inputSchema: {
      type: "object",
      properties: {
        tenantId: {
          type: "string",
          description: "Unique tenant identifier",
        },
      },
      required: ["tenantId"],
    },
  },
  {
    name: "query_signin_logs",
    description: "Query Entra ID sign-in events with granular filtering by status (failed, ca_blocked, report_only_failed, success), user principal name, risk level, or error code.",
    inputSchema: {
      type: "object",
      properties: {
        tenantId: {
          type: "string",
          description: "Unique tenant identifier",
        },
        status: {
          type: "string",
          enum: ["all", "success", "failed", "ca_blocked", "report_only_failed"],
          description: "Filter by sign-in outcome",
        },
        userPrincipalName: {
          type: "string",
          description: "Optional UPN to filter by specific user",
        },
        onlyRisky: {
          type: "boolean",
          description: "If true, only returns events flagged as medium or high risk",
        },
      },
      required: ["tenantId"],
    },
  },
  {
    name: "audit_mfa_methods",
    description: "Audit MFA enforcement status and exact authentication methods (Passkey FIDO2, MS Authenticator push/totp, SMS, Email OTP) across all directory users. Flags weak authentication and un-enrolled accounts.",
    inputSchema: {
      type: "object",
      properties: {
        tenantId: {
          type: "string",
          description: "Unique tenant identifier",
        },
        onlyWeakAuth: {
          type: "boolean",
          description: "If true, returns only users without MFA or using weak methods (SMS/Email OTP)",
        },
      },
      required: ["tenantId"],
    },
  },
  {
    name: "audit_email_forwarding",
    description: "Detect and audit all automatic email forwarding vectors (Exchange transport rules, mailbox inbox rules, and SMTP forwarding addresses) with critical alert level for external targets.",
    inputSchema: {
      type: "object",
      properties: {
        tenantId: {
          type: "string",
          description: "Unique tenant identifier",
        },
      },
      required: ["tenantId"],
    },
  },
  {
    name: "manage_tabl",
    description: "View, add, or remove entries in Defender for Office 365 Tenant Allow/Block List (TABL) for domains, senders, URLs, or file hashes.",
    inputSchema: {
      type: "object",
      properties: {
        tenantId: {
          type: "string",
          description: "Unique tenant identifier",
        },
        action: {
          type: "string",
          enum: ["list", "add", "remove"],
          description: "Action to perform on TABL",
        },
        entry: {
          type: "object",
          properties: {
            listType: { type: "string", enum: ["allow", "block"] },
            entryType: { type: "string", enum: ["domain", "sender", "url", "file_hash"] },
            value: { type: "string" },
            notes: { type: "string" },
            addedBy: { type: "string" },
          },
        },
        entryId: {
          type: "string",
          description: "Entry ID to remove when action is 'remove'",
        },
      },
      required: ["tenantId", "action"],
    },
  },
  {
    name: "generate_remediation_plan",
    description: "Generate comprehensive step-by-step PowerShell / Microsoft Graph API remediation scripts, impact analysis, and rollback procedures for security findings in a tenant.",
    inputSchema: {
      type: "object",
      properties: {
        tenantId: {
          type: "string",
          description: "Unique tenant identifier",
        },
        findingType: {
          type: "string",
          enum: ["all", "conditional_access", "email_forwarding", "mfa_audit", "user_classification"],
          description: "Scope of remediation plan",
        },
      },
      required: ["tenantId"],
    },
  },
];

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
