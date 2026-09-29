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
            expirationDate: {
              type: "string",
              description: "ISO date string, or 'Never' for no expiration (not recommended). Defaults to 90 days out if omitted.",
            },
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
    name: "query_data_protection_recommendations",
    description: "Query Clarity365's DLP and sensitivity-label recommendation catalog by regulation and/or data type. Read-only and catalog-only - unlike every other tool here, this one takes no tenantId and never reads or writes any tenant's real DLP/label configuration. Every recommendation is guidance meant to be applied by hand in the Microsoft Purview portal, or via a generated (unverified) PowerShell script.",
    inputSchema: {
      type: "object",
      properties: {
        regulation: {
          type: "string",
          enum: ["popia", "gdpr_uk_gdpr", "hipaa"],
          description: "Optional filter to recommendations tagged with this regulation. A recommendation with no regulation (e.g. the IP/contracts entry) is only returned when this filter is omitted.",
        },
        dataCategory: {
          type: "string",
          enum: [
            "government_id",
            "health",
            "financial_banking",
            "payment_card",
            "credentials_secrets",
            "bulk_pii",
            "ip_contracts",
            "cross_border_transfer",
          ],
          description: "Optional filter to recommendations tagged with this data category.",
        },
        minimumLicenseTier: {
          type: "string",
          enum: ["business_premium_e3", "e5"],
          description: "Optional filter to recommendations whose minimum license tier exactly matches this value.",
        },
        recommendationId: {
          type: "string",
          description: "If set, ignores the filters above and returns full detail (portal steps, generated PowerShell script, caveats) for this one recommendation id, as returned by a prior filtered query.",
        },
      },
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
          enum: ["all", "conditional_access", "email_forwarding", "mfa_audit", "user_classification", "sharepoint_sharing", "unprotected_admins"],
          description: "Scope of remediation plan",
        },
      },
      required: ["tenantId"],
    },
  },
];
