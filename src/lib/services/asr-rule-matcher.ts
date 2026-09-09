// Traffic-light tiering for Attack Surface Reduction rules. A fresh,
// purpose-built 4-state enum rather than a forced reuse of MfaRiskTier from
// mfa-risk-tier.ts - this is rule configuration status, not user risk, and
// the states genuinely differ (there's no "disabled/no color" equivalent for
// a policy). Critical is reserved for a Standard Protection rule sitting at
// Not Configured, since Microsoft's own docs call those 3 out as the
// foundational, lowest-friction set to enable first.
export type AsrTier = "critical" | "gap" | "in_progress" | "protected";

export function classifyAsrRuleTier(input: {
  mode: "not_configured" | "audit" | "warn" | "block";
  isStandardProtection: boolean;
}): AsrTier {
  if (input.mode === "block") return "protected";
  if (input.mode === "audit" || input.mode === "warn") return "in_progress";
  return input.isStandardProtection ? "critical" : "gap";
}

export const ASR_TIER_LABEL: Record<AsrTier, { label: string; description: string }> = {
  critical: { label: "Critical", description: "A Standard Protection rule is not configured at all." },
  gap: { label: "Gap", description: "This rule is not configured." },
  in_progress: { label: "In Progress", description: "Configured in Audit or Warn mode, not yet enforcing." },
  protected: { label: "Protected", description: "Configured in Block mode." },
};

export const ASR_TIER_SEVERITY: Record<AsrTier, number> = {
  critical: 0,
  gap: 1,
  in_progress: 2,
  protected: 3,
};
