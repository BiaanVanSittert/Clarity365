import { MailflowTransportRule, MailflowBaselineResult, MdoThreatPolicy, MailflowConnector } from "../types";
import { MAILFLOW_BASELINE_STANDARDS } from "../data/mailflow-baseline-definitions";
import { computeBaselineCoveragePercent } from "./ca-baseline-matcher";

export interface MailflowBaselineInput {
  transportRules: MailflowTransportRule[];
  policies: MdoThreatPolicy[];
  connectors: MailflowConnector[];
  remoteDomainAutoForwardBlocked?: boolean;
  externalSenderTagEnabled?: boolean;
}

// Scores live mail-flow data (transport rules, connectors, the two org-wide
// auto-forward switches, and the AntiSpamOutbound policy already fetched for
// MDO) against MAILFLOW_BASELINE_STANDARDS. MF01-03/05-06 are "does anything
// violate this" checks — met only if zero rules/connectors do, with every
// offender named so an admin can judge intent before acting. MF04/07/08 are
// single tenant-wide settings, same shape as an MDO0x check.
function evaluateCode(code: string, input: MailflowBaselineInput): MailflowBaselineResult {
  const enabledRules = input.transportRules.filter((r) => r.state === "Enabled");
  const enabledConnectors = input.connectors.filter((c) => c.enabled);

  if (code === "MF01") {
    const offenders = enabledRules.filter((r) => r.redirectsExternally);
    return {
      code,
      met: offenders.length === 0,
      offendingRuleNames: offenders.length > 0 ? offenders.map((r) => r.name) : undefined,
      offendingRuleIds: offenders.length > 0 ? offenders.map((r) => r.id) : undefined,
    };
  }
  if (code === "MF02") {
    const offenders = enabledRules.filter((r) => r.overridesSpamConfidence);
    return {
      code,
      met: offenders.length === 0,
      offendingRuleNames: offenders.length > 0 ? offenders.map((r) => r.name) : undefined,
      offendingRuleIds: offenders.length > 0 ? offenders.map((r) => r.id) : undefined,
    };
  }
  if (code === "MF03") {
    const offenders = enabledRules.filter((r) => r.hasNoScopingConditions && !r.hasExpiry);
    return {
      code,
      met: offenders.length === 0,
      offendingRuleNames: offenders.length > 0 ? offenders.map((r) => r.name) : undefined,
      offendingRuleIds: offenders.length > 0 ? offenders.map((r) => r.id) : undefined,
    };
  }
  if (code === "MF04") {
    const outboundPolicy = input.policies.find((p) => p.policyType === "AntiSpamOutbound");
    return { code, met: !!outboundPolicy?.autoForwardingBlocked };
  }
  if (code === "MF05") {
    const offenders = enabledConnectors.filter((c) => c.trustsAnonymousSenders);
    return {
      code,
      met: offenders.length === 0,
      offendingRuleNames: offenders.length > 0 ? offenders.map((c) => c.name) : undefined,
      offendingRuleIds: offenders.length > 0 ? offenders.map((c) => c.id) : undefined,
    };
  }
  if (code === "MF06") {
    const offenders = enabledConnectors.filter((c) => !c.requiresTls);
    return {
      code,
      met: offenders.length === 0,
      offendingRuleNames: offenders.length > 0 ? offenders.map((c) => c.name) : undefined,
      offendingRuleIds: offenders.length > 0 ? offenders.map((c) => c.id) : undefined,
    };
  }
  if (code === "MF07") {
    return { code, met: input.remoteDomainAutoForwardBlocked === true };
  }
  if (code === "MF08") {
    return { code, met: input.externalSenderTagEnabled === true };
  }
  return { code, met: false };
}

export function evaluateMailflowBaseline(input: MailflowBaselineInput): {
  results: MailflowBaselineResult[];
  coveragePercent: number;
} {
  const results = MAILFLOW_BASELINE_STANDARDS.map((standard) => evaluateCode(standard.code, input));
  const metCount = results.filter((r) => r.met).length;
  return { results, coveragePercent: computeBaselineCoveragePercent(metCount, MAILFLOW_BASELINE_STANDARDS.length) };
}
