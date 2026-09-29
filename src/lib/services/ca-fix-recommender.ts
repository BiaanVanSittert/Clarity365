import { CAPolicyRule } from "../types";
import {
  CaEnvironment,
  CaExclusionHit,
  CaOutcomeSummary,
  CaRequirementKind,
  SignInContext,
  describeExclusion,
  evaluateSignIn,
} from "./ca-policy-evaluator";
import { BreakGlassCandidate, isLikelyBreakGlassRef } from "./ca-sim-context";

// Recommends how to reach a sign-in's desired outcome. Every "enable" and
// "remove exclusion" suggestion is PROVEN by re-running the evaluator on a
// modified copy of the tenant, so a recommendation can never disagree with
// what the engine itself would then conclude.

export type CaDesiredOutcome =
  // Access must be blocked outright.
  | "block"
  // Blocked, or at least an MFA-level challenge.
  | "strongAuth"
  // Blocked, or phishing-resistant MFA required.
  | "phishingResistant"
  // Blocked, or a secure password change required (user risk remediation).
  | "passwordChange"
  // Blocked, or access only through an approved/app-protected mobile app.
  | "appProtection";

export type CaFixKind = "enableReportOnly" | "removeExclusion" | "reviewUncertain" | "deployBaseline" | "createPolicy";

export interface CaFixRecommendation {
  kind: CaFixKind;
  title: string;
  detail: string;
  policyIds?: string[];
  baselineCode?: string;
  // Set when acting on this would touch a likely emergency-access account.
  warning?: string;
}

export function meetsDesiredOutcome(summary: CaOutcomeSummary, desired: CaDesiredOutcome): boolean {
  if (summary.outcome === "blocked") return true;
  if (desired === "block" || summary.outcome !== "challenged") return false;
  const kinds = new Set<CaRequirementKind>(summary.requirementKinds);
  switch (desired) {
    case "strongAuth":
      return kinds.size > 0;
    case "phishingResistant":
      return kinds.has("phishingResistantMfa");
    case "passwordChange":
      return kinds.has("passwordChange");
    case "appProtection":
      return kinds.has("appProtection");
  }
}

function withPolicy(env: CaEnvironment, policyId: string, change: (p: CAPolicyRule) => CAPolicyRule): CaEnvironment {
  return { ...env, policies: env.policies.map((p) => (p.id === policyId ? change(p) : p)) };
}

function removeExclusions(policy: CAPolicyRule, hits: CaExclusionHit[]): CAPolicyRule {
  const refs = new Set(hits.map((h) => h.ref));
  const users = policy.conditions.users;
  return {
    ...policy,
    conditions: {
      ...policy.conditions,
      users: {
        ...users,
        exclude: (users.exclude || []).filter((e) => !refs.has(e)),
        excludeRoles: (users.excludeRoles || []).filter((r) => !refs.has(r)),
        excludeGroupIds: (users.excludeGroupIds || []).filter((g) => !refs.has(g)),
      },
    },
  };
}

export interface CaFixOptions {
  // The CA01-CA10 baseline that addresses this situation, if any.
  baselineCode?: string;
  baselineName?: string;
  // Plain-language description of the policy to create when nothing
  // existing can be enabled or widened.
  newPolicyDescription: string;
  breakGlass: BreakGlassCandidate[];
}

export function recommendFixes(ctx: SignInContext, env: CaEnvironment, desired: CaDesiredOutcome, options: CaFixOptions): CaFixRecommendation[] {
  const current = evaluateSignIn(ctx, env);
  if (meetsDesiredOutcome(current.enforced, desired)) return [];

  const fixes: CaFixRecommendation[] = [];

  // 1. A report-only policy that would reach the desired outcome on its own.
  const reportOnly = env.policies.filter((p) => p.state === "enabledForReportingButNotEnforced");
  for (const p of reportOnly) {
    const trial = evaluateSignIn(ctx, withPolicy(env, p.id, (x) => ({ ...x, state: "enabled" })));
    if (meetsDesiredOutcome(trial.enforced, desired)) {
      fixes.push({
        kind: "enableReportOnly",
        title: `Enable report-only policy "${p.name}"`,
        detail: "This policy is in report-only mode. Switched on, it would stop this situation. Review its sign-in log impact first.",
        policyIds: [p.id],
      });
    }
  }
  if (fixes.length === 0 && reportOnly.length > 1 && meetsDesiredOutcome(current.withReportOnly, desired)) {
    const involved = current.reportOnlyHits.map((h) => h.policyId);
    fixes.push({
      kind: "enableReportOnly",
      title: "Enable the report-only policies together",
      detail: `No single report-only policy is enough, but these together would stop this situation: ${current.reportOnlyHits.map((h) => h.policyName).join(", ")}.`,
      policyIds: involved,
    });
  }

  // 2. An enabled or report-only policy that would apply if the user weren't excluded.
  for (const t of current.trace) {
    if (!t.excludedBy || t.excludedBy.length === 0 || t.source !== "policy") continue;
    const policy = env.policies.find((p) => p.id === t.policyId);
    if (!policy || policy.state === "disabled") continue;
    const trialEnv = withPolicy(env, policy.id, (p) => ({ ...removeExclusions(p, t.excludedBy!), state: "enabled" }));
    if (!meetsDesiredOutcome(evaluateSignIn(ctx, trialEnv).enforced, desired)) continue;

    const breakGlass = t.excludedBy.map((h) => isLikelyBreakGlassRef(h.ref, options.breakGlass)).find(Boolean);
    const exclusionText = t.excludedBy.map(describeExclusion).join(", ");
    fixes.push({
      kind: "removeExclusion",
      title: `Review the exclusion on "${policy.name}"`,
      detail:
        `This policy would stop the situation, but ${exclusionText}.` +
        (policy.state === "enabledForReportingButNotEnforced" ? " The policy is also still in report-only mode." : ""),
      policyIds: [policy.id],
      warning: breakGlass
        ? `This exclusion looks like an emergency-access (break-glass) account (${breakGlass.reasons.join("; ")}). Microsoft recommends keeping those excluded; confirm it is one, and that it is monitored, rather than removing it.`
        : undefined,
    });
  }

  // 3. Policies that might apply but couldn't be confirmed.
  for (const u of current.enforced.uncertainPolicies) {
    fixes.push({
      kind: "reviewUncertain",
      title: `Check whether "${u.policyName}" applies`,
      detail: `This policy might stop the situation, but the simulator couldn't confirm it applies: ${u.reason}.`,
      policyIds: [u.policyId],
    });
  }

  // 4. The matching baseline, if it isn't already enabled.
  if (options.baselineCode) {
    const deployed = env.policies.some((p) => p.baselineCode === options.baselineCode && p.state === "enabled");
    if (!deployed) {
      fixes.push({
        kind: "deployBaseline",
        title: `Deploy ${options.baselineCode}${options.baselineName ? `: ${options.baselineName}` : ""}`,
        detail: "Clarity365's baseline policy for this situation isn't enabled. Deploy it from the CA Policy Baseline module (it's created in report-only mode first).",
        baselineCode: options.baselineCode,
      });
    }
  }

  // 5. Otherwise, a new policy.
  if (!fixes.some((f) => f.kind === "enableReportOnly" || f.kind === "removeExclusion" || f.kind === "deployBaseline")) {
    fixes.push({ kind: "createPolicy", title: "Create a new Conditional Access policy", detail: options.newPolicyDescription });
  }

  return fixes;
}
