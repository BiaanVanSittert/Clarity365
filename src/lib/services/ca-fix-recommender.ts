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

export type CaFixKind = "licence" | "enableReportOnly" | "removeExclusion" | "reviewUncertain" | "deployBaseline" | "createPolicy";

export interface CaFixRecommendation {
  kind: CaFixKind;
  title: string;
  detail: string;
  policyIds?: string[];
  baselineCode?: string;
  // Set when acting on this would touch a likely emergency-access account.
  warning?: string;
  // Set when the fix would ALSO block the situation's normal, benign
  // counterpart (options.normalContext): a broad fix rather than a targeted
  // one. Found live: "require a compliant device for everyone" was the
  // suggested fix for foreign-country, device-code, user-risk and guest
  // situations alike, because every situation modelled an unmanaged device.
  // Broad fixes are listed after targeted ones.
  sideEffect?: string;
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
  // The same sign-in with the risky part removed (home country instead of a
  // foreign one, a normal flow instead of device code, a compliant device
  // instead of an unmanaged one). Used to tell a targeted fix from one that
  // would block normal sign-ins too.
  normalContext?: SignInContext;
}

function sideEffectOf(trialEnv: CaEnvironment, env: CaEnvironment, normal: SignInContext | undefined): string | undefined {
  if (!normal) return undefined;
  const before = evaluateSignIn(normal, env).enforced.outcome;
  const after = evaluateSignIn(normal, trialEnv).enforced.outcome;
  return before !== "blocked" && after === "blocked" ? "This would also block this user's normal sign-ins, not just this situation." : undefined;
}

export function recommendFixes(ctx: SignInContext, env: CaEnvironment, desired: CaDesiredOutcome, options: CaFixOptions): CaFixRecommendation[] {
  const current = evaluateSignIn(ctx, env);
  if (meetsDesiredOutcome(current.enforced, desired)) return [];

  const fixes: CaFixRecommendation[] = [];

  // 0. Risk-based situations can't be handled by any policy without Entra ID P2.
  const riskSituation = ctx.signInRisk !== "none" || ctx.userRisk !== "none";
  const riskUnlicensed = riskSituation && !env.entraP2Licensed;
  if (riskUnlicensed) {
    fixes.push({
      kind: "licence",
      title: "License Microsoft Entra ID P2",
      detail:
        "Sign-in and user risk conditions only work with Entra ID P2 (Microsoft 365 E5, or the P2 add-on). Without it no risk-based policy is ever evaluated, so the tenant can't respond to this situation automatically.",
    });
  }

  // 1. A report-only policy that would reach the desired outcome on its own.
  const reportOnly = env.policies.filter((p) => p.state === "enabledForReportingButNotEnforced");
  for (const p of reportOnly) {
    const trialEnv = withPolicy(env, p.id, (x) => ({ ...x, state: "enabled" }));
    if (meetsDesiredOutcome(evaluateSignIn(ctx, trialEnv).enforced, desired)) {
      fixes.push({
        kind: "enableReportOnly",
        title: `Enable report-only policy "${p.name}"`,
        detail: "This policy is in report-only mode. Switched on, it would stop this situation. Review its sign-in log impact first.",
        policyIds: [p.id],
        sideEffect: sideEffectOf(trialEnv, env, options.normalContext),
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
    // Excluding guests from an all-users policy is normal when a dedicated
    // guest policy exists; only suggest undoing it when nothing else can.
    if (t.excludedBy.every((h) => h.kind === "guests") && fixes.some((f) => f.kind === "enableReportOnly" && !f.sideEffect)) continue;

    const breakGlass = t.excludedBy.map((h) => isLikelyBreakGlassRef(h.ref, options.breakGlass)).find(Boolean);
    const exclusionText = t.excludedBy.map(describeExclusion).join(", ");
    fixes.push({
      kind: "removeExclusion",
      title: `Review the exclusion on "${policy.name}"`,
      detail:
        `This policy would stop the situation, but ${exclusionText}.` +
        (policy.state === "enabledForReportingButNotEnforced" ? " The policy is also still in report-only mode." : ""),
      policyIds: [policy.id],
      sideEffect: sideEffectOf(trialEnv, env, options.normalContext),
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

  // 5. Otherwise, a new policy. Broad fixes alone don't count as an answer.
  const hasTargetedFix = fixes.some(
    (f) => (f.kind === "enableReportOnly" || f.kind === "removeExclusion" || f.kind === "deployBaseline") && !f.sideEffect
  );
  if (!hasTargetedFix && !riskUnlicensed) {
    fixes.push({ kind: "createPolicy", title: "Create a new Conditional Access policy", detail: options.newPolicyDescription });
  }

  // Targeted fixes first; otherwise stable, so the order above holds.
  return fixes
    .map((f, i) => ({ f, i }))
    .sort((a, b) => Number(!!a.f.sideEffect) - Number(!!b.f.sideEffect) || a.i - b.i)
    .map((x) => x.f);
}
