import { TenantSecuritySnapshot } from "../types";
import { PERSONA_NORMAL, SIGNIN_SITUATIONS, SigninSituation, SituationContext, SituationPersona } from "../data/signin-situation-definitions";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { detectMostCommonCountry } from "../utils/sign-in-country";
import { CaEnvironment, CaEvaluationResult, CaSimLocation, CaSimUser, SignInContext, evaluateSignIn } from "./ca-policy-evaluator";
import { BreakGlassCandidate, buildCaEnvironment, detectLikelyBreakGlassAccounts } from "./ca-sim-context";
import { CaFixRecommendation, recommendFixes } from "./ca-fix-recommender";
import { describeSignInCoverage, getSignInCoverage } from "../utils/sign-in-coverage";

// Runs the Sign-in Situations (signin-situation-definitions.ts) through the
// CA engine for one chosen account, and applies the user's colour rules
// (Security Simulations Plan, "Decisions"):
//   green  = prevented (blocked)
//   orange = allowed only after MFA / app protection / password change,
//            or the result couldn't be confirmed
//   red    = allowed with nothing stopping it
// A good-path situation (guest collaboration) flips this: the expected
// "allowed after MFA" is green and a block is orange.

export type SituationVerdict = "prevented" | "partial" | "notPrevented" | "unknown";

export interface SituationRunResult {
  situation: SigninSituation;
  verdict: SituationVerdict;
  // Short badge text, e.g. "Blocked", "Allowed after MFA", "Allowed".
  verdictLabel: string;
  // One sentence: what happens and because of which policy.
  outcomeText: string;
  // When not blocked: why nothing stopped it.
  whyNotBlocked: string[];
  result?: CaEvaluationResult;
  fixes: CaFixRecommendation[];
  // Real sign-ins by the chosen account that look like this situation.
  // coverage: the period the synced sign-ins cover, so "none found" isn't
  // read as "never happened".
  evidence?: { matched: number; succeeded: number; coverage: string };
  notes: string[];
}

export interface SituationRunOptions {
  homeCountry: string;
  foreignCountry: string;
}

export function detectHomeCountry(snapshot: TenantSecuritySnapshot): string {
  const fromSignIns = detectMostCommonCountry(snapshot.signIns || []);
  if (fromSignIns) return fromSignIns;
  // Otherwise the first country of a country named location - usually the
  // tenant's own "allowed countries" list.
  const countryLoc = (snapshot.conditionalAccess?.namedLocations || []).find((l) => l.kind === "country" && (l.countries || []).length > 0);
  return countryLoc?.countries?.[0] || "US";
}

function trustedIpLocationIds(env: CaEnvironment): string[] {
  return (env.namedLocations || []).filter((l) => l.kind === "ip" && l.isTrusted).map((l) => l.id);
}

function resolveLocation(kind: SituationContext["location"], env: CaEnvironment, opts: SituationRunOptions): CaSimLocation {
  switch (kind) {
    case "foreign":
      return { country: opts.foreignCountry, ipNamedLocationIds: [] };
    case "trusted":
      return { country: opts.homeCountry, ipNamedLocationIds: trustedIpLocationIds(env) };
    default:
      return { country: opts.homeCountry, ipNamedLocationIds: [] };
  }
}

export function buildSituationContext(situation: SigninSituation, which: "attack" | "normal", user: CaSimUser, env: CaEnvironment, opts: SituationRunOptions): SignInContext {
  const base = PERSONA_NORMAL[situation.persona];
  const overrides = which === "attack" ? situation.context : situation.normal;
  const { location, ...rest } = { ...base, ...overrides };
  return { ...rest, user, location: resolveLocation(location, env, opts) };
}

const REQUIREMENT_VERDICT_LABEL: Record<string, string> = {
  mfa: "Allowed after MFA",
  phishingResistantMfa: "Allowed after phishing-resistant MFA",
  authenticationStrength: "Allowed after strong authentication",
  appProtection: "Allowed in protected apps only",
  passwordChange: "Password change required",
  other: "Allowed after extra checks",
};

function joinNames(names: string[]): string {
  const unique = [...new Set(names)];
  return unique.map((n) => `"${n}"`).join(", ");
}

function describeRequirements(result: CaEvaluationResult): string {
  return result.enforced.requirements
    .map((r) => `${r.paths.map((path) => path.map((req) => req.label).join(" + ")).join(" or ")} (${r.policyName})`)
    .join("; ");
}

function explainNotBlocked(result: CaEvaluationResult): string[] {
  const out: string[] = [];
  for (const t of result.trace) {
    if (t.state === "enabled" && t.excludedBy && t.excludedBy.length > 0) out.push(`Excluded from "${t.policyName}": ${t.reason.replace(/^User is excluded \((.*)\)$/, "$1")}`);
  }
  for (const hit of result.reportOnlyHits) {
    const effect = hit.grant.kind === "block" || hit.grant.kind === "unsatisfiable" ? "would block this" : "would require more checks";
    out.push(`"${hit.policyName}" ${effect}, but it's in report-only mode`);
  }
  for (const t of result.trace) {
    if (t.state === "enabled" && t.applies === "no" && /P2|home organization/.test(t.reason)) out.push(`"${t.policyName}": ${t.reason}`);
  }
  for (const x of result.enforced.partialCoverage) {
    out.push(`"${x.policyName}" ${x.effect === "block" ? "blocks" : "adds checks for"} ${x.coverage} only, so the rest of Office 365 isn't covered`);
  }
  if (out.length === 0) out.push("No enabled policy targets this situation");
  return out;
}

export function classifySituation(situation: SigninSituation, result: CaEvaluationResult): { verdict: SituationVerdict; label: string; text: string } {
  const e = result.enforced;
  if (e.outcome === "indeterminate") {
    return {
      verdict: "unknown",
      label: "Can't confirm",
      text: `Can't confirm: ${e.uncertainPolicies.map((u) => `"${u.policyName}" (${u.reason})`).join("; ")}`,
    };
  }
  if (e.outcome === "blocked") {
    const text = `Blocked by ${e.blockedBy.map((b) => `"${b.policyName}"${b.reason !== "Blocks access" ? ` (${b.reason.replace(/^Policy /, "")})` : ""}`).join(", ")}`;
    return situation.goodPath ? { verdict: "partial", label: "Blocked", text: `${text}. Guests can't collaborate in this situation.` } : { verdict: "prevented", label: "Blocked", text };
  }
  const partial = e.partialCoverage.filter((x) => x.effect === "block");
  const partialText = partial.length > 0 ? ` ${partial.map((x) => `"${x.policyName}" blocks ${x.coverage} only`).join("; ")}.` : "";
  if (e.outcome === "challenged") {
    const strongest = (["phishingResistantMfa", "passwordChange", "appProtection", "authenticationStrength", "mfa", "other"] as const).find((k) => e.requirementKinds.includes(k))!;
    const label = REQUIREMENT_VERDICT_LABEL[strongest];
    const text = `Allowed after ${describeRequirements(result)}.${partialText}`;
    return situation.goodPath ? { verdict: "prevented", label: "Working as intended", text } : { verdict: "partial", label, text };
  }
  if (partial.length > 0 && !situation.goodPath) {
    return { verdict: "partial", label: "Partly blocked", text: `Partly blocked:${partialText} The rest of Office 365 stays reachable.` };
  }
  return { verdict: "notPrevented", label: "Allowed", text: "Allowed: nothing stops this sign-in" };
}

export function runSituation(
  situation: SigninSituation,
  user: CaSimUser,
  env: CaEnvironment,
  opts: SituationRunOptions,
  breakGlass: BreakGlassCandidate[],
  snapshot?: TenantSecuritySnapshot
): SituationRunResult {
  const notes: string[] = [];
  if (situation.caveat) notes.push(situation.caveat);

  if (situation.context.location === "trusted" && trustedIpLocationIds(env).length === 0) {
    return {
      situation,
      verdict: "unknown",
      verdictLabel: "No trusted locations",
      outcomeText: env.namedLocations
        ? "This tenant has no trusted IP named locations, so a \"known location\" sign-in can't be simulated."
        : "Named locations haven't been synced yet, so a \"known location\" sign-in can't be simulated.",
      whyNotBlocked: [],
      fixes: [],
      notes: [...notes, "Define your office egress IP ranges as a trusted named location to make location-based policies meaningful."],
    };
  }
  if (situation.context.location === "foreign" && opts.foreignCountry.toUpperCase() === opts.homeCountry.toUpperCase()) {
    notes.push("The foreign country is the same as the home country - pick a different one.");
  }

  const ctx = buildSituationContext(situation, "attack", user, env, opts);
  const result = evaluateSignIn(ctx, env);
  const { verdict, label, text } = classifySituation(situation, result);
  notes.push(...result.notes);

  const baseline = CA_BASELINE_STANDARDS.find((b) => b.code === situation.baselineCode);
  const fixes =
    verdict === "prevented"
      ? []
      : recommendFixes(ctx, env, situation.desired, {
          baselineCode: situation.baselineCode,
          baselineName: baseline?.name,
          newPolicyDescription: situation.newPolicyDescription,
          breakGlass,
          normalContext: buildSituationContext(situation, "normal", user, env, opts),
        });

  let evidence: SituationRunResult["evidence"];
  if (snapshot && situation.evidence && user.userPrincipalName) {
    const upn = user.userPrincipalName.toLowerCase();
    const matched = (snapshot.signIns || []).filter((e) => e.userPrincipalName?.toLowerCase() === upn && situation.evidence!(e, opts.homeCountry));
    evidence = { matched: matched.length, succeeded: matched.filter((e) => e.status === "success").length, coverage: describeSignInCoverage(getSignInCoverage(snapshot)) };
  }

  return {
    situation,
    verdict,
    verdictLabel: label,
    outcomeText: text,
    whyNotBlocked: result.enforced.outcome === "blocked" ? [] : explainNotBlocked(result),
    result,
    fixes,
    evidence,
    notes,
  };
}

export function runSituationsForPersona(
  snapshot: TenantSecuritySnapshot,
  persona: SituationPersona,
  user: CaSimUser,
  opts: SituationRunOptions
): SituationRunResult[] {
  const env = buildCaEnvironment(snapshot);
  const breakGlass = detectLikelyBreakGlassAccounts(snapshot);
  return SIGNIN_SITUATIONS.filter((s) => s.persona === persona).map((s) => runSituation(s, user, env, opts, breakGlass, snapshot));
}

export function summarizeVerdicts(results: SituationRunResult[]): Record<SituationVerdict, number> {
  const counts: Record<SituationVerdict, number> = { prevented: 0, partial: 0, notPrevented: 0, unknown: 0 };
  for (const r of results) counts[r.verdict] += 1;
  return counts;
}
