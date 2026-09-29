// Pulled out of graph-client.ts for the same reason mfa-classifier.ts was:
// the mapping/synthesis rules here are unit-testable pure functions that
// don't need a live Graph response to exercise.
import { ASR_RULE_DEFINITIONS } from "../data/asr-rule-definitions";
import { AsrRuleActivitySummary, AsrRuleMode, AsrDetectionTimeRange } from "../types";

export type AsrDetectionKind = "audit" | "block" | "warn_bypassed";

// Resolves a raw Advanced Hunting DeviceEvents.ActionType (e.g.
// "AsrRansomwareBlocked") back to the rule it belongs to and which bucket it
// counts toward, using the real advancedHuntingActionTypes lists already
// verified in asr-rule-definitions.ts. Returns null for anything that isn't
// a known ASR action type (defensive - Advanced Hunting could add new ones).
export function mapActionTypeToRule(actionType: string): { ruleId: string; kind: AsrDetectionKind } | null {
  for (const def of ASR_RULE_DEFINITIONS) {
    if (!def.advancedHuntingActionTypes.includes(actionType)) continue;
    if (actionType.endsWith("WarnBypassed")) return { ruleId: def.id, kind: "warn_bypassed" };
    if (actionType.endsWith("Blocked")) return { ruleId: def.id, kind: "block" };
    if (actionType.endsWith("Audited")) return { ruleId: def.id, kind: "audit" };
    return null;
  }
  return null;
}

// Turns the aggregate KQL query's natural shape ({ActionType: count}) into
// the full 19-rule array, zero-filled for every rule with no hits, so
// callers can always look up any rule by id without a null check.
export function buildActivitySummaries(actionTypeCounts: Record<string, number>): AsrRuleActivitySummary[] {
  const byRule = new Map<string, AsrRuleActivitySummary>(
    ASR_RULE_DEFINITIONS.map((def) => [def.id, { ruleId: def.id, auditHitCount: 0, blockHitCount: 0, warnBypassedCount: 0 }])
  );

  for (const [actionType, count] of Object.entries(actionTypeCounts)) {
    const resolved = mapActionTypeToRule(actionType);
    if (!resolved) continue;
    const summary = byRule.get(resolved.ruleId);
    if (!summary) continue;
    if (resolved.kind === "audit") summary.auditHitCount += count;
    else if (resolved.kind === "block") summary.blockHitCount += count;
    else summary.warnBypassedCount += count;
  }

  return Array.from(byRule.values());
}

// Deterministic (not random) so repeated fetches within a session show the
// same numbers instead of flickering - a simple string hash seeded by
// tenant id + rule id.
function stableHash(input: string): number {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = (hash * 31 + input.charCodeAt(i)) >>> 0;
  }
  return hash;
}

// Scales the base (30-day) synthesized count for a shorter/longer selected
// window, so the demo experience isn't identical regardless of which range
// is picked - deliberately not a live query against mock data (there isn't
// one), just a proportional adjustment of the same deterministic base.
const TIME_RANGE_SCALE: Record<AsrDetectionTimeRange, number> = {
  "7d": 0.25,
  "30d": 1,
  all: 3,
};

// A rule that isn't enforcing anything can't have logged a detection for it -
// Not Configured and the one rule with no Advanced Hunting telemetry
// (Webshell creation) always synthesize to zero, so the mock demo never
// shows activity for something that couldn't possibly have produced it.
export function synthesizeMockActivity(
  ruleStates: { ruleId: string; mode: AsrRuleMode }[],
  seed: string,
  timeRange: AsrDetectionTimeRange = "30d"
): AsrRuleActivitySummary[] {
  const modeByRule = new Map(ruleStates.map((r) => [r.ruleId, r.mode]));
  const scale = TIME_RANGE_SCALE[timeRange];

  return ASR_RULE_DEFINITIONS.map((def) => {
    const mode = modeByRule.get(def.id) || "not_configured";
    if (!def.hasAdvancedHuntingTelemetry || mode === "not_configured") {
      return { ruleId: def.id, auditHitCount: 0, blockHitCount: 0, warnBypassedCount: 0 };
    }

    const hash = stableHash(`${seed}:${def.id}`);
    if (mode === "block") {
      return { ruleId: def.id, auditHitCount: 0, blockHitCount: Math.round((hash % 7) * scale), warnBypassedCount: 0 };
    }
    // audit or warn: logs everything it would have stopped, so a larger range.
    const warnBypassedCount = def.advancedHuntingActionTypes.some((t) => t.endsWith("WarnBypassed"))
      ? Math.round(((hash >> 4) % 3) * scale)
      : 0;
    return { ruleId: def.id, auditHitCount: Math.round((hash % 16) * scale), blockHitCount: 0, warnBypassedCount };
  });
}
