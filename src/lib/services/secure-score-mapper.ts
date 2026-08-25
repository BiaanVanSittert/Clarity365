import { SecureScoreControl, SecureScoreHistoryPoint } from "../types";

// Maps Microsoft Graph's /security/secureScores + /security/secureScoreControlProfiles
// responses into Clarity365's SecureScoreControl shape. Graph splits "current score
// achieved" (on a secureScores entry's controlScores[], keyed by controlName) from
// "control definition" (title/maxScore/remediation, on the SEPARATE
// secureScoreControlProfiles list, joined by id === controlName) — both are needed
// to build one control row. Pulled out of graph-client.ts so this join/normalization
// logic is unit-testable without a live Graph response driving it.

const CATEGORY_MAP: Record<string, SecureScoreControl["category"]> = {
  identity: "Identity",
  device: "Device",
  apps: "Apps",
  data: "Data",
};

export function normalizeCategory(raw: string | undefined | null): SecureScoreControl["category"] {
  const lower = (raw || "").toLowerCase();
  // Fallback bucket for any Graph category outside the current 4-value union
  // (e.g. "Infrastructure") — exact real-world values should be confirmed
  // against a live tenant.
  return CATEGORY_MAP[lower] || "Apps";
}

const COST_IMPACT_MAP: Record<string, "Low" | "Moderate" | "High"> = {
  low: "Low",
  moderate: "Moderate",
  high: "High",
};

export function normalizeCostOrImpact(raw: string | undefined | null): "Low" | "Moderate" | "High" {
  const lower = (raw || "").toLowerCase();
  return COST_IMPACT_MAP[lower] || "Moderate";
}

export function deriveControlStatus(scoreCurrent: number, scoreMax: number): SecureScoreControl["status"] {
  if (scoreMax <= 0) return "Unresolved";
  if (scoreCurrent >= scoreMax) return "Completed";
  if (scoreCurrent <= 0) return "Unresolved";
  return "Partial";
}

const ACTION_TYPE_MAP: Record<string, SecureScoreControl["actionType"]> = {
  config: "Configuration",
  configuration: "Configuration",
  behavior: "Requirement",
  review: "Requirement",
  purchaseservice: "Policy",
};

export function normalizeActionType(raw: string | undefined | null): SecureScoreControl["actionType"] {
  const lower = (raw || "").toLowerCase();
  return ACTION_TYPE_MAP[lower] || "Configuration";
}

export interface RawControlScore {
  controlName: string;
  score?: number;
  controlCategory?: string;
}

export interface RawControlProfile {
  id: string;
  title?: string;
  maxScore?: number;
  controlCategory?: string;
  implementationCost?: string;
  userImpact?: string;
  actionType?: string;
  remediation?: string | { description?: string };
}

export function mapSecureScoreControl(scoreEntry: RawControlScore, profile: RawControlProfile | undefined): SecureScoreControl {
  const scoreCurrent = scoreEntry.score ?? 0;
  const scoreMax = profile?.maxScore ?? 0;
  const remediationSummary =
    typeof profile?.remediation === "string"
      ? profile.remediation
      : profile?.remediation?.description || "No remediation guidance available for this control.";

  return {
    id: scoreEntry.controlName,
    title: profile?.title || scoreEntry.controlName,
    category: normalizeCategory(profile?.controlCategory || scoreEntry.controlCategory),
    scoreCurrent,
    scoreMax,
    implementationCost: normalizeCostOrImpact(profile?.implementationCost),
    userImpact: normalizeCostOrImpact(profile?.userImpact),
    status: deriveControlStatus(scoreCurrent, scoreMax),
    actionType: normalizeActionType(profile?.actionType),
    remediationSummary,
  };
}

interface ScoreSnapshotEntry {
  createdDateTime: string;
  currentScore: number;
  maxScore: number;
}

function sortByDateDesc<T extends { createdDateTime: string }>(entries: T[]): T[] {
  return [...entries].sort((a, b) => new Date(b.createdDateTime).getTime() - new Date(a.createdDateTime).getTime());
}

// Chronological (oldest-first) order, matching the shape the trend chart expects.
export function buildSecureScoreHistory(rawEntries: ScoreSnapshotEntry[]): SecureScoreHistoryPoint[] {
  return sortByDateDesc(rawEntries)
    .filter((e) => e.maxScore > 0)
    .reverse()
    .map((e) => ({
      date: e.createdDateTime.split("T")[0],
      score: e.currentScore,
      maxScore: e.maxScore,
      percentage: Math.round((e.currentScore / e.maxScore) * 1000) / 10,
    }));
}

// Percentage-point delta between the most recent entry and the closest entry
// at or before `daysAgo` days earlier. Falls back to the oldest available
// entry if history doesn't reach back that far yet.
export function computeScoreDelta(rawEntries: ScoreSnapshotEntry[], daysAgo: number): number {
  const entries = sortByDateDesc(rawEntries);
  if (entries.length === 0) return 0;
  const latest = entries[0];
  if (latest.maxScore <= 0) return 0;

  const targetTime = new Date(latest.createdDateTime).getTime() - daysAgo * 86_400_000;
  let comparison = entries[entries.length - 1];
  for (const e of entries) {
    if (new Date(e.createdDateTime).getTime() <= targetTime) {
      comparison = e;
      break;
    }
  }
  if (!comparison || comparison.maxScore <= 0) return 0;

  const latestPct = (latest.currentScore / latest.maxScore) * 100;
  const comparisonPct = (comparison.currentScore / comparison.maxScore) * 100;
  return Math.round((latestPct - comparisonPct) * 10) / 10;
}

export function extractIndustryBenchmark(
  averageComparativeScores: { basis?: string; averageScore?: number }[] | undefined
): number {
  if (!averageComparativeScores || averageComparativeScores.length === 0) return 0;
  const allTenants = averageComparativeScores.find((s) => s.basis === "AllTenants");
  return allTenants?.averageScore ?? averageComparativeScores[0]?.averageScore ?? 0;
}
