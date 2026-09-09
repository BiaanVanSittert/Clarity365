import React, { useEffect, useMemo, useState } from "react";
import { TenantSecuritySnapshot, AsrRuleActivitySummary, AsrDetectionEvent } from "@/lib/types";
import { ASR_RULE_DEFINITIONS, AsrRuleDefinition } from "@/lib/data/asr-rule-definitions";
import { classifyAsrRuleTier, ASR_TIER_LABEL, ASR_TIER_SEVERITY, AsrTier } from "@/lib/services/asr-rule-matcher";
import { hasDefenderForEndpointCapability } from "@/lib/utils/defender-for-endpoint";
import { Drawer } from "../common/Drawer";
import {
  ShieldHalf,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Eye,
  Info,
  Copy,
  Check,
  Server,
  Activity,
  ChevronRight,
  ChevronDown,
  AlertTriangle,
} from "lucide-react";

interface AsrRulesModuleProps {
  snapshot: TenantSecuritySnapshot;
}

// A rule with no telemetry and a narrow (server-only) applicability is
// excluded from the headline tier counts so a pure-cloud tenant isn't shown
// an inflated gap count for something it has no way to act on. It still
// appears in the list, just visibly tagged instead of counted.
const SERVER_ONLY_RULE_IDS = new Set(["a8f5898e-1dc8-49a9-9878-85004b8a61e6"]);

const MODE_LABEL: Record<string, string> = {
  not_configured: "Not Configured",
  audit: "Audit",
  warn: "Warn",
  block: "Block",
};

const TIER_ICON: Record<AsrTier, React.ElementType> = {
  critical: ShieldX,
  gap: ShieldAlert,
  in_progress: Eye,
  protected: ShieldCheck,
};

const TIER_CHIP_CLASSES: Record<AsrTier, { active: string; inactive: string; text: string }> = {
  critical: {
    active: "bg-rose-900 dark:bg-rose-950 border-rose-950 dark:border-rose-800 ring-1 ring-rose-900",
    inactive: "bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-900 hover:bg-rose-100/60",
    text: "text-rose-900 dark:text-rose-300",
  },
  gap: {
    active: "bg-red-100 dark:bg-red-950/70 border-red-500 ring-1 ring-red-500",
    inactive: "bg-red-50 dark:bg-red-950/30 border-red-300 dark:border-red-800 hover:bg-red-100/60",
    text: "text-red-800 dark:text-red-400",
  },
  in_progress: {
    active: "bg-orange-100 dark:bg-orange-950/70 border-orange-500 ring-1 ring-orange-500",
    inactive: "bg-orange-50 dark:bg-orange-950/30 border-orange-300 dark:border-orange-800 hover:bg-orange-100/60",
    text: "text-orange-800 dark:text-orange-400",
  },
  protected: {
    active: "bg-emerald-100 dark:bg-emerald-950/70 border-emerald-500 ring-1 ring-emerald-500",
    inactive: "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-300 dark:border-emerald-800 hover:bg-emerald-100/60",
    text: "text-emerald-800 dark:text-emerald-400",
  },
};

const TIER_DOT_CLASSES: Record<AsrTier, string> = {
  critical: "bg-rose-800",
  gap: "bg-red-500",
  in_progress: "bg-orange-500",
  protected: "bg-emerald-500",
};

const TIER_BADGE_CLASSES: Record<AsrTier, string> = {
  critical: "bg-rose-900 dark:bg-rose-950 text-white border-rose-950 dark:border-rose-800 font-bold",
  gap: "bg-red-50 dark:bg-red-950 text-red-800 dark:text-red-400 border-red-300 dark:border-red-800",
  in_progress: "bg-orange-50 dark:bg-orange-950 text-orange-800 dark:text-orange-400 border-orange-300 dark:border-orange-800",
  protected: "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800",
};

const TIER_ORDER: AsrTier[] = ["critical", "gap", "in_progress", "protected"];

export const AsrRulesModule: React.FC<AsrRulesModuleProps> = ({ snapshot }) => {
  const [tierFilter, setTierFilter] = useState<AsrTier | "all">("all");
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Detection activity (Advanced Hunting) - on demand, not part of the
  // snapshot. null = still loading; an error means the tenant likely lacks
  // ThreatHunting.Read.All or a Defender for Endpoint P2 license, which is
  // an expected, non-alarming outcome, not a bug.
  const [activitySummaries, setActivitySummaries] = useState<Record<string, AsrRuleActivitySummary> | null>(null);
  const [activityError, setActivityError] = useState<string | null>(null);

  const [eventsByRule, setEventsByRule] = useState<Record<string, AsrDetectionEvent[]>>({});
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [expandedEventIndex, setExpandedEventIndex] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    setActivitySummaries(null);
    setActivityError(null);
    fetch(`/api/tenants/${snapshot.tenant.id}/asr-detections`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    })
      .then((res) => res.json())
      .then((data) => {
        if (cancelled) return;
        if (data.success) {
          const byId: Record<string, AsrRuleActivitySummary> = {};
          for (const s of data.summaries as AsrRuleActivitySummary[]) byId[s.ruleId] = s;
          setActivitySummaries(byId);
        } else {
          setActivityError(data.error || "Detection activity unavailable.");
        }
      })
      .catch(() => {
        if (!cancelled) setActivityError("Detection activity unavailable.");
      });
    return () => {
      cancelled = true;
    };
  }, [snapshot.tenant.id]);

  const hasDefenderForEndpoint = hasDefenderForEndpointCapability(snapshot);

  const asrSyncErrors = (snapshot.syncHealth?.errors || []).filter((e) => e.startsWith("ASR Rules"));

  const ruleStateById = new Map((snapshot.asrRules || []).map((r) => [r.ruleId, r]));

  const rulesWithTier = useMemo(
    () =>
      ASR_RULE_DEFINITIONS.map((def) => {
        const state = ruleStateById.get(def.id);
        const mode = state?.mode || "not_configured";
        const tier = classifyAsrRuleTier({ mode, isStandardProtection: def.category === "standard" });
        return { def, mode, tier, sourcePolicyNames: state?.sourcePolicyNames, hasConflict: state?.hasConflict };
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [snapshot.asrRules]
  );

  const countableRules = rulesWithTier.filter((r) => !SERVER_ONLY_RULE_IDS.has(r.def.id));
  const tierCounts = TIER_ORDER.reduce((acc, tier) => {
    acc[tier] = countableRules.filter((r) => r.tier === tier).length;
    return acc;
  }, {} as Record<AsrTier, number>);

  const filteredRules = rulesWithTier
    .filter((r) => tierFilter === "all" || r.tier === tierFilter)
    .sort((a, b) => ASR_TIER_SEVERITY[a.tier] - ASR_TIER_SEVERITY[b.tier]);

  const standardRules = filteredRules.filter((r) => r.def.category === "standard");
  const otherRules = filteredRules.filter((r) => r.def.category === "other");

  const selected = selectedRuleId ? rulesWithTier.find((r) => r.def.id === selectedRuleId) : undefined;

  useEffect(() => {
    setExpandedEventIndex(null);
    setEventsError(null);
    if (!selected || !selected.def.hasAdvancedHuntingTelemetry) return;
    if (eventsByRule[selected.def.id]) return; // already cached this session

    let cancelled = false;
    setEventsLoading(true);
    fetch(`/api/tenants/${snapshot.tenant.id}/asr-detections`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ruleId: selected.def.id }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (cancelled) return;
        if (data.success) {
          setEventsByRule((prev) => ({ ...prev, [selected.def.id]: data.events || [] }));
        } else {
          setEventsError(data.error || "Detection events unavailable.");
        }
      })
      .catch(() => {
        if (!cancelled) setEventsError("Detection events unavailable.");
      })
      .finally(() => {
        if (!cancelled) setEventsLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedRuleId]);

  const handleCopyGuidance = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!hasDefenderForEndpoint) {
    return (
      <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
        <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex items-center gap-2.5">
          <ShieldHalf size={18} className="text-slate-800 dark:text-slate-200" />
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">Attack Surface Reduction</h2>
        </div>
        <div className="bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm p-8 flex flex-col items-center text-center gap-2">
          <Info size={22} className="text-slate-400" />
          <div className="text-sm font-semibold text-slate-800 dark:text-slate-200">Requires Microsoft Defender for Endpoint</div>
          <div className="text-xs text-slate-500 dark:text-slate-400 max-w-md">
            Attack Surface Reduction rules are a Defender for Endpoint capability. This tenant has no Defender for Endpoint P1 or
            P2 license detected, so there is nothing to configure yet.
          </div>
        </div>
      </div>
    );
  }

  const renderRuleRow = (r: { def: AsrRuleDefinition; mode: string; tier: AsrTier; sourcePolicyNames?: string[]; hasConflict?: boolean }) => {
    const isServerOnly = SERVER_ONLY_RULE_IDS.has(r.def.id);
    const activity = activitySummaries?.[r.def.id];
    const activityCount = activity ? activity.auditHitCount + activity.blockHitCount + activity.warnBypassedCount : 0;
    return (
      <button
        key={r.def.id}
        onClick={() => setSelectedRuleId(r.def.id)}
        className="w-full text-left px-3.5 py-2.5 flex items-center justify-between gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors border-b border-[#E2E8F0] dark:border-slate-700/60 last:border-b-0"
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <span className={`w-2 h-2 rounded-full shrink-0 ${TIER_DOT_CLASSES[r.tier]}`} />
          <span className="text-xs font-medium text-slate-800 dark:text-slate-200 truncate">{r.def.name}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {r.hasConflict && (
            <span
              title="Two or more policies set this rule to different modes - per Intune's merge behavior, none of them are actually being enforced until the conflict is resolved"
              className="inline-flex items-center gap-1 text-[9px] font-mono uppercase font-bold px-1.5 py-0.5 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border border-amber-300 dark:border-amber-800 rounded-sm"
            >
              <AlertTriangle size={9} />
              Conflict
            </span>
          )}
          {isServerOnly && (
            <span className="inline-flex items-center gap-1 text-[9px] font-mono uppercase font-bold px-1.5 py-0.5 bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 border border-slate-300 dark:border-slate-600 rounded-sm">
              <Server size={9} />
              Server Only
            </span>
          )}
          {activityCount > 0 && (
            <span
              title="Detection activity in the last 30 days - not a tier color on purpose, since a Block rule catching something is the system working, not a fault"
              className="inline-flex items-center gap-1 text-[9px] font-mono font-semibold px-1.5 py-0.5 bg-sky-50 dark:bg-sky-950 text-sky-700 dark:text-sky-400 border border-sky-300 dark:border-sky-800 rounded-sm"
            >
              <Activity size={9} />
              {activityCount} (30d)
            </span>
          )}
          <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded-sm border ${TIER_BADGE_CLASSES[r.tier]}`}>
            {MODE_LABEL[r.mode]}
          </span>
        </div>
      </button>
    );
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm">
        <div className="flex items-center gap-2">
          <ShieldHalf size={18} className="text-slate-800 dark:text-slate-200" />
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">Attack Surface Reduction</h2>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
          Every Defender ASR rule, colored by current state. Click a rule for its full description and setup guidance.
        </p>
      </div>

      {/* Tier legend and filter chips */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        {TIER_ORDER.map((tier) => {
          const Icon = TIER_ICON[tier];
          const isActive = tierFilter === tier;
          const classes = TIER_CHIP_CLASSES[tier];
          return (
            <div
              key={tier}
              onClick={() => setTierFilter(isActive ? "all" : tier)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setTierFilter(isActive ? "all" : tier))}
              title={ASR_TIER_LABEL[tier].description}
              className={`p-2.5 border rounded-sm cursor-pointer transition-colors ${isActive ? classes.active : classes.inactive}`}
            >
              <div className={`flex items-center gap-1.5 text-[10px] uppercase font-mono font-semibold ${tier === "critical" && isActive ? "text-white" : classes.text}`}>
                <Icon size={13} />
                <span>{ASR_TIER_LABEL[tier].label}</span>
              </div>
              <div className={`text-xl font-bold font-mono tabular-nums mt-0.5 ${tier === "critical" && isActive ? "text-white" : classes.text}`}>
                {tierCounts[tier]}
              </div>
            </div>
          );
        })}
      </div>

      {asrSyncErrors.length > 0 && (
        <div className="p-3 bg-rose-50 dark:bg-red-950 border border-rose-300 dark:border-red-800 text-rose-900 dark:text-red-300 text-xs rounded-sm space-y-1.5">
          <div className="flex items-center gap-2 font-semibold">
            <AlertTriangle size={14} className="text-rose-600 dark:text-red-400" />
            <span>ASR configuration sync error - rule states below may be incomplete</span>
          </div>
          {asrSyncErrors.map((err, i) => (
            <div key={i} className="text-[11px] font-mono bg-white/70 dark:bg-slate-900/50 p-1.5 border border-rose-200 dark:border-red-800 rounded-sm">
              {err}
            </div>
          ))}
        </div>
      )}

      {activityError && (
        <div className="flex items-center gap-2 px-3.5 py-2 bg-slate-50 dark:bg-slate-800/60 border border-[#E2E8F0] dark:border-slate-700 rounded-sm text-[11px] text-slate-500 dark:text-slate-400">
          <Info size={13} className="shrink-0" />
          <span>Detection activity unavailable: {activityError}</span>
        </div>
      )}

      {/* Standard Protection */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Standard Protection Rules</h3>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Microsoft's own recommended starting set: low friction, high value.</p>
        </div>
        {standardRules.length === 0 ? (
          <div className="p-4 text-center text-xs text-slate-500 dark:text-slate-400">No rules match the current filter.</div>
        ) : (
          standardRules.map(renderRuleRow)
        )}
      </div>

      {/* Other ASR Rules */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Other ASR Rules</h3>
        </div>
        {otherRules.length === 0 ? (
          <div className="p-4 text-center text-xs text-slate-500 dark:text-slate-400">No rules match the current filter.</div>
        ) : (
          otherRules.map(renderRuleRow)
        )}
      </div>

      {/* Rule Detail Drawer */}
      <Drawer
        isOpen={!!selected}
        onClose={() => setSelectedRuleId(null)}
        title={selected?.def.name || ""}
        subtitle={selected ? ASR_TIER_LABEL[selected.tier].label : undefined}
        width="lg"
      >
        {selected && (
          <div className="space-y-4 text-xs">
            <div>
              <div className="text-[10px] font-mono uppercase font-semibold text-slate-500 dark:text-slate-400 mb-1">Current State</div>
              <span className={`inline-flex items-center gap-1 text-[11px] font-mono font-semibold px-2 py-0.5 rounded-sm border ${TIER_BADGE_CLASSES[selected.tier]}`}>
                {MODE_LABEL[selected.mode]}
              </span>
              {!!selected.sourcePolicyNames?.length && (
                <span className="ml-2 text-[11px] text-slate-500 dark:text-slate-400">via {selected.sourcePolicyNames.join(", ")}</span>
              )}
            </div>

            {selected.hasConflict && (
              <div className="bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 rounded-sm p-2.5 flex items-start gap-2">
                <AlertTriangle size={14} className="text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                <div className="text-[11px] text-amber-800 dark:text-amber-300">
                  Conflicting configuration: {selected.sourcePolicyNames?.length || 0} sources set this rule to different modes
                  ({selected.sourcePolicyNames?.join(", ")}). Per Intune's policy merge behavior, none of these settings are
                  actually being enforced on the device until the conflict is resolved.
                </div>
              </div>
            )}

            <div>
              <div className="text-[10px] font-mono uppercase font-semibold text-slate-500 dark:text-slate-400 mb-1">Description</div>
              <p className="text-slate-700 dark:text-slate-300 leading-relaxed">{selected.def.description}</p>
            </div>

            <div>
              <div className="text-[10px] font-mono uppercase font-semibold text-slate-500 dark:text-slate-400 mb-1">Risk Mitigated</div>
              <p className="text-slate-700 dark:text-slate-300 leading-relaxed">{selected.def.riskMitigated}</p>
            </div>

            {(!selected.def.supportsWarnMode || !selected.def.hasAdvancedHuntingTelemetry) && (
              <div className="bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 rounded-sm p-2.5 flex items-start gap-2">
                <Info size={14} className="text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                <div className="text-[11px] text-amber-800 dark:text-amber-300">
                  {!selected.def.supportsWarnMode && <div>This rule does not support Warn mode - only Audit and Block.</div>}
                  {!selected.def.hasAdvancedHuntingTelemetry && (
                    <div>This rule produces no Advanced Hunting telemetry - detection activity can't be reported for it.</div>
                  )}
                </div>
              </div>
            )}

            {selected.def.hasAdvancedHuntingTelemetry && (
              <div>
                <div className="text-[10px] font-mono uppercase font-semibold text-slate-500 dark:text-slate-400 mb-1">
                  Detection Activity (Last 30 Days)
                </div>

                {(() => {
                  const activity = activitySummaries?.[selected.def.id];
                  const events = eventsByRule[selected.def.id];

                  if (!activity && !activityError) {
                    return <div className="text-slate-400 dark:text-slate-500">Loading...</div>;
                  }
                  if (activityError) {
                    return <div className="text-slate-400 dark:text-slate-500">Unavailable: {activityError}</div>;
                  }

                  const total = (activity?.auditHitCount || 0) + (activity?.blockHitCount || 0) + (activity?.warnBypassedCount || 0);
                  if (total === 0) {
                    return <div className="text-slate-400 dark:text-slate-500">No activity recorded.</div>;
                  }

                  return (
                    <div className="space-y-2">
                      <div className="flex items-center gap-3 text-[11px] text-slate-600 dark:text-slate-300">
                        {!!activity?.blockHitCount && <span>{activity.blockHitCount} blocked</span>}
                        {!!activity?.auditHitCount && <span>{activity.auditHitCount} audited</span>}
                        {!!activity?.warnBypassedCount && <span>{activity.warnBypassedCount} warn bypassed</span>}
                      </div>

                      {eventsLoading && !events && <div className="text-slate-400 dark:text-slate-500">Loading events...</div>}
                      {eventsError && <div className="text-slate-400 dark:text-slate-500">{eventsError}</div>}

                      {events && events.length > 0 && (
                        <div className="border border-[#E2E8F0] dark:border-slate-700 rounded-sm overflow-hidden">
                          {events.map((ev, i) => {
                            const isExpanded = expandedEventIndex === i;
                            const kind = ev.actionType.endsWith("Blocked")
                              ? "Blocked"
                              : ev.actionType.endsWith("WarnBypassed")
                              ? "Warn Bypassed"
                              : "Audited";
                            return (
                              <div key={i} className="border-b border-[#E2E8F0] dark:border-slate-700 last:border-b-0">
                                <button
                                  onClick={() => setExpandedEventIndex(isExpanded ? null : i)}
                                  className="w-full text-left px-2.5 py-2 flex items-center justify-between gap-2 hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors"
                                >
                                  <div className="flex items-center gap-2 min-w-0">
                                    {isExpanded ? <ChevronDown size={11} className="shrink-0 text-slate-400" /> : <ChevronRight size={11} className="shrink-0 text-slate-400" />}
                                    <span className="font-mono text-[10px] text-slate-500 dark:text-slate-400 shrink-0">
                                      {new Date(ev.timestamp).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                                    </span>
                                    <span className="text-[11px] text-slate-700 dark:text-slate-300 truncate">{ev.deviceName}</span>
                                    {ev.fileName && <span className="font-mono text-[10px] text-slate-400 truncate">{ev.fileName}</span>}
                                  </div>
                                  <span
                                    className={`text-[9px] font-mono font-semibold uppercase px-1.5 py-0.5 rounded-sm border shrink-0 ${
                                      kind === "Blocked"
                                        ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800"
                                        : "bg-sky-50 dark:bg-sky-950 text-sky-700 dark:text-sky-400 border-sky-300 dark:border-sky-800"
                                    }`}
                                  >
                                    {kind}
                                  </span>
                                </button>
                                {isExpanded && (
                                  <div className="px-2.5 pb-2.5 pt-0.5 bg-[#F8FAFC] dark:bg-slate-900/50">
                                    <div className="font-mono text-[10px] text-slate-600 dark:text-slate-400 space-y-0.5">
                                      {ev.initiatingProcessFileName && <div>Initiating process: {ev.initiatingProcessFileName}</div>}
                                      {ev.initiatingProcessCommandLine && <div>Command line: {ev.initiatingProcessCommandLine}</div>}
                                      {ev.folderPath && <div>Path: {ev.folderPath}</div>}
                                      {ev.additionalFields &&
                                        Object.entries(ev.additionalFields).map(([k, v]) => (
                                          <div key={k}>
                                            {k}: {String(v)}
                                          </div>
                                        ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })()}
              </div>
            )}

            <div>
              <div className="flex items-center justify-between mb-1">
                <div className="text-[10px] font-mono uppercase font-semibold text-slate-500 dark:text-slate-400">How to Enable This Rule</div>
                <button
                  onClick={() => handleCopyGuidance(selected.def.manualSetupGuidance)}
                  className="flex items-center gap-1 text-[10px] font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100"
                >
                  {copied ? <Check size={11} className="text-emerald-500" /> : <Copy size={11} />}
                  <span>{copied ? "Copied" : "Copy"}</span>
                </button>
              </div>
              <pre className="whitespace-pre-wrap font-mono text-[11px] text-slate-700 dark:text-slate-300 bg-[#F8FAFC] dark:bg-slate-900 border border-[#E2E8F0] dark:border-slate-700 rounded-sm p-3 leading-relaxed">
                {selected.def.manualSetupGuidance}
              </pre>
              <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1.5">
                Always start in Audit mode and review activity for 7-14 days before promoting to Block.
              </p>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};
