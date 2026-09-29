"use client";

import React, { useMemo, useState } from "react";
import { Tenant } from "@/lib/types";
import {
  DATA_PROTECTION_RECOMMENDATIONS,
  REGULATION_LABELS,
  DATA_CATEGORY_LABELS,
  Regulation,
  DataCategory,
  DataProtectionCatalogEntry,
  LabelRecommendation,
} from "@/lib/data/data-protection-recommendations";
import {
  ShieldEllipsis,
  Copy,
  Check,
  ListChecks,
  Terminal,
  AlertTriangle,
  BookOpen,
  Sparkles,
  Link2,
  ArrowRight,
  Tags,
  Settings2,
  Wand2,
  Layers,
  Users2,
} from "lucide-react";

// Read-only, static-content module: unlike every other module in this app it
// does not read TenantSecuritySnapshot at all - see the "Delivery order
// (revised 2026-09-22)" note in ai-context-vault/Optimization/DLP &
// Sensitivity Labels Plan.md. This is deliberately a guidance library, not a
// live posture check - there is no read or write path to a real tenant's DLP
// policies or labels here. `tenant` is optional and used only to personalize
// the generated PowerShell script's policy-name prefix.
//
// Holds two kinds of entry in one catalog/list, discriminated by `"kind" in
// entry && entry.kind === "label"` (DLP entries carry no `kind` field at all -
// see DlpRecommendation's own comment) - per explicit user direction
// ("make it a category under the DLP"), sensitivity labels are a category
// within this same module, not a separate one. Added 2026-09-22.
//
// Styling deliberately mirrors SecureScoreModule.tsx/MfaAuditModule.tsx's
// house pattern (p-5 max-w-[1600px] wrapper, bordered header bar, rounded-sm
// cards, light/dark pairs on every color) rather than inventing a new look.
interface DataProtectionModuleProps {
  tenant?: Tenant | null;
}

export const DataProtectionModule: React.FC<DataProtectionModuleProps> = ({ tenant }) => {
  const [regulationFilter, setRegulationFilter] = useState<Regulation | "all">("all");
  const [categoryFilter, setCategoryFilter] = useState<DataCategory | "all">("all");
  const [kindFilter, setKindFilter] = useState<"all" | "dlp" | "label">("all");
  const [selectedId, setSelectedId] = useState<string | null>(
    DATA_PROTECTION_RECOMMENDATIONS[0]?.id || null
  );
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // A real type predicate, not just a boolean helper - lets TypeScript
  // narrow `selected`'s type inside each branch below, so the label-only
  // fields (labels, labelPolicySettings, autoLabeling) and the DLP-only
  // fields (sensitiveInfoTypes, recommendedLocations, ruleLogicSummary,
  // actions) are each only accessed where they actually exist.
  const isLabelEntry = (r: DataProtectionCatalogEntry): r is LabelRecommendation => "kind" in r && r.kind === "label";

  // The reverse of buildsOn - "which entries list this one as a
  // prerequisite" - computed on the fly rather than stored, so each label
  // entry only needs to declare its own backward dependency once (buildsOn)
  // and the forward direction ("what can I add next") never needs to be
  // kept in sync by hand.
  const extendedByIds = (id: string): string[] =>
    DATA_PROTECTION_RECOMMENDATIONS.filter((r) => isLabelEntry(r) && r.buildsOn?.includes(id)).map((r) => r.id);

  const filtered = useMemo(() => {
    return DATA_PROTECTION_RECOMMENDATIONS.filter((r) => {
      if (regulationFilter !== "all" && !r.regulations.includes(regulationFilter)) return false;
      if (categoryFilter !== "all" && !r.dataCategories.includes(categoryFilter)) return false;
      if (kindFilter !== "all" && (isLabelEntry(r) ? "label" : "dlp") !== kindFilter) return false;
      return true;
    });
  }, [regulationFilter, categoryFilter, kindFilter]);

  const selected: DataProtectionCatalogEntry | undefined =
    filtered.find((r) => r.id === selectedId) || filtered[0];
  const selectedIsLabel = selected ? isLabelEntry(selected) : false;

  const policyPrefix = tenant?.displayName || "Clarity365";

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Following a related-recommendation link can jump from deep in one entry's
  // content to the top of another - scroll back up so the new entry's header
  // (and the fact that the selection actually changed) is visible immediately.
  const handleSelectRelated = (id: string) => {
    setSelectedId(id);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const selectClass =
    "bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-600 rounded-sm px-2.5 py-1.5 text-xs text-slate-700 dark:text-slate-200";

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldEllipsis size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Data Protection Recommendations
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 max-w-2xl">
            DLP policies and sensitivity labels, by regulation and data type. Every recommendation here is applied by hand
            in the Microsoft Purview compliance portal - this module never reads or writes a tenant's real DLP/label
            configuration.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value as "all" | "dlp" | "label")}
            className={selectClass}
          >
            <option value="all">DLP &amp; Labels</option>
            <option value="dlp">DLP only</option>
            <option value="label">Sensitivity labels only</option>
          </select>
          <select
            value={regulationFilter}
            onChange={(e) => setRegulationFilter(e.target.value as Regulation | "all")}
            className={selectClass}
          >
            <option value="all">All regulations</option>
            {(Object.keys(REGULATION_LABELS) as Regulation[]).map((r) => (
              <option key={r} value={r}>
                {REGULATION_LABELS[r]}
              </option>
            ))}
          </select>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value as DataCategory | "all")}
            className={selectClass}
          >
            <option value="all">All data types</option>
            {(Object.keys(DATA_CATEGORY_LABELS) as DataCategory[]).map((c) => (
              <option key={c} value={c}>
                {DATA_CATEGORY_LABELS[c]}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-4">
        {/* Recommendation list */}
        <div className="space-y-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 px-1">
            {filtered.length} of {DATA_PROTECTION_RECOMMENDATIONS.length} recommendation(s)
          </h3>
          {filtered.length === 0 && (
            <div className="text-xs text-slate-500 dark:text-slate-400 border border-dashed border-[#CBD5E1] dark:border-slate-700 rounded-sm p-4">
              No recommendations match this filter.
            </div>
          )}
          {filtered.map((r) => {
            const isSelected = selected?.id === r.id;
            const isLabel = isLabelEntry(r);
            return (
              <button
                key={r.id}
                onClick={() => setSelectedId(r.id)}
                className={`w-full text-left border rounded-sm px-3 py-2.5 transition-colors ${
                  isSelected
                    ? "bg-slate-100 dark:bg-slate-700 border-slate-900 dark:border-slate-400 ring-1 ring-slate-900 dark:ring-slate-400"
                    : "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:border-slate-400 dark:hover:border-slate-500"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="text-xs font-bold text-slate-900 dark:text-slate-100 leading-snug">{r.title}</div>
                  <span
                    className={`flex-shrink-0 text-[9px] font-mono uppercase font-bold px-1.5 py-0.5 rounded-sm border ${
                      isLabel
                        ? "bg-indigo-100 dark:bg-indigo-950/70 text-indigo-700 dark:text-indigo-300 border-indigo-300 dark:border-indigo-800"
                        : "bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 border-slate-300 dark:border-slate-600"
                    }`}
                  >
                    {isLabel ? "Label" : "DLP"}
                  </span>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {r.regulations.map((reg) => (
                    <span
                      key={reg}
                      className="text-[9px] font-mono uppercase font-bold px-1.5 py-0.5 bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 border border-slate-300 dark:border-slate-600 rounded-sm"
                    >
                      {REGULATION_LABELS[reg]}
                    </span>
                  ))}
                </div>
                <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-1.5">
                  {r.minimumLicenseTier === "business_premium_e3" ? "Works on Business Premium/E3" : "Requires E5"}
                </div>
              </button>
            );
          })}
        </div>

        {/* Selected recommendation detail */}
        {selected ? (
          <div className="space-y-4">
            <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">{selected.title}</h3>
                    <span
                      className={`text-[9px] font-mono uppercase font-bold px-1.5 py-0.5 rounded-sm border ${
                        selectedIsLabel
                          ? "bg-indigo-100 dark:bg-indigo-950/70 text-indigo-700 dark:text-indigo-300 border-indigo-300 dark:border-indigo-800"
                          : "bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 border-slate-300 dark:border-slate-600"
                      }`}
                    >
                      {selectedIsLabel ? "Sensitivity Label" : "DLP"}
                    </span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {selected.dataCategories.map((c) => (
                      <span
                        key={c}
                        className="text-[10px] font-medium px-2 py-0.5 bg-[#F8FAFC] dark:bg-slate-900/50 text-slate-600 dark:text-slate-300 border border-[#E2E8F0] dark:border-slate-700 rounded-sm"
                      >
                        {DATA_CATEGORY_LABELS[c]}
                      </span>
                    ))}
                  </div>
                </div>
                <span
                  className={`text-[10px] font-bold px-2 py-1 rounded-sm border whitespace-nowrap ${
                    selected.minimumLicenseTier === "business_premium_e3"
                      ? "bg-emerald-100 dark:bg-emerald-950/70 text-emerald-700 dark:text-emerald-400 border-emerald-500"
                      : "bg-orange-100 dark:bg-orange-950/70 text-orange-700 dark:text-orange-400 border-orange-500"
                  }`}
                >
                  {selected.minimumLicenseTier === "business_premium_e3" ? "Business Premium / E3" : "E5 required"}
                </span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-300 mt-3 leading-relaxed">{selected.summary}</p>
              {/* Label-only: which clients this actually fits - added
                  2026-09-22 after direct user feedback that the four label
                  entries looked like interchangeable alternatives rather
                  than a foundation plus three optional layers on it. */}
              {isLabelEntry(selected) && (
                <div className="mt-3 pt-3 border-t border-[#E2E8F0] dark:border-slate-700 flex items-start gap-2">
                  <Users2 size={13} className="text-indigo-600 dark:text-indigo-400 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    <span className="font-bold text-indigo-700 dark:text-indigo-400">Recommended for: </span>
                    {selected.recommendedFor}
                  </p>
                </div>
              )}
            </div>

            {/* Deploy-first / sequence relationships (label entries only) -
                a genuinely different relationship from "Related
                recommendations" below: this means "you need that one
                deployed first," not "here's a related but separate
                question." Kept as its own section, with its own visual
                language, specifically so the two kinds of link never blur
                together the way they did before this section existed. */}
            {isLabelEntry(selected) && (selected.buildsOn?.length || extendedByIds(selected.id).length > 0) && (
              <div className="border border-amber-300 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-500/5 p-4 rounded-sm">
                <h4 className="text-xs font-bold uppercase tracking-wider text-amber-800 dark:text-amber-400 flex items-center gap-1.5 mb-2.5">
                  <Layers size={13} />
                  Deployment sequence
                </h4>
                {selected.buildsOn && selected.buildsOn.length > 0 && (
                  <div className="mb-2">
                    <div className="text-[11px] font-semibold text-amber-800 dark:text-amber-400 mb-1.5">
                      Deploy this first - not usable on its own:
                    </div>
                    <div className="space-y-1.5">
                      {selected.buildsOn.map((id) => {
                        const prereq = DATA_PROTECTION_RECOMMENDATIONS.find((r) => r.id === id);
                        if (!prereq) return null;
                        return (
                          <button
                            key={id}
                            onClick={() => handleSelectRelated(id)}
                            className="w-full flex items-center justify-between gap-2 text-left text-xs bg-white dark:bg-slate-800 border border-amber-200 dark:border-amber-900 rounded-sm px-3 py-2 hover:border-amber-400 transition-colors"
                          >
                            <span className="font-medium text-slate-800 dark:text-slate-200">{prereq.title}</span>
                            <ArrowRight size={12} className="text-amber-500 flex-shrink-0" />
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
                {extendedByIds(selected.id).length > 0 && (
                  <div>
                    <div className="text-[11px] font-semibold text-amber-800 dark:text-amber-400 mb-1.5">
                      Once this is deployed, optionally add:
                    </div>
                    <div className="space-y-1.5">
                      {extendedByIds(selected.id).map((id) => {
                        const next = DATA_PROTECTION_RECOMMENDATIONS.find((r) => r.id === id);
                        if (!next) return null;
                        return (
                          <button
                            key={id}
                            onClick={() => handleSelectRelated(id)}
                            className="w-full flex items-center justify-between gap-2 text-left text-xs bg-white dark:bg-slate-800 border border-amber-200 dark:border-amber-900 rounded-sm px-3 py-2 hover:border-amber-400 transition-colors"
                          >
                            <span className="font-medium text-slate-800 dark:text-slate-200">{next.title}</span>
                            <ArrowRight size={12} className="text-amber-500 flex-shrink-0" />
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Related recommendations - surfaced immediately after the header,
                not buried in caveats, so an entry that overlaps in topic or SIT
                with another one (e.g. the two POPIA entries sharing "South
                Africa Identification Number", or a label entry and its
                matching DLP entry) reads as an intentional, cross-linked pair
                rather than accidental duplicate content. Deliberately does
                NOT carry sequence/prerequisite relationships (see
                "Deployment sequence" above) - this section is only for
                genuinely different questions, never "deploy that first." */}
            {selected.relatedRecommendationIds && selected.relatedRecommendationIds.length > 0 && (
              <div className="border border-[#CBD5E1] dark:border-slate-700 bg-[#F8FAFC] dark:bg-slate-900/50 p-4 rounded-sm">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 flex items-center gap-1.5 mb-2.5">
                  <Link2 size={13} className="text-slate-500 dark:text-slate-400" />
                  Related recommendations - overlapping topic, different question
                </h4>
                <div className="space-y-1.5">
                  {selected.relatedRecommendationIds.map((relatedId) => {
                    const related = DATA_PROTECTION_RECOMMENDATIONS.find((r) => r.id === relatedId);
                    if (!related) return null;
                    return (
                      <button
                        key={relatedId}
                        onClick={() => handleSelectRelated(relatedId)}
                        className="w-full flex items-center justify-between gap-2 text-left text-xs bg-white dark:bg-slate-800 border border-[#E2E8F0] dark:border-slate-700 rounded-sm px-3 py-2 hover:border-slate-400 dark:hover:border-slate-500 transition-colors"
                      >
                        <span className="font-medium text-slate-800 dark:text-slate-200">{related.title}</span>
                        <ArrowRight size={12} className="text-slate-400 flex-shrink-0" />
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {isLabelEntry(selected) ? (
              <>
                {/* Label taxonomy */}
                <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-[#E2E8F0] dark:border-slate-700 pb-2 flex items-center gap-1.5">
                    <Tags size={13} className="text-slate-500 dark:text-slate-400" />
                    Labels
                  </h4>
                  <ul className="space-y-2 mt-3">
                    {selected.labels.map((label) => (
                      <li
                        key={label.name}
                        className="p-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#E2E8F0] dark:border-slate-700 rounded-sm"
                      >
                        <div className="flex items-center justify-between gap-2 flex-wrap">
                          <span className="text-xs font-mono font-bold text-slate-900 dark:text-slate-100">
                            {label.name}
                          </span>
                          <div className="flex items-center gap-1.5">
                            <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded-sm bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400">
                              Priority {label.priority}
                            </span>
                            {label.encrypted && (
                              <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded-sm bg-emerald-100 dark:bg-emerald-950/70 text-emerald-700 dark:text-emerald-400">
                                Encrypted
                              </span>
                            )}
                            {label.contentMarking && (
                              <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded-sm bg-amber-100 dark:bg-amber-950/70 text-amber-700 dark:text-amber-400">
                                Content marking
                              </span>
                            )}
                          </div>
                        </div>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">{label.tooltip}</p>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Label policy settings */}
                <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-[#E2E8F0] dark:border-slate-700 pb-2 flex items-center gap-1.5">
                    <Settings2 size={13} className="text-slate-500 dark:text-slate-400" />
                    Label Policy Settings
                  </h4>
                  <ul className="text-xs text-slate-600 dark:text-slate-300 mt-3 space-y-1.5">
                    <li>
                      <span className="font-semibold text-slate-700 dark:text-slate-300">Default label: </span>
                      {selected.labelPolicySettings.defaultLabelName || "None set"}
                    </li>
                    <li>
                      <span className="font-semibold text-slate-700 dark:text-slate-300">Mandatory labeling: </span>
                      {selected.labelPolicySettings.mandatoryLabeling ? "On" : "Off"}
                    </li>
                    <li>
                      <span className="font-semibold text-slate-700 dark:text-slate-300">Require downgrade justification: </span>
                      {selected.labelPolicySettings.requireDowngradeJustification ? "On" : "Off"}
                    </li>
                    <li>
                      <span className="font-semibold text-slate-700 dark:text-slate-300">Locations: </span>
                      {selected.labelPolicySettings.locations.join(", ")}
                    </li>
                  </ul>
                </div>

                {/* Auto-labeling, only present on the one E5 entry */}
                {selected.autoLabeling && (
                  <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-[#E2E8F0] dark:border-slate-700 pb-2 flex items-center gap-1.5">
                      <Wand2 size={13} className="text-slate-500 dark:text-slate-400" />
                      Auto-Labeling
                    </h4>
                    <div className="text-xs text-slate-600 dark:text-slate-300 mt-3 space-y-2">
                      <p>
                        <span className="font-semibold text-slate-700 dark:text-slate-300">Target label: </span>
                        {selected.autoLabeling.targetLabelName}
                      </p>
                      <p>
                        <span className="font-semibold text-slate-700 dark:text-slate-300">Triggers on: </span>
                        {selected.autoLabeling.sitReferences.join(", ")}
                      </p>
                      <p>
                        <span className="font-semibold text-slate-700 dark:text-slate-300">Starting mode: </span>
                        <span className="font-bold text-amber-700 dark:text-amber-400">{selected.autoLabeling.mode}</span>
                      </p>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <>
                {/* Sensitive info types */}
                <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-[#E2E8F0] dark:border-slate-700 pb-2 flex items-center gap-1.5">
                    <BookOpen size={13} className="text-slate-500 dark:text-slate-400" />
                    Sensitive Information Types to select in the portal
                  </h4>
                  <ul className="space-y-2 mt-3">
                    {selected.sensitiveInfoTypes.map((sit) => (
                      <li
                        key={sit.displayName}
                        className="flex flex-col sm:flex-row sm:items-baseline gap-1 sm:gap-2 p-2 bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#E2E8F0] dark:border-slate-700 rounded-sm"
                      >
                        <span className="text-xs font-mono font-bold text-slate-900 dark:text-slate-100 whitespace-nowrap">
                          {sit.displayName}
                        </span>
                        <span className="text-[11px] text-slate-500 dark:text-slate-400">{sit.matchGuidance}</span>
                      </li>
                    ))}
                  </ul>
                  <div className="mt-3 pt-3 border-t border-[#E2E8F0] dark:border-slate-700 text-[11px] text-slate-500 dark:text-slate-400">
                    Locations: {selected.recommendedLocations.join(", ")} &middot; Starting mode:{" "}
                    <span className="font-bold text-amber-700 dark:text-amber-400">{selected.recommendedStartingMode}</span>
                  </div>
                </div>

                {/* Rule logic + actions */}
                <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-[#E2E8F0] dark:border-slate-700 pb-2">
                    Rule logic
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 mt-3 leading-relaxed">{selected.ruleLogicSummary}</p>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-[#E2E8F0] dark:border-slate-700 pb-2 mt-4">
                    Actions
                  </h4>
                  <ul className="list-disc list-outside ml-4 space-y-1.5 text-xs text-slate-600 dark:text-slate-300 mt-3 leading-relaxed">
                    {selected.actions.map((a, i) => (
                      <li key={i}>{a}</li>
                    ))}
                  </ul>
                </div>
              </>
            )}

            {/* Guided portal steps */}
            <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-[#E2E8F0] dark:border-slate-700 pb-2 flex items-center gap-1.5">
                <ListChecks size={13} className="text-slate-500 dark:text-slate-400" />
                Step-by-step: Microsoft Purview compliance portal
              </h4>
              <ol className="space-y-2.5 mt-3">
                {selected.portalSteps.map((s) => (
                  <li key={s.step} className="flex gap-2.5 text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    <span className="flex-shrink-0 w-5 h-5 rounded-sm bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-600 text-[10px] font-bold flex items-center justify-center">
                      {s.step}
                    </span>
                    <span className="pt-0.5">{s.instruction}</span>
                  </li>
                ))}
              </ol>
            </div>

            {/* PowerShell template - explicitly flagged unverified */}
            <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs">
              <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                  <Terminal size={13} className="text-slate-500 dark:text-slate-400" />
                  Security &amp; Compliance PowerShell (advanced, unverified)
                </h4>
                <button
                  onClick={() => handleCopy(selected.powershellTemplate(policyPrefix), `ps-${selected.id}`)}
                  className="flex items-center gap-1 text-[11px] font-semibold bg-slate-900 hover:bg-slate-800 text-white dark:bg-slate-700 dark:hover:bg-slate-600 px-2.5 py-1 rounded-sm"
                >
                  {copiedKey === `ps-${selected.id}` ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                  <span>{copiedKey === `ps-${selected.id}` ? "Copied" : "Copy"}</span>
                </button>
              </div>
              <div className="flex items-start gap-2 text-[11px] text-amber-800 dark:text-amber-400 bg-amber-50 dark:bg-amber-500/10 border border-amber-300 dark:border-amber-500/30 rounded-sm px-2.5 py-2 mt-3 leading-relaxed">
                <AlertTriangle size={12} className="flex-shrink-0 mt-0.5" />
                <span>
                  Not verified against a live deploy - this app's live connectivity check for the
                  compliance API was inconclusive. Review every line before running it.
                </span>
              </div>
              <pre className="text-[11px] text-slate-200 bg-slate-950 border border-slate-800 rounded-sm p-3 overflow-x-auto whitespace-pre-wrap font-mono leading-relaxed mt-3">
                {selected.powershellTemplate(policyPrefix)}
              </pre>
            </div>

            {/* E5 enhancements */}
            {selected.e5Enhancements && selected.e5Enhancements.length > 0 && (
              <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-[#E2E8F0] dark:border-slate-700 pb-2 flex items-center gap-1.5">
                  <Sparkles size={13} className="text-slate-500 dark:text-slate-400" />
                  With E5 (optional)
                </h4>
                <ul className="list-disc list-outside ml-4 space-y-1.5 text-xs text-slate-600 dark:text-slate-300 mt-3 leading-relaxed">
                  {selected.e5Enhancements.map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Regulation references + caveats */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-[#E2E8F0] dark:border-slate-700 pb-2">
                  Regulation references
                </h4>
                <ul className="space-y-2 mt-3">
                  {selected.regulationRefs.map((ref, i) => (
                    <li key={i} className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                      <span className="font-mono font-bold text-slate-900 dark:text-slate-100">{ref.citation}</span>
                      <span> - {ref.note}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="border border-amber-300 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-500/5 p-4 rounded-sm shadow-xs">
                <h4 className="text-xs font-bold uppercase tracking-wider text-amber-800 dark:text-amber-400 border-b border-amber-300 dark:border-amber-500/30 pb-2 flex items-center gap-1.5">
                  <AlertTriangle size={13} />
                  Caveats
                </h4>
                <ul className="list-disc list-outside ml-4 space-y-1.5 text-xs text-slate-700 dark:text-slate-300 mt-3 leading-relaxed">
                  {selected.caveats.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
};
