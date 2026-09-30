import React, { useMemo, useState } from "react";
import { Swords, ShieldCheck, ShieldAlert, ShieldX, HelpCircle, ChevronDown, ChevronRight, AlertTriangle, ExternalLink, PlayCircle, Wrench } from "lucide-react";
import { TenantSecuritySnapshot } from "@/lib/types";
import { SCENARIO_SECTIONS, ScenarioCheckResult, ScenarioCheckStatus, ScenarioResult, evaluateScenarios } from "@/lib/services/security-scenarios";
import { SituationPersona } from "@/lib/data/signin-situation-definitions";

interface SecurityScenariosModuleProps {
  snapshot: TenantSecuritySnapshot;
  // Opens Sign-in Situations preset to a persona.
  onOpenSituations?: (persona: SituationPersona) => void;
}

// Colour rules from the Security Simulations review: green and red lead;
// orange marks partial protection and anything that couldn't be assessed.
const STATUS_STYLE: Record<ScenarioCheckStatus, { icon: React.ElementType; label: string; text: string; pill: string; bar: string; card: string; activeCard: string }> = {
  prevented: {
    icon: ShieldCheck,
    label: "Prevented",
    text: "text-emerald-800 dark:text-emerald-400",
    pill: "bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800",
    bar: "border-l-emerald-500",
    card: "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-emerald-50/60 dark:hover:bg-emerald-950/40",
    activeCard: "bg-emerald-100 dark:bg-emerald-950 border-emerald-400 dark:border-emerald-800",
  },
  partial: {
    icon: ShieldAlert,
    label: "Partly prevented",
    text: "text-amber-800 dark:text-amber-400",
    pill: "bg-amber-100 text-amber-900 border-amber-300 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800",
    bar: "border-l-amber-500",
    card: "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-amber-50/60 dark:hover:bg-amber-950/40",
    activeCard: "bg-amber-100 dark:bg-amber-950 border-amber-400 dark:border-amber-800",
  },
  notPrevented: {
    icon: ShieldX,
    label: "Not prevented",
    text: "text-red-800 dark:text-red-400",
    pill: "bg-red-100 text-red-800 border-red-300 dark:bg-red-950/60 dark:text-red-300 dark:border-red-800",
    bar: "border-l-red-500",
    card: "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-red-50/60 dark:hover:bg-red-950/40",
    activeCard: "bg-red-100 dark:bg-red-950 border-red-400 dark:border-red-800",
  },
  notAssessed: {
    icon: HelpCircle,
    label: "Not assessed",
    text: "text-orange-800 dark:text-orange-400",
    pill: "bg-orange-50 text-orange-800 border-orange-300 border-dashed dark:bg-orange-950/40 dark:text-orange-300 dark:border-orange-800",
    bar: "border-l-orange-400",
    card: "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-orange-50/60 dark:hover:bg-orange-950/40",
    activeCard: "bg-orange-100 dark:bg-orange-950 border-orange-400 dark:border-orange-800",
  },
};

const STRIP_ORDER: ScenarioCheckStatus[] = ["prevented", "partial", "notPrevented", "notAssessed"];

function countsText(r: ScenarioResult): string {
  const parts = [`${r.counts.prevented} prevented`];
  if (r.counts.partial) parts.push(`${r.counts.partial} partial`);
  parts.push(`${r.counts.notPrevented} not prevented`);
  if (r.counts.notAssessed) parts.push(`${r.counts.notAssessed} not assessed`);
  return `${r.checks.length} checks: ${parts.join(" · ")}`;
}

export const SecurityScenariosModule: React.FC<SecurityScenariosModuleProps> = ({ snapshot, onOpenSituations }) => {
  const results = useMemo(() => evaluateScenarios(snapshot), [snapshot]);
  const [filter, setFilter] = useState<ScenarioCheckStatus | "all">("all");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const scenarioCounts = useMemo(() => {
    const c: Record<ScenarioCheckStatus, number> = { prevented: 0, partial: 0, notPrevented: 0, notAssessed: 0 };
    for (const r of results) c[r.verdict] += 1;
    return c;
  }, [results]);

  const lastSync = snapshot.tenant.lastSyncTimestamp ? new Date(snapshot.tenant.lastSyncTimestamp).toLocaleString() : "never";

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm">
        <div className="flex items-center gap-2">
          <Swords size={18} className="text-slate-800 dark:text-slate-200" />
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">Security Scenarios</h2>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
          Common attacks, each broken into the defences that would stop it. A scenario is red when any one defence would let the attack through.
          Worked out from this tenant&apos;s synced configuration ({lastSync}); nothing is sent to Microsoft.
        </p>
      </div>

      {/* Summary strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5">
        {STRIP_ORDER.map((s) => {
          const style = STATUS_STYLE[s];
          const Icon = style.icon;
          const active = filter === s;
          const toggle = () => setFilter(active ? "all" : s);
          return (
            <div
              key={s}
              role="button"
              tabIndex={0}
              onClick={toggle}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), toggle())}
              title={`Click to show only "${style.label}" scenarios`}
              className={`p-3 border rounded-sm cursor-pointer transition-colors ${active ? style.activeCard : style.card}`}
            >
              <div className={`text-[11px] font-semibold uppercase tracking-wider flex items-center gap-1 ${style.text}`}>
                <Icon size={12} />
                <span>{style.label}</span>
              </div>
              <div className={`text-xl font-bold font-mono mt-1 ${style.text}`}>
                {scenarioCounts[s]} <span className="text-xs font-normal">of {results.length} scenarios</span>
              </div>
              <div className={`text-[10px] mt-0.5 ${style.text}`}>(Click to filter)</div>
            </div>
          );
        })}
      </div>

      {SCENARIO_SECTIONS.map((section) => {
        const inSection = results.filter((r) => r.section === section.id);
        const visible = inSection.filter((r) => filter === "all" || r.verdict === filter);
        if (visible.length === 0) return null;
        const prevented = inSection.filter((r) => r.verdict === "prevented").length;
        const notPrevented = inSection.filter((r) => r.verdict === "notPrevented").length;
        return (
          <section key={section.id} className="space-y-2">
            <div className="flex flex-wrap items-baseline justify-between gap-2 pt-2">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{section.label}</h3>
              <span className="text-[11px] text-slate-500 dark:text-slate-400">
                {inSection.length} scenarios · {prevented} prevented · {notPrevented} not prevented
              </span>
            </div>
            {visible.map((r) => (
              <ScenarioCard
                key={r.id}
                result={r}
                expanded={!!expanded[r.id]}
                onToggle={() => setExpanded((prev) => ({ ...prev, [r.id]: !prev[r.id] }))}
                onOpenSituations={onOpenSituations}
              />
            ))}
          </section>
        );
      })}
    </div>
  );
};

export const ScenarioCard: React.FC<{
  result: ScenarioResult;
  expanded: boolean;
  onToggle: () => void;
  onOpenSituations?: (persona: SituationPersona) => void;
}> = ({ result: r, expanded, onToggle, onOpenSituations }) => {
  const style = STATUS_STYLE[r.verdict];
  const Icon = style.icon;
  return (
    <div className={`border border-[#CBD5E1] dark:border-slate-700 border-l-4 ${style.bar} rounded-sm bg-white dark:bg-slate-800`}>
      <button onClick={onToggle} aria-expanded={expanded} className="w-full text-left p-3 flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-700/40">
        {expanded ? <ChevronDown size={14} className="mt-0.5 text-slate-400 shrink-0" /> : <ChevronRight size={14} className="mt-0.5 text-slate-400 shrink-0" />}
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">{r.title}</span>
            <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded-sm border ${style.pill}`}>
              <Icon size={11} />
              {style.label}
            </span>
            {r.gaps > 0 && (
              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-sm bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200">
                {r.gaps} gap{r.gaps === 1 ? "" : "s"}
              </span>
            )}
          </div>
          <div className="text-[11px] text-slate-600 dark:text-slate-300 mt-1">{countsText(r)}</div>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-1 space-y-3 border-t border-slate-100 dark:border-slate-700">
          <p className="text-[11px] text-slate-500 dark:text-slate-400">{r.description}</p>
          {r.warning && (
            <div className="flex items-start gap-2 p-2.5 rounded-sm border text-[11px] bg-amber-50 border-amber-300 text-amber-900 dark:bg-amber-950/40 dark:border-amber-800 dark:text-amber-200">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              <span>{r.warning}</span>
            </div>
          )}
          <ul className="space-y-2">
            {r.checks.map((c) => (
              <CheckRow key={c.id} check={c} onOpenSituations={onOpenSituations} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

const CheckRow: React.FC<{ check: ScenarioCheckResult; onOpenSituations?: (persona: SituationPersona) => void }> = ({ check: c, onOpenSituations }) => {
  const style = STATUS_STYLE[c.status];
  const Icon = style.icon;
  return (
    <li className="border border-slate-200 dark:border-slate-700 rounded-sm p-2.5 flex flex-col md:flex-row md:items-start gap-2">
      <Icon size={14} className={`mt-0.5 shrink-0 ${style.text}`} aria-label={style.label} />
      <div className="flex-1 min-w-0 text-[11px]">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-semibold text-slate-900 dark:text-slate-100">{c.label}</span>
          <span className={`text-[10px] font-semibold ${style.text}`}>{style.label}</span>
        </div>
        <p className="mt-0.5 text-slate-600 dark:text-slate-300">{c.detail}</p>
        {c.items && c.items.length > 0 && (
          <ul className="mt-1 list-disc pl-4 text-slate-500 dark:text-slate-400 space-y-0.5">
            {c.items.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ul>
        )}
        {c.fix && (
          <p className="mt-1 flex items-start gap-1 font-medium text-slate-800 dark:text-slate-200">
            <Wrench size={11} className="mt-0.5 shrink-0" />
            <span>{c.fix}</span>
          </p>
        )}
      </div>
      <div className="flex md:flex-col gap-2 shrink-0">
        {c.docsUrl && c.status !== "prevented" && (
          <a
            href={c.docsUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 px-2 py-1 text-[10px] font-semibold rounded-sm border border-orange-400 text-orange-600 dark:text-orange-400 hover:bg-orange-50 dark:hover:bg-orange-950/40"
          >
            Microsoft Documentation <ExternalLink size={10} />
          </a>
        )}
        {c.simulatePersona && onOpenSituations && c.status !== "prevented" && (
          <button
            type="button"
            onClick={() => onOpenSituations(c.simulatePersona!)}
            className="inline-flex items-center gap-1 px-2 py-1 text-[10px] font-semibold rounded-sm border border-[#CBD5E1] dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700"
          >
            <PlayCircle size={10} /> Simulate sign-ins
          </button>
        )}
      </div>
    </li>
  );
};
