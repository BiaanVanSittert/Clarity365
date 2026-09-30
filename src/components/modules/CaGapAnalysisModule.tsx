import React, { useMemo } from "react";
import { Grid3x3, ExternalLink, History, Info, PlayCircle } from "lucide-react";
import { TenantSecuritySnapshot } from "@/lib/types";
import {
  analyzeCaGaps,
  CA_GAP_CONTROLS,
  CA_GAP_PERSONAS,
  CaGapCell,
  CaGapCellState,
  CaGapFinding,
  CaGapSeverity,
} from "@/lib/services/ca-gap-analyzer";
import { detectHomeCountry } from "@/lib/services/signin-situation-runner";
import { SituationPersona } from "@/lib/data/signin-situation-definitions";

interface CaGapAnalysisModuleProps {
  snapshot: TenantSecuritySnapshot;
  // Opens Sign-in Situations preset to a persona.
  onOpenSituations?: (persona: SituationPersona) => void;
}

// Cell legend - the same five states as the reference design, plus
// "Can't confirm" for results the simulator couldn't determine.
const CELL_STYLE: Record<CaGapCellState, { cls: string; label: string }> = {
  enforced: { cls: "bg-emerald-500 dark:bg-emerald-500 border-emerald-500", label: "Enforced" },
  reportOnly: { cls: "bg-transparent border-2 border-orange-400", label: "Report-only" },
  noPolicy: { cls: "bg-red-600 dark:bg-red-700 border-red-600 dark:border-red-700", label: "No policy" },
  unlicensed: { cls: "bg-cyan-700 dark:bg-cyan-800 border-cyan-700 dark:border-cyan-800", label: "Unlicensed" },
  notApplicable: { cls: "bg-slate-200 dark:bg-slate-700/60 border-slate-200 dark:border-slate-700", label: "Not applicable" },
  unknown: { cls: "bg-orange-50 dark:bg-orange-950/40 border border-dashed border-orange-400", label: "Can't confirm" },
};

const LEGEND_ORDER: CaGapCellState[] = ["enforced", "reportOnly", "noPolicy", "unlicensed", "notApplicable", "unknown"];

const SEVERITY_STYLE: Record<CaGapSeverity, { dot: string; label: string }> = {
  critical: { dot: "bg-red-600", label: "Critical" },
  high: { dot: "bg-orange-500", label: "High" },
  medium: { dot: "bg-sky-500", label: "Medium" },
  low: { dot: "bg-slate-400", label: "Low" },
};

const PERSONA_TO_SIM: Record<string, SituationPersona | undefined> = { admins: "globalAdmin", users: "user", guests: "guest" };

function scoreColor(score: number): string {
  if (score >= 8) return "text-emerald-600 dark:text-emerald-400";
  if (score >= 5) return "text-amber-600 dark:text-amber-400";
  return "text-red-600 dark:text-red-400";
}

function cellTooltip(cell: CaGapCell): string {
  const persona = CA_GAP_PERSONAS.find((p) => p.id === cell.persona)!.label;
  const control = CA_GAP_CONTROLS.find((c) => c.id === cell.control)!.label;
  const lines = [`${persona} - ${control}: ${CELL_STYLE[cell.state].label}`];
  if (cell.policies.length > 0) lines.push(...cell.policies.map((p) => `• ${p.name}${p.state === "enabledForReportingButNotEnforced" ? " (report-only)" : ""}`));
  if (cell.note) lines.push(cell.note);
  return lines.join("\n");
}

export const CaGapAnalysisModule: React.FC<CaGapAnalysisModuleProps> = ({ snapshot, onOpenSituations }) => {
  const analysis = useMemo(() => analyzeCaGaps(snapshot, new Date(), detectHomeCountry(snapshot)), [snapshot]);
  const { policyCounts, severityCounts } = analysis;
  const lastSync = snapshot.tenant.lastSyncTimestamp ? new Date(snapshot.tenant.lastSyncTimestamp).toLocaleString() : "never";

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm">
        <div className="flex items-center gap-2">
          <Grid3x3 size={18} className="text-slate-800 dark:text-slate-200" />
          <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">CA Gap Analysis</h2>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
          How well Conditional Access covers each kind of identity, where the gaps are, and what to fix first. Worked out from this tenant&apos;s
          policies as of the last sync ({lastSync}) with the same engine as Sign-in Situations.
        </p>
      </div>

      {analysis.needsResync && (
        <Banner icon={History}>
          Some policies were synced before simulation support, so their conditions are incomplete and affected cells show &quot;Can&apos;t confirm&quot;.
          Re-sync this tenant for exact results.
        </Banner>
      )}

      {/* Score + matrix */}
      <div className="grid grid-cols-1 xl:grid-cols-[260px_1fr] gap-4">
        <div className="bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm p-5 flex flex-col items-center justify-center text-center">
          <div className="flex items-baseline gap-1">
            <span className={`text-5xl font-bold font-mono ${scoreColor(analysis.score)}`}>{analysis.score}</span>
            <span className="text-lg font-mono text-slate-500 dark:text-slate-400">/ {analysis.maxScore}</span>
          </div>
          <div
            className="mt-2 text-[11px] font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-300"
            title="Enforced controls as a share of every applicable, licensed cell in the grid, scaled to 10. MFA for admins and users, phishing-resistant MFA for admins, MFA for guests and the legacy-authentication block for admins and users count double. Report-only counts as not enforced. Workload identities aren't scored because their licence can't be detected."
          >
            Conditional Access Score
          </div>
          <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
            {analysis.enforcedControls} of {analysis.scoredControls} controls enforced · {severityCounts.critical} critical, {severityCounts.high} high
            findings
          </div>
        </div>

        <div className="bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm p-4">
          <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">Coverage by persona</div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            {policyCounts.total} policies · {policyCounts.enabled} enforced · {policyCounts.reportOnly} report-only · {policyCounts.disabled} disabled.
            Personas come from how each policy targets identities; hover a cell for the policies behind it, click a gap to simulate it.
          </div>

          <div className="mt-4 overflow-x-auto">
            <table className="w-full border-separate" style={{ borderSpacing: "6px 6px" }}>
              <thead>
                <tr>
                  <th className="w-36" />
                  {CA_GAP_CONTROLS.map((c) => (
                    <th key={c.id} className="text-[10px] font-medium text-slate-500 dark:text-slate-400 text-center align-bottom leading-tight min-w-[90px]">
                      {c.label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {CA_GAP_PERSONAS.map((p) => (
                  <tr key={p.id}>
                    <td className="text-xs text-slate-700 dark:text-slate-300 pr-2 whitespace-nowrap">{p.label}</td>
                    {CA_GAP_CONTROLS.map((c) => {
                      const cell = analysis.matrix.find((m) => m.persona === p.id && m.control === c.id)!;
                      const simPersona = PERSONA_TO_SIM[p.id];
                      const clickable = !!onOpenSituations && !!simPersona && (cell.state === "noPolicy" || cell.state === "reportOnly" || cell.state === "unknown");
                      const style = CELL_STYLE[cell.state];
                      return (
                        <td key={c.id} className="p-0">
                          {clickable ? (
                            <button
                              type="button"
                              title={`${cellTooltip(cell)}\n\nClick to simulate this persona's sign-ins.`}
                              aria-label={cellTooltip(cell)}
                              onClick={() => onOpenSituations!(simPersona!)}
                              className={`block w-full h-6 rounded-sm border ${style.cls} hover:opacity-80 focus:outline-none focus:ring-2 focus:ring-slate-400`}
                            />
                          ) : (
                            <div title={cellTooltip(cell)} aria-label={cellTooltip(cell)} className={`w-full h-6 rounded-sm border ${style.cls}`} />
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1">
            {LEGEND_ORDER.map((s) => (
              <span key={s} className="inline-flex items-center gap-1.5 text-[11px] text-slate-600 dark:text-slate-300">
                <span className={`inline-block w-3 h-3 rounded-sm border ${CELL_STYLE[s].cls}`} />
                {CELL_STYLE[s].label}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Findings */}
      <div className="bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="p-4 border-b border-slate-100 dark:border-slate-700">
          <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">Policy findings</div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            {analysis.findings.length} finding{analysis.findings.length === 1 ? "" : "s"} from the synced policies, most severe first
          </div>
        </div>
        {analysis.findings.length === 0 ? (
          <div className="p-4 text-xs text-slate-500 dark:text-slate-400">No findings - every applicable control is enforced.</div>
        ) : (
          <ul>
            {analysis.findings.map((f) => (
              <FindingRow key={f.id} finding={f} onOpenSituations={onOpenSituations} />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

const Banner: React.FC<{ icon: React.ElementType; children: React.ReactNode }> = ({ icon: Icon, children }) => (
  <div className="flex items-start gap-2 p-3 rounded-sm border text-xs bg-amber-50 border-amber-300 text-amber-900 dark:bg-amber-950/40 dark:border-amber-800 dark:text-amber-200">
    <Icon size={14} className="mt-0.5 shrink-0" />
    <div>{children}</div>
  </div>
);

export const FindingRow: React.FC<{ finding: CaGapFinding; onOpenSituations?: (persona: SituationPersona) => void }> = ({ finding: f, onOpenSituations }) => {
  const sev = SEVERITY_STYLE[f.severity];
  return (
    <li className="p-4 border-b last:border-b-0 border-slate-100 dark:border-slate-700 flex flex-col md:flex-row md:items-start gap-3">
      <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${sev.dot}`} aria-hidden="true" />
      <div className="flex-1 min-w-0 text-xs">
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="font-semibold text-slate-900 dark:text-slate-100">{f.title}</span>
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            {sev.label} · {f.source}
          </span>
        </div>
        <p className="mt-1 text-slate-600 dark:text-slate-300">{f.detail}</p>
        {f.policies.length > 0 && <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">Policies: {f.policies.join(", ")}</p>}
        <p className="mt-1 text-[11px] font-medium text-slate-800 dark:text-slate-200">Fix: {f.fix}</p>
      </div>
      <div className="flex md:flex-col gap-2 shrink-0">
        {f.docsUrl && (
          <a
            href={f.docsUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-semibold rounded-sm border border-orange-400 text-orange-600 dark:text-orange-400 hover:bg-orange-50 dark:hover:bg-orange-950/40"
          >
            Microsoft Documentation <ExternalLink size={11} />
          </a>
        )}
        {f.simulatePersona && onOpenSituations && (
          <button
            type="button"
            onClick={() => onOpenSituations(f.simulatePersona!)}
            className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-semibold rounded-sm border border-[#CBD5E1] dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700"
          >
            <PlayCircle size={11} /> Simulate sign-ins
          </button>
        )}
        {!f.docsUrl && !f.simulatePersona && <Info size={12} className="text-slate-300 dark:text-slate-600" aria-hidden="true" />}
      </div>
    </li>
  );
};
