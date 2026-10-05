"use client";

import React, { useMemo } from "react";
import { BookOpen, FileText, Printer, Terminal } from "lucide-react";
import { Modal } from "../common/Modal";
import { TenantSecuritySnapshot } from "@/lib/types";
import { STATUS_TEXT, buildHardeningPlan, planFileStem, planTitle, renderHardeningPlanHtml, renderHardeningPlanScript } from "@/lib/services/hardening-plan";

// Hardening plan (whole tenant) or Prevention plan (one scenario): the
// outstanding guides for THIS tenant in order, with the checklist (print /
// HTML) and one PowerShell script to download. Nothing is sent to Microsoft.

const STATUS_TONE = {
  prevented: "text-emerald-700 dark:text-emerald-400",
  partial: "text-amber-700 dark:text-amber-400",
  notPrevented: "text-red-700 dark:text-red-400",
  notAssessed: "text-orange-700 dark:text-orange-400",
} as const;

function download(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export const HardeningPlanModal: React.FC<{
  snapshot: TenantSecuritySnapshot;
  scenarioId?: string;
  onClose: () => void;
  onOpenGuide: (guideId: string) => void;
}> = ({ snapshot, scenarioId, onClose, onOpenGuide }) => {
  const plan = useMemo(() => buildHardeningPlan(snapshot, { scenarioId }), [snapshot, scenarioId]);
  const stem = planFileStem(plan);
  const empty = plan.counts.guides === 0;

  const openPrintable = () => window.open(URL.createObjectURL(new Blob([renderHardeningPlanHtml(plan)], { type: "text/html;charset=utf-8" })), "_blank", "noopener");
  // UTF-8 with a byte-order mark and CRLF line endings, so Windows PowerShell 5.1 reads it correctly too.
  const downloadScript = () => download(`${stem}.ps1`, "﻿" + renderHardeningPlanScript(plan).replace(/\r?\n/g, "\r\n"), "text/plain;charset=utf-8");
  const downloadChecklist = () => download(`${stem}.html`, renderHardeningPlanHtml(plan), "text/html;charset=utf-8");

  const button =
    "px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 disabled:opacity-50";
  let n = 0;

  return (
    <Modal isOpen onClose={onClose} title={planTitle(plan)} subtitle={snapshot.tenant.displayName} maxWidth="3xl">
      <div className="space-y-3 text-xs text-slate-700 dark:text-slate-300 max-h-[75vh] overflow-y-auto pr-1">
        <p>
          {empty
            ? "Nothing to fix here: no outstanding check has a guide."
            : `${plan.counts.guides} fix${plan.counts.guides === 1 ? "" : "es"} covering ${plan.counts.checks} check${plan.counts.checks === 1 ? "" : "s"}, in the order to work through them: active threats and logging first, then the changes that affect how people sign in and share.`}
          {plan.counts.notAssessed > 0 && ` ${plan.counts.notAssessed} of the checks couldn't be assessed; the guide's first steps tell you how to check them.`}
        </p>

        <div className="flex flex-wrap gap-2">
          <button onClick={openPrintable} disabled={empty} className={`${button} !bg-slate-900 !text-white !border-slate-900 hover:!bg-slate-800`}>
            <Printer size={13} /> Open checklist (print or save as PDF)
          </button>
          <button onClick={downloadChecklist} disabled={empty} className={button}>
            <FileText size={13} /> Download checklist
          </button>
          <button onClick={downloadScript} disabled={empty} className={button} title="One PowerShell script with every command in this plan. Each section asks before it runs.">
            <Terminal size={13} /> Download script (.ps1)
          </button>
        </div>

        {plan.phases.map((p) => (
          <section key={p.id} className="space-y-1.5">
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 pt-1">{p.title}</h4>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">{p.why}</p>
            <ol className="space-y-1.5">
              {p.entries.map((e) => {
                n++;
                return (
                  <li key={e.guideId} className="border border-slate-200 dark:border-slate-700 rounded-sm p-2 flex items-start gap-2">
                    <span className="font-mono text-slate-400 w-5 shrink-0 text-right">{n}.</span>
                    <div className="flex-1 min-w-0">
                      <div className="font-semibold text-slate-900 dark:text-slate-100">{e.guide.title}</div>
                      <ul className="mt-0.5 space-y-0.5">
                        {e.checks.map((c) => (
                          <li key={`${c.scenarioId}/${c.checkId}`} className="text-[11px]">
                            <span className={`font-semibold ${STATUS_TONE[c.status]}`}>{STATUS_TEXT[c.status]}</span>{" "}
                            <span className="text-slate-500 dark:text-slate-400">
                              {plan.kind === "tenant" ? `${c.scenarioTitle}: ` : ""}
                              {c.label}
                            </span>
                          </li>
                        ))}
                      </ul>
                      {e.guide.warnings.length > 0 && <div className="mt-0.5 text-[11px] text-amber-700 dark:text-amber-400">{e.guide.warnings.length} thing(s) to fill in or check first; see the guide.</div>}
                    </div>
                    <button
                      type="button"
                      onClick={() => onOpenGuide(e.guideId)}
                      className="shrink-0 inline-flex items-center gap-1 px-2 py-1 text-[10px] font-semibold rounded-sm border border-indigo-400 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-50 dark:hover:bg-indigo-950/40"
                    >
                      <BookOpen size={10} /> Open guide
                    </button>
                  </li>
                );
              })}
            </ol>
          </section>
        ))}

        {plan.other.length > 0 && (
          <section className="space-y-1">
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 pt-1">Also outstanding (no guide)</h4>
            <ul className="space-y-0.5">
              {plan.other.map((o) => (
                <li key={`${o.scenarioId}/${o.checkId}`} className="text-[11px]">
                  <span className={`font-semibold ${STATUS_TONE[o.status]}`}>{STATUS_TEXT[o.status]}</span> {plan.kind === "tenant" ? `${o.scenarioTitle}: ` : ""}
                  {o.label}
                  {o.fix && <span className="text-slate-500 dark:text-slate-400"> - {o.fix}</span>}
                </li>
              ))}
            </ul>
          </section>
        )}
        <p className="text-[10px] text-slate-400 dark:text-slate-500">Clarity365 doesn&apos;t make these changes. You run them, then re-sync this tenant to see the result.</p>
      </div>
    </Modal>
  );
};
