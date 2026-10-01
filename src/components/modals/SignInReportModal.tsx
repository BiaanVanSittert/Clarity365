"use client";

import React, { useMemo, useState } from "react";
import { Download, FileText, Printer } from "lucide-react";
import { Modal } from "../common/Modal";
import { TenantSecuritySnapshot } from "@/lib/types";
import { buildSignInReport, renderSignInReportHtml, signInReportCsvTables } from "@/lib/services/signin-report";
import { csvFilename, exportToCsv } from "@/lib/utils/csv";

interface SignInReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  snapshot: TenantSecuritySnapshot;
  // The home country chosen in the Sign-In Logs module, so the report agrees with the screen.
  homeCountry?: string | null;
}

const PERIODS: { label: string; days: number | undefined }[] = [
  { label: "Last 7 days", days: 7 },
  { label: "Last 14 days", days: 14 },
  { label: "Last 30 days", days: 30 },
  { label: "Everything synced", days: undefined },
];

// Sign-in report for one tenant: pick a period (and optionally a user), see
// the headline numbers, then print it / save it as PDF or download each
// table as CSV. All figures come from buildSignInReport(); this only shows them.
export const SignInReportModal: React.FC<SignInReportModalProps> = ({ isOpen, onClose, snapshot, homeCountry }) => {
  const [days, setDays] = useState<number | undefined>(30);
  const [user, setUser] = useState("");

  const report = useMemo(() => buildSignInReport(snapshot, { days, user, homeCountry: homeCountry || undefined }), [snapshot, days, user, homeCountry]);
  const tables = useMemo(() => signInReportCsvTables(report), [report]);

  const fileStem = `Clarity365_SignInReport_${snapshot.tenant.defaultDomainName}_${report.generatedAt.slice(0, 10)}`;
  const htmlBlobUrl = () => URL.createObjectURL(new Blob([renderSignInReportHtml(report)], { type: "text/html;charset=utf-8" }));

  const openPrintable = () => {
    window.open(htmlBlobUrl(), "_blank", "noopener");
  };

  const downloadHtml = () => {
    const url = htmlBlobUrl();
    const link = document.createElement("a");
    link.href = url;
    link.download = `${fileStem}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const s = report.summary;
  const stats: { label: string; value: number | string; tone?: "red" | "orange" | "green" }[] = [
    { label: "Sign-ins", value: s.total },
    { label: "Succeeded", value: s.succeeded, tone: "green" },
    { label: "Failed", value: s.failed, tone: s.failed ? "orange" : undefined },
    { label: "Blocked by CA", value: s.blocked },
    { label: "Users", value: s.users },
    { label: "Countries", value: s.countries },
    { label: "IP addresses", value: s.ipAddresses },
    { label: `Outside ${report.homeCountry || "home"}`, value: s.outsideHome, tone: s.outsideHome ? "orange" : undefined },
    { label: "Succeeded with MFA", value: report.authDetailsAvailable ? s.mfaRequired : "n/a", tone: "green" },
    { label: "MFA not required", value: report.authDetailsAvailable ? s.withoutMfa : "n/a", tone: s.withoutMfa ? "orange" : undefined },
    { label: "Legacy protocol", value: s.legacy, tone: s.legacy ? "red" : undefined },
    { label: "Risky", value: s.risky, tone: s.risky ? "red" : undefined },
  ];
  const toneClass = { red: "text-rose-700 dark:text-red-400", orange: "text-amber-700 dark:text-amber-400", green: "text-emerald-700 dark:text-emerald-400" };
  const button =
    "px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 disabled:opacity-50";

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Sign-in report" subtitle={snapshot.tenant.displayName} maxWidth="3xl">
      <div className="space-y-3 text-xs text-slate-700 dark:text-slate-300 max-h-[75vh] overflow-y-auto pr-1">
        {/* Period and user */}
        <div className="flex flex-wrap items-center gap-2">
          {PERIODS.map((p) => (
            <button
              key={p.label}
              onClick={() => setDays(p.days)}
              className={`px-2.5 py-1 rounded-sm border text-xs font-medium ${
                days === p.days
                  ? "bg-slate-900 text-white border-slate-900 dark:bg-slate-100 dark:text-slate-900 dark:border-slate-100"
                  : "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700"
              }`}
            >
              {p.label}
            </button>
          ))}
          <input
            value={user}
            onChange={(e) => setUser(e.target.value)}
            placeholder="Only this user (optional)"
            className="flex-1 min-w-[180px] px-2 py-1 text-xs bg-white dark:bg-slate-900 border border-[#CBD5E1] dark:border-slate-700 rounded-sm"
          />
        </div>

        {/* What the data covers */}
        <div
          className={`px-3 py-1.5 rounded-sm border text-[11px] ${
            report.coverage.complete && !report.periodWarning
              ? "bg-slate-50 dark:bg-slate-900/50 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400"
              : "bg-amber-50 dark:bg-amber-950/50 border-amber-200 dark:border-amber-800 text-amber-900 dark:text-amber-300"
          }`}
        >
          {report.coverageNote}
          {report.periodWarning && <div className="mt-0.5 font-medium">{report.periodWarning}</div>}
          {!report.authDetailsAvailable && s.total > 0 && <div className="mt-0.5">The MFA method is not available for these sign-ins. Sync the tenant again to load it.</div>}
        </div>

        {/* Headline numbers */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {stats.map((stat) => (
            <div key={stat.label} className="border border-[#CBD5E1] dark:border-slate-700 rounded-sm px-2.5 py-2">
              <div className={`text-lg font-semibold tabular-nums ${stat.tone ? toneClass[stat.tone] : "text-slate-900 dark:text-slate-100"}`}>{stat.value}</div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Worth a look */}
        <div>
          <div className="font-semibold text-slate-900 dark:text-slate-100 mb-1">Worth a look</div>
          {report.findings.length === 0 ? (
            <div className="text-emerald-700 dark:text-emerald-400">Nothing stood out in this period.</div>
          ) : (
            <ul className="space-y-1">
              {report.findings.map((f) => (
                <li key={f.id} className={`pl-2 border-l-4 ${f.severity === "red" ? "border-rose-500" : "border-amber-500"}`}>
                  <span className="font-medium text-slate-900 dark:text-slate-100">{f.title}</span>{" "}
                  <span className="px-1.5 rounded-full bg-slate-200 dark:bg-slate-700 font-semibold tabular-nums">{f.total}</span>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">{f.detail}</div>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Downloads */}
        <div className="pt-2 border-t border-[#E2E8F0] dark:border-slate-700 space-y-2">
          <div className="flex flex-wrap gap-2">
            <button onClick={openPrintable} disabled={s.total === 0} className={`${button} !bg-slate-900 !text-white !border-slate-900 hover:!bg-slate-800`}>
              <Printer size={13} />
              <span>Open report (print or save as PDF)</span>
            </button>
            <button onClick={downloadHtml} disabled={s.total === 0} className={button}>
              <FileText size={13} />
              <span>Download report</span>
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] text-slate-500 dark:text-slate-400">Data (CSV):</span>
            {tables.map((t) => (
              <button
                key={t.name}
                onClick={() => exportToCsv(csvFilename(`SignInReport_${t.name}`, snapshot.tenant.defaultDomainName), t.headers, t.rows)}
                disabled={t.rows.length === 0}
                className={button}
              >
                <Download size={12} />
                <span>
                  {t.name.replace(/([a-z])([A-Z])/g, "$1 $2")} ({t.rows.length})
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </Modal>
  );
};
