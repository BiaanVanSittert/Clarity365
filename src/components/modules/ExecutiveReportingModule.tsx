import React, { useState, useMemo } from "react";
import { Tenant, TenantSecuritySnapshot, ExecutiveQbrReport } from "@/lib/types";
import { generateTenantQbrReport } from "@/lib/services/report-generator";
import { ReportPreviewModal } from "../modals/ReportPreviewModal";
import {
  FileText,
  Printer,
  Download,
  Calendar,
  Building2,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  ChevronRight,
  TrendingUp,
  DollarSign,
  Lock,
  Users,
  CheckCircle2,
  Sparkles,
} from "lucide-react";
import { exportToCsv } from "@/lib/utils/csv";

interface ExecutiveReportingModuleProps {
  tenants: Tenant[];
  snapshots: TenantSecuritySnapshot[];
  onSelectTenant: (tenantId: string, targetModule?: string, targetEntityId?: string) => void;
}

export const ExecutiveReportingModule: React.FC<ExecutiveReportingModuleProps> = ({
  tenants,
  snapshots,
  onSelectTenant,
}) => {
  const [selectedTenantId, setSelectedTenantId] = useState<string>(tenants[0]?.id || "");
  const [selectedPeriod, setSelectedPeriod] = useState<string>("Q3 2026");
  const [previewReport, setPreviewReport] = useState<ExecutiveQbrReport | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  // Snapshot map
  const snapshotMap = useMemo(() => {
    const map = new Map<string, TenantSecuritySnapshot>();
    for (const snap of snapshots) {
      map.set(snap.tenant.id, snap);
    }
    return map;
  }, [snapshots]);

  // Active snapshot & generated report
  const activeSnapshot = snapshotMap.get(selectedTenantId);

  const currentReport = useMemo(() => {
    if (!activeSnapshot) return null;
    return generateTenantQbrReport(activeSnapshot, selectedPeriod);
  }, [activeSnapshot, selectedPeriod]);

  const handleOpenPreview = () => {
    if (currentReport) {
      setPreviewReport(currentReport);
      setIsModalOpen(true);
    }
  };

  const handleExportCsv = () => {
    if (!currentReport) return;
    const headers = ["Section", "Metric", "Value", "Status / Notes"];
    const rows = [
      ["Executive Summary", "Overall Health Score", `${currentReport.executiveSummary.overallHealthScore}/100`, currentReport.executiveSummary.headlineStatus],
      ["Executive Summary", "Secure Score", `${currentReport.executiveSummary.secureScorePercent}%`, "vs 63% industry benchmark"],
      ["Executive Summary", "Golden Baseline Score", `${currentReport.executiveSummary.baselineAdoptionScore}%`, `${currentReport.goldenBaselineSection.enforcedCount} Enforced, ${currentReport.goldenBaselineSection.reportOnlyCount} Audit`],
      ["Executive Summary", "Monthly Identified Waste", `$${currentReport.executiveSummary.totalMonthlyCostSavingsIdentified}/mo`, `$${currentReport.costOptimizationSection.totalEstimatedAnnualWaste}/yr`],
      ["Identity & Access", "MFA Adoption", `${currentReport.identityMfaSection.mfaEnforcedPercent}%`, `${currentReport.identityMfaSection.totalUsers} total identities`],
      ["Identity & Access", "Admins With Phishing-Resistant MFA", `${currentReport.identityMfaSection.adminsWithPhishingResistantMfa}/${currentReport.identityMfaSection.adminCount}`, "FIDO2 / Passkey"],
      ["Threats & Hygiene", "External Forwarding Rules Blocked", `${currentReport.threatsAndHygieneSection.externalForwardingRulesBlocked}`, "Auto-forwarding killswitch"],
      ["Threats & Hygiene", "Unmanaged Devices", `${currentReport.threatsAndHygieneSection.unmanagedDevicesCount}`, "Endpoints"],
      ["Threats & Hygiene", "Anonymous SharePoint Links", `${currentReport.threatsAndHygieneSection.anonymousSharePointLinksCount}`, "External file shares"],
    ];

    exportToCsv(`Executive_Summary_${currentReport.tenant.defaultDomain}_${selectedPeriod.replace(/\s+/g, "_")}.csv`, headers, rows);
  };

  if (!activeSnapshot || !currentReport) {
    return (
      <div className="p-8 text-center text-slate-500 font-mono text-xs">
        No active tenant security snapshot available.
      </div>
    );
  }

  const { executiveSummary, identityMfaSection, goldenBaselineSection, costOptimizationSection } = currentReport;

  const statusColors = {
    optimal: "bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300",
    acceptable: "bg-blue-50 text-blue-800 border-blue-300 dark:bg-blue-950 dark:text-blue-300",
    needs_attention: "bg-amber-50 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300",
    critical_risk: "bg-rose-50 text-rose-800 border-rose-300 dark:bg-rose-950 dark:text-rose-300",
  };

  const statusLabels = {
    optimal: "Optimal Posture",
    acceptable: "Acceptable (Monitored)",
    needs_attention: "Attention Required",
    critical_risk: "Critical Security Risks",
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-white dark:bg-slate-800 p-5 border border-slate-200 dark:border-slate-700 rounded-sm shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <FileText className="text-emerald-600 dark:text-emerald-400" size={18} />
              <span>Executive Cybersecurity & QBR Reporting</span>
            </h2>
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 rounded-sm">
              PHASE 2.3
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Generate white-labeled executive briefings, Quarterly Business Reviews (QBR), and posture scorecards for client leadership.
          </p>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            onClick={handleExportCsv}
            className="px-3 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-slate-300 dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handleOpenPreview}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 dark:bg-emerald-600 dark:hover:bg-emerald-500 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Printer size={14} />
            <span>Generate Client QBR Report (PDF/Print)</span>
          </button>
        </div>
      </div>

      {/* Filter & Period Selector Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-slate-500 flex items-center gap-1 mr-1">
            <Building2 size={13} />
            <span>Target Client Tenant:</span>
          </span>
          {tenants.map((t) => (
            <button
              key={t.id}
              onClick={() => setSelectedTenantId(t.id)}
              className={`px-2.5 py-1 text-xs font-medium rounded-sm border transition-colors ${
                selectedTenantId === t.id
                  ? "bg-slate-900 text-white border-slate-900 dark:bg-slate-100 dark:text-slate-900 dark:border-slate-100 font-bold"
                  : "bg-slate-50 dark:bg-slate-900 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:bg-slate-100"
              }`}
            >
              {t.displayName}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <Calendar size={13} className="text-slate-500" />
          <span className="text-xs font-semibold text-slate-500">Period:</span>
          <select
            value={selectedPeriod}
            onChange={(e) => setSelectedPeriod(e.target.value)}
            className="px-2.5 py-1 text-xs border border-slate-300 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 font-medium"
          >
            <option value="Q3 2026">Q3 2026 (Current Quarter)</option>
            <option value="August 2026">August 2026 (Monthly Review)</option>
            <option value="July 2026">July 2026</option>
            <option value="Annual Review 2026">Annual Executive Review 2026</option>
          </select>
        </div>
      </div>

      {/* Executive Scorecard Matrix */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Overall Posture</span>
            <span className={`px-2 py-0.5 text-[10px] font-bold rounded-sm border ${statusColors[executiveSummary.headlineStatus]}`}>
              {statusLabels[executiveSummary.headlineStatus]}
            </span>
          </div>
          <div className="text-3xl font-black text-slate-900 dark:text-slate-100 mt-2">
            {executiveSummary.overallHealthScore}
            <span className="text-base font-normal text-slate-400">/100</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Multi-factor composite health score</p>
        </div>

        <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">M365 Secure Score</span>
            <TrendingUp size={14} className="text-emerald-500" />
          </div>
          <div className="text-3xl font-black text-emerald-700 dark:text-emerald-400 mt-2">
            {executiveSummary.secureScorePercent}%
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Industry benchmark: 63.4%</p>
        </div>

        <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Golden Baseline</span>
            <Lock size={14} className="text-blue-500" />
          </div>
          <div className="text-3xl font-black text-blue-700 dark:text-blue-400 mt-2">
            {executiveSummary.baselineAdoptionScore}%
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            {goldenBaselineSection.enforcedCount} Enforced • {goldenBaselineSection.reportOnlyCount} Audit
          </p>
        </div>

        <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">License Waste</span>
            <DollarSign size={14} className="text-amber-500" />
          </div>
          <div className="text-3xl font-black text-amber-700 dark:text-amber-400 mt-2">
            ${executiveSummary.totalMonthlyCostSavingsIdentified}
            <span className="text-xs font-normal text-slate-400">/mo</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            ${costOptimizationSection.totalEstimatedAnnualWaste.toLocaleString()} annual recoverable spend
          </p>
        </div>
      </div>

      {/* Strategic Highlights & Key Defenses */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Achievements Card */}
        <div className="p-5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm space-y-3 shadow-2xs">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-700 pb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-800 dark:text-emerald-400 flex items-center gap-1.5">
              <ShieldCheck size={16} className="text-emerald-600" />
              <span>Quarterly Defenses & Milestones</span>
            </h3>
            <span className="text-[11px] text-slate-400 font-mono">{executiveSummary.keyAchievements.length} Key Signals</span>
          </div>
          <ul className="space-y-2.5">
            {executiveSummary.keyAchievements.map((item, idx) => (
              <li key={idx} className="flex items-start gap-2 text-xs text-slate-800 dark:text-slate-200">
                <CheckCircle2 size={14} className="text-emerald-600 shrink-0 mt-0.5" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Priority Action Items */}
        <div className="p-5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm space-y-3 shadow-2xs">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-700 pb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-rose-800 dark:text-rose-400 flex items-center gap-1.5">
              <AlertTriangle size={16} className="text-rose-600" />
              <span>Prioritized Strategic Actions</span>
            </h3>
            <span className="text-[11px] text-slate-400 font-mono">QBR Agenda</span>
          </div>
          <ul className="space-y-2.5">
            {executiveSummary.topActionItems.map((item, idx) => (
              <li key={idx} className="flex items-start gap-2 text-xs text-slate-800 dark:text-slate-200">
                <ChevronRight size={14} className="text-rose-600 shrink-0 mt-0.5" />
                <span className="font-medium">{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Quick Actions Footer Banner */}
      <div className="p-4 bg-gradient-to-r from-slate-900 to-slate-800 text-white rounded-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-sm bg-emerald-500/20 border border-emerald-400/30 flex items-center justify-center text-emerald-400">
            <Sparkles size={20} />
          </div>
          <div>
            <div className="text-sm font-bold">Ready to present to {currentReport.tenant.displayName}?</div>
            <div className="text-xs text-slate-400 mt-0.5">
              Launch the formatted deliverable preview with client branding, customized analyst sign-off, and print-ready layout.
            </div>
          </div>
        </div>

        <button
          onClick={handleOpenPreview}
          className="px-4 py-2 text-xs font-bold text-slate-900 bg-emerald-400 hover:bg-emerald-300 rounded-sm flex items-center gap-1.5 transition-colors shrink-0"
        >
          <Printer size={14} />
          <span>Launch Presentation View</span>
        </button>
      </div>

      {/* Preview Modal */}
      <ReportPreviewModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        report={previewReport}
      />
    </div>
  );
};
