import React, { useState } from "react";
import { Modal } from "../common/Modal";
import { ExecutiveQbrReport } from "@/lib/types";
import {
  ShieldCheck,
  ShieldAlert,
  Printer,
  Download,
  FileCode,
  DollarSign,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Mail,
  Share2,
  Users,
  Settings,
  ChevronRight,
  ExternalLink,
} from "lucide-react";

interface ReportPreviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: ExecutiveQbrReport | null;
  onUpdateBranding?: (branding: { mspName: string; preparedBy: string }) => void;
}

export const ReportPreviewModal: React.FC<ReportPreviewModalProps> = ({
  isOpen,
  onClose,
  report,
  onUpdateBranding,
}) => {
  const [isEditingBranding, setIsEditingBranding] = useState(false);
  const [mspName, setMspName] = useState(report?.branding.mspName || "Clarity365 Cyber Defense");
  const [preparedBy, setPreparedBy] = useState(report?.branding.preparedBy || "Lead Cloud Security Architect");

  if (!report) return null;

  const handleSaveBranding = () => {
    setIsEditingBranding(false);
    if (onUpdateBranding) {
      onUpdateBranding({ mspName, preparedBy });
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `QBR_Report_${report.tenant.defaultDomain}_${report.period}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const {
    executiveSummary,
    identityMfaSection,
    goldenBaselineSection,
    threatsAndHygieneSection,
    costOptimizationSection,
  } = report;

  const statusColors = {
    optimal: "bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800",
    acceptable: "bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-800",
    needs_attention: "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800",
    critical_risk: "bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950 dark:text-rose-300 dark:border-rose-800",
  };

  const statusLabels = {
    optimal: "Optimal Security Posture",
    acceptable: "Acceptable Posture (Monitored)",
    needs_attention: "Action Required (Drift Detected)",
    critical_risk: "Critical Security Risks Present",
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Executive QBR Deliverable Preview" maxWidth="3xl">
      {/* Top Toolbar (Hidden during Print) */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 mb-4 border-b border-slate-200 dark:border-slate-800 print:hidden">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-bold text-slate-500 uppercase tracking-wider">
            Executive Deliverable Preview
          </span>
          <span className="px-2 py-0.5 text-[10px] font-bold rounded-sm bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
            {report.period}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsEditingBranding(!isEditingBranding)}
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-sm hover:bg-slate-50 dark:hover:bg-slate-700 flex items-center gap-1.5"
          >
            <Settings size={13} />
            <span>Customize Branding</span>
          </button>
          <button
            onClick={handleExportJson}
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-sm hover:bg-slate-50 dark:hover:bg-slate-700 flex items-center gap-1.5"
          >
            <Download size={13} />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrint}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 dark:bg-emerald-600 dark:hover:bg-emerald-500 rounded-sm flex items-center gap-1.5 shadow-sm"
          >
            <Printer size={14} />
            <span>Print to PDF</span>
          </button>
        </div>
      </div>

      {/* Branding Editor Drawer */}
      {isEditingBranding && (
        <div className="p-3 mb-4 border border-blue-200 dark:border-blue-900 bg-blue-50/50 dark:bg-blue-950/30 rounded-sm space-y-3 print:hidden">
          <div className="text-xs font-bold text-blue-900 dark:text-blue-300">Customize MSP Deliverable Header</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 block mb-1">MSP / Advisory Organization</label>
              <input
                type="text"
                value={mspName}
                onChange={(e) => setMspName(e.target.value)}
                className="w-full px-2.5 py-1 text-xs border border-slate-300 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900"
              />
            </div>
            <div>
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 block mb-1">Prepared By (Lead Security Analyst)</label>
              <input
                type="text"
                value={preparedBy}
                onChange={(e) => setPreparedBy(e.target.value)}
                className="w-full px-2.5 py-1 text-xs border border-slate-300 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button
              onClick={() => setIsEditingBranding(false)}
              className="px-2.5 py-1 text-xs text-slate-600 hover:bg-slate-200 rounded-sm"
            >
              Cancel
            </button>
            <button
              onClick={handleSaveBranding}
              className="px-3 py-1 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-sm"
            >
              Apply Updates
            </button>
          </div>
        </div>
      )}

      {/* Printable Report Document Body */}
      <div className="print-report space-y-6 text-slate-900 dark:text-slate-100">
        {/* Cover / Header Section */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-5 border-b-2 border-slate-900 dark:border-slate-700 gap-4">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400 font-mono">
              {mspName}
            </div>
            <h1 className="text-xl sm:text-2xl font-black tracking-tight text-slate-900 dark:text-slate-100 mt-1">
              Executive Cybersecurity & Cloud Posture Review
            </h1>
            <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400 mt-1.5 font-medium">
              <span>Client: <strong className="text-slate-800 dark:text-slate-200">{report.tenant.displayName}</strong></span>
              <span>•</span>
              <span>Tenant: <code className="font-mono text-[11px]">{report.tenant.defaultDomain}</code></span>
              <span>•</span>
              <span>Tier: <span className="font-semibold">{report.tenant.tier.replace("_", " ")}</span></span>
            </div>
          </div>

          <div className="sm:text-right">
            <span className={`inline-block px-3 py-1 text-xs font-bold rounded-sm border ${statusColors[executiveSummary.headlineStatus]}`}>
              {statusLabels[executiveSummary.headlineStatus]}
            </span>
            <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
              Period: {report.period} | Prepared by: {preparedBy}
            </div>
          </div>
        </div>

        {/* Executive Scorecard Matrix */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 rounded-sm">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Overall Posture</div>
            <div className="text-2xl font-black text-slate-900 dark:text-slate-100 mt-1">
              {executiveSummary.overallHealthScore}<span className="text-sm font-normal text-slate-400">/100</span>
            </div>
            <div className="text-[10px] text-slate-500 mt-1">Weighted composite health</div>
          </div>

          <div className="p-3 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 rounded-sm">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">M365 Secure Score</div>
            <div className="text-2xl font-black text-emerald-700 dark:text-emerald-400 mt-1">
              {executiveSummary.secureScorePercent}%
            </div>
            <div className="text-[10px] text-slate-500 mt-1">vs 63% industry benchmark</div>
          </div>

          <div className="p-3 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 rounded-sm">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Golden Baseline</div>
            <div className="text-2xl font-black text-blue-700 dark:text-blue-400 mt-1">
              {executiveSummary.baselineAdoptionScore}%
            </div>
            <div className="text-[10px] text-slate-500 mt-1">
              {goldenBaselineSection.enforcedCount} Enforced, {goldenBaselineSection.reportOnlyCount} Audit
            </div>
          </div>

          <div className="p-3 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 rounded-sm">
            <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Subscription Waste</div>
            <div className="text-2xl font-black text-amber-700 dark:text-amber-400 mt-1">
              ${executiveSummary.totalMonthlyCostSavingsIdentified.toLocaleString()}
              <span className="text-xs font-medium text-slate-500">/mo</span>
            </div>
            <div className="text-[10px] text-slate-500 mt-1">
              ${costOptimizationSection.totalEstimatedAnnualWaste.toLocaleString()} annual recovery
            </div>
          </div>
        </div>

        {/* Executive Highlights & Immediate Action Items */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="p-4 border border-emerald-200 dark:border-emerald-900 bg-emerald-50/40 dark:bg-emerald-950/20 rounded-sm space-y-2">
            <div className="text-xs font-bold text-emerald-900 dark:text-emerald-300 uppercase tracking-wider flex items-center gap-1.5">
              <ShieldCheck size={14} className="text-emerald-600" />
              <span>Key Defenses & Achievements</span>
            </div>
            <ul className="space-y-1.5 text-xs text-emerald-950 dark:text-emerald-200">
              {executiveSummary.keyAchievements.map((item, idx) => (
                <li key={idx} className="flex items-start gap-1.5">
                  <CheckCircle2 size={13} className="text-emerald-600 shrink-0 mt-0.5" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="p-4 border border-rose-200 dark:border-rose-900 bg-rose-50/40 dark:bg-rose-950/20 rounded-sm space-y-2">
            <div className="text-xs font-bold text-rose-900 dark:text-rose-300 uppercase tracking-wider flex items-center gap-1.5">
              <AlertTriangle size={14} className="text-rose-600" />
              <span>Prioritized Strategic Action Items</span>
            </div>
            <ul className="space-y-1.5 text-xs text-rose-950 dark:text-rose-200">
              {executiveSummary.topActionItems.map((item, idx) => (
                <li key={idx} className="flex items-start gap-1.5">
                  <ChevronRight size={13} className="text-rose-600 shrink-0 mt-0.5" />
                  <span className="font-medium">{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Section 1: Identity Resilience & MFA Governance */}
        <div className="space-y-2.5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-slate-200 dark:border-slate-800 pb-1 flex items-center gap-1.5">
            <Users size={14} className="text-slate-500" />
            <span>1. Identity Security & Access Governance</span>
          </h3>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            <div className="p-2.5 border border-slate-200 dark:border-slate-700 rounded-sm">
              <div className="text-slate-500">MFA Adoption Rate</div>
              <div className="text-lg font-bold mt-0.5">{identityMfaSection.mfaEnforcedPercent}%</div>
              <div className="text-[10px] text-slate-400">{identityMfaSection.totalUsers} total directory identities</div>
            </div>
            <div className="p-2.5 border border-slate-200 dark:border-slate-700 rounded-sm">
              <div className="text-slate-500">Administrator Accounts</div>
              <div className="text-lg font-bold mt-0.5">{identityMfaSection.adminCount}</div>
              <div className="text-[10px] text-slate-400">Privileged roles assigned</div>
            </div>
            <div className="p-2.5 border border-slate-200 dark:border-slate-700 rounded-sm">
              <div className="text-slate-500">Phishing-Resistant MFA</div>
              <div className="text-lg font-bold text-emerald-600 mt-0.5">
                {identityMfaSection.adminsWithPhishingResistantMfa} / {identityMfaSection.adminCount}
              </div>
              <div className="text-[10px] text-slate-400">FIDO2 / Passkey / Hello keys</div>
            </div>
            <div className="p-2.5 border border-slate-200 dark:border-slate-700 rounded-sm">
              <div className="text-slate-500">Risky / Compromised Users</div>
              <div className="text-lg font-bold text-rose-600 mt-0.5">{identityMfaSection.riskyUsersCount}</div>
              <div className="text-[10px] text-slate-400">Flagged by Entra Protection</div>
            </div>
          </div>
        </div>

        {/* Section 2: Golden Baseline Standards Status */}
        <div className="space-y-2.5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-slate-200 dark:border-slate-800 pb-1 flex items-center gap-1.5">
            <Lock size={14} className="text-slate-500" />
            <span>2. Zero-Trust Golden Baseline Compliance (CA01 - CA10)</span>
          </h3>

          <div className="border border-slate-200 dark:border-slate-700 rounded-sm overflow-hidden text-xs">
            <table className="w-full text-left border-collapse">
              <thead className="bg-slate-50 dark:bg-slate-800/80 text-[11px] font-semibold text-slate-600 dark:text-slate-300">
                <tr>
                  <th className="py-2 px-3 w-16">Code</th>
                  <th className="py-2 px-3">Policy Baseline Standard</th>
                  <th className="py-2 px-3 w-32">Status</th>
                  <th className="py-2 px-3">Protected Impact / Residual Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {goldenBaselineSection.policies.map((p) => (
                  <tr key={p.code} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/40">
                    <td className="py-2 px-3 font-mono font-bold text-slate-900 dark:text-slate-100">{p.code}</td>
                    <td className="py-2 px-3 font-medium text-slate-800 dark:text-slate-200">{p.name}</td>
                    <td className="py-2 px-3">
                      {p.state === "enforced" ? (
                        <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-sm bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300">
                          Enforced
                        </span>
                      ) : p.state === "report_only" ? (
                        <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-sm bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300">
                          Report-Only
                        </span>
                      ) : p.state === "misconfigured" ? (
                        <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-sm bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300">
                          Misconfigured
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-sm bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300">
                          Missing
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-[11px] text-slate-600 dark:text-slate-400">{p.impact}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section 3: Threats, Data Exfiltration & Hygiene */}
        <div className="space-y-2.5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-slate-200 dark:border-slate-800 pb-1 flex items-center gap-1.5">
            <Share2 size={14} className="text-slate-500" />
            <span>3. Threat Mitigation, Email Forwarding & Collaboration Controls</span>
          </h3>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            <div className="p-2.5 border border-slate-200 dark:border-slate-700 rounded-sm">
              <div className="text-slate-500">External Forwarding</div>
              <div className={`text-lg font-bold mt-0.5 ${threatsAndHygieneSection.externalForwardingRulesBlocked > 0 ? "text-emerald-600" : "text-slate-900"}`}>
                {threatsAndHygieneSection.externalForwardingRulesBlocked} Blocked
              </div>
              <div className="text-[10px] text-slate-400">0 auto-exfiltration rules active</div>
            </div>
            <div className="p-2.5 border border-slate-200 dark:border-slate-700 rounded-sm">
              <div className="text-slate-500">Fleet TABL Threat Blocks</div>
              <div className="text-lg font-bold text-blue-600 mt-0.5">{threatsAndHygieneSection.threatIndicatorsActive} Active</div>
              <div className="text-[10px] text-slate-400">Malicious domains & hashes</div>
            </div>
            <div className="p-2.5 border border-slate-200 dark:border-slate-700 rounded-sm">
              <div className="text-slate-500">Unmanaged / Non-Compliant Devices</div>
              <div className={`text-lg font-bold mt-0.5 ${threatsAndHygieneSection.unmanagedDevicesCount > 0 ? "text-amber-600" : "text-slate-900"}`}>
                {threatsAndHygieneSection.unmanagedDevicesCount}
              </div>
              <div className="text-[10px] text-slate-400">Untrusted endpoints accessing apps</div>
            </div>
            <div className="p-2.5 border border-slate-200 dark:border-slate-700 rounded-sm">
              <div className="text-slate-500">Anonymous SharePoint Links</div>
              <div className={`text-lg font-bold mt-0.5 ${threatsAndHygieneSection.anonymousSharePointLinksCount > 0 ? "text-rose-600" : "text-emerald-600"}`}>
                {threatsAndHygieneSection.anonymousSharePointLinksCount}
              </div>
              <div className="text-[10px] text-slate-400">'Anyone with link' public shares</div>
            </div>
          </div>
        </div>

        {/* Section 4: Cost Optimization & License Hygiene Recovery */}
        <div className="space-y-2.5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 border-b border-slate-200 dark:border-slate-800 pb-1 flex items-center gap-1.5">
            <DollarSign size={14} className="text-slate-500" />
            <span>4. Subscription Efficiency & Financial Waste Recovery</span>
          </h3>

          <div className="p-3 bg-amber-50/50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800 rounded-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
            <div>
              <span className="font-bold text-amber-900 dark:text-amber-300">
                Identified Reclaimable Spend: ${costOptimizationSection.totalEstimatedAnnualWaste.toLocaleString()} / year
              </span>
              <p className="text-[11px] text-amber-800 dark:text-amber-400 mt-0.5">
                {costOptimizationSection.inactiveLicensedUsersCount} inactive account(s) and {costOptimizationSection.wastedSharedMailboxLicensesCount} paid shared mailbox(es) consuming subscription costs without active usage.
              </p>
            </div>
            <div className="text-right whitespace-nowrap">
              <span className="px-2 py-1 text-[11px] font-bold rounded-sm bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300">
                Reclaim Potential: ${executiveSummary.totalMonthlyCostSavingsIdentified}/mo
              </span>
            </div>
          </div>
        </div>

        {/* Sign-off / Confidentiality Footer */}
        <div className="pt-4 border-t border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between text-[11px] text-slate-400">
          <span>Clarity365 Automated Governance Platform • Confidential Client Deliverable</span>
          <span>Generated: {new Date(report.generatedAt).toLocaleDateString()}</span>
        </div>
      </div>
    </Modal>
  );
};
