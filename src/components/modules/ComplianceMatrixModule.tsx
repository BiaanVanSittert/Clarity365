import React, { useState, useMemo } from "react";
import {
  Tenant,
  TenantSecuritySnapshot,
  ComplianceFramework,
  ComplianceControlItem,
} from "@/lib/types";
import {
  evaluateTenantCompliance,
  evaluateFleetCompliance,
} from "@/lib/services/compliance-evaluator";
import {
  Award,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Search,
  Filter,
  Download,
  Building2,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Info,
} from "lucide-react";
import { exportToCsv } from "@/lib/utils/csv";

interface ComplianceMatrixModuleProps {
  tenants: Tenant[];
  snapshots: TenantSecuritySnapshot[];
  onSelectTenant: (tenantId: string, targetModule?: string, targetEntityId?: string) => void;
}

export const ComplianceMatrixModule: React.FC<ComplianceMatrixModuleProps> = ({
  tenants,
  snapshots,
  onSelectTenant,
}) => {
  const [selectedFramework, setSelectedFramework] = useState<ComplianceFramework>("cis_m365_v3");
  const [selectedTenantId, setSelectedTenantId] = useState<string>("fleet");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [expandedControlId, setExpandedControlId] = useState<string | null>(null);

  // Snapshot map
  const snapshotMap = useMemo(() => {
    const map = new Map<string, TenantSecuritySnapshot>();
    for (const snap of snapshots) {
      map.set(snap.tenant.id, snap);
    }
    return map;
  }, [snapshots]);

  // Assessment computation
  const assessment = useMemo(() => {
    if (selectedTenantId === "fleet") {
      // Evaluate first tenant or aggregate
      const firstSnap = snapshots[0];
      return firstSnap ? evaluateTenantCompliance(firstSnap, selectedFramework) : null;
    }
    const snap = snapshotMap.get(selectedTenantId);
    return snap ? evaluateTenantCompliance(snap, selectedFramework) : null;
  }, [selectedTenantId, selectedFramework, snapshots, snapshotMap]);

  const fleetSummary = useMemo(() => {
    return evaluateFleetCompliance(snapshots, selectedFramework);
  }, [snapshots, selectedFramework]);

  // Filtered controls
  const filteredControls = useMemo(() => {
    if (!assessment) return [];
    return assessment.controls.filter((ctrl) => {
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        ctrl.controlNumber.toLowerCase().includes(q) ||
        ctrl.title.toLowerCase().includes(q) ||
        ctrl.description.toLowerCase().includes(q) ||
        ctrl.section.toLowerCase().includes(q);

      if (!matchesSearch) return false;

      if (statusFilter !== "all" && ctrl.status !== statusFilter) return false;
      if (levelFilter !== "all" && ctrl.level !== levelFilter) return false;

      return true;
    });
  }, [assessment, searchQuery, statusFilter, levelFilter]);

  const handleExportCsv = () => {
    if (!assessment) return;
    const headers = ["ControlNumber", "Section", "Title", "Level", "Status", "Relevance", "Evidence", "RemediationGuide"];
    const rows = assessment.controls.map((c) => [
      c.controlNumber,
      c.section,
      c.title,
      c.level || "N/A",
      c.status,
      c.relevance,
      c.evidence,
      c.remediationGuide,
    ]);

    exportToCsv(`Compliance_${selectedFramework}_${selectedTenantId}.csv`, headers, rows);
  };

  const statusIcons = {
    compliant: <CheckCircle2 size={15} className="text-emerald-600 dark:text-emerald-400" />,
    non_compliant: <XCircle size={15} className="text-rose-600 dark:text-rose-400" />,
    partially_compliant: <AlertTriangle size={15} className="text-amber-600 dark:text-amber-400" />,
    not_applicable: <HelpCircle size={15} className="text-slate-400" />,
  };

  const statusBadges = {
    compliant: "bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800",
    non_compliant: "bg-rose-50 text-rose-800 border-rose-300 dark:bg-rose-950 dark:text-rose-300 dark:border-rose-800",
    partially_compliant: "bg-amber-50 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800",
    not_applicable: "bg-slate-100 text-slate-600 border-slate-300 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
  };

  const statusLabels = {
    compliant: "Compliant (Pass)",
    non_compliant: "Non-Compliant (Fail)",
    partially_compliant: "Partially Compliant",
    not_applicable: "Not Applicable (License Gated)",
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-white dark:bg-slate-800 p-5 border border-slate-200 dark:border-slate-700 rounded-sm shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Award className="text-emerald-600 dark:text-emerald-400" size={18} />
              <span>Compliance Frameworks & Audit Evidence</span>
            </h2>
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 rounded-sm">
              PHASE 2.3
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Automated alignment against the CIS Microsoft 365 Foundations Benchmark, NIST CSF 2.0, and Essential Eight with technical audit evidence.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCsv}
            className="px-3.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-slate-300 dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} />
            <span>Export Audit CSV</span>
          </button>
        </div>
      </div>

      {/* Framework Selector Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-700 pb-2 overflow-x-auto">
        <button
          onClick={() => setSelectedFramework("cis_m365_v3")}
          className={`px-3.5 py-2 text-xs font-semibold rounded-sm border transition-colors flex items-center gap-2 ${
            selectedFramework === "cis_m365_v3"
              ? "bg-slate-900 text-white border-slate-900 dark:bg-emerald-600 dark:border-emerald-600 shadow-xs"
              : "bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:bg-slate-50"
          }`}
        >
          <Award size={14} />
          <span>CIS Microsoft 365 Foundations v3.0</span>
        </button>

        <button
          onClick={() => setSelectedFramework("nist_csf_v2")}
          className={`px-3.5 py-2 text-xs font-semibold rounded-sm border transition-colors flex items-center gap-2 ${
            selectedFramework === "nist_csf_v2"
              ? "bg-slate-900 text-white border-slate-900 dark:bg-emerald-600 dark:border-emerald-600 shadow-xs"
              : "bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:bg-slate-50"
          }`}
        >
          <ShieldCheck size={14} />
          <span>NIST Cybersecurity Framework (CSF 2.0)</span>
        </button>

        <button
          onClick={() => setSelectedFramework("essential_eight")}
          className={`px-3.5 py-2 text-xs font-semibold rounded-sm border transition-colors flex items-center gap-2 ${
            selectedFramework === "essential_eight"
              ? "bg-slate-900 text-white border-slate-900 dark:bg-emerald-600 dark:border-emerald-600 shadow-xs"
              : "bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:bg-slate-50"
          }`}
        >
          <ShieldAlert size={14} />
          <span>Essential Eight (ACSC)</span>
        </button>
      </div>

      {/* Tenant Filter Selector */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-slate-500 flex items-center gap-1 mr-1">
            <Building2 size={13} />
            <span>Scope:</span>
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

        <div className="text-xs text-slate-500 font-mono">
          Fleet Avg: <strong className="text-slate-800 dark:text-slate-200">{fleetSummary.overallFleetCompliancePercentage}%</strong>
        </div>
      </div>

      {/* Assessment Scorecards */}
      {assessment && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
            <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Compliance Score</div>
            <div className="text-3xl font-black text-slate-900 dark:text-slate-100 mt-1">
              {assessment.scorePercentage}%
            </div>
            <p className="text-[10px] text-slate-500 mt-1">
              {assessment.compliantCount} of {assessment.totalControls} controls passing
            </p>
          </div>

          <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
            <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Level 1 (Foundations)</div>
            <div className="text-3xl font-black text-emerald-700 dark:text-emerald-400 mt-1">
              {assessment.level1ScorePercentage !== undefined ? `${assessment.level1ScorePercentage}%` : "100%"}
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Essential defense baseline</p>
          </div>

          <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
            <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Level 2 (Hardened)</div>
            <div className="text-3xl font-black text-blue-700 dark:text-blue-400 mt-1">
              {assessment.level2ScorePercentage !== undefined ? `${assessment.level2ScorePercentage}%` : "N/A"}
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Defense-in-depth risk policies</p>
          </div>

          <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
            <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Non-Compliant Gaps</div>
            <div className="text-3xl font-black text-rose-600 mt-1">
              {assessment.nonCompliantCount}
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Immediate remediation targets</p>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search controls, sections, or keywords..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-slate-200 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2 py-1 text-xs border border-slate-200 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
          >
            <option value="all">All Statuses</option>
            <option value="non_compliant">Non-Compliant (Failing)</option>
            <option value="compliant">Compliant (Pass)</option>
            <option value="partially_compliant">Partially Compliant</option>
          </select>

          {selectedFramework === "cis_m365_v3" && (
            <select
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value)}
              className="px-2 py-1 text-xs border border-slate-200 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
            >
              <option value="all">All Levels (L1 & L2)</option>
              <option value="Level 1">Level 1 Only</option>
              <option value="Level 2">Level 2 Only</option>
            </select>
          )}
        </div>
      </div>

      {/* Controls Evaluation Table */}
      <div className="border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-slate-50 dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            {assessment?.frameworkTitle} Control Specification
          </h3>
          <span className="text-[11px] font-mono text-slate-500">
            {filteredControls.length} Controls Evaluated
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-10"></th>
                <th className="w-20">Control</th>
                <th className="w-48">Section</th>
                <th>Requirement & Title</th>
                <th className="w-24">Level</th>
                <th className="w-48">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredControls.map((ctrl) => {
                const isExpanded = expandedControlId === ctrl.id;

                return (
                  <React.Fragment key={ctrl.id}>
                    <tr
                      onClick={() => setExpandedControlId(isExpanded ? null : ctrl.id)}
                      className="cursor-pointer hover:bg-slate-50/80 dark:hover:bg-slate-800/60 transition-colors"
                    >
                      <td className="text-center text-slate-400">
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </td>
                      <td className="font-mono font-bold text-xs text-slate-900 dark:text-slate-100">
                        {ctrl.controlNumber}
                      </td>
                      <td className="text-xs text-slate-500 font-medium truncate max-w-[180px]" title={ctrl.section}>
                        {ctrl.section}
                      </td>
                      <td>
                        <div className="font-semibold text-xs text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                          <span>{ctrl.title}</span>
                          {ctrl.relatedBaselineCode && (
                            <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 rounded-sm">
                              {ctrl.relatedBaselineCode}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 line-clamp-1">
                          {ctrl.description}
                        </div>
                      </td>
                      <td>
                        {ctrl.level ? (
                          <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-sm bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                            {ctrl.level}
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-400 font-mono">-</span>
                        )}
                      </td>
                      <td>
                        <div className="flex items-center gap-1.5">
                          {statusIcons[ctrl.status]}
                          <span className={`px-2 py-0.5 text-[11px] font-bold rounded-sm border ${statusBadges[ctrl.status]}`}>
                            {statusLabels[ctrl.status]}
                          </span>
                        </div>
                      </td>
                    </tr>

                    {/* Expandable Technical Evidence & Remediation Drawer */}
                    {isExpanded && (
                      <tr className="bg-slate-50/50 dark:bg-slate-900/40">
                        <td></td>
                        <td colSpan={5} className="py-3 px-4 space-y-2.5">
                          <div className="p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm space-y-2 shadow-2xs">
                            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800 dark:text-slate-200">
                              <Info size={14} className="text-blue-500" />
                              <span>Verifiable Technical Audit Evidence</span>
                            </div>
                            <div className="p-2.5 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-sm font-mono text-[11px] text-slate-800 dark:text-slate-200">
                              {ctrl.evidence}
                            </div>

                            <div className="pt-2 border-t border-slate-100 dark:border-slate-700 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs">
                              <div>
                                <span className="font-bold text-slate-700 dark:text-slate-300">Remediation Guidance: </span>
                                <span className="text-slate-600 dark:text-slate-400">{ctrl.remediationGuide}</span>
                              </div>

                              {ctrl.relatedBaselineCode && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onSelectTenant(selectedTenantId === "fleet" ? tenants[0]?.id : selectedTenantId, "fleet_rollout");
                                  }}
                                  className="px-2.5 py-1 text-[11px] font-semibold text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 rounded-sm flex items-center gap-1 shrink-0"
                                >
                                  <span>Deploy {ctrl.relatedBaselineCode}</span>
                                  <ExternalLink size={12} />
                                </button>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
