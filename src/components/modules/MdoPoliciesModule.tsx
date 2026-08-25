import React, { useState } from "react";
import { TenantSecuritySnapshot, TablEntry, MdoThreatPolicy, MdoBaselineResult } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Modal } from "../common/Modal";
import { LocalOnlyNotice } from "../common/LocalOnlyNotice";
import { evaluateMdoBaseline } from "@/lib/services/mdo-baseline-matcher";
import { MDO_BASELINE_STANDARDS } from "@/lib/data/mdo-baseline-definitions";
import {
  Layers,
  Plus,
  Trash2,
  Search,
  Filter,
  AlertTriangle,
  Download,
  ExternalLink,
  Info,
  Mail,
  Wrench,
  ShieldCheck,
} from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";

interface MdoPoliciesModuleProps {
  snapshot: TenantSecuritySnapshot;
  onLocalRefresh: () => void;
  onOpenPermissions: () => void;
}

const STALE_NOTES = new Set(["Added via Clarity365 TABL Manager", "No expiration configured.", ""]);

function isTablEntryStale(entry: TablEntry): boolean {
  if (entry.expirationDate === "Never") return true;
  const daysUntilExpiry = (new Date(entry.expirationDate).getTime() - Date.now()) / 86_400_000;
  if (!isNaN(daysUntilExpiry) && daysUntilExpiry <= 14) return true;
  return STALE_NOTES.has(entry.notes.trim());
}

function defaultExpirationInput(): string {
  return new Date(Date.now() + 90 * 86_400_000).toISOString().slice(0, 10);
}

export const MdoPoliciesModule: React.FC<MdoPoliciesModuleProps> = ({ snapshot, onLocalRefresh, onOpenPermissions }) => {
  const { mdoThreat, tenant } = snapshot;
  const [activeTab, setActiveTab] = useState<"baseline" | "policies" | "tabl" | "alerts">("baseline");
  const [searchQuery, setSearchQuery] = useState("");
  const [tablFilter, setTablFilter] = useState<string>("all");

  const exoConnected = !!tenant.credentials.exoRefreshToken;
  const exoWriteEnabled = !!tenant.credentials.exoWriteEnabled;
  const mdoPolicySyncErrors = (snapshot.syncHealth?.errors || []).filter((e) => e.startsWith("MDO Policies:"));
  const mdoAlertSyncErrors = (snapshot.syncHealth?.errors || []).filter((e) => e.startsWith("MDO Threat Alerts:"));

  const policies = mdoThreat.policies;
  const tablEntries = mdoThreat.tabl;
  const alerts = mdoThreat.alerts;

  const { results: baselineResults, coveragePercent } = evaluateMdoBaseline(policies);
  const policiesBelowCount = baselineResults.filter((r) => !r.met).length;
  const unresolvedHighAlertCount = alerts.filter((a) => a.status !== "resolved" && a.severity === "high").length;
  const needsReviewCount = tablEntries.filter(isTablEntryStale).length;

  // ---- Baseline & Posture tab: apply a one-setting EXO fix -------------------------
  const [fixModalCode, setFixModalCode] = useState<string | null>(null);
  const [isFixing, setIsFixing] = useState(false);
  const [fixError, setFixError] = useState<string | null>(null);

  const fixStandard = fixModalCode ? MDO_BASELINE_STANDARDS.find((s) => s.code === fixModalCode) : undefined;

  const applyFix = async () => {
    if (!fixModalCode) return;
    setIsFixing(true);
    setFixError(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/mdo-fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: fixModalCode }),
      });
      const data = await res.json();
      if (data.success) {
        setFixModalCode(null);
        onLocalRefresh();
      } else {
        setFixError(data.error || "Failed to apply fix.");
      }
    } catch (err: any) {
      setFixError(err.message || "Network error while applying fix.");
    } finally {
      setIsFixing(false);
    }
  };

  // ---- Add TABL Modal State ---------------------------------------------------------
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [listType, setListType] = useState<"allow" | "block">("block");
  const [entryType, setEntryType] = useState<"domain" | "sender" | "url" | "file_hash">("domain");
  const [entryValue, setEntryValue] = useState("");
  const [entryNotes, setEntryNotes] = useState("");
  const [noExpiration, setNoExpiration] = useState(false);
  const [expirationInput, setExpirationInput] = useState(defaultExpirationInput());
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  // Real Exchange Online writes get a mandatory confirm step before the actual
  // API call fires — these entries take effect immediately with no
  // report-only equivalent, mirroring DeployCaPolicyModal's showConfirmDeploy
  // safety pattern for the (less consequential) CA auto-deploy feature.
  const [showWriteConfirm, setShowWriteConfirm] = useState(false);

  // Inline remove-confirmation for live-write-enabled tenants only; local-only
  // tenants keep the original single-click delete since nothing live is at risk.
  const [pendingRemoveId, setPendingRemoveId] = useState<string | null>(null);
  const [isRemoving, setIsRemoving] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);

  const resetAddForm = () => {
    setEntryValue("");
    setEntryNotes("");
    setNoExpiration(false);
    setExpirationInput(defaultExpirationInput());
  };

  const closeAddModal = () => {
    setIsAddModalOpen(false);
    setShowWriteConfirm(false);
    setAddError(null);
    resetAddForm();
  };

  const performAdd = async () => {
    setIsSubmitting(true);
    setAddError(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/tabl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          listType,
          entryType,
          value: entryValue.trim(),
          notes: entryNotes.trim(),
          addedBy: "secops-admin@clarity365.local",
          expirationDate: noExpiration ? "Never" : new Date(expirationInput).toISOString(),
        }),
      });
      const data = await res.json();
      if (data.success) {
        closeAddModal();
        onLocalRefresh();
      } else {
        setAddError(data.error || "Failed to add TABL entry.");
      }
    } catch (err: any) {
      setAddError(err.message || "Network error while adding TABL entry.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (exoConnected && exoWriteEnabled) {
      setShowWriteConfirm(true);
      return;
    }
    performAdd();
  };

  const performRemove = async (entryId: string) => {
    setIsRemoving(true);
    setRemoveError(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/tabl?entryId=${encodeURIComponent(entryId)}`, {
        method: "DELETE",
      });
      const data = await res.json();
      if (data.success) {
        setPendingRemoveId(null);
        onLocalRefresh();
      } else {
        setRemoveError(data.error || "Failed to remove TABL entry.");
      }
    } catch (err: any) {
      setRemoveError(err.message || "Network error while removing TABL entry.");
    } finally {
      setIsRemoving(false);
    }
  };

  const handleRemoveTabl = (entryId: string) => {
    if (exoConnected && exoWriteEnabled) {
      setRemoveError(null);
      setPendingRemoveId(entryId);
    } else {
      performRemove(entryId);
    }
  };

  const filteredTabl = tablEntries.filter((e) => {
    const matchesSearch =
      e.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.notes.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.addedBy.toLowerCase().includes(searchQuery.toLowerCase());

    if (tablFilter === "all") return matchesSearch;
    if (tablFilter === "block") return matchesSearch && e.listType === "block";
    if (tablFilter === "allow") return matchesSearch && e.listType === "allow";
    if (tablFilter === "needs_review") return matchesSearch && isTablEntryStale(e);
    return matchesSearch;
  });

  const handleExportPoliciesCSV = () => {
    const headers = ["PolicyType", "DisplayName", "AssignedScope", "ImpersonationProtection", "SpoofIntelligence", "ZapEnabled", "ComplianceRating"];
    const rows = policies.map((pol) => [
      pol.policyType,
      pol.displayName,
      pol.assignedScope,
      pol.impersonationProtection ? "Active" : "Off",
      pol.spoofIntelligence ? "Active" : "Off",
      pol.zapEnabled ? "Active" : "Off",
      pol.complianceRating,
    ]);
    exportToCsv(csvFilename("MdoPolicies", tenant.defaultDomainName), headers, rows);
  };

  const handleExportTablCSV = () => {
    const headers = ["Action", "Type", "Value", "Notes", "AddedBy"];
    const rows = filteredTabl.map((entry) => [entry.listType, entry.entryType, entry.value, entry.notes, entry.addedBy]);
    exportToCsv(csvFilename("TABL", tenant.defaultDomainName), headers, rows);
  };

  const resultFor = (code: string): MdoBaselineResult => baselineResults.find((r) => r.code === code)!;

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Layers size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 8: Email Threat Protection Posture (MDO Policies & TABL)
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Score Defender for Office 365 configuration against Microsoft's recommended baseline, govern the Allow/Block List, and surface real detected threats.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Plus size={14} />
            <span>Add Allow/Block Entry</span>
          </button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white border border-[#CBD5E1] rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 font-semibold">Baseline Coverage</div>
          <div className="text-xl font-bold font-mono text-slate-900 tabular-nums mt-0.5">{coveragePercent}%</div>
          <div className="text-[11px] text-slate-500 mt-0.5">
            {baselineResults.length - policiesBelowCount} / {baselineResults.length} checks met
          </div>
        </div>
        <div className={`p-3 border rounded-sm ${policiesBelowCount > 0 ? "bg-[#FEF2F2] border-[#EF4444]" : "bg-white border-[#CBD5E1]"}`}>
          <div className={`text-[10px] uppercase font-mono font-semibold ${policiesBelowCount > 0 ? "text-[#991B1B]" : "text-slate-500"}`}>
            Policies Below Recommended
          </div>
          <div className={`text-xl font-bold font-mono tabular-nums mt-0.5 ${policiesBelowCount > 0 ? "text-[#991B1B]" : "text-slate-900"}`}>
            {policiesBelowCount}
          </div>
          <div className={`text-[11px] mt-0.5 ${policiesBelowCount > 0 ? "text-[#991B1B]" : "text-slate-500"}`}>Out of {baselineResults.length} checks</div>
        </div>
        <div className={`p-3 border rounded-sm ${unresolvedHighAlertCount > 0 ? "bg-[#FEF2F2] border-[#EF4444]" : "bg-white border-[#CBD5E1]"}`}>
          <div className={`text-[10px] uppercase font-mono font-semibold ${unresolvedHighAlertCount > 0 ? "text-[#991B1B]" : "text-slate-500"}`}>
            Threats Detected (30d)
          </div>
          <div className={`text-xl font-bold font-mono tabular-nums mt-0.5 ${unresolvedHighAlertCount > 0 ? "text-[#991B1B]" : "text-slate-900"}`}>
            {alerts.length}
          </div>
          <div className={`text-[11px] mt-0.5 ${unresolvedHighAlertCount > 0 ? "text-[#991B1B]" : "text-slate-500"}`}>
            {unresolvedHighAlertCount} unresolved (high)
          </div>
        </div>
        <div className={`p-3 border rounded-sm ${needsReviewCount > 0 ? "bg-[#FFFBEB] border-[#F59E0B]" : "bg-white border-[#CBD5E1]"}`}>
          <div className={`text-[10px] uppercase font-mono font-semibold ${needsReviewCount > 0 ? "text-[#92400E]" : "text-slate-500"}`}>
            TABL Entries Needing Review
          </div>
          <div className={`text-xl font-bold font-mono tabular-nums mt-0.5 ${needsReviewCount > 0 ? "text-[#92400E]" : "text-slate-900"}`}>
            {needsReviewCount}
          </div>
          <div className={`text-[11px] mt-0.5 ${needsReviewCount > 0 ? "text-[#92400E]" : "text-slate-500"}`}>Out of {tablEntries.length} entries</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center justify-between border-b border-[#CBD5E1] bg-white px-2 pt-2">
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setActiveTab("baseline")}
            className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === "baseline" ? "border-slate-900 text-slate-900" : "border-transparent text-slate-500 hover:text-slate-900"
            }`}
          >
            Baseline & Posture ({coveragePercent}%)
          </button>
          <button
            onClick={() => setActiveTab("policies")}
            className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === "policies" ? "border-slate-900 text-slate-900" : "border-transparent text-slate-500 hover:text-slate-900"
            }`}
          >
            All Policies ({policies.length})
          </button>
          <button
            onClick={() => setActiveTab("tabl")}
            className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === "tabl" ? "border-slate-900 text-slate-900" : "border-transparent text-slate-500 hover:text-slate-900"
            }`}
          >
            Allow/Block List ({tablEntries.length})
          </button>
          <button
            onClick={() => setActiveTab("alerts")}
            className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === "alerts" ? "border-slate-900 text-slate-900" : "border-transparent text-slate-500 hover:text-slate-900"
            }`}
          >
            Threat Detections ({alerts.length})
          </button>
        </div>
      </div>

      {removeError && (
        <div className="p-2.5 bg-rose-50 border border-rose-300 text-rose-900 text-xs rounded-sm">{removeError}</div>
      )}

      {/* TAB: Baseline & Posture */}
      {activeTab === "baseline" && (
        <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
          <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Standard Baseline Specification & Configuration Alignment
            </h3>
            <span className="text-[11px] font-mono text-slate-500">
              {coveragePercent}% ({baselineResults.length - policiesBelowCount}/{baselineResults.length})
            </span>
          </div>

          {!exoConnected ? (
            <div className="p-6 text-center space-y-2">
              <Mail className="w-6 h-6 text-slate-300 mx-auto" />
              <p className="text-xs text-slate-500">Connect Exchange Online to score your Defender for Office 365 configuration.</p>
              <button
                onClick={onOpenPermissions}
                className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm inline-flex items-center gap-1.5"
              >
                <ExternalLink size={13} />
                <span>Connect Exchange Online</span>
              </button>
            </div>
          ) : (
            <>
              {mdoPolicySyncErrors.length > 0 && (
                <div className="m-3 p-3 bg-rose-50 border border-rose-300 text-rose-900 text-xs rounded-sm space-y-1.5">
                  <div className="flex items-center gap-2 font-semibold">
                    <AlertTriangle size={14} className="text-rose-600" />
                    <span>Exchange Online sync error</span>
                  </div>
                  {mdoPolicySyncErrors.map((err, i) => (
                    <div key={i} className="text-[11px] font-mono bg-white/70 p-1.5 border border-rose-200 rounded-sm">
                      {err}
                    </div>
                  ))}
                </div>
              )}
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse table-dense">
                  <thead>
                    <tr>
                      <th className="w-16">Code</th>
                      <th>Baseline Check</th>
                      <th className="w-36">Policy Type</th>
                      <th className="w-32">Status</th>
                      <th className="w-44 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {MDO_BASELINE_STANDARDS.map((standard) => {
                      const result = resultFor(standard.code);
                      return (
                        <tr key={standard.code}>
                          <td className="font-mono font-bold text-xs text-slate-900">{standard.code}</td>
                          <td>
                            <div className="font-semibold text-xs text-slate-900">{standard.name}</div>
                            <div className="text-[11px] text-slate-500 mt-0.5">{standard.description}</div>
                            <div className="text-[10px] text-slate-400 mt-0.5">Mitigates: {standard.riskMitigated}</div>
                          </td>
                          <td className="text-xs font-mono text-slate-700">{standard.policyType}</td>
                          <td>
                            {!result.policyFound ? (
                              <StatusPill status="fail" label="No Policy Found" size="sm" />
                            ) : result.met ? (
                              <StatusPill status="pass" label="Met" size="sm" />
                            ) : (
                              <StatusPill status="fail" label="Below Recommended" size="sm" />
                            )}
                          </td>
                          <td className="text-right">
                            {result.met ? (
                              <span className="text-[11px] text-slate-400">No action needed</span>
                            ) : !result.policyFound ? (
                              <span className="text-[11px] text-slate-400">Create the policy first</span>
                            ) : !standard.remediation ? (
                              <span className="text-[11px] text-slate-500">Manual review required</span>
                            ) : exoConnected && exoWriteEnabled ? (
                              <button
                                onClick={() => {
                                  setFixError(null);
                                  setFixModalCode(standard.code);
                                }}
                                className="px-2.5 py-1 text-[11px] font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm inline-flex items-center gap-1"
                              >
                                <Wrench size={11} />
                                <span>Fix This</span>
                              </button>
                            ) : (
                              <span className="text-[11px] text-slate-400" title="Enable live Exchange Online writes in the Permissions check to use one-click fixes">
                                Enable write access to fix
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      {/* TAB: All Policies */}
      {activeTab === "policies" && (
        <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
          <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Configured Defender for Office 365 Threat Policies
            </h3>
            <div className="flex items-center gap-3">
              <span className="text-[11px] font-mono text-slate-500">{policies.length} Policies Active</span>
              <button
                onClick={handleExportPoliciesCSV}
                title="Export policies to CSV"
                className="px-2 py-1 text-[11px] font-medium text-slate-700 bg-white hover:bg-slate-50 border border-[#CBD5E1] rounded-sm flex items-center gap-1 transition-colors"
              >
                <Download size={12} className="text-slate-500" />
                <span>Export CSV</span>
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse table-dense">
              <thead>
                <tr>
                  <th className="w-36">Policy Type</th>
                  <th>Display Name & Scope</th>
                  <th>Impersonation Protection</th>
                  <th>Spoof Intelligence</th>
                  <th>Zero-Hour Auto Purge (ZAP)</th>
                  <th className="w-28 text-right">Compliance</th>
                </tr>
              </thead>
              <tbody>
                {policies.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-4 text-center text-xs text-slate-500">
                      {!exoConnected ? (
                        <div className="space-y-2 py-2">
                          <Mail className="w-6 h-6 text-slate-300 mx-auto" />
                          <p>Connect Exchange Online to sync Defender for Office 365 policies.</p>
                          <button
                            onClick={onOpenPermissions}
                            className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm inline-flex items-center gap-1.5"
                          >
                            <ExternalLink size={13} />
                            <span>Connect Exchange Online</span>
                          </button>
                        </div>
                      ) : mdoPolicySyncErrors.length > 0 ? (
                        "Policies couldn't be loaded due to a sync error — see the Baseline & Posture tab."
                      ) : (
                        "No custom Defender for Office 365 policies configured. Default tenant presets apply."
                      )}
                    </td>
                  </tr>
                ) : (
                  policies.map((pol) => (
                    <tr key={pol.id}>
                      <td className="font-mono text-xs font-bold text-slate-900">{pol.policyType}</td>
                      <td>
                        <div className="font-semibold text-xs text-slate-900">{pol.displayName}</div>
                        <div className="text-[11px] text-slate-500">{pol.assignedScope}</div>
                      </td>
                      <td>
                        <StatusPill status={pol.impersonationProtection ? "pass" : "disabled"} label={pol.impersonationProtection ? "Active" : "Off"} size="sm" />
                      </td>
                      <td>
                        <StatusPill status={pol.spoofIntelligence ? "pass" : "disabled"} label={pol.spoofIntelligence ? "Active" : "Off"} size="sm" />
                      </td>
                      <td>
                        <StatusPill status={pol.zapEnabled ? "pass" : "disabled"} label={pol.zapEnabled ? "ZAP Enabled" : "Off"} size="sm" />
                      </td>
                      <td className="text-right">
                        <StatusPill status={pol.complianceRating} label={pol.complianceRating.toUpperCase()} size="sm" />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB: Allow/Block List */}
      {activeTab === "tabl" && (
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
            <div className="relative w-full sm:w-80">
              <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search domain, sender, URL, or notes..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <Filter size={14} className="text-slate-500" />
              <select
                value={tablFilter}
                onChange={(e) => setTablFilter(e.target.value)}
                className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
              >
                <option value="all">All Lists (Allow & Block)</option>
                <option value="block">Block List Only ({tablEntries.filter((e) => e.listType === "block").length})</option>
                <option value="allow">Allow List Only ({tablEntries.filter((e) => e.listType === "allow").length})</option>
                <option value="needs_review">Needs Review ({needsReviewCount})</option>
              </select>

              <button
                onClick={handleExportTablCSV}
                title="Export filtered TABL entries to CSV"
                className="px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-[#CBD5E1] rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
              >
                <Download size={13} className="text-slate-500" />
                <span>Export CSV</span>
              </button>
            </div>
          </div>

          <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
            <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                Tenant Allow/Block List (TABL) Indicators
              </h3>
              <span className="text-[11px] font-mono text-slate-500">{filteredTabl.length} Entries</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse table-dense">
                <thead>
                  <tr>
                    <th className="w-24">Action</th>
                    <th className="w-28">Type</th>
                    <th>Value / Indicator</th>
                    <th>Audit Reason / Security Notes</th>
                    <th className="w-28">Expires</th>
                    <th>Added By</th>
                    <th className="w-36 text-right">Delete</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTabl.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="p-4 text-center text-xs text-slate-500">
                        {tablEntries.length === 0 && !exoConnected ? (
                          <div className="space-y-2 py-2">
                            <Mail className="w-6 h-6 text-slate-300 mx-auto" />
                            <p>Connect Exchange Online to sync the live list, or add a local-only entry above.</p>
                            <button
                              onClick={onOpenPermissions}
                              className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm inline-flex items-center gap-1.5"
                            >
                              <ExternalLink size={13} />
                              <span>Connect Exchange Online</span>
                            </button>
                          </div>
                        ) : tablEntries.length === 0 && mdoPolicySyncErrors.length > 0 ? (
                          "Entries couldn't be loaded due to a sync error — see the Baseline & Posture tab."
                        ) : (
                          "No allow/block indicators found matching search."
                        )}
                      </td>
                    </tr>
                  ) : (
                    filteredTabl.map((entry) => {
                      const stale = isTablEntryStale(entry);
                      return (
                        <tr key={entry.id} className={entry.listType === "block" ? "bg-red-50/20" : "bg-emerald-50/20"}>
                          <td>
                            <StatusPill status={entry.listType === "block" ? "fail" : "pass"} label={entry.listType.toUpperCase()} size="sm" />
                          </td>
                          <td>
                            <span className="font-mono text-xs text-slate-700 uppercase font-semibold">{entry.entryType}</span>
                          </td>
                          <td>
                            <span className="font-mono text-xs font-bold text-slate-900">{entry.value}</span>
                          </td>
                          <td className="text-xs text-slate-600">
                            {entry.notes}
                            {stale && (
                              <span className="ml-1.5 text-[9px] font-mono uppercase px-1 bg-amber-100 text-amber-800 border border-amber-300 rounded-sm font-bold align-middle">
                                Needs Review
                              </span>
                            )}
                          </td>
                          <td className="text-[11px] font-mono text-slate-500">
                            {entry.expirationDate === "Never" ? "Never" : new Date(entry.expirationDate).toLocaleDateString()}
                          </td>
                          <td className="text-[11px] font-mono text-slate-500">{entry.addedBy}</td>
                          <td className="text-right">
                            {pendingRemoveId === entry.id ? (
                              <div className="flex items-center justify-end gap-1.5">
                                <span className="text-[10px] text-amber-800 font-medium">Remove from live EXO?</span>
                                <button
                                  onClick={() => setPendingRemoveId(null)}
                                  disabled={isRemoving}
                                  className="px-1.5 py-0.5 text-[10px] font-medium text-slate-600 bg-white border border-slate-300 rounded-sm hover:bg-slate-50 disabled:opacity-50"
                                >
                                  Cancel
                                </button>
                                <button
                                  onClick={() => performRemove(entry.id)}
                                  disabled={isRemoving}
                                  className="px-1.5 py-0.5 text-[10px] font-semibold text-white bg-red-600 hover:bg-red-700 rounded-sm disabled:opacity-50"
                                >
                                  {isRemoving ? "..." : "Remove"}
                                </button>
                              </div>
                            ) : (
                              <button
                                onClick={() => handleRemoveTabl(entry.id)}
                                title="Remove indicator"
                                className="p-1 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-sm transition-colors"
                              >
                                <Trash2 size={13} />
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB: Threat Detections */}
      {activeTab === "alerts" && (
        <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
          <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Defender for Office 365 Threat Detections (Last 30 Days)
            </h3>
            <span className="text-[11px] font-mono text-slate-500">{alerts.length} Alerts</span>
          </div>

          {mdoAlertSyncErrors.length > 0 && (
            <div className="m-3 p-3 bg-rose-50 border border-rose-300 text-rose-900 text-xs rounded-sm space-y-1.5">
              <div className="flex items-center gap-2 font-semibold">
                <AlertTriangle size={14} className="text-rose-600" />
                <span>Threat alert sync error</span>
              </div>
              {mdoAlertSyncErrors.map((err, i) => (
                <div key={i} className="text-[11px] font-mono bg-white/70 p-1.5 border border-rose-200 rounded-sm">
                  {err}
                </div>
              ))}
              <p className="text-[10px] text-rose-700">
                Ensure your App Registration has been granted <strong>SecurityAlert.Read.All</strong> with admin consent.
              </p>
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse table-dense">
              <thead>
                <tr>
                  <th className="w-20">Severity</th>
                  <th>Title & Description</th>
                  <th className="w-28">Category</th>
                  <th className="w-24">Status</th>
                  <th className="w-28">Classification</th>
                  <th className="w-28">Detected</th>
                  <th>Affected Users</th>
                  <th className="w-10"></th>
                </tr>
              </thead>
              <tbody>
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-4 text-center text-xs text-slate-500">
                      {mdoAlertSyncErrors.length > 0 ? (
                        "Threat alerts couldn't be loaded due to the sync error above."
                      ) : (
                        <div className="space-y-1.5 py-2">
                          <ShieldCheck className="w-6 h-6 text-emerald-400 mx-auto" />
                          <p>No Defender for Office 365 threats detected in the last 30 days.</p>
                        </div>
                      )}
                    </td>
                  </tr>
                ) : (
                  alerts.map((alert) => (
                    <tr key={alert.id}>
                      <td>
                        <StatusPill
                          status={alert.severity === "high" ? "fail" : alert.severity === "medium" ? "warn" : "info"}
                          label={alert.severity.toUpperCase()}
                          size="sm"
                        />
                      </td>
                      <td>
                        <div className="font-semibold text-xs text-slate-900">{alert.title}</div>
                        <div className="text-[11px] text-slate-500 mt-0.5">{alert.description}</div>
                      </td>
                      <td className="text-xs font-mono text-slate-700">{alert.category}</td>
                      <td>
                        <StatusPill
                          status={alert.status === "resolved" ? "pass" : alert.status === "inProgress" ? "warn" : "fail"}
                          label={alert.status}
                          size="sm"
                        />
                      </td>
                      <td className="text-[11px] font-mono text-slate-600">{alert.classification}</td>
                      <td className="text-[11px] font-mono text-slate-500">{new Date(alert.createdDateTime).toLocaleDateString()}</td>
                      <td className="text-[11px] font-mono text-slate-600">
                        {alert.affectedUsers.length > 0 ? alert.affectedUsers.join(", ") : "—"}
                      </td>
                      <td className="text-right">
                        {alert.webUrl && (
                          <a href={alert.webUrl} target="_blank" rel="noopener noreferrer" title="Open in Microsoft Defender" className="p-1 text-slate-400 hover:text-slate-900 inline-block">
                            <ExternalLink size={13} />
                          </a>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Confirm Remediation Modal */}
      <Modal
        isOpen={!!fixModalCode}
        onClose={() => setFixModalCode(null)}
        title="Confirm Remediation"
        subtitle={fixStandard ? `${fixStandard.code}: ${fixStandard.name}` : undefined}
        maxWidth="md"
      >
        {fixStandard?.remediation && (
          <div className="space-y-3">
            <div className="p-3.5 bg-slate-900 text-white rounded-sm space-y-2.5 border border-slate-800">
              <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs">
                <AlertTriangle className="w-4 h-4" />
                <span>Confirm Live Write to Exchange Online</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">{fixStandard.remediation.summary}</p>
              <div className="p-2 bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 rounded-sm">
                {fixStandard.remediation.cmdlet}
              </div>
              {fixError && (
                <div className="p-2 bg-rose-950 border border-rose-800 text-rose-200 text-[11px] rounded-sm">{fixError}</div>
              )}
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setFixModalCode(null)}
                  disabled={isFixing}
                  className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-sm transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={applyFix}
                  disabled={isFixing}
                  className="px-4 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-sm transition-colors disabled:opacity-50"
                >
                  {isFixing ? "Applying..." : "Confirm & Apply Fix"}
                </button>
              </div>
            </div>
          </div>
        )}
      </Modal>

      {/* Add TABL Entry Modal */}
      <Modal
        isOpen={isAddModalOpen}
        onClose={closeAddModal}
        title="Add Indicator to Tenant Allow/Block List"
        subtitle="Enforce tenant-wide domain, sender, URL, or hash block/allow rules"
        maxWidth="md"
      >
        {showWriteConfirm ? (
          <div className="space-y-3">
            <div className="p-3.5 bg-slate-900 text-white rounded-sm space-y-2.5 border border-slate-800">
              <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs">
                <AlertTriangle className="w-4 h-4" />
                <span>Confirm Live Write to Exchange Online</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                This will immediately {listType === "block" ? "block" : "allow"} <strong>{entryValue}</strong> in{" "}
                <strong>{tenant.displayName}</strong>'s live Exchange Online Tenant Allow/Block List, expiring{" "}
                {noExpiration ? "never" : new Date(expirationInput).toLocaleDateString()}. This takes effect right
                away — there is no report-only mode and no undo from here.
              </p>
              {addError && (
                <div className="p-2 bg-rose-950 border border-rose-800 text-rose-200 text-[11px] rounded-sm">{addError}</div>
              )}
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setShowWriteConfirm(false)}
                  disabled={isSubmitting}
                  className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-sm transition-colors disabled:opacity-50"
                >
                  Back
                </button>
                <button
                  type="button"
                  onClick={performAdd}
                  disabled={isSubmitting}
                  className="px-4 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-sm transition-colors disabled:opacity-50"
                >
                  {isSubmitting ? "Writing..." : "Confirm & Write to Exchange Online"}
                </button>
              </div>
            </div>
          </div>
        ) : (
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">List Target Action</label>
                <select
                  value={listType}
                  onChange={(e) => setListType(e.target.value as "allow" | "block")}
                  className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
                >
                  <option value="block">Block Indicator</option>
                  <option value="allow">Allow Indicator (Exemption)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Indicator Type</label>
                <select
                  value={entryType}
                  onChange={(e) => setEntryType(e.target.value as any)}
                  className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
                >
                  <option value="domain">Domain</option>
                  <option value="sender">Sender Email</option>
                  <option value="url">URL</option>
                  <option value="file_hash">SHA-256 File Hash</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Indicator Value <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                required
                placeholder={
                  entryType === "domain"
                    ? "e.g. malicious-phish.net"
                    : entryType === "sender"
                    ? "e.g. ceo-spoof@fraud.com"
                    : entryType === "url"
                    ? "https://bad-login.xyz/auth"
                    : "64-character SHA256 hex string"
                }
                value={entryValue}
                onChange={(e) => setEntryValue(e.target.value)}
                className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Security / Audit Reason <span className="text-red-500">*</span>
              </label>
              <textarea
                rows={2}
                required
                minLength={10}
                placeholder="Required — why is this being added? Incident ticket #, SOC analysis, business justification..."
                value={entryNotes}
                onChange={(e) => setEntryNotes(e.target.value)}
                className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
              />
            </div>

            <div>
              <label className="flex items-center gap-2 mb-1.5">
                <input type="checkbox" checked={noExpiration} onChange={(e) => setNoExpiration(e.target.checked)} />
                <span className="text-xs font-semibold text-slate-700">No expiration (not recommended)</span>
              </label>
              {!noExpiration && (
                <input
                  type="date"
                  required
                  value={expirationInput}
                  min={new Date().toISOString().slice(0, 10)}
                  onChange={(e) => setExpirationInput(e.target.value)}
                  className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
                />
              )}
            </div>

            {!exoConnected ? (
              <LocalOnlyNotice />
            ) : !exoWriteEnabled ? (
              <div className="flex items-start gap-2 p-2.5 bg-slate-50 border border-slate-200 rounded-sm text-[11px] text-slate-600">
                <Info size={13} className="text-slate-400 shrink-0 mt-0.5" />
                <span>
                  Exchange Online is connected, but live writes are disabled. This entry will be tracked in
                  Clarity365 only. Enable write access in the Permissions check to make changes reach Microsoft 365.
                </span>
              </div>
            ) : (
              <div className="flex items-start gap-2 p-2.5 bg-amber-50 border border-amber-300 rounded-sm text-[11px] text-amber-900">
                <AlertTriangle size={13} className="text-amber-600 shrink-0 mt-0.5" />
                <span>Live writes are enabled. You'll be asked to confirm before this reaches Exchange Online.</span>
              </div>
            )}

            {addError && (
              <div className="p-2 bg-rose-50 border border-rose-300 text-rose-900 text-[11px] rounded-sm">{addError}</div>
            )}

            <div className="flex justify-end gap-2 pt-2 border-t border-[#E2E8F0]">
              <button
                type="button"
                onClick={closeAddModal}
                className="px-3 py-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 border border-[#CBD5E1] bg-white rounded-sm hover:bg-slate-50 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Plus size={14} />
                <span>
                  {exoConnected && exoWriteEnabled ? "Review & Write" : isSubmitting ? "Adding..." : "Add to TABL"}
                </span>
              </button>
            </div>
          </form>
        )}
      </Modal>
    </div>
  );
};
