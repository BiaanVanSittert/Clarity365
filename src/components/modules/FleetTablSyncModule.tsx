import React, { useState, useEffect } from "react";
import { FleetTablEntry, Tenant } from "@/lib/types";
import {
  Share2,
  Plus,
  ShieldBan,
  CheckCircle2,
  AlertTriangle,
  Download,
  Search,
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  Globe,
  Mail,
  FileCode,
  Link2,
} from "lucide-react";
import { exportToCsv } from "@/lib/utils/csv";
import { ChangeConfirmationModal, ChangeItemSummary } from "../modals/ChangeConfirmationModal";

interface FleetTablSyncModuleProps {
  tenants: Tenant[];
  onSelectTenant: (tenantId: string, targetModule?: string, targetEntityId?: string) => void;
}

export const FleetTablSyncModule: React.FC<FleetTablSyncModuleProps> = ({
  tenants,
  onSelectTenant,
}) => {
  const [entries, setEntries] = useState<FleetTablEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");

  // New Rule Form State
  const [showAddForm, setShowAddForm] = useState(false);
  const [newType, setNewType] = useState<"domain" | "sender" | "url" | "fileHash" | "ip">("domain");
  const [newValue, setNewValue] = useState("");
  const [newReason, setNewReason] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitSuccess, setSubmitSuccess] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [showConfirmModal, setShowConfirmModal] = useState(false);

  const fetchEntries = async () => {
    try {
      setIsLoading(true);
      const res = await fetch("/api/fleet/sync-tabl");
      const data = await res.json();
      if (data.success && data.entries) {
        setEntries(data.entries);
      }
    } catch (err) {
      console.error("Failed to fetch TABL entries:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchEntries();
  }, []);

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newValue.trim() || !newReason.trim()) return;
    setSubmitError(null);
    setShowConfirmModal(true);
  };

  const handleExecuteBroadcast = async () => {
    setIsSubmitting(true);
    setSubmitError(null);
    setSubmitSuccess(null);

    try {
      const res = await fetch("/api/fleet/sync-tabl", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: newType,
          value: newValue.trim(),
          action: "block",
          reason: newReason.trim(),
          addedBy: "SecOps Lead Analyst",
        }),
      });

      const data = await res.json();
      if (data.success && data.entry) {
        setEntries([data.entry, ...entries]);
        setSubmitSuccess(`Successfully broadcasted block rule for '${newValue.trim()}' across all ${tenants.length} customer tenants!`);
        setNewValue("");
        setNewReason("");
        setShowAddForm(false);
        setShowConfirmModal(false);
      } else {
        setSubmitError(data.error || "Failed to broadcast threat indicator.");
      }
    } catch (err: any) {
      setSubmitError(err.message || "Network error broadcasting threat indicator.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const changesSummaryList: ChangeItemSummary[] = tenants.map((t) => ({
    tenantName: t.displayName,
    targetComponent: "DEFENDER MDO (TABL)",
    actionDescription: `Add ${newType.toUpperCase()} block rule for '${newValue}' (${newReason})`,
    beforeState: "Not Blocked",
    afterState: "Strictly Blocked",
    isReportOnly: false,
  }));

  const filteredEntries = entries.filter((it) => {
    const q = searchQuery.toLowerCase();
    if (q && !it.value.toLowerCase().includes(q) && !it.reason.toLowerCase().includes(q) && !it.addedBy.toLowerCase().includes(q)) {
      return false;
    }
    if (typeFilter !== "all" && it.type !== typeFilter) {
      return false;
    }
    return true;
  });

  const handleExportCsv = () => {
    const headers = ["Threat Type", "Indicator Value", "Action", "Threat Justification", "Created By", "Date Added", "Synced Tenants Count"];
    const rows = filteredEntries.map((it) => [
      it.type.toUpperCase(),
      it.value,
      it.action.toUpperCase(),
      it.reason,
      it.addedBy,
      new Date(it.createdAt).toLocaleDateString(),
      `${it.syncedTenants.filter((t) => t.status === "synced").length} / ${it.syncedTenants.length}`,
    ]);
    exportToCsv(`clarity365-fleet-tabl-blocklist-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto select-none font-sans">
      {/* Top Banner */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-slate-900 dark:bg-slate-800 text-white rounded-sm border border-slate-700">
              <Share2 size={18} className="text-rose-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
                  Cross-Tenant Threat Synchronizer (TABL Engine)
                </h1>
                <span className="text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border border-rose-300 dark:border-rose-800 rounded-sm">
                  {entries.length} Threat Indicators Synchronized
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Centralized threat intelligence distributor: push malicious domains, phishing sender addresses, and malware file hashes across all customer Defender for Office 365 Tenant Allow/Block Lists simultaneously.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCsv}
            className="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-200 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-xs"
          >
            <Download size={13} />
            <span>Export Blocklist (CSV)</span>
          </button>
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 dark:bg-rose-700 dark:hover:bg-rose-600 rounded-sm flex items-center gap-1.5 transition-colors shadow-xs"
          >
            <Plus size={13} />
            <span>Broadcast New Threat Indicator</span>
          </button>
        </div>
      </div>

      {/* Success Notification */}
      {submitSuccess && (
        <div className="p-3 bg-emerald-50 dark:bg-emerald-950/70 border border-emerald-300 dark:border-emerald-800 text-emerald-950 dark:text-emerald-300 rounded-sm flex items-center gap-2 text-xs font-medium">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
          <span>{submitSuccess}</span>
        </div>
      )}

      {/* New Threat Broadcast Form Drawer */}
      {showAddForm && (
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-sm space-y-3 animate-in fade-in duration-150">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
            <div className="flex items-center gap-2 font-bold text-xs text-slate-900 dark:text-slate-100">
              <ShieldBan className="w-4 h-4 text-rose-600" />
              <span>Broadcast New Block Indicator Across {tenants.length} Customer Tenants</span>
            </div>
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="text-slate-400 hover:text-slate-600 text-xs"
            >
              Cancel
            </button>
          </div>

          <form onSubmit={handleFormSubmit} className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div>
              <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Threat Indicator Type</label>
              <select
                value={newType}
                onChange={(e) => setNewType(e.target.value as any)}
                className="w-full px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-sm"
              >
                <option value="domain">Malicious Sender Domain</option>
                <option value="sender">Phishing Sender Email Address</option>
                <option value="url">Malicious URL / Link</option>
                <option value="fileHash">Malware File Hash (SHA-256)</option>
                <option value="ip">Malicious Host / IP Address</option>
              </select>
            </div>

            <div>
              <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Indicator Value</label>
              <input
                type="text"
                required
                placeholder={
                  newType === "domain"
                    ? "e.g. login-secure-update.com"
                    : newType === "sender"
                    ? "e.g. attacker@spoof-domain.com"
                    : newType === "fileHash"
                    ? "64-character SHA256 hex string"
                    : "http://malicious-link.net/payload"
                }
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
                className="w-full px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-sm font-mono"
              />
            </div>

            <div>
              <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1">Threat Context / Reason</label>
              <input
                type="text"
                required
                placeholder="e.g. DarkGate campaign active phishing campaign"
                value={newReason}
                onChange={(e) => setNewReason(e.target.value)}
                className="w-full px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-sm"
              />
            </div>

            <div className="md:col-span-3 flex justify-end gap-2 pt-2 border-t border-slate-200 dark:border-slate-800">
              <button
                type="submit"
                className="px-4 py-1.5 bg-rose-700 hover:bg-rose-800 text-white font-semibold rounded-sm flex items-center gap-1.5 transition-colors"
              >
                <Share2 className="w-3.5 h-3.5" />
                <span>Review & Broadcast Block to Fleet</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Filter Bar */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm p-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-1 max-w-md">
          <div className="relative flex-1">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search threat indicators, hashes, or reasons..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-500 font-sans placeholder:text-slate-400"
            />
          </div>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-2.5 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200 font-semibold"
          >
            <option value="all">All Threat Types ({entries.length})</option>
            <option value="domain">Domains ({entries.filter((e) => e.type === "domain").length})</option>
            <option value="sender">Sender Emails ({entries.filter((e) => e.type === "sender").length})</option>
            <option value="fileHash">File Hashes ({entries.filter((e) => e.type === "fileHash").length})</option>
            <option value="url">URLs ({entries.filter((e) => e.type === "url").length})</option>
          </select>
        </div>

        <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">
          Coverage: {tenants.length} customer tenants synchronized
        </div>
      </div>

      {/* Threat List Table */}
      <div className="bg-white dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#CBD5E1] dark:border-slate-700 bg-slate-100/70 dark:bg-slate-800/80 text-[11px] font-mono text-slate-600 dark:text-slate-300 uppercase tracking-wider">
                <th className="py-2.5 px-3.5 whitespace-nowrap">Type</th>
                <th className="py-2.5 px-3">Threat Indicator Value</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Threat Justification</th>
                <th className="py-2.5 px-3 whitespace-nowrap">Broadcast By & Date</th>
                <th className="py-2.5 px-3.5 text-right whitespace-nowrap">Fleet Sync Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] dark:divide-slate-700/60 bg-white dark:bg-slate-900/30">
              {filteredEntries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 dark:text-slate-400">
                    No threat indicators match the filter.
                  </td>
                </tr>
              ) : (
                filteredEntries.map((entry) => {
                  const syncedCount = entry.syncedTenants.filter((t) => t.status === "synced").length;
                  const isFullySynced = syncedCount === entry.syncedTenants.length;

                  return (
                    <tr
                      key={entry.id}
                      className="hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors group"
                    >
                      {/* Type Badge */}
                      <td className="py-3 px-3.5 whitespace-nowrap">
                        <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded-sm bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700">
                          {entry.type === "domain" && <Globe size={11} className="text-blue-500" />}
                          {entry.type === "sender" && <Mail size={11} className="text-amber-500" />}
                          {entry.type === "fileHash" && <FileCode size={11} className="text-purple-500" />}
                          {entry.type === "url" && <Link2 size={11} className="text-emerald-500" />}
                          <span>{entry.type}</span>
                        </span>
                      </td>

                      {/* Value */}
                      <td className="py-3 px-3 font-mono font-bold text-slate-900 dark:text-slate-100 text-xs">
                        {entry.value}
                      </td>

                      {/* Action */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 bg-rose-50 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border border-rose-300 rounded-sm">
                          {entry.action}
                        </span>
                      </td>

                      {/* Reason */}
                      <td className="py-3 px-3 text-slate-600 dark:text-slate-300 text-xs max-w-sm">
                        {entry.reason}
                      </td>

                      {/* Added By & Date */}
                      <td className="py-3 px-3 whitespace-nowrap text-[11px] text-slate-500 dark:text-slate-400">
                        <div className="font-medium text-slate-700 dark:text-slate-300">{entry.addedBy}</div>
                        <div>{new Date(entry.createdAt).toLocaleDateString()}</div>
                      </td>

                      {/* Fleet Sync Status */}
                      <td className="py-3 px-3.5 text-right whitespace-nowrap">
                        <span
                          title={`Broadcasted to: ${entry.syncedTenants.map((t) => t.tenantName).join(", ")}`}
                          className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-sm border ${
                            isFullySynced
                              ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border-emerald-300"
                              : "bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border-amber-300"
                          }`}
                        >
                          <CheckCircle2 size={12} className={isFullySynced ? "text-emerald-600" : "text-amber-600"} />
                          <span>{syncedCount} / {entry.syncedTenants.length} Tenants Synced</span>
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Threat Broadcast Confirmation Modal */}
      <ChangeConfirmationModal
        isOpen={showConfirmModal}
        onClose={() => setShowConfirmModal(false)}
        onConfirm={handleExecuteBroadcast}
        title={`Confirm Fleet Threat Broadcast (${newType.toUpperCase()})`}
        warningMessage={`You are about to broadcast a live BLOCK rule for ${newType} '${newValue}' across all ${tenants.length} customer organizations. Incoming mail matching this indicator will be quarantined or rejected across all tenants.`}
        isAuditMode={false}
        changes={changesSummaryList}
        confirmButtonText="Confirm & Broadcast Block Rule"
        isExecuting={isSubmitting}
        error={submitError}
      />
    </div>
  );
};
