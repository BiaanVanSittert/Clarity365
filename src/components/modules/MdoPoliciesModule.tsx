import React, { useState } from "react";
import { TenantSecuritySnapshot, TablEntry, MdoThreatPolicy } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Modal } from "../common/Modal";
import { Layers, ShieldCheck, ShieldAlert, Plus, Trash2, Search, Filter, CheckCircle2, AlertTriangle } from "lucide-react";

interface MdoPoliciesModuleProps {
  snapshot: TenantSecuritySnapshot;
  onLocalRefresh: () => void;
}

export const MdoPoliciesModule: React.FC<MdoPoliciesModuleProps> = ({ snapshot, onLocalRefresh }) => {
  const { mdoThreat, tenant } = snapshot;
  const [activeTab, setActiveTab] = useState<"policies" | "tabl">("policies");
  const [searchQuery, setSearchQuery] = useState("");
  const [tablFilter, setTablFilter] = useState<string>("all");

  // Add TABL Modal State
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [listType, setListType] = useState<"allow" | "block">("block");
  const [entryType, setEntryType] = useState<"domain" | "sender" | "url" | "file_hash">("domain");
  const [entryValue, setEntryValue] = useState("");
  const [entryNotes, setEntryNotes] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const policies = mdoThreat.policies;
  const tablEntries = mdoThreat.tabl;

  const handleAddTabl = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/tabl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          listType,
          entryType,
          value: entryValue.trim(),
          notes: entryNotes.trim() || "Added via Clarity365 TABL Manager",
          addedBy: "secops-admin@clarity365.local",
          expirationDate: "Never",
        }),
      });
      const data = await res.json();
      if (data.success) {
        setIsAddModalOpen(false);
        setEntryValue("");
        setEntryNotes("");
        onLocalRefresh();
      }
    } catch (err) {
      console.error("Failed to add TABL entry", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRemoveTabl = async (entryId: string) => {
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/tabl?entryId=${encodeURIComponent(entryId)}`, {
        method: "DELETE",
      });
      const data = await res.json();
      if (data.success) {
        onLocalRefresh();
      }
    } catch (err) {
      console.error("Failed to remove TABL entry", err);
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
    return matchesSearch;
  });

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Layers size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 8: Defender for Office 365 (MDO) & Tenant Allow/Block List (TABL)
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Audit Anti-Spam, Anti-Phishing, Safe Links/Attachments policies and manage tenant-wide allow/block indicators.
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

      {/* Tabs */}
      <div className="flex items-center justify-between border-b border-[#CBD5E1] bg-white px-2 pt-2">
        <div className="flex gap-2">
          <button
            onClick={() => setActiveTab("policies")}
            className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === "policies"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-900"
            }`}
          >
            MDO Threat Policies ({policies.length})
          </button>
          <button
            onClick={() => setActiveTab("tabl")}
            className={`px-3 py-2 text-xs font-semibold border-b-2 transition-colors ${
              activeTab === "tabl"
                ? "border-slate-900 text-slate-900"
                : "border-transparent text-slate-500 hover:text-slate-900"
            }`}
          >
            Tenant Allow/Block List ({tablEntries.length})
          </button>
        </div>
      </div>

      {/* VIEW 1: Threat Policies */}
      {activeTab === "policies" && (
        <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
          <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Configured Defender for Office 365 Threat Policies
            </h3>
            <span className="text-[11px] font-mono text-slate-500">{policies.length} Policies Active</span>
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
                      No custom Defender for Office 365 policies configured. Default tenant presets apply.
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

      {/* VIEW 2: TABL Manager */}
      {activeTab === "tabl" && (
        <div className="space-y-3">
          {/* TABL Filter & Search */}
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
              </select>
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
                    <th>Added By</th>
                    <th className="w-20 text-right">Delete</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTabl.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="p-4 text-center text-xs text-slate-500">
                        No allow/block indicators found matching search.
                      </td>
                    </tr>
                  ) : (
                    filteredTabl.map((entry) => (
                      <tr key={entry.id} className={entry.listType === "block" ? "bg-red-50/20" : "bg-emerald-50/20"}>
                        <td>
                          <StatusPill
                            status={entry.listType === "block" ? "fail" : "pass"}
                            label={entry.listType.toUpperCase()}
                            size="sm"
                          />
                        </td>
                        <td>
                          <span className="font-mono text-xs text-slate-700 uppercase font-semibold">
                            {entry.entryType}
                          </span>
                        </td>
                        <td>
                          <span className="font-mono text-xs font-bold text-slate-900">{entry.value}</span>
                        </td>
                        <td className="text-xs text-slate-600">{entry.notes}</td>
                        <td className="text-[11px] font-mono text-slate-500">{entry.addedBy}</td>
                        <td className="text-right">
                          <button
                            onClick={() => handleRemoveTabl(entry.id)}
                            title="Remove indicator"
                            className="p-1 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-sm transition-colors"
                          >
                            <Trash2 size={13} />
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Add TABL Entry Modal */}
      <Modal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        title="Add Indicator to Tenant Allow/Block List"
        subtitle="Enforce tenant-wide domain, sender, URL, or hash block/allow rules"
        maxWidth="md"
      >
        <form onSubmit={handleAddTabl} className="space-y-4">
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
            <label className="block text-xs font-semibold text-slate-700 mb-1">Security / Audit Notes</label>
            <textarea
              rows={2}
              placeholder="Reason for addition, incident ticket #, or SOC analysis..."
              value={entryNotes}
              onChange={(e) => setEntryNotes(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-[#E2E8F0]">
            <button
              type="button"
              onClick={() => setIsAddModalOpen(false)}
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
              <span>{isSubmitting ? "Adding..." : "Add to TABL"}</span>
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
