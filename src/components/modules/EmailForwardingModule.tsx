import React, { useState } from "react";
import { TenantSecuritySnapshot, EmailForwardingRule } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Share2, AlertTriangle, ShieldAlert, Search, Filter, Terminal, Shield, ArrowRight } from "lucide-react";

interface EmailForwardingModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenRemediation: (findingType?: string) => void;
}

export const EmailForwardingModule: React.FC<EmailForwardingModuleProps> = ({
  snapshot,
  onOpenRemediation,
}) => {
  const { emailForwarding } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [filterScope, setFilterScope] = useState<string>("all");

  const externalRules = emailForwarding.filter((r) => r.isExternal);
  const criticalCount = emailForwarding.filter((r) => r.alertLevel === "critical" && r.state === "Enabled").length;

  const filteredRules = emailForwarding.filter((r) => {
    const matchesSearch =
      r.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.forwardingAddress.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.mailboxOwner && r.mailboxOwner.toLowerCase().includes(searchQuery.toLowerCase()));

    if (filterScope === "all") return matchesSearch;
    if (filterScope === "external") return matchesSearch && r.isExternal;
    if (filterScope === "transport") return matchesSearch && r.scope === "transport_rule";
    if (filterScope === "inbox") return matchesSearch && r.scope === "inbox_rule";
    return matchesSearch;
  });

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Share2 size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 7: Automatic Email Forwarding & Exfiltration Vectors
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Audit Exchange Transport rules, mailbox inbox rules, and SMTP forwarding addresses to prevent BEC data exfiltration.
          </p>
        </div>

        <button
          onClick={() => onOpenRemediation("email_forwarding")}
          className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
        >
          <ShieldAlert size={14} className="text-red-400" />
          <span>Disable All External Forwarding</span>
        </button>
      </div>

      {/* Critical Alert Banner if External Rules Found */}
      {criticalCount > 0 && (
        <div className="p-3.5 bg-red-50 border border-red-300 rounded-sm flex items-start gap-3">
          <AlertTriangle size={18} className="text-red-600 shrink-0 mt-0.5" />
          <div className="text-xs text-red-900 space-y-1">
            <p className="font-bold">
              CRITICAL SECURITY THREAT: {criticalCount} Active External Forwarding Rule(s) Detected
            </p>
            <p className="text-red-800">
              Corporate email is automatically leaving the Microsoft 365 tenant boundaries to external destinations. This is a top indicator of Business Email Compromise (BEC) and unauthorized surveillance.
            </p>
          </div>
        </div>
      )}

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search forwarding rules or recipient address..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={filterScope}
            onChange={(e) => setFilterScope(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
          >
            <option value="all">All Forwarding Vectors ({emailForwarding.length})</option>
            <option value="external">External Recipients Only ({externalRules.length})</option>
            <option value="transport">Exchange Transport / Mailflow Rules</option>
            <option value="inbox">User Inbox Rules</option>
          </select>
        </div>
      </div>

      {/* Forwarding Rules Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            Detected Email Forwarding Configuration & Rule Parameters
          </h3>
          <span className="text-[11px] font-mono text-slate-500">{filteredRules.length} Rules Listed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-40">Vector / Scope</th>
                <th>Rule Name & Target Mailbox</th>
                <th>Forwarding Action</th>
                <th>Recipient Destination</th>
                <th className="w-24">State</th>
                <th className="w-32 text-right">Risk Classification</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-4 text-center text-xs text-slate-500">
                    No active email forwarding rules detected in this tenant.
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => (
                  <tr key={rule.id} className={rule.isExternal ? "bg-red-50/30" : ""}>
                    <td>
                      <span className="font-mono text-xs font-semibold text-slate-800 uppercase">
                        {rule.scope === "transport_rule"
                          ? "Transport Rule"
                          : rule.scope === "inbox_rule"
                          ? "Inbox Rule"
                          : "SMTP Forward"}
                      </span>
                    </td>
                    <td>
                      <div className="font-semibold text-xs text-slate-900">{rule.name}</div>
                      {rule.mailboxOwner && (
                        <div className="text-[11px] font-mono text-slate-500">Owner: {rule.mailboxOwner}</div>
                      )}
                    </td>
                    <td>
                      <span className="font-mono text-xs text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded-sm border border-slate-200">
                        {rule.ruleAction}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <span className={`font-mono text-xs font-bold ${rule.isExternal ? "text-red-700" : "text-slate-800"}`}>
                          {rule.forwardingAddress}
                        </span>
                        {rule.isExternal && (
                          <span className="text-[9px] font-mono uppercase px-1 bg-red-100 text-red-800 border border-red-300 rounded-sm font-bold">
                            EXTERNAL
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      <StatusPill status={rule.state === "Enabled" ? "enabled" : "disabled"} label={rule.state} size="sm" />
                    </td>
                    <td className="text-right">
                      <StatusPill
                        status={rule.alertLevel === "critical" ? "fail" : rule.alertLevel === "warning" ? "warn" : "info"}
                        label={rule.alertLevel === "critical" ? "CRITICAL RISK" : "Normal"}
                        size="sm"
                      />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
