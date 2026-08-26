import React, { useState } from "react";
import { TenantSecuritySnapshot, EmailForwardingRule } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Modal } from "../common/Modal";
import { Share2, AlertTriangle, ShieldAlert, Search, Filter, Terminal, Shield, ArrowRight, Download, Wrench, ExternalLink } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";

interface EmailForwardingModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenRemediation: (findingType?: string) => void;
  onLocalRefresh: () => void;
  onOpenPermissions: () => void;
}

export const EmailForwardingModule: React.FC<EmailForwardingModuleProps> = ({
  snapshot,
  onOpenRemediation,
  onLocalRefresh,
  onOpenPermissions,
}) => {
  const { emailForwarding, tenant } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [filterScope, setFilterScope] = useState<string>("all");

  const exoConnected = !!tenant.credentials.exoRefreshToken;
  const exoWriteEnabled = !!tenant.credentials.exoWriteEnabled;

  // ---- Disable-one-rule confirm modal ------------------------------------
  const [fixRuleId, setFixRuleId] = useState<string | null>(null);
  const [isFixing, setIsFixing] = useState(false);
  const [fixError, setFixError] = useState<string | null>(null);
  const fixRule = fixRuleId ? emailForwarding.find((r) => r.id === fixRuleId) : undefined;

  const closeFixModal = () => {
    setFixRuleId(null);
    setFixError(null);
  };

  const applyFix = async () => {
    if (!fixRuleId) return;
    setIsFixing(true);
    setFixError(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/mailflow-fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "disable_forwarding_rule", ruleId: fixRuleId }),
      });
      const data = await res.json();
      if (data.success) {
        closeFixModal();
        onLocalRefresh();
      } else {
        setFixError(data.error || "Failed to disable rule.");
      }
    } catch (err: any) {
      setFixError(err.message || "Network error while disabling rule.");
    } finally {
      setIsFixing(false);
    }
  };

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

  const handleExportCSV = () => {
    const headers = ["Scope", "RuleName", "MailboxOwner", "RuleAction", "ForwardingAddress", "IsExternal", "State", "AlertLevel"];
    const rows = filteredRules.map((rule) => [
      rule.scope,
      rule.name,
      rule.mailboxOwner || "",
      rule.ruleAction,
      rule.forwardingAddress,
      rule.isExternal ? "Yes" : "No",
      rule.state,
      rule.alertLevel,
    ]);
    exportToCsv(csvFilename("EmailForwarding", snapshot.tenant.defaultDomainName), headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Share2 size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Module 7: Automatic Email Forwarding & Exfiltration Vectors
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
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
        <div className="p-3.5 bg-red-50 dark:bg-red-950 border border-red-300 dark:border-red-800 rounded-sm flex items-start gap-3">
          <AlertTriangle size={18} className="text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
          <div className="text-xs text-red-900 dark:text-red-400 space-y-1">
            <p className="font-bold">
              CRITICAL SECURITY THREAT: {criticalCount} Active External Forwarding Rule(s) Detected
            </p>
            <p className="text-red-800 dark:text-red-400">
              Corporate email is automatically leaving the Microsoft 365 tenant boundaries to external destinations. This is a top indicator of Business Email Compromise (BEC) and unauthorized surveillance.
            </p>
          </div>
        </div>
      )}

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Search forwarding rules or recipient address..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500 dark:text-slate-400" />
          <select
            value={filterScope}
            onChange={(e) => setFilterScope(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
          >
            <option value="all">All Forwarding Vectors ({emailForwarding.length})</option>
            <option value="external">External Recipients Only ({externalRules.length})</option>
            <option value="transport">Exchange Transport / Mailflow Rules</option>
            <option value="inbox">User Inbox Rules</option>
          </select>

          <button
            onClick={handleExportCSV}
            title="Export filtered rules to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500 dark:text-slate-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Forwarding Rules Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Detected Email Forwarding Configuration & Rule Parameters
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{filteredRules.length} Rules Listed</span>
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
                <th className="w-32">Risk Classification</th>
                <th className="w-40 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-4 text-center text-xs text-slate-500 dark:text-slate-400">
                    No active email forwarding rules detected in this tenant.
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => (
                  <tr key={rule.id} className={rule.isExternal ? "bg-red-50/30 dark:bg-red-950" : ""}>
                    <td>
                      <span className="font-mono text-xs font-semibold text-slate-800 dark:text-slate-200 uppercase">
                        {rule.scope === "transport_rule"
                          ? "Transport Rule"
                          : rule.scope === "inbox_rule"
                          ? "Inbox Rule"
                          : "SMTP Forward"}
                      </span>
                    </td>
                    <td>
                      <div className="font-semibold text-xs text-slate-900 dark:text-slate-100">{rule.name}</div>
                      {rule.mailboxOwner && (
                        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">Owner: {rule.mailboxOwner}</div>
                      )}
                    </td>
                    <td>
                      <span className="font-mono text-xs text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 px-1.5 py-0.5 rounded-sm border border-slate-200 dark:border-slate-700">
                        {rule.ruleAction}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <span className={`font-mono text-xs font-bold ${rule.isExternal ? "text-red-700 dark:text-red-400" : "text-slate-800 dark:text-slate-200"}`}>
                          {rule.forwardingAddress}
                        </span>
                        {rule.isExternal && (
                          <span className="text-[9px] font-mono uppercase px-1 bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-400 border border-red-300 dark:border-red-800 rounded-sm font-bold">
                            EXTERNAL
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      <StatusPill status={rule.state === "Enabled" ? "enabled" : "disabled"} label={rule.state} size="sm" />
                    </td>
                    <td>
                      <StatusPill
                        status={rule.alertLevel === "critical" ? "fail" : rule.alertLevel === "warning" ? "warn" : "info"}
                        label={rule.alertLevel === "critical" ? "CRITICAL RISK" : "Normal"}
                        size="sm"
                      />
                    </td>
                    <td className="text-right">
                      {rule.state === "Disabled" ? (
                        <span className="text-[11px] text-slate-400 dark:text-slate-500">Already disabled</span>
                      ) : !exoConnected ? (
                        <button
                          onClick={onOpenPermissions}
                          title="Connect Exchange Online to enable one-click fixes"
                          className="text-[11px] text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 inline-flex items-center gap-1 underline decoration-dotted"
                        >
                          <ExternalLink size={11} />
                          <span>Connect EXO to fix</span>
                        </button>
                      ) : exoWriteEnabled ? (
                        <button
                          onClick={() => {
                            setFixError(null);
                            setFixRuleId(rule.id);
                          }}
                          className="px-2.5 py-1 text-[11px] font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm inline-flex items-center gap-1"
                        >
                          <Wrench size={11} />
                          <span>Disable</span>
                        </button>
                      ) : (
                        <span
                          className="text-[11px] text-slate-400 dark:text-slate-500"
                          title="Enable live Exchange Online writes in the Permissions check to use one-click fixes"
                        >
                          Enable write access to fix
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Confirm Disable Modal */}
      <Modal
        isOpen={!!fixRuleId}
        onClose={closeFixModal}
        title="Confirm Live Write to Exchange Online"
        subtitle={fixRule ? fixRule.name : undefined}
        maxWidth="md"
      >
        {fixRule && (
          <div className="space-y-3">
            <div className="p-3.5 bg-slate-900 text-white rounded-sm space-y-2.5 border border-slate-800">
              <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs">
                <AlertTriangle className="w-4 h-4" />
                <span>Confirm Live Write to Exchange Online</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                This will immediately disable{" "}
                {fixRule.scope === "transport_rule"
                  ? "the transport rule"
                  : fixRule.scope === "inbox_rule"
                  ? "the inbox rule"
                  : "mailbox-level auto-forward"}{" "}
                that forwards mail to <strong>{fixRule.forwardingAddress}</strong>. This takes effect right away —
                there is no undo from here (the rule can be manually re-enabled in Exchange Online if needed).
              </p>
              <div className="p-2 bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 rounded-sm">
                {fixRule.scope === "transport_rule"
                  ? `Disable-TransportRule -Identity "${fixRule.name}"`
                  : fixRule.scope === "inbox_rule"
                  ? `Disable-InboxRule -Mailbox "${fixRule.mailboxOwner}" -Identity "${fixRule.name}"`
                  : `Set-Mailbox -Identity "${fixRule.mailboxOwner}" -ForwardingSmtpAddress $null -ForwardingAddress $null`}
              </div>
              {fixError && (
                <div className="p-2 bg-rose-950 border border-rose-800 text-rose-200 text-[11px] rounded-sm">{fixError}</div>
              )}
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={closeFixModal}
                  disabled={isFixing}
                  className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-sm transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={applyFix}
                  disabled={isFixing}
                  className="px-4 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-700 dark:bg-emerald-700 dark:hover:bg-emerald-600 rounded-sm transition-colors disabled:opacity-50"
                >
                  {isFixing ? "Disabling..." : "Confirm & Disable"}
                </button>
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
