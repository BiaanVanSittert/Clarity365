import React, { useState } from "react";
import { TenantSecuritySnapshot, MailboxItem, MailboxDelegation } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Modal } from "../common/Modal";
import { Mail, Users, AlertTriangle, Search, Filter, HardDrive, DollarSign, Download, ShieldCheck, ShieldAlert, Wrench, ExternalLink, Trash2 } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import { EmptyStateRow } from "../common/EmptyStateRow";

interface MailboxPermissionsModuleProps {
  snapshot: TenantSecuritySnapshot;
  onLocalRefresh: () => void;
  onOpenPermissions: () => void;
}

export const MailboxPermissionsModule: React.FC<MailboxPermissionsModuleProps> = ({
  snapshot,
  onLocalRefresh,
  onOpenPermissions,
}) => {
  const { mailboxes, tenant, mailboxAuditingEnabled } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<string>("all");

  const exoConnected = !!tenant.credentials.exoRefreshToken;
  const exoWriteEnabled = !!tenant.credentials.exoWriteEnabled;

  // ---- Revoke-delegation confirm modal -----------------------------------
  const [revokeTarget, setRevokeTarget] = useState<{ mailbox: MailboxItem; delegation: MailboxDelegation } | null>(null);
  const [isRevoking, setIsRevoking] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  const closeRevokeModal = () => {
    setRevokeTarget(null);
    setRevokeError(null);
  };

  const applyRevoke = async () => {
    if (!revokeTarget) return;
    setIsRevoking(true);
    setRevokeError(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/mailflow-fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "revoke_delegation",
          mailboxId: revokeTarget.mailbox.id,
          principalUserPrincipalName: revokeTarget.delegation.principalUserPrincipalName,
          accessRight: revokeTarget.delegation.accessRight,
        }),
      });
      const data = await res.json();
      if (data.success) {
        closeRevokeModal();
        onLocalRefresh();
      } else {
        setRevokeError(data.error || "Failed to revoke delegation.");
      }
    } catch (err: any) {
      setRevokeError(err.message || "Network error while revoking delegation.");
    } finally {
      setIsRevoking(false);
    }
  };

  // ---- Enable-mailbox-auditing action -------------------------------------
  const [isEnablingAudit, setIsEnablingAudit] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);

  const enableMailboxAuditing = async () => {
    setIsEnablingAudit(true);
    setAuditError(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/mailflow-fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "enable_mailbox_auditing" }),
      });
      const data = await res.json();
      if (data.success) {
        onLocalRefresh();
      } else {
        setAuditError(data.error || "Failed to enable mailbox auditing.");
      }
    } catch (err: any) {
      setAuditError(err.message || "Network error while enabling mailbox auditing.");
    } finally {
      setIsEnablingAudit(false);
    }
  };

  const filteredMailboxes = mailboxes.filter((mbx) => {
    const matchesSearch =
      mbx.displayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      mbx.userPrincipalName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      mbx.delegations.some((d) => d.principalDisplayName.toLowerCase().includes(searchQuery.toLowerCase()));

    if (filterType === "all") return matchesSearch;
    if (filterType === "shared") return matchesSearch && mbx.recipientType === "SharedMailbox";
    if (filterType === "waste") return matchesSearch && mbx.recipientType === "SharedMailbox" && mbx.hasDirectLicense;
    if (filterType === "user") return matchesSearch && mbx.recipientType === "UserMailbox";
    return matchesSearch;
  });

  const sharedCount = mailboxes.filter((m) => m.recipientType === "SharedMailbox").length;
  const licensedWasteCount = mailboxes.filter((m) => m.recipientType === "SharedMailbox" && m.hasDirectLicense).length;

  const handleExportCSV = () => {
    const headers = ["DisplayName", "UserPrincipalName", "RecipientType", "StorageUsedGB", "ArchiveStatus", "Delegations", "LicenseAdvisory"];
    const rows = filteredMailboxes.map((mbx) => [
      mbx.displayName,
      mbx.userPrincipalName,
      mbx.recipientType,
      (mbx.totalItemSizeMB / 1024).toFixed(1),
      mbx.archiveStatus,
      mbx.delegations.map((d) => `${d.principalDisplayName}:${d.accessRight}`).join("; "),
      mbx.recipientType === "SharedMailbox" && mbx.hasDirectLicense ? "Paid License Waste" : "Normal",
    ]);
    exportToCsv(csvFilename("MailboxPermissions", snapshot.tenant.defaultDomainName), headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Mail size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Module 6: Exchange Mailbox Permissions & Delegation Audit
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Audit Full Access, Send As, and Send on Behalf delegations across User & Shared mailboxes with license waste detection.
          </p>
        </div>

        {licensedWasteCount > 0 && (
          <div className="p-2.5 bg-amber-50 dark:bg-amber-950 border border-amber-300 dark:border-amber-800 rounded-sm flex items-center gap-2 text-xs text-amber-900 dark:text-amber-400">
            <DollarSign size={16} className="text-amber-700 dark:text-amber-400 shrink-0" />
            <span>
              <strong>{licensedWasteCount} Shared Mailbox(es)</strong> have paid licenses attached ($20–$40/mo potential savings).
            </span>
          </div>
        )}
      </div>

      {/* Mailbox Audit Logging gate - every delegation finding below is only
          investigable after the fact if this is on, so it's surfaced first,
          not buried in a table row. */}
      {mailboxAuditingEnabled === false ? (
        <div className="p-3.5 bg-red-50 dark:bg-red-950 border border-red-300 dark:border-red-800 rounded-sm flex items-start gap-3">
          <ShieldAlert size={18} className="text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
          <div className="text-xs text-red-900 dark:text-red-400 space-y-1.5 flex-1">
            <p className="font-bold">Mailbox audit logging is OFF for this tenant.</p>
            <p className="text-red-800 dark:text-red-400">
              Every delegation and access-right finding in the table below can only be investigated after the fact
              if mailbox auditing is enabled - without it, you can see that an account has Full Access to a
              mailbox, but never whether it was actually used, or for what.
            </p>
            {auditError && (
              <div className="p-2 bg-white/70 dark:bg-slate-900/50 border border-red-300 dark:border-red-800 text-red-900 dark:text-red-300 rounded-sm">
                {auditError}
              </div>
            )}
            <div className="pt-1">
              {!exoConnected ? (
                <button
                  onClick={onOpenPermissions}
                  className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm inline-flex items-center gap-1.5"
                >
                  <ExternalLink size={13} />
                  <span>Connect Exchange Online</span>
                </button>
              ) : exoWriteEnabled ? (
                <button
                  onClick={enableMailboxAuditing}
                  disabled={isEnablingAudit}
                  className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm inline-flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Wrench size={13} />
                  <span>{isEnablingAudit ? "Enabling..." : "Enable Mailbox Auditing"}</span>
                </button>
              ) : (
                <span className="text-[11px] text-red-700 dark:text-red-400" title="Enable live Exchange Online writes in the Permissions check to use one-click fixes">
                  Enable write access in the Permissions check to fix this in one click.
                </span>
              )}
            </div>
          </div>
        </div>
      ) : mailboxAuditingEnabled === true ? (
        <div className="p-2.5 bg-emerald-50 dark:bg-emerald-950 border border-emerald-300 dark:border-emerald-800 rounded-sm flex items-center gap-2 text-xs text-emerald-900 dark:text-emerald-400">
          <ShieldCheck size={16} className="text-emerald-700 dark:text-emerald-400 shrink-0" />
          <span>Mailbox audit logging is enabled - delegation and access-right findings below are investigable after the fact.</span>
        </div>
      ) : null}

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Search mailboxes or delegated users..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500 dark:text-slate-400" />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
          >
            <option value="all">All Mailboxes ({mailboxes.length})</option>
            <option value="shared">Shared Mailboxes ({sharedCount})</option>
            <option value="waste">Licensed Shared Mailboxes (Cost Waste)</option>
            <option value="user">User Mailboxes</option>
          </select>

          <button
            onClick={handleExportCSV}
            title="Export filtered mailboxes to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500 dark:text-slate-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Mailbox Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Mailbox Inventory & Explicit Delegation Matrix
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{filteredMailboxes.length} Mailboxes</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Mailbox / Identity</th>
                <th className="w-32">Type</th>
                <th className="w-28">Storage Used</th>
                <th className="w-24">Archive</th>
                <th>Explicit Delegated Permissions</th>
                <th className="w-36 text-right">License Advisory</th>
              </tr>
            </thead>
            <tbody>
              {filteredMailboxes.length === 0 ? (
                <EmptyStateRow colSpan={6} entityLabel="mailboxes" isFiltered={searchQuery.trim().length > 0 || filterType !== "all"} />
              ) : (
                filteredMailboxes.map((mbx) => (
                  <tr key={mbx.id} className={mbx.hasDirectLicense && mbx.recipientType === "SharedMailbox" ? "bg-amber-50/30 dark:bg-amber-950" : ""}>
                    <td>
                      <div className="font-semibold text-xs text-slate-900 dark:text-slate-100">{mbx.displayName}</div>
                      <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{mbx.userPrincipalName}</div>
                    </td>
                    <td>
                      <StatusPill
                        status={mbx.recipientType === "SharedMailbox" ? "info" : "pass"}
                        label={mbx.recipientType === "SharedMailbox" ? "Shared Mailbox" : "User Mailbox"}
                        size="sm"
                      />
                    </td>
                    <td className="font-mono text-xs text-slate-800 dark:text-slate-200 tabular-nums">
                      {(mbx.totalItemSizeMB / 1024).toFixed(1)} GB
                    </td>
                    <td>
                      <span className={`text-xs font-mono ${mbx.archiveStatus === "Enabled" ? "text-emerald-700 dark:text-emerald-400 font-semibold" : "text-slate-500 dark:text-slate-400"}`}>
                        {mbx.archiveStatus}
                      </span>
                    </td>
                    <td>
                      {mbx.delegations.length === 0 ? (
                        <span className="text-slate-400 dark:text-slate-500 text-[11px] italic">No active delegations</span>
                      ) : (
                        <div className="space-y-1">
                          {mbx.delegations.map((d, dIdx) => (
                            <div key={dIdx} className="text-[11px] flex items-center gap-1.5">
                              <span className="font-semibold text-slate-800 dark:text-slate-200">{d.principalDisplayName}:</span>
                              <span className="font-mono bg-slate-100 dark:bg-slate-700 border border-slate-200 dark:border-slate-700 px-1 py-0.2 rounded-sm text-slate-700 dark:text-slate-300">
                                {d.accessRight}
                              </span>
                              {d.isInherited && <span className="text-slate-400 dark:text-slate-500 italic">(inherited)</span>}
                              {!d.isInherited && exoConnected && exoWriteEnabled && (
                                <button
                                  onClick={() => {
                                    setRevokeError(null);
                                    setRevokeTarget({ mailbox: mbx, delegation: d });
                                  }}
                                  title={`Revoke ${d.accessRight} for ${d.principalDisplayName}`}
                                  className="p-0.5 text-slate-400 dark:text-slate-500 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-950 rounded-sm transition-colors"
                                >
                                  <Trash2 size={11} />
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="text-right">
                      {mbx.recipientType === "SharedMailbox" && mbx.hasDirectLicense ? (
                        <span className="text-[11px] font-semibold text-amber-800 dark:text-amber-400">
                          Paid License Waste
                        </span>
                      ) : (
                        <span className="text-[11px] text-slate-500 dark:text-slate-400">Normal</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Confirm Revoke Modal */}
      <Modal
        isOpen={!!revokeTarget}
        onClose={closeRevokeModal}
        title="Confirm Live Write to Exchange Online"
        subtitle={revokeTarget ? `${revokeTarget.delegation.principalDisplayName} on ${revokeTarget.mailbox.userPrincipalName}` : undefined}
        maxWidth="md"
      >
        {revokeTarget && (
          <div className="space-y-3">
            <div className="p-3.5 bg-slate-900 text-white rounded-sm space-y-2.5 border border-slate-800">
              <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs">
                <AlertTriangle className="w-4 h-4" />
                <span>Confirm Live Write to Exchange Online</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                This will immediately revoke <strong>{revokeTarget.delegation.principalDisplayName}</strong>&apos;s{" "}
                <strong>{revokeTarget.delegation.accessRight}</strong> access to{" "}
                <strong>{revokeTarget.mailbox.userPrincipalName}</strong>. This takes effect right away - there is
                no undo from here (the permission can be manually re-granted in Exchange Online if needed).
              </p>
              <div className="p-2 bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 rounded-sm">
                {revokeTarget.delegation.accessRight === "FullAccess"
                  ? `Remove-MailboxPermission -Identity "${revokeTarget.mailbox.userPrincipalName}" -User "${revokeTarget.delegation.principalUserPrincipalName}" -AccessRights FullAccess`
                  : revokeTarget.delegation.accessRight === "SendAs"
                  ? `Remove-RecipientPermission -Identity "${revokeTarget.mailbox.userPrincipalName}" -Trustee "${revokeTarget.delegation.principalUserPrincipalName}" -AccessRights SendAs`
                  : `Set-Mailbox -Identity "${revokeTarget.mailbox.userPrincipalName}" -GrantSendOnBehalfTo @(...)`}
              </div>
              {revokeError && (
                <div className="p-2 bg-rose-950 border border-rose-800 text-rose-200 text-[11px] rounded-sm">{revokeError}</div>
              )}
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={closeRevokeModal}
                  disabled={isRevoking}
                  className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-sm transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={applyRevoke}
                  disabled={isRevoking}
                  className="px-4 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-700 dark:bg-emerald-700 dark:hover:bg-emerald-600 rounded-sm transition-colors disabled:opacity-50"
                >
                  {isRevoking ? "Revoking..." : "Confirm & Revoke"}
                </button>
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
