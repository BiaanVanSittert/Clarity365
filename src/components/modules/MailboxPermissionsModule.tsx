import React, { useState } from "react";
import { TenantSecuritySnapshot, MailboxItem } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Mail, Users, AlertTriangle, Search, Filter, HardDrive, DollarSign } from "lucide-react";

interface MailboxPermissionsModuleProps {
  snapshot: TenantSecuritySnapshot;
}

export const MailboxPermissionsModule: React.FC<MailboxPermissionsModuleProps> = ({ snapshot }) => {
  const { mailboxes } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<string>("all");

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

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Mail size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 6: Exchange Mailbox Permissions & Delegation Audit
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Audit Full Access, Send As, and Send on Behalf delegations across User & Shared mailboxes with license waste detection.
          </p>
        </div>

        {licensedWasteCount > 0 && (
          <div className="p-2.5 bg-amber-50 border border-amber-300 rounded-sm flex items-center gap-2 text-xs text-amber-900">
            <DollarSign size={16} className="text-amber-700 shrink-0" />
            <span>
              <strong>{licensedWasteCount} Shared Mailbox(es)</strong> have paid licenses attached ($20–$40/mo potential savings).
            </span>
          </div>
        )}
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search mailboxes or delegated users..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
          >
            <option value="all">All Mailboxes ({mailboxes.length})</option>
            <option value="shared">Shared Mailboxes ({sharedCount})</option>
            <option value="waste">Licensed Shared Mailboxes (Cost Waste)</option>
            <option value="user">User Mailboxes</option>
          </select>
        </div>
      </div>

      {/* Mailbox Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            Mailbox Inventory & Explicit Delegation Matrix
          </h3>
          <span className="text-[11px] font-mono text-slate-500">{filteredMailboxes.length} Mailboxes</span>
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
                <tr>
                  <td colSpan={6} className="p-4 text-center text-xs text-slate-500">
                    No mailboxes found matching active filter.
                  </td>
                </tr>
              ) : (
                filteredMailboxes.map((mbx) => (
                  <tr key={mbx.id} className={mbx.hasDirectLicense && mbx.recipientType === "SharedMailbox" ? "bg-amber-50/30" : ""}>
                    <td>
                      <div className="font-semibold text-xs text-slate-900">{mbx.displayName}</div>
                      <div className="text-[11px] font-mono text-slate-500">{mbx.userPrincipalName}</div>
                    </td>
                    <td>
                      <StatusPill
                        status={mbx.recipientType === "SharedMailbox" ? "info" : "pass"}
                        label={mbx.recipientType === "SharedMailbox" ? "Shared Mailbox" : "User Mailbox"}
                        size="sm"
                      />
                    </td>
                    <td className="font-mono text-xs text-slate-800 tabular-nums">
                      {(mbx.totalItemSizeMB / 1024).toFixed(1)} GB
                    </td>
                    <td>
                      <span className={`text-xs font-mono ${mbx.archiveStatus === "Enabled" ? "text-emerald-700 font-semibold" : "text-slate-500"}`}>
                        {mbx.archiveStatus}
                      </span>
                    </td>
                    <td>
                      {mbx.delegations.length === 0 ? (
                        <span className="text-slate-400 text-[11px] italic">No active delegations</span>
                      ) : (
                        <div className="space-y-1">
                          {mbx.delegations.map((d, dIdx) => (
                            <div key={dIdx} className="text-[11px] flex items-center gap-1.5">
                              <span className="font-semibold text-slate-800">{d.principalDisplayName}:</span>
                              <span className="font-mono bg-slate-100 border border-slate-200 px-1 py-0.2 rounded-sm text-slate-700">
                                {d.accessRight}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="text-right">
                      {mbx.recipientType === "SharedMailbox" && mbx.hasDirectLicense ? (
                        <span className="text-[11px] font-semibold text-amber-800">
                          Paid License Waste
                        </span>
                      ) : (
                        <span className="text-[11px] text-slate-500">Normal</span>
                      )}
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
