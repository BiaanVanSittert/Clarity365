import React, { useState } from "react";
import { TenantSecuritySnapshot, TenantGroup } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Modal } from "../common/Modal";
import { Drawer } from "../common/Drawer";
import { LocalOnlyNotice } from "../common/LocalOnlyNotice";
import { EmptyStateRow } from "../common/EmptyStateRow";
import { Users, Plus, Search, Filter, Shield, Mail, CheckCircle2, ChevronRight, Download, AlertTriangle } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import { evaluateGroupsBaseline } from "@/lib/services/groups-baseline-matcher";
import { GROUPS_BASELINE_STANDARDS } from "@/lib/data/groups-baseline-definitions";

interface GroupsManagementModuleProps {
  snapshot: TenantSecuritySnapshot;
  onLocalRefresh: () => void;
}

export const GroupsManagementModule: React.FC<GroupsManagementModuleProps> = ({ snapshot, onLocalRefresh }) => {
  const { groups, tenant, conditionalAccess, mfaAudit } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [selectedGroup, setSelectedGroup] = useState<TenantGroup | null>(null);

  const caExclusionGroupIds = new Set(
    conditionalAccess.policies.flatMap((p) => p.conditions.users.excludeGroupIds || [])
  );
  const weakMfaUserPrincipalNamesLower = new Set(
    mfaAudit.filter((u) => u.isWeakAuth || !u.mfaRegistered).map((u) => u.userPrincipalName.toLowerCase())
  );
  const { results: baselineResults, coveragePercent } = evaluateGroupsBaseline({
    groups,
    caExclusionGroupIds,
    weakMfaUserPrincipalNamesLower,
    groupExpirationPolicyEnabled: snapshot.groupExpirationPolicyEnabled,
    groupSelfServiceCreationRestricted: snapshot.groupSelfServiceCreationRestricted,
    groupNamingPolicyEnabled: snapshot.groupNamingPolicyEnabled,
  });
  const checksBelowCount = baselineResults.filter((r) => !r.met).length;
  const resultFor = (code: string) => baselineResults.find((r) => r.code === code)!;

  // Create Group Modal State
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [newDisplayName, setNewDisplayName] = useState("");
  const [newMailNickname, setNewMailNickname] = useState("");
  const [newGroupType, setNewGroupType] = useState<TenantGroup["groupType"]>("Security");
  const [newMembershipType, setNewMembershipType] = useState<"Assigned" | "Dynamic">("Assigned");
  const [newOwner, setNewOwner] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleCreateGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    try {
      const res = await fetch(`/api/tenants/${tenant.id}/groups`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          displayName: newDisplayName.trim(),
          mailNickname: newMailNickname.trim().toLowerCase(),
          groupType: newGroupType,
          membershipType: newMembershipType,
          ownersCount: 1,
          membersCount: 1,
          owners: [newOwner.trim() || `admin@${tenant.defaultDomainName}`],
          members: [newOwner.trim() || `admin@${tenant.defaultDomainName}`],
          isPrivileged: false,
          isAssignableToRole: false,
          guestMemberCount: 0,
          syncSource: "Cloud",
        }),
      });

      const data = await res.json();
      if (data.success) {
        setIsCreateOpen(false);
        setNewDisplayName("");
        setNewMailNickname("");
        setNewOwner("");
        onLocalRefresh();
      }
    } catch (err) {
      console.error("Failed to create group", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const filteredGroups = groups.filter((g) => {
    const matchesSearch =
      g.displayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      g.mailNickname.toLowerCase().includes(searchQuery.toLowerCase()) ||
      g.owners.some((o) => o.toLowerCase().includes(searchQuery.toLowerCase()));

    if (typeFilter === "all") return matchesSearch;
    return matchesSearch && g.groupType === typeFilter;
  });

  const handleExportCSV = () => {
    const headers = [
      "DisplayName",
      "MailNickname",
      "GroupType",
      "MembershipType",
      "OwnersCount",
      "MembersCount",
      "SyncSource",
      "IsAssignableToRole",
      "GuestMemberCount",
    ];
    const rows = filteredGroups.map((g) => [
      g.displayName,
      g.mailNickname,
      g.groupType,
      g.membershipType,
      g.ownersCount,
      g.membersCount,
      g.syncSource,
      g.isAssignableToRole ? "Yes" : "No",
      g.guestMemberCount,
    ]);
    exportToCsv(csvFilename("Groups", tenant.defaultDomainName), headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Users size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Module 11: Microsoft Groups & Distribution Management
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Audit Security Groups, M365 Unified Teams, Distribution Lists, Mail-Enabled Security, and Privileged Roles.
          </p>
        </div>

        <button
          onClick={() => setIsCreateOpen(true)}
          className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
        >
          <Plus size={14} />
          <span>Create Directory Group</span>
        </button>
      </div>

      {/* Baseline & Posture */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Group Governance Baseline
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
            {coveragePercent}% ({baselineResults.length - checksBelowCount}/{baselineResults.length})
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-16">Code</th>
                <th>Baseline Check</th>
                <th className="w-32">Status</th>
              </tr>
            </thead>
            <tbody>
              {GROUPS_BASELINE_STANDARDS.map((standard) => {
                const result = resultFor(standard.code);
                return (
                  <tr key={standard.code}>
                    <td className="font-mono font-bold text-xs text-slate-900 dark:text-slate-100">{standard.code}</td>
                    <td>
                      <div className="font-semibold text-xs text-slate-900 dark:text-slate-100">{standard.name}</div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">{standard.description}</div>
                      <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">Mitigates: {standard.riskMitigated}</div>
                    </td>
                    <td>
                      {result.met ? (
                        <StatusPill status="pass" label="Met" size="sm" />
                      ) : (
                        <StatusPill
                          status="fail"
                          label={result.offendingGroupNames ? `${result.offendingGroupNames.length} group(s) flagged` : "Below Recommended"}
                          size="sm"
                        />
                      )}
                      {!result.met && result.offendingGroupNames && (
                        <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 max-w-md">
                          {result.offendingGroupNames.join(", ")}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Search groups by name or owner..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500 dark:text-slate-400" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
          >
            <option value="all">All Group Types ({groups.length})</option>
            <option value="Security">Security Groups</option>
            <option value="M365Unified">Microsoft 365 (Unified) Groups</option>
            <option value="DistributionList">Distribution Lists (DL)</option>
            <option value="MailEnabledSecurity">Mail-Enabled Security Groups</option>
          </select>

          <button
            onClick={handleExportCSV}
            title="Export filtered groups to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500 dark:text-slate-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Groups Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Directory Group Hierarchy & Ownership Matrix
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{filteredGroups.length} Groups Listed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Group Name & Email Alias</th>
                <th className="w-36">Category</th>
                <th className="w-28">Membership</th>
                <th className="w-24">Owners</th>
                <th className="w-24">Members</th>
                <th className="w-28">Sync Source</th>
                <th className="w-20 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody>
              {filteredGroups.length === 0 ? (
                <EmptyStateRow colSpan={7} entityLabel="groups" isFiltered={searchQuery.trim().length > 0 || typeFilter !== "all"} />
              ) : (
                filteredGroups.map((grp) => (
                  <tr
                    key={grp.id}
                    onClick={() => setSelectedGroup(grp)}
                    tabIndex={0}
                    role="button"
                    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setSelectedGroup(grp))}
                    className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors focus:outline focus:outline-2 focus:outline-slate-400 focus:-outline-offset-2"
                  >
                    <td>
                      <div className="font-semibold text-xs text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                        {grp.displayName}
                        {grp.isPrivileged && (
                          <span
                            title="isAssignableToRole - membership in this group IS an admin role grant"
                            className="text-[9px] font-mono uppercase px-1 bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-400 border border-red-300 dark:border-red-800 rounded-sm font-bold"
                          >
                            ROLE-ASSIGNABLE
                          </span>
                        )}
                        {grp.guestMemberCount > 0 && (
                          <span
                            title={`${grp.guestMemberCount} guest member(s)`}
                            className="text-[9px] font-mono uppercase px-1 bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-400 border border-amber-300 dark:border-amber-800 rounded-sm font-bold"
                          >
                            {grp.guestMemberCount} GUEST{grp.guestMemberCount > 1 ? "S" : ""}
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{grp.mailNickname}@{tenant.defaultDomainName}</div>
                    </td>
                    <td>
                      <StatusPill
                        status="info"
                        label={
                          grp.groupType === "M365Unified"
                            ? "M365 Unified"
                            : grp.groupType === "DistributionList"
                            ? "Distribution List"
                            : grp.groupType === "MailEnabledSecurity"
                            ? "Mail-Enabled Sec"
                            : "Security Group"
                        }
                        size="sm"
                      />
                    </td>
                    <td className="text-xs font-mono text-slate-700 dark:text-slate-300">{grp.membershipType}</td>
                    <td className="font-mono text-xs font-bold text-slate-900 dark:text-slate-100 tabular-nums">{grp.ownersCount}</td>
                    <td className="font-mono text-xs font-bold text-slate-900 dark:text-slate-100 tabular-nums">{grp.membersCount}</td>
                    <td>
                      <span className="text-xs font-mono text-slate-600 dark:text-slate-400">{grp.syncSource}</span>
                    </td>
                    <td className="text-right">
                      <button
                        aria-label="View group details"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedGroup(grp);
                        }}
                        className="p-1 text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:text-slate-100 rounded-sm"
                      >
                        <ChevronRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspect Group Drawer */}
      {selectedGroup && (
        <Drawer
          isOpen={!!selectedGroup}
          onClose={() => setSelectedGroup(null)}
          title={`Group: ${selectedGroup.displayName}`}
          subtitle={`Type: ${selectedGroup.groupType} • Created: ${new Date(selectedGroup.createdDateTime).toLocaleDateString()}`}
          width="lg"
        >
          <div className="space-y-4">
            {selectedGroup.membershipType === "Dynamic" && (
              <div className="border border-[#CBD5E1] dark:border-slate-700 p-3 rounded-sm bg-[#F8FAFC] dark:bg-slate-900/50 space-y-1.5">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                  Dynamic Membership Rule
                </h4>
                {selectedGroup.membershipRule ? (
                  <div className="text-[11px] font-mono text-slate-800 dark:text-slate-200 p-1.5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm break-all">
                    {selectedGroup.membershipRule}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 dark:text-slate-400 italic">Rule text not available.</p>
                )}
              </div>
            )}

            {selectedGroup.guestMemberCount > 0 && (
              <div className="p-2.5 bg-amber-50 dark:bg-amber-950 border border-amber-300 dark:border-amber-800 rounded-sm flex items-center gap-2 text-xs text-amber-900 dark:text-amber-400">
                <AlertTriangle size={14} className="text-amber-700 dark:text-amber-400 shrink-0" />
                <span>
                  <strong>{selectedGroup.guestMemberCount} guest member(s)</strong> in this group
                  {selectedGroup.isAssignableToRole && " - and this group is role-assignable, so an external account effectively holds a directory role"}.
                </span>
              </div>
            )}

            <div className="border border-[#CBD5E1] dark:border-slate-700 p-3 rounded-sm bg-[#F8FAFC] dark:bg-slate-900/50 space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                Designated Group Owners ({selectedGroup.owners.length})
              </h4>
              {selectedGroup.owners.length === 0 ? (
                <p className="text-xs text-amber-800 dark:text-amber-400 italic">No assigned owners (Orphaned Group Risk).</p>
              ) : (
                <div className="space-y-1">
                  {selectedGroup.owners.map((owner, idx) => (
                    <div key={idx} className="text-xs font-mono text-slate-800 dark:text-slate-200 p-1.5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm">
                      {owner}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="border border-[#CBD5E1] dark:border-slate-700 p-3 rounded-sm bg-white dark:bg-slate-800 space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
                Direct Assigned Members ({selectedGroup.members.length})
              </h4>
              {selectedGroup.members.length === 0 ? (
                <p className="text-xs text-slate-500 dark:text-slate-400 italic">No direct members listed.</p>
              ) : (
                <div className="space-y-1">
                  {selectedGroup.members.map((member, idx) => (
                    <div key={idx} className="text-xs font-mono text-slate-800 dark:text-slate-200 p-1.5 bg-[#F8FAFC] dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700 rounded-sm">
                      {member}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </Drawer>
      )}

      {/* Create Group Modal */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Create New Microsoft Directory Group"
        subtitle="Provision a Security or M365 Unified collaboration group"
        maxWidth="md"
      >
        <form onSubmit={handleCreateGroup} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
              Group Display Name <span className="text-red-500 dark:text-red-400">*</span>
            </label>
            <input
              type="text"
              required
              placeholder="e.g. SOC Tier 1 Analysts"
              value={newDisplayName}
              onChange={(e) => setNewDisplayName(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                Mail Nickname / Alias <span className="text-red-500 dark:text-red-400">*</span>
              </label>
              <input
                type="text"
                required
                placeholder="soc-tier1"
                value={newMailNickname}
                onChange={(e) => setNewMailNickname(e.target.value)}
                className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Group Type</label>
              <select
                value={newGroupType}
                onChange={(e) => setNewGroupType(e.target.value as any)}
                className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
              >
                <option value="Security">Security Group</option>
                <option value="M365Unified">Microsoft 365 (Unified)</option>
                <option value="DistributionList">Distribution List</option>
                <option value="MailEnabledSecurity">Mail-Enabled Security</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Initial Owner UPN</label>
            <input
              type="email"
              placeholder={`admin@${tenant.defaultDomainName}`}
              value={newOwner}
              onChange={(e) => setNewOwner(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
            />
          </div>

          <LocalOnlyNotice />

          <div className="flex justify-end gap-2 pt-2 border-t border-[#E2E8F0] dark:border-slate-700">
            <button
              type="button"
              onClick={() => setIsCreateOpen(false)}
              className="px-3 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <Plus size={14} />
              <span>{isSubmitting ? "Creating..." : "Create Group"}</span>
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
