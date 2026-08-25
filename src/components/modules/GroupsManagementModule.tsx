import React, { useState } from "react";
import { TenantSecuritySnapshot, TenantGroup } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Modal } from "../common/Modal";
import { Drawer } from "../common/Drawer";
import { LocalOnlyNotice } from "../common/LocalOnlyNotice";
import { Users, Plus, Search, Filter, Shield, Mail, CheckCircle2, ChevronRight } from "lucide-react";

interface GroupsManagementModuleProps {
  snapshot: TenantSecuritySnapshot;
  onLocalRefresh: () => void;
}

export const GroupsManagementModule: React.FC<GroupsManagementModuleProps> = ({ snapshot, onLocalRefresh }) => {
  const { groups, tenant } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [selectedGroup, setSelectedGroup] = useState<TenantGroup | null>(null);

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

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Users size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 11: Microsoft Groups & Distribution Management
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
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

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search groups by name or owner..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
          >
            <option value="all">All Group Types ({groups.length})</option>
            <option value="Security">Security Groups</option>
            <option value="M365Unified">Microsoft 365 (Unified) Groups</option>
            <option value="DistributionList">Distribution Lists (DL)</option>
            <option value="MailEnabledSecurity">Mail-Enabled Security Groups</option>
          </select>
        </div>
      </div>

      {/* Groups Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            Directory Group Hierarchy & Ownership Matrix
          </h3>
          <span className="text-[11px] font-mono text-slate-500">{filteredGroups.length} Groups Listed</span>
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
                <tr>
                  <td colSpan={7} className="p-4 text-center text-xs text-slate-500">
                    No groups found matching active filter.
                  </td>
                </tr>
              ) : (
                filteredGroups.map((grp) => (
                  <tr
                    key={grp.id}
                    onClick={() => setSelectedGroup(grp)}
                    tabIndex={0}
                    role="button"
                    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setSelectedGroup(grp))}
                    className="cursor-pointer hover:bg-slate-50 transition-colors focus:outline focus:outline-2 focus:outline-slate-400 focus:-outline-offset-2"
                  >
                    <td>
                      <div className="font-semibold text-xs text-slate-900 flex items-center gap-1.5">
                        {grp.displayName}
                        {grp.isPrivileged && (
                          <span className="text-[9px] font-mono uppercase px-1 bg-red-100 text-red-800 border border-red-300 rounded-sm font-bold">
                            PRIVILEGED
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">{grp.mailNickname}@{tenant.defaultDomainName}</div>
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
                    <td className="text-xs font-mono text-slate-700">{grp.membershipType}</td>
                    <td className="font-mono text-xs font-bold text-slate-900 tabular-nums">{grp.ownersCount}</td>
                    <td className="font-mono text-xs font-bold text-slate-900 tabular-nums">{grp.membersCount}</td>
                    <td>
                      <span className="text-xs font-mono text-slate-600">{grp.syncSource}</span>
                    </td>
                    <td className="text-right">
                      <button
                        aria-label="View group details"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedGroup(grp);
                        }}
                        className="p-1 text-slate-400 hover:text-slate-900 rounded-sm"
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
            <div className="border border-[#CBD5E1] p-3 rounded-sm bg-[#F8FAFC] space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                Designated Group Owners ({selectedGroup.owners.length})
              </h4>
              {selectedGroup.owners.length === 0 ? (
                <p className="text-xs text-amber-800 italic">No assigned owners (Orphaned Group Risk).</p>
              ) : (
                <div className="space-y-1">
                  {selectedGroup.owners.map((owner, idx) => (
                    <div key={idx} className="text-xs font-mono text-slate-800 p-1.5 bg-white border border-slate-200 rounded-sm">
                      {owner}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="border border-[#CBD5E1] p-3 rounded-sm bg-white space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                Direct Assigned Members ({selectedGroup.members.length})
              </h4>
              {selectedGroup.members.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No direct members listed.</p>
              ) : (
                <div className="space-y-1">
                  {selectedGroup.members.map((member, idx) => (
                    <div key={idx} className="text-xs font-mono text-slate-800 p-1.5 bg-[#F8FAFC] border border-slate-200 rounded-sm">
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
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Group Display Name <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              required
              placeholder="e.g. SOC Tier 1 Analysts"
              value={newDisplayName}
              onChange={(e) => setNewDisplayName(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Mail Nickname / Alias <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                required
                placeholder="soc-tier1"
                value={newMailNickname}
                onChange={(e) => setNewMailNickname(e.target.value)}
                className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">Group Type</label>
              <select
                value={newGroupType}
                onChange={(e) => setNewGroupType(e.target.value as any)}
                className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
              >
                <option value="Security">Security Group</option>
                <option value="M365Unified">Microsoft 365 (Unified)</option>
                <option value="DistributionList">Distribution List</option>
                <option value="MailEnabledSecurity">Mail-Enabled Security</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">Initial Owner UPN</label>
            <input
              type="email"
              placeholder={`admin@${tenant.defaultDomainName}`}
              value={newOwner}
              onChange={(e) => setNewOwner(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
            />
          </div>

          <LocalOnlyNotice />

          <div className="flex justify-end gap-2 pt-2 border-t border-[#E2E8F0]">
            <button
              type="button"
              onClick={() => setIsCreateOpen(false)}
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
              <span>{isSubmitting ? "Creating..." : "Create Group"}</span>
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
