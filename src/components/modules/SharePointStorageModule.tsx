import React, { useState } from "react";
import { TenantSecuritySnapshot, SharePointSiteItem } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { LocalOnlyNotice } from "../common/LocalOnlyNotice";
import { FileSpreadsheet, HardDrive, Share2, AlertTriangle, Search, Filter, ShieldCheck, Check } from "lucide-react";

interface SharePointStorageModuleProps {
  snapshot: TenantSecuritySnapshot;
  onLocalRefresh: () => void;
}

export const SharePointStorageModule: React.FC<SharePointStorageModuleProps> = ({ snapshot, onLocalRefresh }) => {
  const { sharePoint, tenant } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [sharingFilter, setSharingFilter] = useState<string>("all");
  const [tenantSharingLevel, setTenantSharingLevel] = useState(sharePoint.tenantSharingLevel);
  const [isSavingPolicy, setIsSavingPolicy] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const sites = sharePoint.sites;

  const handleUpdateTenantPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingPolicy(true);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/sharepoint`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenantSharingLevel }),
      });
      const data = await res.json();
      if (data.success) {
        setSaveSuccess(true);
        setTimeout(() => setSaveSuccess(false), 1500);
        onLocalRefresh();
      }
    } catch (err) {
      console.error("Failed to update SharePoint policy", err);
    } finally {
      setIsSavingPolicy(false);
    }
  };

  const filteredSites = sites.filter((site) => {
    const matchesSearch =
      site.siteName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      site.siteUrl.toLowerCase().includes(searchQuery.toLowerCase()) ||
      site.ownerUPN.toLowerCase().includes(searchQuery.toLowerCase());

    if (sharingFilter === "all") return matchesSearch;
    return matchesSearch && site.sharingCapability === sharingFilter;
  });

  const getSharingPill = (tier: string) => {
    switch (tier) {
      case "Anyone":
        return <StatusPill status="fail" label="Anyone (Anonymous Links)" size="sm" />;
      case "NewAndExistingGuests":
        return <StatusPill status="warn" label="New & Existing Guests" size="sm" />;
      case "ExistingGuests":
        return <StatusPill status="warn" label="Existing Guests Only" size="sm" />;
      case "OnlyPeopleInOrg":
      default:
        return <StatusPill status="pass" label="Organization Only (Secure)" size="sm" />;
    }
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileSpreadsheet size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 12: SharePoint & OneDrive Storage & External Sharing Tiers
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Audit quota consumption, storage limits, and manage tenant-wide / site-level external sharing tiers.
          </p>
        </div>

        <div className="text-right">
          <div className="text-xs font-semibold text-slate-700">Storage Consumption</div>
          <div className="text-lg font-bold font-mono text-slate-900 tabular-nums">
            {sharePoint.totalStorageUsedTB.toFixed(1)} TB / {sharePoint.totalStorageAllocatedTB.toFixed(1)} TB ({Math.round((sharePoint.totalStorageUsedTB / sharePoint.totalStorageAllocatedTB) * 100)}%)
          </div>
        </div>
      </div>

      {/* Tenant-Wide Sharing Policy Configuration Card */}
      <div className="border border-[#CBD5E1] bg-white p-4 rounded-sm shadow-xs space-y-3">
        <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2">
          <div className="flex items-center gap-2">
            <Share2 size={16} className="text-slate-800" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
              Tenant-Wide External Sharing Governance Tier
            </h3>
          </div>
          {getSharingPill(sharePoint.tenantSharingLevel)}
        </div>

        <form onSubmit={handleUpdateTenantPolicy} className="flex flex-col sm:flex-row items-center gap-3">
          <div className="flex-1 w-full">
            <select
              value={tenantSharingLevel}
              onChange={(e) => setTenantSharingLevel(e.target.value as any)}
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
            >
              <option value="OnlyPeopleInOrg">1. Only people in your organization (Most secure - Zero External Sharing)</option>
              <option value="ExistingGuests">2. Existing guests only (Guests already in Entra directory)</option>
              <option value="NewAndExistingGuests">3. New and existing guests (Requires email invitation sign-in)</option>
              <option value="Anyone">4. Anyone (Anonymous & Unauthenticated Links - HIGH RISK)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={isSavingPolicy}
            className="w-full sm:w-auto px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50"
          >
            {saveSuccess ? <Check size={14} className="text-emerald-400" /> : <Share2 size={14} />}
            <span>{isSavingPolicy ? "Updating..." : saveSuccess ? "Policy Applied" : "Update Tenant Policy"}</span>
          </button>
        </form>
        <LocalOnlyNotice />
      </div>

      {/* Site Filter & Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search site collection name, URL, or owner..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={sharingFilter}
            onChange={(e) => setSharingFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
          >
            <option value="all">All Sharing Tiers ({sites.length})</option>
            <option value="Anyone">Anyone (Anonymous Open Links)</option>
            <option value="NewAndExistingGuests">New and Existing Guests</option>
            <option value="ExistingGuests">Existing Guests Only</option>
            <option value="OnlyPeopleInOrg">Internal Only</option>
          </select>
        </div>
      </div>

      {/* Sites Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            SharePoint Site Collections & Storage Quotas
          </h3>
          <span className="text-[11px] font-mono text-slate-500">{filteredSites.length} Sites Listed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Site Collection Name & URL</th>
                <th className="w-36">Template</th>
                <th className="w-48">Storage Quota Utilization</th>
                <th className="w-32">Primary Owner</th>
                <th className="w-44 text-right">Site Sharing Tier</th>
              </tr>
            </thead>
            <tbody>
              {filteredSites.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-4 text-center text-xs text-slate-500">
                    No site collections found matching active filter.
                  </td>
                </tr>
              ) : (
                filteredSites.map((site) => {
                  const percentUsed = Math.round((site.storageUsedGB / site.storageAllocatedGB) * 100);
                  return (
                    <tr key={site.id} className={site.sharingCapability === "Anyone" ? "bg-red-50/20" : ""}>
                      <td>
                        <div className="font-semibold text-xs text-slate-900">{site.siteName}</div>
                        <div className="text-[11px] font-mono text-slate-500 truncate max-w-[320px]">
                          {site.siteUrl}
                        </div>
                      </td>
                      <td>
                        <span className="font-mono text-xs text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded-sm border border-slate-200">
                          {site.template}
                        </span>
                      </td>
                      <td>
                        <div className="space-y-1">
                          <div className="flex justify-between text-[11px] font-mono">
                            <span>{(site.storageUsedGB / 1024).toFixed(1)} GB used</span>
                            <span className="font-bold text-slate-700">{percentUsed}%</span>
                          </div>
                          <div className="w-full bg-[#E2E8F0] h-1.5 rounded-sm overflow-hidden">
                            <div
                              className={`h-full ${percentUsed > 85 ? "bg-red-500" : percentUsed > 60 ? "bg-amber-500" : "bg-slate-700"}`}
                              style={{ width: `${Math.min(100, percentUsed)}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="font-mono text-[11px] text-slate-600 truncate max-w-[150px]">
                        {site.ownerUPN}
                      </td>
                      <td className="text-right">
                        {getSharingPill(site.sharingCapability)}
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
  );
};
