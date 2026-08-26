import React, { useState } from "react";
import { TenantSecuritySnapshot, SharePointSiteItem } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { LocalOnlyNotice } from "../common/LocalOnlyNotice";
import { EmptyStateRow } from "../common/EmptyStateRow";
import { FileSpreadsheet, HardDrive, Share2, AlertTriangle, Search, Filter, ShieldCheck, Check, Download } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import { evaluateSharePointBaseline } from "@/lib/services/sharepoint-baseline-matcher";
import { SHAREPOINT_BASELINE_STANDARDS } from "@/lib/data/sharepoint-baseline-definitions";

interface SharePointStorageModuleProps {
  snapshot: TenantSecuritySnapshot;
  onLocalRefresh: () => void;
}

export const SharePointStorageModule: React.FC<SharePointStorageModuleProps> = ({ snapshot, onLocalRefresh }) => {
  const { sharePoint, tenant, accountClassification } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [sharingFilter, setSharingFilter] = useState<string>("all");
  const [tenantSharingLevel, setTenantSharingLevel] = useState(sharePoint.tenantSharingLevel);
  const [isSavingPolicy, setIsSavingPolicy] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const sites = sharePoint.sites;

  const inactiveUserPrincipalNamesLower = new Set(
    accountClassification.users
      .filter((u) => u.classification === "disabled" || u.classification === "unlicensed_active")
      .map((u) => u.userPrincipalName.toLowerCase())
  );
  const { results: baselineResults, coveragePercent } = evaluateSharePointBaseline({
    policy: sharePoint,
    inactiveUserPrincipalNamesLower,
  });
  const checksBelowCount = baselineResults.filter((r) => !r.met).length;
  const resultFor = (code: string) => baselineResults.find((r) => r.code === code)!;

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

  const handleExportCSV = () => {
    const headers = ["SiteName", "SiteUrl", "Template", "StorageUsedGB", "StorageAllocatedGB", "OwnerUPN", "SharingCapability", "SensitiveDataHeuristic"];
    const rows = filteredSites.map((site) => [
      site.siteName,
      site.siteUrl,
      site.template,
      site.storageUsedGB,
      site.storageAllocatedGB,
      site.ownerUPN,
      site.sharingCapability,
      site.isSensitiveDataPresent ? "Yes" : "No",
    ]);
    exportToCsv(csvFilename("SharePointSites", tenant.defaultDomainName), headers, rows);
  };

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
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileSpreadsheet size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Module 12: SharePoint & OneDrive Storage & External Sharing Tiers
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Audit quota consumption, storage limits, and manage tenant-wide / site-level external sharing tiers.
          </p>
        </div>

        <div className="text-right">
          <div className="text-xs font-semibold text-slate-700 dark:text-slate-300">Storage Consumption</div>
          <div className="text-lg font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums">
            {sharePoint.totalStorageUsedTB.toFixed(1)} TB / {sharePoint.totalStorageAllocatedTB.toFixed(1)} TB (
            {sharePoint.totalStorageAllocatedTB > 0 ? Math.round((sharePoint.totalStorageUsedTB / sharePoint.totalStorageAllocatedTB) * 100) : 0}%)
          </div>
        </div>
      </div>

      {/* Tenant-Wide Sharing Policy Configuration Card */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 p-4 rounded-sm shadow-xs space-y-3">
        <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2">
          <div className="flex items-center gap-2">
            <Share2 size={16} className="text-slate-800 dark:text-slate-200" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
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
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
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

      {/* Baseline & Posture */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            SharePoint & Storage Governance Baseline
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
              {SHAREPOINT_BASELINE_STANDARDS.map((standard) => {
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
                          label={result.offendingSiteNames ? `${result.offendingSiteNames.length} site(s) flagged` : "Below Recommended"}
                          size="sm"
                        />
                      )}
                      {!result.met && result.offendingSiteNames && (
                        <div className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 max-w-md">
                          {result.offendingSiteNames.join(", ")}
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

      {/* Site Filter & Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Search site collection name, URL, or owner..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500 dark:text-slate-400" />
          <select
            value={sharingFilter}
            onChange={(e) => setSharingFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
          >
            <option value="all">All Sharing Tiers ({sites.length})</option>
            <option value="Anyone">Anyone (Anonymous Open Links)</option>
            <option value="NewAndExistingGuests">New and Existing Guests</option>
            <option value="ExistingGuests">Existing Guests Only</option>
            <option value="OnlyPeopleInOrg">Internal Only</option>
          </select>

          <button
            onClick={handleExportCSV}
            title="Export filtered sites to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500 dark:text-slate-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Sites Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            SharePoint Site Collections & Storage Quotas
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{filteredSites.length} Sites Listed</span>
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
                <EmptyStateRow colSpan={5} entityLabel="site collections" isFiltered={searchQuery.trim().length > 0 || sharingFilter !== "all"} />
              ) : (
                filteredSites.map((site) => {
                  const percentUsed = site.storageAllocatedGB > 0 ? Math.round((site.storageUsedGB / site.storageAllocatedGB) * 100) : 0;
                  const ownerInactive = !!site.ownerUPN && inactiveUserPrincipalNamesLower.has(site.ownerUPN.toLowerCase());
                  const compoundRisk = site.isSensitiveDataPresent && (site.sharingCapability === "Anyone" || site.sharingCapability === "NewAndExistingGuests");
                  return (
                    <tr key={site.id} className={site.sharingCapability === "Anyone" ? "bg-red-50/20 dark:bg-red-950" : ""}>
                      <td>
                        <div className="font-semibold text-xs text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                          {site.siteName}
                          {site.isSensitiveDataPresent && (
                            <span
                              title={compoundRisk ? "Likely contains sensitive data AND allows open sharing — compound risk" : "Likely contains sensitive data (name/URL heuristic, not a Purview signal)"}
                              className={`text-[9px] font-mono uppercase px-1 rounded-sm font-bold border ${compoundRisk ? "bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-400 border-red-300 dark:border-red-800" : "bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-600"}`}
                            >
                              Sensitive
                            </span>
                          )}
                          {ownerInactive && (
                            <span
                              title={`Owner ${site.ownerUPN} is disabled or unlicensed-active`}
                              className="text-[9px] font-mono uppercase px-1 bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-400 border border-amber-300 dark:border-amber-800 rounded-sm font-bold"
                            >
                              Owner Inactive
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate max-w-[320px]">
                          {site.siteUrl}
                        </div>
                      </td>
                      <td>
                        <span className="font-mono text-xs text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 px-1.5 py-0.5 rounded-sm border border-slate-200 dark:border-slate-700">
                          {site.template}
                        </span>
                      </td>
                      <td>
                        <div className="space-y-1">
                          <div className="flex justify-between text-[11px] font-mono">
                            <span>{(site.storageUsedGB / 1024).toFixed(1)} GB used</span>
                            <span className="font-bold text-slate-700 dark:text-slate-300">{percentUsed}%</span>
                          </div>
                          <div className="w-full bg-[#E2E8F0] dark:bg-slate-700 h-1.5 rounded-sm overflow-hidden">
                            <div
                              className={`h-full ${percentUsed > 85 ? "bg-red-600 dark:bg-red-500" : percentUsed > 60 ? "bg-amber-600 dark:bg-amber-500" : "bg-slate-700"}`}
                              style={{ width: `${Math.min(100, percentUsed)}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="font-mono text-[11px] text-slate-600 dark:text-slate-400 truncate max-w-[150px]">
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
