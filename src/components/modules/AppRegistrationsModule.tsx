import React, { useState } from "react";
import { TenantSecuritySnapshot, AppRegistrationItem } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Server, AlertTriangle, Key, Search, Filter, ShieldAlert, ShieldCheck, Download } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";

interface AppRegistrationsModuleProps {
  snapshot: TenantSecuritySnapshot;
}

export const AppRegistrationsModule: React.FC<AppRegistrationsModuleProps> = ({ snapshot }) => {
  const { appRegistrations } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<string>("all");

  const filteredApps = appRegistrations.filter((app) => {
    const matchesSearch =
      app.displayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      app.publisher.toLowerCase().includes(searchQuery.toLowerCase()) ||
      app.appId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      app.highPrivilegePermissions.some((p) => p.toLowerCase().includes(searchQuery.toLowerCase()));

    if (riskFilter === "all") return matchesSearch;
    if (riskFilter === "critical") return matchesSearch && app.riskCategory === "critical";
    if (riskFilter === "high_privilege") return matchesSearch && app.highPrivilegePermissions.length > 0;
    return matchesSearch;
  });

  const handleExportCSV = () => {
    const headers = ["DisplayName", "Publisher", "AppId", "HighPrivilegePermissions", "SecretsCount", "CertificatesCount", "ExpiringCredentialsCount", "RiskTier"];
    const rows = filteredApps.map((app) => [
      app.displayName,
      app.publisher,
      app.appId,
      app.highPrivilegePermissions.join("; "),
      app.secretsCount,
      app.certificatesCount,
      app.expiringCredentialsCount,
      app.riskCategory,
    ]);
    exportToCsv(csvFilename("AppRegistrations", snapshot.tenant.defaultDomainName), headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Server size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 9: Enterprise Applications, App Registrations & OAuth Permissions
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Audit high-privilege Microsoft Graph API permissions, expiring client secrets, and third-party SaaS integrations.
          </p>
        </div>

        <div className="text-right">
          <div className="text-xs font-semibold text-slate-700">Total Applications</div>
          <div className="text-lg font-bold font-mono text-slate-900 tabular-nums">
            {appRegistrations.length} Connected
          </div>
        </div>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search applications, publishers, or permissions..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
          >
            <option value="all">All Applications ({appRegistrations.length})</option>
            <option value="critical">Critical Risk Only</option>
            <option value="high_privilege">High-Privilege Graph Permissions</option>
          </select>

          <button
            onClick={handleExportCSV}
            title="Export filtered applications to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-[#CBD5E1] rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* App Registration Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            Registered Application Inventory & Permission Grants
          </h3>
          <span className="text-[11px] font-mono text-slate-500">{filteredApps.length} Apps Listed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Application Name & Publisher</th>
                <th className="w-36">Application ID</th>
                <th>High-Privilege Graph Scopes</th>
                <th className="w-28">Credentials</th>
                <th className="w-28 text-right">Risk Tier</th>
              </tr>
            </thead>
            <tbody>
              {filteredApps.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-4 text-center text-xs text-slate-500">
                    No application registrations found.
                  </td>
                </tr>
              ) : (
                filteredApps.map((app) => (
                  <tr key={app.id} className={app.riskCategory === "critical" ? "bg-red-50/20" : ""}>
                    <td>
                      <div className="font-semibold text-xs text-slate-900">{app.displayName}</div>
                      <div className="text-[11px] text-slate-500 font-medium">Publisher: {app.publisher}</div>
                    </td>
                    <td className="font-mono text-[11px] text-slate-600 truncate max-w-[140px]">
                      {app.appId}
                    </td>
                    <td>
                      {app.highPrivilegePermissions.length === 0 ? (
                        <span className="text-slate-400 text-[11px] italic">Standard / Low Privilege</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {app.highPrivilegePermissions.map((perm, pIdx) => (
                            <span
                              key={pIdx}
                              className="font-mono text-[10px] font-bold px-1.5 py-0.5 bg-red-50 text-red-800 border border-red-200 rounded-sm"
                            >
                              {perm}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="text-xs font-mono text-slate-700">
                      <div>{app.secretsCount} Secrets • {app.certificatesCount} Certs</div>
                      {app.expiringCredentialsCount > 0 && (
                        <span className="text-[10px] text-amber-700 font-bold block">
                          {app.expiringCredentialsCount} Expiring Soon
                        </span>
                      )}
                    </td>
                    <td className="text-right">
                      <StatusPill status={app.riskCategory} label={app.riskCategory.toUpperCase()} size="sm" />
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
