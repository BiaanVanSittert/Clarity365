import React, { useState, useEffect, useCallback } from "react";
import { AuditLogEntry, Tenant } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Pagination } from "../common/Pagination";
import { History, Search, Filter, RefreshCw, ShieldCheck, Bot, XCircle, Download } from "lucide-react";

interface AuditLogModuleProps {
  tenants: Tenant[];
}

const CATEGORY_LABELS: Record<string, string> = {
  ca_policy_deploy: "CA Policy Deploy",
  mcp_tool_call: "MCP Tool Call",
  tenant_sync_failure: "Tenant Sync Failure",
};

export const AuditLogModule: React.FC<AuditLogModuleProps> = ({ tenants }) => {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [tenantFilter, setTenantFilter] = useState<string>("all");

  const fetchLog = useCallback(async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      if (tenantFilter !== "all") params.set("tenantId", tenantFilter);
      if (categoryFilter !== "all") params.set("category", categoryFilter);
      const res = await fetch(`/api/audit-log?${params.toString()}`);
      const data = await res.json();
      if (data.success) setEntries(data.entries);
    } catch (err) {
      console.error("Failed to load audit log", err);
    } finally {
      setIsLoading(false);
    }
  }, [tenantFilter, categoryFilter]);

  useEffect(() => {
    fetchLog();
  }, [fetchLog]);

  const filteredEntries = entries.filter((e) => {
    const q = searchQuery.toLowerCase();
    if (!q) return true;
    return (
      e.action.toLowerCase().includes(q) ||
      (e.tenantName || "").toLowerCase().includes(q) ||
      (e.detail || "").toLowerCase().includes(q)
    );
  });

  const AUDIT_PAGE_SIZE = 50;
  const [page, setPage] = useState(1);
  useEffect(() => {
    setPage(1);
  }, [searchQuery, categoryFilter, tenantFilter]);
  const paginatedEntries = filteredEntries.slice((page - 1) * AUDIT_PAGE_SIZE, page * AUDIT_PAGE_SIZE);

  const deployCount = entries.filter((e) => e.category === "ca_policy_deploy").length;
  const mcpCount = entries.filter((e) => e.category === "mcp_tool_call").length;
  const failureCount = entries.filter((e) => !e.success).length;

  // Export to CSV
  const handleExportCSV = () => {
    const headers = ["Timestamp", "Category", "Action", "Tenant", "Detail", "Outcome"];

    const rows = filteredEntries.map((e) => [
      `"${e.timestamp}"`,
      `"${CATEGORY_LABELS[e.category] || e.category}"`,
      `"${e.action.replace(/"/g, '""')}"`,
      `"${e.tenantName || ""}"`,
      `"${(e.detail || "").replace(/"/g, '""')}"`,
      e.success ? "Success" : "Failure",
    ]);

    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `Clarity365_AuditLog_${new Date().toISOString().split("T")[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <History size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">System Audit Log</h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Record of Conditional Access baseline deployments and MCP agent tool executions across all tenants.
          </p>
        </div>

        <button
          onClick={() => fetchLog()}
          disabled={isLoading}
          className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-60 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
        >
          <RefreshCw size={13} className={isLoading ? "animate-spin" : ""} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white border border-[#CBD5E1] rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 font-semibold">Total Entries</div>
          <div className="text-xl font-bold font-mono text-slate-900 tabular-nums mt-0.5">{entries.length}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Within retention window</div>
        </div>

        <div className="p-3 bg-white border border-[#CBD5E1] rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 font-semibold flex items-center gap-1">
            <ShieldCheck size={11} />
            <span>CA Policy Deploys</span>
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 tabular-nums mt-0.5">{deployCount}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Baseline policies pushed</div>
        </div>

        <div className="p-3 bg-white border border-[#CBD5E1] rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 font-semibold flex items-center gap-1">
            <Bot size={11} />
            <span>MCP Tool Calls</span>
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 tabular-nums mt-0.5">{mcpCount}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Agent-executed actions</div>
        </div>

        <div className={`p-3 border rounded-sm ${failureCount > 0 ? "bg-[#FEF2F2] border-[#EF4444]" : "bg-white border-[#CBD5E1]"}`}>
          <div className={`text-[10px] uppercase font-mono font-semibold flex items-center gap-1 ${failureCount > 0 ? "text-[#991B1B]" : "text-slate-500"}`}>
            <XCircle size={11} />
            <span>Failures</span>
          </div>
          <div className={`text-xl font-bold font-mono tabular-nums mt-0.5 ${failureCount > 0 ? "text-[#991B1B]" : "text-slate-900"}`}>
            {failureCount}
          </div>
          <div className={`text-[11px] mt-0.5 ${failureCount > 0 ? "text-[#991B1B]" : "text-slate-500"}`}>Errored actions</div>
        </div>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search action, tenant, or detail..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
          >
            <option value="all">All Categories</option>
            <option value="ca_policy_deploy">CA Policy Deploy</option>
            <option value="mcp_tool_call">MCP Tool Call</option>
            <option value="tenant_sync_failure">Tenant Sync Failure</option>
          </select>

          <select
            value={tenantFilter}
            onChange={(e) => setTenantFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
          >
            <option value="all">All Tenants</option>
            {tenants.map((t) => (
              <option key={t.id} value={t.id}>
                {t.displayName}
              </option>
            ))}
          </select>

          <button
            onClick={handleExportCSV}
            title="Export filtered entries to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-[#CBD5E1] rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Log Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">Audit Trail</h3>
          <span className="text-[11px] font-mono text-slate-500">{filteredEntries.length} Entries Listed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Category</th>
                <th>Action</th>
                <th>Tenant</th>
                <th>Detail</th>
                <th className="w-24 text-right">Outcome</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="p-4 text-center text-xs text-slate-500">
                    Loading audit log...
                  </td>
                </tr>
              ) : filteredEntries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-4 text-center text-xs text-slate-500">
                    No audit entries match the active filter criteria.
                  </td>
                </tr>
              ) : (
                paginatedEntries.map((entry) => (
                  <tr key={entry.id} className={!entry.success ? "bg-red-50/20" : ""}>
                    <td className="font-mono text-[11px] text-slate-600 whitespace-nowrap">
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className="text-[11px] font-medium text-slate-700">
                        {CATEGORY_LABELS[entry.category] || entry.category}
                      </span>
                    </td>
                    <td className="text-xs font-semibold text-slate-900">{entry.action}</td>
                    <td className="text-[11px] text-slate-600">{entry.tenantName || "—"}</td>
                    <td className="text-[11px] text-slate-500 max-w-[420px] truncate" title={entry.detail}>
                      {entry.detail || "—"}
                    </td>
                    <td className="text-right">
                      <StatusPill status={entry.success ? "pass" : "fail"} label={entry.success ? "Success" : "Failed"} size="sm" />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <Pagination
          page={page}
          pageSize={AUDIT_PAGE_SIZE}
          totalItems={filteredEntries.length}
          onPageChange={setPage}
        />
      </div>
    </div>
  );
};
