import React, { useState, useMemo } from "react";
import { TenantSecuritySnapshot, SecurityIncidentItem, IncidentSeverity, IncidentStatus } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Drawer } from "../common/Drawer";
import { CompromisedAccountModal } from "../modals/CompromisedAccountModal";
import { DeviceIsolationModal } from "../modals/DeviceIsolationModal";
import { EmptyStateRow } from "../common/EmptyStateRow";
import { Pagination } from "../common/Pagination";
import {
  Flame,
  ShieldAlert,
  Search,
  Filter,
  UserX,
  Radio,
  CheckCircle2,
  Clock,
  Laptop,
  User,
  Terminal,
  ExternalLink,
  RefreshCw,
  AlertTriangle,
  FileText,
  Copy,
  Check,
  ShieldCheck,
} from "lucide-react";
import { exportToCsv } from "@/lib/utils/csv";

interface EventResponseModuleProps {
  snapshot: TenantSecuritySnapshot;
  onLocalRefresh?: () => void;
}

const SEVERITY_COLORS: Record<IncidentSeverity, string> = {
  critical: "bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border-red-300 dark:border-red-800",
  high: "bg-amber-50 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800",
  medium: "bg-orange-50 dark:bg-orange-950/60 text-orange-800 dark:text-orange-300 border-orange-300 dark:border-orange-800",
  low: "bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border-blue-300 dark:border-blue-800",
  informational: "bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700",
};

export const EventResponseModule: React.FC<EventResponseModuleProps> = ({
  snapshot,
  onLocalRefresh,
}) => {
  const incidents = useMemo(() => snapshot.incidents || [], [snapshot.incidents]);

  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [mitreFilter, setMitreFilter] = useState<string>("all");
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncidentItem | null>(null);

  // Containment Modals State
  const [containmentTarget, setContainmentTarget] = useState<{ upn: string; id?: string } | null>(null);
  const [isolationTarget, setIsolationTarget] = useState<{ deviceId: string; deviceName: string } | null>(null);
  const [copiedReport, setCopiedReport] = useState(false);

  // Pagination
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 15;

  // Filtered List
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const q = searchQuery.toLowerCase();
      if (
        q &&
        !inc.displayName.toLowerCase().includes(q) &&
        !inc.incidentId.toLowerCase().includes(q) &&
        !inc.impactedUsers.some((u) => u.userPrincipalName.toLowerCase().includes(q) || u.displayName.toLowerCase().includes(q)) &&
        !inc.impactedDevices.some((d) => d.deviceName.toLowerCase().includes(q))
      ) {
        return false;
      }

      if (severityFilter !== "all" && inc.severity !== severityFilter) return false;
      if (statusFilter !== "all" && inc.status !== statusFilter) return false;
      if (mitreFilter !== "all" && !inc.mitreTechniques.some((m) => m.includes(mitreFilter))) return false;

      return true;
    });
  }, [incidents, searchQuery, severityFilter, statusFilter, mitreFilter]);

  const paginatedIncidents = useMemo(() => {
    return filteredIncidents.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  }, [filteredIncidents, page]);

  // Aggregate Metrics
  const activeCount = incidents.filter((i) => i.status === "active" || i.status === "inProgress").length;
  const criticalHighCount = incidents.filter((i) => (i.severity === "critical" || i.severity === "high") && i.status !== "resolved").length;
  const impactedUsersCount = new Set(
    incidents.filter((i) => i.status !== "resolved").flatMap((i) => i.impactedUsers.map((u) => u.userPrincipalName.toLowerCase()))
  ).size;
  const isolatedDevicesCount = snapshot.intune.devices.filter((d: any) => d.isIsolated).length;

  const handleUpdateStatus = async (incidentId: string, newStatus: IncidentStatus) => {
    try {
      await fetch(`/api/tenants/${snapshot.tenant.id}/incident-response/incidents/${incidentId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (selectedIncident && (selectedIncident.id === incidentId || selectedIncident.incidentId === incidentId)) {
        setSelectedIncident({ ...selectedIncident, status: newStatus });
      }
      if (onLocalRefresh) onLocalRefresh();
    } catch (err) {
      console.error("Failed to update incident status", err);
    }
  };

  const handleExportCSV = () => {
    const headers = ["Incident ID", "Title", "Severity", "Status", "Created Date", "Impacted Users", "Impacted Devices", "MITRE Tactics", "Description"];
    const rows = filteredIncidents.map((i) => [
      i.incidentId,
      i.displayName,
      i.severity.toUpperCase(),
      i.status.toUpperCase(),
      i.createdDateTime,
      i.impactedUsers.map((u) => u.userPrincipalName).join("; "),
      i.impactedDevices.map((d) => d.deviceName).join("; "),
      i.mitreTechniques.join("; "),
      i.description,
    ]);
    exportToCsv(`Clarity365_Incidents_${snapshot.tenant.defaultDomainName}_${new Date().toISOString().split("T")[0]}.csv`, headers, rows);
  };

  const handleCopyReport = async () => {
    if (!selectedIncident) return;
    const reportText = `[CLARITY365 INCIDENT TRIAGE REPORT]
Tenant: ${snapshot.tenant.displayName} (${snapshot.tenant.defaultDomainName})
Incident: #${selectedIncident.incidentId} - ${selectedIncident.displayName}
Severity: ${selectedIncident.severity.toUpperCase()} | Status: ${selectedIncident.status.toUpperCase()}
Created: ${new Date(selectedIncident.createdDateTime).toLocaleString()}
MITRE ATT&CK: ${selectedIncident.mitreTechniques.join(", ") || "None"}

Impacted Users:
${selectedIncident.impactedUsers.map((u) => `- ${u.displayName} (${u.userPrincipalName})`).join("\n") || "- None recorded"}

Impacted Endpoints:
${selectedIncident.impactedDevices.map((d) => `- ${d.deviceName} (${d.operatingSystem || "Unknown OS"}) [Isolated: ${d.isIsolated ? "YES" : "NO"}]`).join("\n") || "- None recorded"}

Summary:
${selectedIncident.description}

Recommended Containment Actions:
${selectedIncident.recommendedActions.map((a, i) => `${i + 1}. ${a}`).join("\n")}`;

    await navigator.clipboard.writeText(reportText);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Flame size={18} className="text-red-600 dark:text-red-400" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Module 8.6: Security Operations & Event Response Center
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Real-time incident triage and automated containment across Microsoft Defender XDR, Entra ID, and Exchange Online.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCSV}
            className="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-sm inline-flex items-center gap-1.5 transition-colors shadow-xs"
          >
            <FileText size={13} />
            <span>Export Incident Log</span>
          </button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold flex items-center gap-1">
            <ShieldAlert size={12} />
            <span>Active Incidents</span>
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">
            {activeCount}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Requiring analyst investigation</div>
        </div>

        <div className={`p-3 border rounded-sm ${criticalHighCount > 0 ? "bg-red-50/80 dark:bg-red-950/60 border-red-300 dark:border-red-800" : "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700"}`}>
          <div className={`text-[10px] uppercase font-mono font-semibold flex items-center gap-1 ${criticalHighCount > 0 ? "text-red-700 dark:text-red-400" : "text-slate-500 dark:text-slate-400"}`}>
            <Flame size={12} className={criticalHighCount > 0 ? "animate-pulse text-red-600" : ""} />
            <span>Critical & High Severity</span>
          </div>
          <div className={`text-xl font-bold font-mono tabular-nums mt-0.5 ${criticalHighCount > 0 ? "text-red-900 dark:text-red-200" : "text-slate-900 dark:text-slate-100"}`}>
            {criticalHighCount}
          </div>
          <div className={`text-[11px] mt-0.5 ${criticalHighCount > 0 ? "text-red-700 dark:text-red-400" : "text-slate-500 dark:text-slate-400"}`}>Immediate containment priority</div>
        </div>

        <div className="p-3 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold flex items-center gap-1">
            <UserX size={12} />
            <span>Impacted Accounts</span>
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">
            {impactedUsersCount}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Users with active threat alerts</div>
        </div>

        <div className="p-3 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold flex items-center gap-1">
            <Radio size={12} />
            <span>Isolated Endpoints</span>
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">
            {isolatedDevicesCount}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Contained via Defender for Endpoint</div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Search title, incident ID, user, device..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500 dark:text-slate-400" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="inProgress">In Progress</option>
            <option value="resolved">Resolved</option>
          </select>

          <select
            value={mitreFilter}
            onChange={(e) => setMitreFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
          >
            <option value="all">All MITRE Tactics</option>
            <option value="T1566">T1566: Phishing</option>
            <option value="T1114">T1114: Email Collection</option>
            <option value="T1059">T1059: Command & Scripting</option>
            <option value="T1528">T1528: Steal Token</option>
            <option value="T1078">T1078: Valid Accounts</option>
            <option value="T1110">T1110: Brute Force</option>
          </select>
        </div>
      </div>

      {/* Incident Queue Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 text-slate-700 dark:text-slate-300 font-semibold uppercase text-[10px] tracking-wider">
              <tr>
                <th className="p-3 w-28">Severity</th>
                <th className="p-3 w-24">Incident ID</th>
                <th className="p-3 min-w-[260px]">Threat Title & MITRE Tactics</th>
                <th className="p-3 w-56">Impacted Entities</th>
                <th className="p-3 w-32">Status</th>
                <th className="p-3 w-32">Detected</th>
                <th className="p-3 w-48 text-right">Containment Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] dark:divide-slate-700">
              {paginatedIncidents.length === 0 ? (
                <EmptyStateRow
                  colSpan={7}
                  entityLabel="security incidents"
                  isFiltered={Boolean(searchQuery || severityFilter !== "all" || statusFilter !== "all" || mitreFilter !== "all")}
                />
              ) : (
                paginatedIncidents.map((inc) => (
                  <tr
                    key={inc.id}
                    className="hover:bg-slate-50/80 dark:hover:bg-slate-700/50 cursor-pointer transition-colors"
                    onClick={() => setSelectedIncident(inc)}
                  >
                    {/* Severity Pill */}
                    <td className="p-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${SEVERITY_COLORS[inc.severity]}`}>
                        {inc.severity === "critical" && <span className="w-1.5 h-1.5 rounded-full bg-red-600 animate-ping" />}
                        {inc.severity}
                      </span>
                    </td>

                    {/* Incident ID */}
                    <td className="p-3 font-mono text-[11px] font-bold text-slate-700 dark:text-slate-300">
                      #{inc.incidentId}
                    </td>

                    {/* Threat Title & MITRE */}
                    <td className="p-3 space-y-1">
                      <div className="font-semibold text-slate-900 dark:text-slate-100 text-xs flex items-center gap-1.5">
                        <span>{inc.displayName}</span>
                      </div>
                      {inc.mitreTechniques.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {inc.mitreTechniques.map((m, idx) => (
                            <span
                              key={idx}
                              className="px-1.5 py-0.2 bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 text-[9px] font-mono rounded border border-slate-200 dark:border-slate-600"
                            >
                              {m}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>

                    {/* Impacted Entities */}
                    <td className="p-3 space-y-1 text-[11px]">
                      {inc.impactedUsers.length > 0 && (
                        <div className="flex items-center gap-1 text-slate-700 dark:text-slate-300 truncate">
                          <User size={12} className="text-slate-400 shrink-0" />
                          <span className="truncate" title={inc.impactedUsers.map((u) => u.userPrincipalName).join(", ")}>
                            {inc.impactedUsers[0].displayName || inc.impactedUsers[0].userPrincipalName}
                            {inc.impactedUsers.length > 1 && ` +${inc.impactedUsers.length - 1}`}
                          </span>
                        </div>
                      )}
                      {inc.impactedDevices.length > 0 && (
                        <div className="flex items-center gap-1 text-slate-600 dark:text-slate-400 truncate">
                          <Laptop size={12} className="text-slate-400 shrink-0" />
                          <span className="truncate" title={inc.impactedDevices.map((d) => d.deviceName).join(", ")}>
                            {inc.impactedDevices[0].deviceName}
                            {inc.impactedDevices[0].isIsolated && (
                              <span className="ml-1 text-[9px] text-red-600 dark:text-red-400 font-semibold">[ISOLATED]</span>
                            )}
                          </span>
                        </div>
                      )}
                      {inc.impactedUsers.length === 0 && inc.impactedDevices.length === 0 && (
                        <span className="text-slate-400 dark:text-slate-500 italic text-[11px]">Tenant-wide policy event</span>
                      )}
                    </td>

                    {/* Status */}
                    <td className="p-3">
                      <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${
                        inc.status === "active"
                          ? "bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-300"
                          : inc.status === "inProgress"
                          ? "bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300"
                          : "bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300"
                      }`}>
                        {inc.status === "inProgress" ? "In Progress" : inc.status.toUpperCase()}
                      </span>
                    </td>

                    {/* Detected Timestamp */}
                    <td className="p-3 text-[11px] font-mono text-slate-500 dark:text-slate-400">
                      {new Date(inc.createdDateTime).toLocaleDateString()}
                    </td>

                    {/* Containment Actions */}
                    <td className="p-3 text-right space-x-1.5" onClick={(e) => e.stopPropagation()}>
                      {inc.impactedUsers.length > 0 && (
                        <button
                          onClick={() => setContainmentTarget({ upn: inc.impactedUsers[0].userPrincipalName, id: inc.impactedUsers[0].id })}
                          title="Launch emergency account containment playbook"
                          className="px-2 py-1 text-[10px] font-semibold text-white bg-red-600 hover:bg-red-700 rounded-sm inline-flex items-center gap-1 shadow-xs"
                        >
                          <UserX size={11} />
                          <span>Contain User</span>
                        </button>
                      )}
                      {inc.impactedDevices.length > 0 && (
                        <button
                          onClick={() => setIsolationTarget({ deviceId: inc.impactedDevices[0].id || inc.impactedDevices[0].deviceName, deviceName: inc.impactedDevices[0].deviceName })}
                          title="Isolate device from network"
                          className="px-2 py-1 text-[10px] font-semibold text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-sm inline-flex items-center gap-1 border border-slate-300 dark:border-slate-600"
                        >
                          <Radio size={11} />
                          <span>Isolate</span>
                        </button>
                      )}
                      <button
                        onClick={() => setSelectedIncident(inc)}
                        className="px-2 py-1 text-[10px] font-semibold text-slate-900 dark:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-sm inline-flex items-center gap-1 border border-slate-300 dark:border-slate-600"
                      >
                        <span>Triage</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <Pagination
          page={page}
          totalItems={filteredIncidents.length}
          pageSize={PAGE_SIZE}
          onPageChange={setPage}
        />
      </div>

      {/* Incident Detail Drawer */}
      {selectedIncident && (
        <Drawer
          isOpen={!!selectedIncident}
          onClose={() => setSelectedIncident(null)}
          title={`Incident #${selectedIncident.incidentId}: ${selectedIncident.displayName}`}
          subtitle={`Threat Investigation & Response | ${snapshot.tenant.displayName}`}
          width="2xl"
        >
          <div className="space-y-5">
            {/* Status & Severity Bar */}
            <div className="p-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-sm flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold uppercase border ${SEVERITY_COLORS[selectedIncident.severity]}`}>
                  {selectedIncident.severity.toUpperCase()}
                </span>
                <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  Status: <strong className="text-slate-900 dark:text-slate-100 uppercase">{selectedIncident.status}</strong>
                </span>
              </div>

              <div className="flex items-center gap-2">
                {selectedIncident.status !== "resolved" ? (
                  <button
                    onClick={() => handleUpdateStatus(selectedIncident.id, "resolved")}
                    className="px-2.5 py-1 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-sm inline-flex items-center gap-1"
                  >
                    <CheckCircle2 size={12} />
                    <span>Mark Resolved</span>
                  </button>
                ) : (
                  <button
                    onClick={() => handleUpdateStatus(selectedIncident.id, "active")}
                    className="px-2.5 py-1 text-xs font-semibold text-slate-700 dark:text-slate-300 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 rounded-sm inline-flex items-center gap-1"
                  >
                    <RefreshCw size={12} />
                    <span>Reopen Incident</span>
                  </button>
                )}

                <button
                  onClick={handleCopyReport}
                  className="px-2.5 py-1 text-xs font-semibold text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-sm inline-flex items-center gap-1"
                >
                  {copiedReport ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                  <span>{copiedReport ? "Copied" : "Copy Report"}</span>
                </button>
              </div>
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <div className="text-[11px] font-semibold uppercase text-slate-500 dark:text-slate-400 font-mono">
                Threat Description & Analysis
              </div>
              <p className="text-xs text-slate-800 dark:text-slate-200 leading-relaxed bg-white dark:bg-slate-800 p-3 border border-slate-200 dark:border-slate-700 rounded-sm">
                {selectedIncident.description}
              </p>
            </div>

            {/* MITRE ATT&CK Matrix Techniques */}
            {selectedIncident.mitreTechniques.length > 0 && (
              <div className="space-y-1.5">
                <div className="text-[11px] font-semibold uppercase text-slate-500 dark:text-slate-400 font-mono">
                  MITRE ATT&CK Alignment
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {selectedIncident.mitreTechniques.map((m, i) => (
                    <span
                      key={i}
                      className="px-2.5 py-1 text-xs font-mono bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 rounded-sm"
                    >
                      {m}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Impacted Entities Graph */}
            <div className="space-y-2">
              <div className="text-[11px] font-semibold uppercase text-slate-500 dark:text-slate-400 font-mono">
                Impacted Security Entities ({selectedIncident.impactedUsers.length + selectedIncident.impactedDevices.length})
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {selectedIncident.impactedUsers.map((u, i) => (
                  <div
                    key={i}
                    className="p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm flex items-center justify-between gap-2"
                  >
                    <div className="flex items-center gap-2 truncate">
                      <User className="w-4 h-4 text-slate-400 shrink-0" />
                      <div className="truncate">
                        <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">{u.displayName}</div>
                        <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate">{u.userPrincipalName}</div>
                      </div>
                    </div>
                    <button
                      onClick={() => setContainmentTarget({ upn: u.userPrincipalName, id: u.id })}
                      className="px-2 py-1 text-[10px] font-semibold text-white bg-red-600 hover:bg-red-700 rounded shrink-0 flex items-center gap-1"
                    >
                      <UserX size={11} />
                      <span>Contain</span>
                    </button>
                  </div>
                ))}

                {selectedIncident.impactedDevices.map((d, i) => (
                  <div
                    key={i}
                    className="p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm flex items-center justify-between gap-2"
                  >
                    <div className="flex items-center gap-2 truncate">
                      <Laptop className="w-4 h-4 text-slate-400 shrink-0" />
                      <div className="truncate">
                        <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">{d.deviceName}</div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                          {d.operatingSystem || "Windows Endpoint"} {d.isIsolated && <span className="text-red-500 font-bold">[ISOLATED]</span>}
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => setIsolationTarget({ deviceId: d.id || d.deviceName, deviceName: d.deviceName })}
                      className="px-2 py-1 text-[10px] font-semibold text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded shrink-0 border border-slate-300 dark:border-slate-600 flex items-center gap-1"
                    >
                      <Radio size={11} />
                      <span>Isolate</span>
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommended Containment Checklist */}
            <div className="space-y-2">
              <div className="text-[11px] font-semibold uppercase text-slate-500 dark:text-slate-400 font-mono flex items-center gap-1.5">
                <ShieldCheck size={13} className="text-emerald-500" />
                <span>Recommended Containment Playbook</span>
              </div>

              <div className="space-y-1.5 border border-slate-200 dark:border-slate-700 p-3 rounded-sm bg-white dark:bg-slate-800">
                {selectedIncident.recommendedActions.map((action, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-xs text-slate-800 dark:text-slate-200">
                    <span className="font-mono text-slate-400 shrink-0">{idx + 1}.</span>
                    <span className="leading-snug">{action}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Drawer>
      )}

      {/* Compromised Account Modal */}
      {containmentTarget && (
        <CompromisedAccountModal
          isOpen={!!containmentTarget}
          onClose={() => setContainmentTarget(null)}
          tenantId={snapshot.tenant.id}
          tenantName={snapshot.tenant.displayName}
          targetUserUPN={containmentTarget.upn}
          targetUserId={containmentTarget.id}
          onSuccess={onLocalRefresh}
        />
      )}

      {/* Device Isolation Modal */}
      {isolationTarget && (
        <DeviceIsolationModal
          isOpen={!!isolationTarget}
          onClose={() => setIsolationTarget(null)}
          tenantId={snapshot.tenant.id}
          tenantName={snapshot.tenant.displayName}
          deviceId={isolationTarget.deviceId}
          deviceName={isolationTarget.deviceName}
          onSuccess={onLocalRefresh}
        />
      )}
    </div>
  );
};
