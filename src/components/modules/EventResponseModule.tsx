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
  UserCheck,
  Radio,
  Wifi,
  WifiOff,
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
  ChevronDown,
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
  const [statusFilter, setStatusFilter] = useState<string>("open"); // Default to open (Active + In Progress)
  const [mitreFilter, setMitreFilter] = useState<string>("all");
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncidentItem | null>(null);

  // Containment & Restoration Modals State
  const [containmentTarget, setContainmentTarget] = useState<{ upn: string; id?: string; mode?: "contain" | "restore" } | null>(null);
  const [isolationTarget, setIsolationTarget] = useState<{ deviceId: string; deviceName: string; isCurrentlyIsolated?: boolean } | null>(null);
  const [copiedReport, setCopiedReport] = useState(false);

  // Pagination
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 15;

  // Helper to check if a user is currently disabled in snapshot
  const isUserDisabled = (upn: string) => {
    const user = snapshot.accountClassification.users.find((u) => u.userPrincipalName.toLowerCase() === upn.toLowerCase());
    return user ? user.accountEnabled === false : false;
  };

  // Helper to check if a device is currently isolated in snapshot
  const isDeviceIsolated = (deviceName: string, deviceId?: string) => {
    const dev = snapshot.intune.devices.find((d: any) => d.id === deviceId || d.deviceName.toLowerCase() === deviceName.toLowerCase());
    return dev ? Boolean((dev as any).isIsolated) : false;
  };

  // Helper to evaluate if a resolved incident has unresolved underlying risk
  const checkPersistentRisk = (inc: SecurityIncidentItem) => {
    const hasActiveForwarding = inc.impactedUsers.some((u) =>
      snapshot.emailForwarding.some(
        (f) => f.mailboxOwner?.toLowerCase() === u.userPrincipalName.toLowerCase() && f.state === "Enabled" && f.isExternal
      )
    );
    const hasNonCompliantDevice = inc.impactedDevices.some((d) =>
      snapshot.intune.devices.some(
        (dev) => (dev.id === d.id || dev.deviceName.toLowerCase() === d.deviceName.toLowerCase()) && dev.complianceState === "noncompliant"
      )
    );
    return {
      hasRisk: hasActiveForwarding || hasNonCompliantDevice,
      reason: hasActiveForwarding
        ? "Active external email forwarding rule still enabled"
        : hasNonCompliantDevice
        ? "Impacted device remains non-compliant in Intune"
        : null,
    };
  };

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
      
      // Status Filter logic: 'open' shows active + inProgress; 'all' shows everything
      if (statusFilter === "open" && inc.status === "resolved") return false;
      if (statusFilter !== "all" && statusFilter !== "open" && inc.status !== statusFilter) return false;

      if (mitreFilter !== "all" && !inc.mitreTechniques.some((m) => m.includes(mitreFilter))) return false;

      return true;
    });
  }, [incidents, searchQuery, severityFilter, statusFilter, mitreFilter]);

  const paginatedIncidents = useMemo(() => {
    return filteredIncidents.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  }, [filteredIncidents, page]);

  // Aggregate Metrics
  const activeCount = incidents.filter((i) => i.status === "active").length;
  const inProgressCount = incidents.filter((i) => i.status === "inProgress").length;
  const resolvedCount = incidents.filter((i) => i.status === "resolved").length;
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
${selectedIncident.impactedUsers.map((u) => `- ${u.displayName} (${u.userPrincipalName}) [Disabled: ${isUserDisabled(u.userPrincipalName) ? "YES" : "NO"}]`).join("\n") || "- None recorded"}

Impacted Endpoints:
${selectedIncident.impactedDevices.map((d) => `- ${d.deviceName} (${d.operatingSystem || "Windows"}) [Isolated: ${isDeviceIsolated(d.deviceName, d.id) ? "YES" : "NO"}]`).join("\n") || "- None recorded"}

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
            Real-time incident triage, automated emergency playbooks, and entity lifecycle containment.
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
        <div
          onClick={() => setStatusFilter("open")}
          className={`p-3 border rounded-sm cursor-pointer transition-all ${statusFilter === "open" ? "ring-2 ring-slate-800 dark:ring-slate-400" : ""} bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700`}
        >
          <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold flex items-center justify-between">
            <div className="flex items-center gap-1">
              <ShieldAlert size={12} />
              <span>Open Incidents</span>
            </div>
            <span className="text-[9px] px-1.5 py-0.2 bg-slate-100 dark:bg-slate-700 rounded font-normal">Active + Investigating</span>
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">
            {activeCount + inProgressCount}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            {activeCount} Active • {inProgressCount} In Progress
          </div>
        </div>

        <div
          onClick={() => { setStatusFilter("open"); setSeverityFilter("critical"); }}
          className={`p-3 border rounded-sm cursor-pointer transition-all ${criticalHighCount > 0 ? "bg-red-50/80 dark:bg-red-950/60 border-red-300 dark:border-red-800" : "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700"}`}
        >
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
          <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold flex items-center justify-between">
            <div className="flex items-center gap-1">
              <Radio size={12} />
              <span>Isolated Endpoints</span>
            </div>
            <span className="text-[9px] text-slate-500">{resolvedCount} Resolved</span>
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
          
          {/* Status Filter (Supports All Open, All, Active, In Progress, Resolved) */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-semibold"
          >
            <option value="open">⚡ All Open (Active + In Progress)</option>
            <option value="all">🌐 All Statuses (Including Resolved)</option>
            <option value="active">🔴 Active Only</option>
            <option value="inProgress">🟡 In Progress Only</option>
            <option value="resolved">🟢 Resolved Only</option>
          </select>

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
                <th className="p-3 w-36">Status</th>
                <th className="p-3 w-28">Detected</th>
                <th className="p-3 w-56 text-right">Response Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] dark:divide-slate-700">
              {paginatedIncidents.length === 0 ? (
                <EmptyStateRow
                  colSpan={7}
                  entityLabel="security incidents"
                  isFiltered={Boolean(searchQuery || severityFilter !== "all" || statusFilter !== "open" || mitreFilter !== "all")}
                />
              ) : (
                paginatedIncidents.map((inc) => {
                  const persistentRisk = checkPersistentRisk(inc);
                  return (
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
                        <div className="flex flex-wrap items-center gap-1">
                          {inc.mitreTechniques.map((m, idx) => (
                            <span
                              key={idx}
                              className="px-1.5 py-0.2 bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 text-[9px] font-mono rounded border border-slate-200 dark:border-slate-600"
                            >
                              {m}
                            </span>
                          ))}
                          {inc.status === "resolved" && persistentRisk.hasRisk && (
                            <span
                              title={persistentRisk.reason || "Underlying threat configuration still active in tenant"}
                              className="px-1.5 py-0.2 bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 text-[9px] font-semibold rounded border border-amber-300 dark:border-amber-700 flex items-center gap-1"
                            >
                              <AlertTriangle size={10} />
                              <span>Risk Still Present</span>
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Impacted Entities */}
                      <td className="p-3 space-y-1 text-[11px]">
                        {inc.impactedUsers.length > 0 && (
                          <div className="flex items-center gap-1 text-slate-700 dark:text-slate-300 truncate">
                            <User size={12} className="text-slate-400 shrink-0" />
                            <span className="truncate" title={inc.impactedUsers.map((u) => u.userPrincipalName).join(", ")}>
                              {inc.impactedUsers[0].displayName || inc.impactedUsers[0].userPrincipalName}
                              {isUserDisabled(inc.impactedUsers[0].userPrincipalName) && (
                                <span className="ml-1 text-[9px] text-amber-600 dark:text-amber-400 font-semibold">[CONTAINED]</span>
                              )}
                              {inc.impactedUsers.length > 1 && ` +${inc.impactedUsers.length - 1}`}
                            </span>
                          </div>
                        )}
                        {inc.impactedDevices.length > 0 && (
                          <div className="flex items-center gap-1 text-slate-600 dark:text-slate-400 truncate">
                            <Laptop size={12} className="text-slate-400 shrink-0" />
                            <span className="truncate" title={inc.impactedDevices.map((d) => d.deviceName).join(", ")}>
                              {inc.impactedDevices[0].deviceName}
                              {isDeviceIsolated(inc.impactedDevices[0].deviceName, inc.impactedDevices[0].id) && (
                                <span className="ml-1 text-[9px] text-red-600 dark:text-red-400 font-semibold">[ISOLATED]</span>
                              )}
                            </span>
                          </div>
                        )}
                        {inc.impactedUsers.length === 0 && inc.impactedDevices.length === 0 && (
                          <span className="text-slate-400 dark:text-slate-500 italic text-[11px]">Tenant-wide policy event</span>
                        )}
                      </td>

                      {/* Status Dropdown Selector */}
                      <td className="p-3" onClick={(e) => e.stopPropagation()}>
                        <select
                          value={inc.status}
                          onChange={(e) => handleUpdateStatus(inc.id, e.target.value as IncidentStatus)}
                          className={`text-[10px] font-semibold px-2 py-1 rounded border focus:outline-none cursor-pointer transition-colors ${
                            inc.status === "active"
                              ? "bg-red-50 dark:bg-red-950 text-red-800 dark:text-red-300 border-red-300 dark:border-red-800"
                              : inc.status === "inProgress"
                              ? "bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800"
                              : "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800"
                          }`}
                        >
                          <option value="active">🔴 Active</option>
                          <option value="inProgress">🟡 In Progress</option>
                          <option value="resolved">🟢 Resolved</option>
                          <option value="redirected">⚪ Redirected</option>
                        </select>
                      </td>

                      {/* Detected Timestamp */}
                      <td className="p-3 text-[11px] font-mono text-slate-500 dark:text-slate-400">
                        {new Date(inc.createdDateTime).toLocaleDateString()}
                      </td>

                      {/* Containment Actions */}
                      <td className="p-3 text-right space-x-1.5" onClick={(e) => e.stopPropagation()}>
                        {inc.impactedUsers.length > 0 && (
                          isUserDisabled(inc.impactedUsers[0].userPrincipalName) ? (
                            <button
                              onClick={() => setContainmentTarget({ upn: inc.impactedUsers[0].userPrincipalName, id: inc.impactedUsers[0].id, mode: "restore" })}
                              title="Re-enable and restore user account in Entra ID"
                              className="px-2 py-1 text-[10px] font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded-sm inline-flex items-center gap-1 shadow-xs"
                            >
                              <UserCheck size={11} />
                              <span>Restore</span>
                            </button>
                          ) : (
                            <button
                              onClick={() => setContainmentTarget({ upn: inc.impactedUsers[0].userPrincipalName, id: inc.impactedUsers[0].id, mode: "contain" })}
                              title="Launch emergency account containment playbook"
                              className="px-2 py-1 text-[10px] font-semibold text-white bg-red-600 hover:bg-red-700 rounded-sm inline-flex items-center gap-1 shadow-xs"
                            >
                              <UserX size={11} />
                              <span>Contain User</span>
                            </button>
                          )
                        )}
                        {inc.impactedDevices.length > 0 && (
                          isDeviceIsolated(inc.impactedDevices[0].deviceName, inc.impactedDevices[0].id) ? (
                            <button
                              onClick={() => setIsolationTarget({ deviceId: inc.impactedDevices[0].id || inc.impactedDevices[0].deviceName, deviceName: inc.impactedDevices[0].deviceName, isCurrentlyIsolated: true })}
                              title="Release device from network isolation"
                              className="px-2 py-1 text-[10px] font-semibold text-emerald-800 dark:text-emerald-200 bg-emerald-50 dark:bg-emerald-950/60 hover:bg-emerald-100 rounded-sm inline-flex items-center gap-1 border border-emerald-300 dark:border-emerald-700"
                            >
                              <Wifi size={11} />
                              <span>Release</span>
                            </button>
                          ) : (
                            <button
                              onClick={() => setIsolationTarget({ deviceId: inc.impactedDevices[0].id || inc.impactedDevices[0].deviceName, deviceName: inc.impactedDevices[0].deviceName, isCurrentlyIsolated: false })}
                              title="Isolate device from network"
                              className="px-2 py-1 text-[10px] font-semibold text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-sm inline-flex items-center gap-1 border border-slate-300 dark:border-slate-600"
                            >
                              <WifiOff size={11} />
                              <span>Isolate</span>
                            </button>
                          )
                        )}
                        <button
                          onClick={() => setSelectedIncident(inc)}
                          className="px-2 py-1 text-[10px] font-semibold text-slate-900 dark:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-sm inline-flex items-center gap-1 border border-slate-300 dark:border-slate-600"
                        >
                          <span>Triage</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
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
            {/* Status & Severity Bar with Full Status Selector */}
            <div className="p-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold uppercase border ${SEVERITY_COLORS[selectedIncident.severity]}`}>
                  {selectedIncident.severity.toUpperCase()}
                </span>

                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300">
                  <span>Lifecycle Status:</span>
                  <select
                    value={selectedIncident.status}
                    onChange={(e) => handleUpdateStatus(selectedIncident.id, e.target.value as IncidentStatus)}
                    className="px-2 py-0.5 text-xs font-semibold rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none"
                  >
                    <option value="active">🔴 Active</option>
                    <option value="inProgress">🟡 In Progress</option>
                    <option value="resolved">🟢 Resolved</option>
                    <option value="redirected">⚪ Redirected</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyReport}
                  className="px-2.5 py-1 text-xs font-semibold text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-sm inline-flex items-center gap-1"
                >
                  {copiedReport ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                  <span>{copiedReport ? "Copied" : "Copy Report"}</span>
                </button>
              </div>
            </div>

            {/* Persistent Risk Alert if Resolved */}
            {selectedIncident.status === "resolved" && checkPersistentRisk(selectedIncident).hasRisk && (
              <div className="p-3 bg-amber-50 dark:bg-amber-950/60 border border-amber-300 dark:border-amber-700 text-amber-950 dark:text-amber-200 rounded-sm flex items-start justify-between gap-3">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                  <div className="text-xs space-y-0.5">
                    <div className="font-bold">Underlying Threat Signal Remains Active</div>
                    <p className="text-[11px] text-amber-800 dark:text-amber-300">
                      {checkPersistentRisk(selectedIncident).reason}. The incident is marked resolved, but configuration risks are still detected.
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => handleUpdateStatus(selectedIncident.id, "active")}
                  className="px-2.5 py-1 bg-amber-700 hover:bg-amber-800 text-white text-xs font-semibold rounded-sm shrink-0 shadow-xs"
                >
                  Reopen Incident
                </button>
              </div>
            )}

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
                {selectedIncident.impactedUsers.map((u, i) => {
                  const disabled = isUserDisabled(u.userPrincipalName);
                  return (
                    <div
                      key={i}
                      className="p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm flex items-center justify-between gap-2"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <User className="w-4 h-4 text-slate-400 shrink-0" />
                        <div className="truncate">
                          <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate flex items-center gap-1.5">
                            <span>{u.displayName}</span>
                            {disabled && (
                              <span className="text-[9px] px-1 py-0.2 bg-amber-100 text-amber-800 rounded font-semibold">Disabled</span>
                            )}
                          </div>
                          <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate">{u.userPrincipalName}</div>
                        </div>
                      </div>
                      {disabled ? (
                        <button
                          onClick={() => setContainmentTarget({ upn: u.userPrincipalName, id: u.id, mode: "restore" })}
                          className="px-2 py-1 text-[10px] font-semibold text-white bg-emerald-600 hover:bg-emerald-700 rounded shrink-0 flex items-center gap-1 shadow-xs"
                        >
                          <UserCheck size={11} />
                          <span>Restore</span>
                        </button>
                      ) : (
                        <button
                          onClick={() => setContainmentTarget({ upn: u.userPrincipalName, id: u.id, mode: "contain" })}
                          className="px-2 py-1 text-[10px] font-semibold text-white bg-red-600 hover:bg-red-700 rounded shrink-0 flex items-center gap-1 shadow-xs"
                        >
                          <UserX size={11} />
                          <span>Contain</span>
                        </button>
                      )}
                    </div>
                  );
                })}

                {selectedIncident.impactedDevices.map((d, i) => {
                  const isolated = isDeviceIsolated(d.deviceName, d.id);
                  return (
                    <div
                      key={i}
                      className="p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm flex items-center justify-between gap-2"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <Laptop className="w-4 h-4 text-slate-400 shrink-0" />
                        <div className="truncate">
                          <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate flex items-center gap-1.5">
                            <span>{d.deviceName}</span>
                            {isolated && (
                              <span className="text-[9px] px-1 py-0.2 bg-red-100 text-red-800 rounded font-semibold">Isolated</span>
                            )}
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                            {d.operatingSystem || "Windows Endpoint"}
                          </div>
                        </div>
                      </div>
                      {isolated ? (
                        <button
                          onClick={() => setIsolationTarget({ deviceId: d.id || d.deviceName, deviceName: d.deviceName, isCurrentlyIsolated: true })}
                          className="px-2 py-1 text-[10px] font-semibold text-emerald-800 dark:text-emerald-200 bg-emerald-50 dark:bg-emerald-950/60 hover:bg-emerald-100 rounded shrink-0 border border-emerald-300 dark:border-emerald-700 flex items-center gap-1 shadow-xs"
                        >
                          <Wifi size={11} />
                          <span>Release</span>
                        </button>
                      ) : (
                        <button
                          onClick={() => setIsolationTarget({ deviceId: d.id || d.deviceName, deviceName: d.deviceName, isCurrentlyIsolated: false })}
                          className="px-2 py-1 text-[10px] font-semibold text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded shrink-0 border border-slate-300 dark:border-slate-600 flex items-center gap-1 shadow-xs"
                        >
                          <WifiOff size={11} />
                          <span>Isolate</span>
                        </button>
                      )}
                    </div>
                  );
                })}
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
          initialMode={containmentTarget.mode || "contain"}
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
          isCurrentlyIsolated={isolationTarget.isCurrentlyIsolated}
          onSuccess={onLocalRefresh}
        />
      )}
    </div>
  );
};
