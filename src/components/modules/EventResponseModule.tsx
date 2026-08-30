import React, { useState, useMemo, useEffect, useRef } from "react";
import {
  TenantSecuritySnapshot,
  SecurityIncidentItem,
  IncidentSeverity,
  IncidentStatus,
  Tenant,
} from "@/lib/types";
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
  Building2,
  ChevronRight,
} from "lucide-react";
import { exportToCsv } from "@/lib/utils/csv";

export type CrossTenantIncidentItem = SecurityIncidentItem & {
  tenantId?: string;
  tenantName?: string;
};

interface EventResponseModuleProps {
  snapshot?: TenantSecuritySnapshot | null;
  isFleetMode?: boolean;
  fleetIncidents?: CrossTenantIncidentItem[];
  tenants?: Tenant[];
  onLocalRefresh?: () => void;
  highlightEntityId?: string | null;
  onClearHighlight?: () => void;
  onSelectTenant?: (tenantId: string, targetModule?: string, targetEntityId?: string) => void;
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
  isFleetMode = false,
  fleetIncidents = [],
  tenants = [],
  onLocalRefresh,
  highlightEntityId,
  onClearHighlight,
  onSelectTenant,
}) => {
  const incidents: CrossTenantIncidentItem[] = useMemo(() => {
    if (isFleetMode) {
      return fleetIncidents;
    }
    return (snapshot?.incidents || []).map((inc) => ({
      ...inc,
      tenantId: snapshot?.tenant?.id,
      tenantName: snapshot?.tenant?.displayName,
    }));
  }, [isFleetMode, fleetIncidents, snapshot?.incidents, snapshot?.tenant]);

  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("open");
  const [mitreFilter, setMitreFilter] = useState<string>("all");
  const [tenantFilter, setTenantFilter] = useState<string>("all");
  const [selectedIncident, setSelectedIncident] = useState<CrossTenantIncidentItem | null>(null);

  // Containment & Restoration Modals State
  const [containmentTarget, setContainmentTarget] = useState<{
    upn: string;
    id?: string;
    mode?: "contain" | "restore";
    tenantId?: string;
  } | null>(null);
  const [isolationTarget, setIsolationTarget] = useState<{
    deviceId: string;
    deviceName: string;
    isCurrentlyIsolated?: boolean;
    tenantId?: string;
  } | null>(null);
  const [copiedReport, setCopiedReport] = useState(false);

  // Pagination
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 15;

  // Highlighting ref
  const highlightedRowRef = useRef<HTMLTableRowElement | null>(null);

  useEffect(() => {
    if (highlightEntityId && highlightedRowRef.current) {
      highlightedRowRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [highlightEntityId, incidents]);

  // Helper to check if a user is currently disabled
  const isUserDisabled = (upn: string) => {
    if (!snapshot) return false;
    const user = snapshot.accountClassification.users.find(
      (u) => u.userPrincipalName.toLowerCase() === upn.toLowerCase()
    );
    return user ? user.accountEnabled === false : false;
  };

  // Helper to check if a device is currently isolated
  const isDeviceIsolated = (deviceName: string, deviceId?: string) => {
    if (!snapshot) return false;
    const dev = snapshot.intune.devices.find(
      (d: any) => d.id === deviceId || d.deviceName.toLowerCase() === deviceName.toLowerCase()
    );
    return dev ? Boolean((dev as any).isIsolated) : false;
  };

  // Helper to evaluate persistent risk
  const checkPersistentRisk = (inc: CrossTenantIncidentItem) => {
    if (!snapshot) return { hasRisk: false, reason: null };
    const hasActiveForwarding = inc.impactedUsers.some((u) =>
      snapshot.emailForwarding.some(
        (f) =>
          f.mailboxOwner?.toLowerCase() === u.userPrincipalName.toLowerCase() &&
          f.state === "Enabled" &&
          f.isExternal
      )
    );
    const hasNonCompliantDevice = inc.impactedDevices.some((d) =>
      snapshot.intune.devices.some(
        (dev) =>
          (dev.id === d.id || dev.deviceName.toLowerCase() === d.deviceName.toLowerCase()) &&
          dev.complianceState === "noncompliant"
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
        !(inc.tenantName || "").toLowerCase().includes(q) &&
        !inc.impactedUsers.some(
          (u) =>
            u.userPrincipalName.toLowerCase().includes(q) ||
            u.displayName.toLowerCase().includes(q)
        ) &&
        !inc.impactedDevices.some((d) => d.deviceName.toLowerCase().includes(q))
      ) {
        return false;
      }

      if (severityFilter !== "all" && inc.severity !== severityFilter) return false;

      if (statusFilter === "open" && inc.status === "resolved") return false;
      if (statusFilter !== "all" && statusFilter !== "open" && inc.status !== statusFilter) return false;

      if (mitreFilter !== "all" && !inc.mitreTechniques.some((m) => m.includes(mitreFilter))) return false;

      if (isFleetMode && tenantFilter !== "all" && inc.tenantId !== tenantFilter) return false;

      return true;
    });
  }, [incidents, searchQuery, severityFilter, statusFilter, mitreFilter, tenantFilter, isFleetMode]);

  const paginatedIncidents = useMemo(() => {
    return filteredIncidents.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  }, [filteredIncidents, page]);

  // Aggregate Metrics
  const activeCount = incidents.filter((i) => i.status === "active").length;
  const inProgressCount = incidents.filter((i) => i.status === "inProgress").length;
  const resolvedCount = incidents.filter((i) => i.status === "resolved").length;
  const criticalHighCount = incidents.filter(
    (i) => (i.severity === "critical" || i.severity === "high") && i.status !== "resolved"
  ).length;

  const handleUpdateStatus = async (incident: CrossTenantIncidentItem, newStatus: IncidentStatus) => {
    const targetTenantId = incident.tenantId || snapshot?.tenant?.id;
    if (!targetTenantId) return;

    try {
      await fetch(`/api/tenants/${targetTenantId}/incident-response/incidents/${incident.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (selectedIncident && (selectedIncident.id === incident.id || selectedIncident.incidentId === incident.incidentId)) {
        setSelectedIncident({ ...selectedIncident, status: newStatus });
      }
      if (onLocalRefresh) onLocalRefresh();
    } catch (err) {
      console.error("Failed to update incident status", err);
    }
  };

  const handleExportCSV = () => {
    const headers = [
      "Tenant Name",
      "Incident ID",
      "Title",
      "Severity",
      "Status",
      "Created Date",
      "Impacted Users",
      "Impacted Devices",
      "MITRE Tactics",
      "Description",
    ];
    const rows = filteredIncidents.map((i) => [
      i.tenantName || snapshot?.tenant?.displayName || "N/A",
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
    const domain = snapshot?.tenant?.defaultDomainName || "fleet";
    exportToCsv(`Clarity365_Incidents_${domain}_${new Date().toISOString().split("T")[0]}.csv`, headers, rows);
  };

  const handleCopyReport = async () => {
    if (!selectedIncident) return;
    const tenantName = selectedIncident.tenantName || snapshot?.tenant?.displayName || "Organization";
    const reportText = `[CLARITY365 INCIDENT TRIAGE REPORT]
Tenant: ${tenantName}
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
    <div
      className="p-5 space-y-4 max-w-[1600px] mx-auto select-none"
      onClick={() => {
        if (highlightEntityId && onClearHighlight) {
          onClearHighlight();
        }
      }}
    >
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Flame size={18} className="text-red-600 dark:text-red-400" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              {isFleetMode
                ? "Cross-Tenant Security Operations & Event Response Feed"
                : `Module 8.6: Security Operations & Event Response Center — ${snapshot?.tenant?.displayName || ""}`}
            </h2>
            {isFleetMode && (
              <span className="text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 bg-indigo-100 dark:bg-indigo-950 text-indigo-800 dark:text-indigo-300 border border-indigo-300 dark:border-indigo-800 rounded-sm">
                Fleet Feed
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Real-time incident triage, automated emergency playbooks, and entity lifecycle containment across customer organizations.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCSV}
            className="px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-sm inline-flex items-center gap-1.5 transition-colors shadow-xs"
          >
            <FileText size={13} />
            <span>Export Incident Log (CSV)</span>
          </button>
        </div>
      </div>

      {/* KPI Cards (Clickable Filters) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div
          onClick={() => {
            setSeverityFilter(severityFilter === "critical" ? "all" : "critical");
            setPage(1);
          }}
          className={`p-3 rounded-sm cursor-pointer transition-all border ${
            severityFilter === "critical"
              ? "bg-red-100 dark:bg-red-950/70 border-red-500 ring-1 ring-red-500 shadow-xs"
              : "bg-red-50/50 dark:bg-red-950/20 border-red-200 dark:border-red-800/60 hover:bg-red-100/40 hover:border-red-400"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-red-700 dark:text-red-300 font-semibold uppercase tracking-wider text-[10px]">
            <span>Critical / High Incidents</span>
            <ShieldAlert size={14} />
          </div>
          <div className="text-2xl font-bold font-mono text-red-950 dark:text-red-100 mt-1">
            {criticalHighCount}
          </div>
          <div className="text-[11px] text-red-800/80 dark:text-red-300/80 mt-0.5">
            Requires immediate containment action
          </div>
        </div>

        <div
          onClick={() => {
            setStatusFilter(statusFilter === "open" ? "all" : "open");
            setPage(1);
          }}
          className={`p-3 rounded-sm cursor-pointer transition-all border ${
            statusFilter === "open"
              ? "bg-amber-100 dark:bg-amber-950/70 border-amber-500 ring-1 ring-amber-500 shadow-xs"
              : "bg-amber-50/50 dark:bg-amber-950/20 border-amber-200 dark:border-amber-800/60 hover:bg-amber-100/40 hover:border-amber-400"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-amber-700 dark:text-amber-300 font-semibold uppercase tracking-wider text-[10px]">
            <span>Active & In-Progress</span>
            <Clock size={14} />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-950 dark:text-amber-100 mt-1">
            {activeCount + inProgressCount}
          </div>
          <div className="text-[11px] text-amber-800/80 dark:text-amber-300/80 mt-0.5">
            {activeCount} active, {inProgressCount} in progress
          </div>
        </div>

        <div
          onClick={() => {
            setStatusFilter(statusFilter === "resolved" ? "all" : "resolved");
            setPage(1);
          }}
          className={`p-3 rounded-sm cursor-pointer transition-all border ${
            statusFilter === "resolved"
              ? "bg-emerald-100 dark:bg-emerald-950/70 border-emerald-500 ring-1 ring-emerald-500 shadow-xs"
              : "bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-800/60 hover:bg-emerald-100/40 hover:border-emerald-400"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-emerald-700 dark:text-emerald-300 font-semibold uppercase tracking-wider text-[10px]">
            <span>Resolved Incidents</span>
            <CheckCircle2 size={14} />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-950 dark:text-emerald-100 mt-1">
            {resolvedCount}
          </div>
          <div className="text-[11px] text-emerald-800/80 dark:text-emerald-300/80 mt-0.5">
            Remediation executed & verified
          </div>
        </div>

        <div
          onClick={() => {
            setSeverityFilter("all");
            setStatusFilter("all");
            setPage(1);
          }}
          className={`p-3 rounded-sm cursor-pointer transition-all border ${
            severityFilter === "all" && statusFilter === "all"
              ? "bg-slate-100 dark:bg-slate-800 border-slate-500 ring-1 ring-slate-400 shadow-xs"
              : "bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 hover:border-slate-400"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
            <span>Total Managed Incidents</span>
            <Flame size={14} />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100 mt-1">
            {incidents.length}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            Across {isFleetMode ? `${tenants.length || 4} tenants` : "active organization"}
          </div>
        </div>
      </div>

      {/* Incident Table Card */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 rounded-sm overflow-hidden shadow-xs">
        {/* Table Filters */}
        <div className="p-3 border-b border-[#CBD5E1] dark:border-slate-700 bg-white/70 dark:bg-slate-900/60 flex flex-col md:flex-row md:items-center justify-between gap-2.5">
          <div className="flex items-center gap-2 flex-1 max-w-md">
            <div className="relative flex-1">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search incidents, users, devices, tactics, or organization..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setPage(1);
                }}
                className="w-full pl-8 pr-3 py-1 text-xs bg-[#F8FAFC] dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-500 font-sans placeholder:text-slate-400"
              />
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Tenant Filter (Fleet Mode) */}
            {isFleetMode && (
              <select
                value={tenantFilter}
                onChange={(e) => {
                  setTenantFilter(e.target.value);
                  setPage(1);
                }}
                className="px-2 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200"
              >
                <option value="all">All Organizations ({tenants.length})</option>
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.displayName}
                  </option>
                ))}
              </select>
            )}

            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="px-2 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="px-2 py-1 text-xs bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm text-slate-700 dark:text-slate-200"
            >
              <option value="open">Open (Active &amp; In-Progress)</option>
              <option value="active">Active Only</option>
              <option value="inProgress">In-Progress Only</option>
              <option value="resolved">Resolved Only</option>
              <option value="all">All Statuses</option>
            </select>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#CBD5E1] dark:border-slate-700 bg-slate-100/70 dark:bg-slate-800/80 text-[11px] font-mono text-slate-600 dark:text-slate-300 uppercase tracking-wider">
                {isFleetMode && <th className="py-2.5 px-3">Organization</th>}
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Incident &amp; ID</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Impacted Entities</th>
                <th className="py-2.5 px-3">MITRE ATT&amp;CK</th>
                <th className="py-2.5 px-3">Created</th>
                <th className="py-2.5 px-3 text-right">Quick Containment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] dark:divide-slate-700/60 bg-white dark:bg-slate-900/30 font-sans">
              {paginatedIncidents.length === 0 ? (
                <EmptyStateRow
                  colSpan={isFleetMode ? 8 : 7}
                  entityLabel="security incidents"
                  isFiltered={searchQuery.trim().length > 0 || severityFilter !== "all" || statusFilter !== "open"}
                />
              ) : (
                paginatedIncidents.map((inc) => {
                  const isHighlighted =
                    Boolean(highlightEntityId) &&
                    (highlightEntityId === inc.id ||
                      highlightEntityId === inc.incidentId ||
                      inc.impactedUsers.some(
                        (u) =>
                          u.userPrincipalName.toLowerCase() ===
                          highlightEntityId?.toLowerCase()
                      ) ||
                      inc.impactedDevices.some(
                        (d) =>
                          d.deviceName.toLowerCase() ===
                          highlightEntityId?.toLowerCase()
                      ));

                  return (
                    <tr
                      key={inc.id}
                      ref={isHighlighted ? highlightedRowRef : null}
                      className={`transition-colors group ${
                        isHighlighted
                          ? "animate-slow-flash"
                          : "hover:bg-slate-50 dark:hover:bg-slate-800/60"
                      }`}
                    >
                      {/* Organization (Fleet Mode) */}
                      {isFleetMode && (
                        <td className="py-2.5 px-3 font-semibold text-slate-800 dark:text-slate-200">
                          <button
                            onClick={() => {
                              if (onSelectTenant && inc.tenantId) {
                                onSelectTenant(inc.tenantId, "event_response", inc.incidentId);
                              }
                            }}
                            className="text-[11px] font-mono font-bold text-slate-700 dark:text-slate-300 hover:text-indigo-600 dark:hover:text-indigo-400 inline-flex items-center gap-1 hover:underline"
                          >
                            <span>{inc.tenantName || "Tenant"}</span>
                            <ChevronRight size={11} className="opacity-50" />
                          </button>
                        </td>
                      )}

                      {/* Severity */}
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-1.5 py-0.5 rounded-sm text-[10px] font-mono font-bold uppercase border ${
                            SEVERITY_COLORS[inc.severity]
                          }`}
                        >
                          {inc.severity}
                        </span>
                      </td>

                      {/* Title & Incident ID */}
                      <td className="py-2.5 px-3 max-w-xs">
                        <div className="font-semibold text-slate-900 dark:text-slate-100 truncate">
                          {inc.displayName}
                        </div>
                        <div className="text-[10px] font-mono text-slate-400 dark:text-slate-500 mt-0.5">
                          ID: #{inc.incidentId}
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-2.5 px-3">
                        <StatusPill
                          status={
                            inc.status === "resolved"
                              ? "pass"
                              : inc.status === "inProgress"
                              ? "warn"
                              : "fail"
                          }
                          label={inc.status}
                          size="sm"
                        />
                      </td>

                      {/* Impacted Entities */}
                      <td className="py-2.5 px-3">
                        <div className="space-y-0.5">
                          {inc.impactedUsers.map((u) => (
                            <div
                              key={u.userPrincipalName}
                              className="text-[11px] font-mono text-slate-700 dark:text-slate-300 flex items-center gap-1"
                            >
                              <User size={10} className="text-slate-400 shrink-0" />
                              <span className="truncate">{u.userPrincipalName}</span>
                            </div>
                          ))}
                          {inc.impactedDevices.map((d) => (
                            <div
                              key={d.deviceName}
                              className="text-[11px] font-mono text-slate-500 dark:text-slate-400 flex items-center gap-1"
                            >
                              <Laptop size={10} className="text-slate-400 shrink-0" />
                              <span className="truncate">{d.deviceName}</span>
                            </div>
                          ))}
                        </div>
                      </td>

                      {/* MITRE ATT&CK */}
                      <td className="py-2.5 px-3">
                        <div className="flex flex-wrap gap-1">
                          {inc.mitreTechniques.map((m) => (
                            <span
                              key={m}
                              className="px-1.5 py-0.2 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 rounded text-[9px] font-mono"
                            >
                              {m}
                            </span>
                          ))}
                        </div>
                      </td>

                      {/* Created */}
                      <td className="py-2.5 px-3 font-mono text-[10px] text-slate-500 dark:text-slate-400 whitespace-nowrap">
                        {new Date(inc.createdDateTime).toLocaleDateString()}
                      </td>

                      {/* Quick Containment Actions */}
                      <td className="py-2.5 px-3 text-right whitespace-nowrap space-x-1.5">
                        {inc.impactedUsers.length > 0 && (
                          <button
                            onClick={() =>
                              setContainmentTarget({
                                upn: inc.impactedUsers[0].userPrincipalName,
                                mode: "contain",
                                tenantId: inc.tenantId || snapshot?.tenant?.id,
                              })
                            }
                            className="px-2 py-1 text-[10px] font-semibold text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/60 hover:bg-rose-100 rounded-sm inline-flex items-center gap-1 border border-rose-300 dark:border-rose-800"
                            title={`Disable compromised account ${inc.impactedUsers[0].userPrincipalName}`}
                          >
                            <UserX size={11} />
                            <span>Disable</span>
                          </button>
                        )}
                        {inc.impactedDevices.length > 0 && (
                          <button
                            onClick={() =>
                              setIsolationTarget({
                                deviceId: inc.impactedDevices[0].id || inc.impactedDevices[0].deviceName,
                                deviceName: inc.impactedDevices[0].deviceName,
                                isCurrentlyIsolated: inc.impactedDevices[0].isIsolated || false,
                                tenantId: inc.tenantId || snapshot?.tenant?.id,
                              })
                            }
                            className={`px-2 py-1 text-[10px] font-semibold rounded-sm inline-flex items-center gap-1 border transition-colors ${
                              inc.impactedDevices[0].isIsolated
                                ? "text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/60 hover:bg-emerald-100 border-emerald-300 dark:border-emerald-800"
                                : "text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/60 hover:bg-amber-100 border-amber-300 dark:border-amber-800"
                            }`}
                            title={
                              inc.impactedDevices[0].isIsolated
                                ? `Release device ${inc.impactedDevices[0].deviceName} from isolation`
                                : `Isolate infected device ${inc.impactedDevices[0].deviceName}`
                            }
                          >
                            {inc.impactedDevices[0].isIsolated ? <Wifi size={11} /> : <WifiOff size={11} />}
                            <span>{inc.impactedDevices[0].isIsolated ? "Release" : "Isolate"}</span>
                          </button>
                        )}
                        <button
                          onClick={() => setSelectedIncident(inc)}
                          className="px-2.5 py-1 text-[10px] font-semibold text-slate-900 dark:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-sm inline-flex items-center gap-1 border border-slate-300 dark:border-slate-600"
                        >
                          <span>Triage</span>
                          <ChevronRight size={11} />
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
          subtitle={`Threat Investigation & Response | ${
            selectedIncident.tenantName || snapshot?.tenant?.displayName || "Organization"
          }`}
          width="2xl"
        >
          <div className="space-y-5">
            {/* Status & Severity Bar */}
            <div className="p-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span
                  className={`px-2 py-0.5 rounded text-xs font-mono font-bold uppercase border ${
                    SEVERITY_COLORS[selectedIncident.severity]
                  }`}
                >
                  {selectedIncident.severity.toUpperCase()}
                </span>

                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300">
                  <span>Status:</span>
                  <select
                    value={selectedIncident.status}
                    onChange={(e) =>
                      handleUpdateStatus(selectedIncident, e.target.value as IncidentStatus)
                    }
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
                  className="px-2.5 py-1 text-xs font-medium bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded flex items-center gap-1.5 text-slate-700 dark:text-slate-200 hover:bg-slate-100"
                >
                  {copiedReport ? <Check size={12} className="text-emerald-600" /> : <Copy size={12} />}
                  <span>{copiedReport ? "Report Copied" : "Copy Triage Summary"}</span>
                </button>
              </div>
            </div>

            {/* Description & Overview */}
            <div className="space-y-1.5">
              <h3 className="text-xs font-bold uppercase text-slate-500 font-mono">Incident Summary</h3>
              <p className="text-xs text-slate-800 dark:text-slate-200 leading-relaxed bg-slate-50 dark:bg-slate-900/60 p-3 rounded border border-slate-200 dark:border-slate-800">
                {selectedIncident.description}
              </p>
            </div>

            {/* Impacted Identities & Containment Controls */}
            <div className="space-y-2">
              <h3 className="text-xs font-bold uppercase text-slate-500 font-mono">
                Impacted User Accounts ({selectedIncident.impactedUsers.length})
              </h3>
              <div className="space-y-1.5">
                {selectedIncident.impactedUsers.map((u) => {
                  const disabled = isUserDisabled(u.userPrincipalName);
                  return (
                    <div
                      key={u.userPrincipalName}
                      className="p-2.5 bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded flex items-center justify-between gap-3"
                    >
                      <div className="flex items-center gap-2.5">
                        <div className="p-1.5 bg-slate-100 dark:bg-slate-700 rounded text-slate-600 dark:text-slate-300">
                          <User size={14} />
                        </div>
                        <div>
                          <div className="font-semibold text-xs text-slate-900 dark:text-slate-100">
                            {u.displayName}
                          </div>
                          <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                            {u.userPrincipalName}
                          </div>
                        </div>
                      </div>

                      <button
                        onClick={() =>
                          setContainmentTarget({
                            upn: u.userPrincipalName,
                            mode: disabled ? "restore" : "contain",
                            tenantId: selectedIncident.tenantId || snapshot?.tenant?.id,
                          })
                        }
                        className={`px-2.5 py-1 text-xs font-bold rounded flex items-center gap-1.5 border transition-colors ${
                          disabled
                            ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border-emerald-300"
                            : "bg-rose-50 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border-rose-300"
                        }`}
                      >
                        {disabled ? <UserCheck size={13} /> : <UserX size={13} />}
                        <span>{disabled ? "Restore Account" : "Disable Account"}</span>
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Impacted Devices & Isolation Controls */}
            {selectedIncident.impactedDevices.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-bold uppercase text-slate-500 font-mono">
                  Impacted Managed Endpoints ({selectedIncident.impactedDevices.length})
                </h3>
                <div className="space-y-1.5">
                  {selectedIncident.impactedDevices.map((d) => {
                    const isolated = d.isIsolated;
                    return (
                      <div
                        key={d.id || d.deviceName}
                        className="p-2.5 bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded flex items-center justify-between gap-3"
                      >
                        <div className="flex items-center gap-2.5">
                          <div className="p-1.5 bg-slate-100 dark:bg-slate-700 rounded text-slate-600 dark:text-slate-300">
                            <Laptop size={14} />
                          </div>
                          <div>
                            <div className="font-semibold text-xs text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                              <span>{d.deviceName}</span>
                              {d.operatingSystem && (
                                <span className="text-[10px] font-mono text-slate-400">({d.operatingSystem})</span>
                              )}
                            </div>
                            <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                              {d.id ? `Device ID: ${d.id}` : `Target: ${d.deviceName}`}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() =>
                              setIsolationTarget({
                                deviceId: d.id || d.deviceName,
                                deviceName: d.deviceName,
                                isCurrentlyIsolated: isolated || false,
                                tenantId: selectedIncident.tenantId || snapshot?.tenant?.id,
                              })
                            }
                            className={`px-2.5 py-1 text-xs font-bold rounded flex items-center gap-1.5 border transition-colors ${
                              isolated
                                ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border-emerald-300"
                                : "bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border-amber-300"
                            }`}
                          >
                            {isolated ? <Wifi size={13} /> : <WifiOff size={13} />}
                            <span>{isolated ? "Release Device" : "Isolate Device"}</span>
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Recommended Containment Actions */}
            <div className="space-y-2">
              <h3 className="text-xs font-bold uppercase text-slate-500 font-mono">Recommended Playbooks</h3>
              <div className="space-y-1.5 bg-slate-50 dark:bg-slate-900/40 p-3 rounded border border-slate-200 dark:border-slate-800">
                {selectedIncident.recommendedActions.map((action, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-300">
                    <span className="font-bold font-mono text-slate-400">{idx + 1}.</span>
                    <span>{action}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Drawer>
      )}

      {/* Containment Modals */}
      {containmentTarget && (
        <CompromisedAccountModal
          isOpen={!!containmentTarget}
          onClose={() => setContainmentTarget(null)}
          targetUserUPN={containmentTarget.upn}
          tenantId={containmentTarget.tenantId || snapshot?.tenant?.id || ""}
          tenantName={
            tenants.find((t) => t.id === (containmentTarget.tenantId || snapshot?.tenant?.id))?.displayName ||
            snapshot?.tenant?.displayName ||
            "Organization"
          }
          initialMode={containmentTarget.mode}
          onSuccess={() => {
            if (onLocalRefresh) onLocalRefresh();
          }}
        />
      )}

      {isolationTarget && (
        <DeviceIsolationModal
          isOpen={!!isolationTarget}
          onClose={() => setIsolationTarget(null)}
          deviceId={isolationTarget.deviceId}
          deviceName={isolationTarget.deviceName}
          tenantId={isolationTarget.tenantId || snapshot?.tenant?.id || ""}
          tenantName={
            tenants.find((t) => t.id === (isolationTarget.tenantId || snapshot?.tenant?.id))?.displayName ||
            snapshot?.tenant?.displayName ||
            "Organization"
          }
          isCurrentlyIsolated={isolationTarget.isCurrentlyIsolated || false}
          onSuccess={() => {
            if (onLocalRefresh) onLocalRefresh();
          }}
        />
      )}
    </div>
  );
};
