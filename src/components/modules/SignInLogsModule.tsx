import React, { useState, useMemo } from "react";
import { TenantSecuritySnapshot, SignInEvent } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Drawer } from "../common/Drawer";
import {
  Key,
  Search,
  Filter,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  MapPin,
  Laptop,
  CheckCircle2,
  XCircle,
  Clock,
  Layers,
  ChevronRight,
  AppWindow,
  AlertOctagon,
  ShieldX,
  Sparkles,
  Info,
} from "lucide-react";

interface SignInLogsModuleProps {
  snapshot: TenantSecuritySnapshot;
}

const ERROR_CODE_TRANSLATIONS: Record<number, { title: string; explanation: string }> = {
  0: { title: "Success", explanation: "Authentication succeeded and all evaluated Conditional Access policies passed." },
  50126: { title: "Invalid Credentials", explanation: "Error validating credentials due to invalid username or password." },
  53003: { title: "Blocked by Conditional Access", explanation: "Access has been blocked by Conditional Access policies. The access policy does not allow token issuance." },
  50074: { title: "Strong Authentication Required", explanation: "Strong Authentication is required (user did not complete MFA challenge)." },
  50076: { title: "Admin MFA Required", explanation: "User was required to perform MFA because of administrator role assignment." },
  50053: { title: "Account Locked Out", explanation: "The account is locked; tried to sign in too many times with an incorrect user ID or password." },
  50140: { title: "Keep Me Signed In Interrupt", explanation: "This occurred due to 'Keep me signed in' interrupt when the user was signing in." },
  65001: { title: "Application Consent Missing", explanation: "The user or administrator has not consented to use the application. Interactive authorization required." },
  50058: { title: "Silent Session Expired", explanation: "User session cookie expired or continuous access evaluation revoked the token." },
  50011: { title: "Redirect URI Mismatch", explanation: "The redirect URI specified in the request does not match the URIs configured for the application." },
  500113: { title: "Missing Reply Address", explanation: "No reply address is registered for the application." },
};

export const SignInLogsModule: React.FC<SignInLogsModuleProps> = ({ snapshot }) => {
  const { signIns } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [serviceFilter, setServiceFilter] = useState<string>("all");
  const [selectedEvent, setSelectedEvent] = useState<SignInEvent | null>(null);

  // Compute unique service names for filtering
  const availableServices = useMemo(() => {
    const services = new Set<string>();
    signIns.forEach((s) => {
      if (s.appDisplayName) services.add(s.appDisplayName);
    });
    return Array.from(services).sort();
  }, [signIns]);

  // Compute high-level analytics
  const stats = useMemo(() => {
    const total = signIns.length;
    const successful = signIns.filter((s) => s.status === "success" || s.errorCode === 0).length;
    const failed = signIns.filter((s) => s.status === "failed" || (s.errorCode !== 0 && s.status !== "report_only_failed")).length;
    const caBlocked = signIns.filter((s) => s.status === "ca_blocked" || s.errorCode === 53003).length;
    const reportOnlyFailed = signIns.filter((s) => s.hasReportOnlyFailure || s.status === "report_only_failed").length;

    const successRate = total > 0 ? Math.round((successful / total) * 100) : 100;

    return { total, successful, failed, caBlocked, reportOnlyFailed, successRate };
  }, [signIns]);

  const filteredSignIns = useMemo(() => {
    return signIns.filter((evt) => {
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        evt.userPrincipalName.toLowerCase().includes(q) ||
        evt.userDisplayName.toLowerCase().includes(q) ||
        evt.appDisplayName.toLowerCase().includes(q) ||
        (evt.failureReason && evt.failureReason.toLowerCase().includes(q)) ||
        evt.ipAddress.includes(q) ||
        evt.location.city.toLowerCase().includes(q);

      const matchesService = serviceFilter === "all" || evt.appDisplayName === serviceFilter;

      if (!matchesSearch || !matchesService) return false;

      if (statusFilter === "all") return true;
      if (statusFilter === "success") return evt.status === "success" || evt.errorCode === 0;
      if (statusFilter === "failed") return evt.status === "failed" || (evt.errorCode !== 0 && evt.status !== "report_only_failed");
      if (statusFilter === "ca_blocked") return evt.status === "ca_blocked" || evt.errorCode === 53003;
      if (statusFilter === "report_only_failed") return evt.hasReportOnlyFailure || evt.status === "report_only_failed";
      if (statusFilter === "risky") return evt.isRisky;
      return true;
    });
  }, [signIns, searchQuery, statusFilter, serviceFilter]);

  const getStatusDisplay = (evt: SignInEvent) => {
    if (evt.status === "ca_blocked" || evt.errorCode === 53003) {
      return <StatusPill status="fail" label="CA Blocked" size="sm" />;
    }
    if (evt.hasReportOnlyFailure || evt.status === "report_only_failed") {
      return <StatusPill status="warn" label="Report-Only Fail" size="sm" />;
    }
    if (evt.errorCode === 0 || evt.status === "success") {
      return <StatusPill status="pass" label="Succeeded" size="sm" />;
    }
    return <StatusPill status="fail" label={`Failed (${evt.errorCode})`} size="sm" />;
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Key size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 2: Entra ID Sign-In Logs & CA Diagnostic Engine
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time interactive log streamer with Conditional Access policy rule-chain inspection, failure reasons, and Report-Only impact analytics.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-xs font-semibold text-slate-700">Events Streamed</div>
            <div className="text-lg font-bold font-mono text-slate-900 tabular-nums">
              {signIns.length} Logged
            </div>
          </div>
        </div>
      </div>

      {/* Analytics KPI Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white border border-[#CBD5E1] rounded-sm">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Total Sign-Ins</div>
          <div className="text-xl font-bold font-mono text-slate-900 mt-1">{stats.total}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">Live Graph Events</div>
        </div>

        <div className="p-3 bg-white border border-[#CBD5E1] rounded-sm">
          <div className="text-[11px] font-semibold text-emerald-700 uppercase tracking-wider flex items-center gap-1">
            <CheckCircle2 size={12} />
            <span>Succeeded</span>
          </div>
          <div className="text-xl font-bold font-mono text-emerald-900 mt-1">
            {stats.successful} <span className="text-xs font-normal text-emerald-600">({stats.successRate}%)</span>
          </div>
          <div className="text-[10px] text-emerald-600 mt-0.5">Passed all evaluations</div>
        </div>

        <div className="p-3 bg-white border border-[#CBD5E1] rounded-sm">
          <div className="text-[11px] font-semibold text-rose-700 uppercase tracking-wider flex items-center gap-1">
            <XCircle size={12} />
            <span>Auth Failures</span>
          </div>
          <div className="text-xl font-bold font-mono text-rose-900 mt-1">{stats.failed}</div>
          <div className="text-[10px] text-rose-600 mt-0.5">Bad password / interrupts</div>
        </div>

        <div
          onClick={() => setStatusFilter(statusFilter === "report_only_failed" ? "all" : "report_only_failed")}
          className={`p-3 border rounded-sm cursor-pointer transition-colors ${
            statusFilter === "report_only_failed"
              ? "bg-amber-100 border-amber-400"
              : "bg-amber-50/60 border-amber-200 hover:bg-amber-100/70"
          }`}
        >
          <div className="text-[11px] font-semibold text-amber-800 uppercase tracking-wider flex items-center gap-1">
            <AlertTriangle size={12} />
            <span>CA Report-Only Failures</span>
          </div>
          <div className="text-xl font-bold font-mono text-amber-950 mt-1">{stats.reportOnlyFailed}</div>
          <div className="text-[10px] text-amber-700 mt-0.5">Would block if enabled (Click to filter)</div>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
        <div className="relative w-full md:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search by User (UPN), Service, Failure Reason..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          {/* Status Filter */}
          <div className="flex items-center gap-1.5">
            <Filter size={13} className="text-slate-500" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium text-slate-700"
            >
              <option value="all">All Outcomes</option>
              <option value="success">Succeeded Logins</option>
              <option value="failed">Failed Logins</option>
              <option value="report_only_failed">Failing Report-Only CA</option>
              <option value="ca_blocked">CA Blocked</option>
              <option value="risky">Flagged as Risky</option>
            </select>
          </div>

          {/* Service Filter */}
          <div className="flex items-center gap-1.5">
            <AppWindow size={13} className="text-slate-500" />
            <select
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium text-slate-700 max-w-[200px] truncate"
            >
              <option value="all">All Services ({availableServices.length})</option>
              {availableServices.map((svc) => (
                <option key={svc} value={svc}>
                  {svc}
                </option>
              ))}
            </select>
          </div>

          {(statusFilter !== "all" || serviceFilter !== "all" || searchQuery) && (
            <button
              onClick={() => {
                setStatusFilter("all");
                setServiceFilter("all");
                setSearchQuery("");
              }}
              className="px-2.5 py-1 text-xs text-slate-600 hover:text-slate-900 border border-slate-300 rounded-sm hover:bg-slate-50"
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Log Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            Authentication & Session Audit Stream
          </h3>
          <span className="text-[11px] font-mono text-slate-500">
            {filteredSignIns.length} Records Matching
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-28">Timestamp</th>
                <th className="min-w-[200px]">User (Identity)</th>
                <th className="w-28">Status</th>
                <th className="min-w-[170px]">Service</th>
                <th className="min-w-[260px]">Failure Reason</th>
                <th className="min-w-[200px]">CA Report-Only Failure</th>
                <th className="w-16 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody>
              {filteredSignIns.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-6 text-center text-xs text-slate-500">
                    No sign-in events match the active filter criteria.
                  </td>
                </tr>
              ) : (
                filteredSignIns.map((evt) => (
                  <tr
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    className="cursor-pointer hover:bg-slate-50 transition-colors"
                  >
                    {/* Timestamp */}
                    <td className="font-mono text-[11px] text-slate-600 whitespace-nowrap">
                      <div>{new Date(evt.createdDateTime).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</div>
                      <div className="text-[10px] text-slate-400">{new Date(evt.createdDateTime).toLocaleDateString([], { month: "short", day: "numeric" })}</div>
                    </td>

                    {/* User */}
                    <td>
                      <div className="font-mono font-semibold text-xs text-slate-900 leading-tight">
                        {evt.userPrincipalName}
                      </div>
                      <div className="text-[11px] text-slate-500 flex items-center gap-1.5 mt-0.5">
                        <span>{evt.userDisplayName || evt.userPrincipalName}</span>
                        {evt.isRisky && (
                          <span className="text-[9px] font-mono uppercase px-1 bg-red-100 text-red-800 border border-red-300 rounded-sm">
                            {evt.riskLevel} Risk
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Status */}
                    <td>{getStatusDisplay(evt)}</td>

                    {/* Service */}
                    <td>
                      <div className="font-semibold text-xs text-slate-800 flex items-center gap-1.5">
                        <AppWindow size={13} className="text-slate-400 flex-shrink-0" />
                        <span className="truncate">{evt.appDisplayName}</span>
                      </div>
                      <div className="text-[10px] font-mono text-slate-400 mt-0.5 flex items-center gap-1">
                        <MapPin size={10} />
                        <span>{evt.location.city || "Unknown"}, {evt.location.country || "ZA"}</span>
                      </div>
                    </td>

                    {/* Failure Reason */}
                    <td className="text-xs">
                      {evt.errorCode === 0 && !evt.hasReportOnlyFailure ? (
                        <span className="text-slate-400 text-[11px] italic">None (Authentication Successful)</span>
                      ) : evt.errorCode !== 0 ? (
                        <div className="text-rose-900 bg-rose-50 border border-rose-200 p-1.5 rounded-sm text-[11px] leading-snug">
                          <span className="font-mono font-bold text-rose-800 mr-1">[{evt.errorCode}]</span>
                          <span>{evt.failureReason || ERROR_CODE_TRANSLATIONS[evt.errorCode]?.explanation || "Authentication failed"}</span>
                        </div>
                      ) : (
                        <span className="text-slate-500 text-[11px]">{evt.failureReason || "Authentication successful"}</span>
                      )}
                    </td>

                    {/* CA Report-Only Failure */}
                    <td>
                      {evt.hasReportOnlyFailure && evt.reportOnlyFailedPolicies && evt.reportOnlyFailedPolicies.length > 0 ? (
                        <div className="space-y-1">
                          {evt.reportOnlyFailedPolicies.map((polName, idx) => (
                            <div
                              key={idx}
                              className="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-50 border border-amber-300 text-amber-900 text-[11px] font-medium rounded-sm"
                              title={`This policy evaluated to 'reportOnlyFailure'. If enabled, it would block or challenge this login.`}
                            >
                              <AlertTriangle size={11} className="text-amber-700 flex-shrink-0" />
                              <span className="truncate max-w-[200px]">{polName}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <span className="text-[11px] text-slate-400 flex items-center gap-1 font-mono">
                          <CheckCircle2 size={12} className="text-emerald-500" />
                          <span>Passed / None</span>
                        </span>
                      )}
                    </td>

                    {/* Details Chevron */}
                    <td className="text-right">
                      <button className="p-1 text-slate-400 hover:text-slate-900 rounded-sm">
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

      {/* Drill-down Diagnostic Drawer */}
      {selectedEvent && (
        <Drawer
          isOpen={!!selectedEvent}
          onClose={() => setSelectedEvent(null)}
          title="Sign-In Diagnostics & CA Rule-Chain Inspector"
          subtitle={`Session ID: ${selectedEvent.id} • ${new Date(selectedEvent.createdDateTime).toLocaleString()}`}
          width="xl"
        >
          <div className="space-y-4">
            {/* Outcome Banner */}
            <div
              className={`p-3.5 border rounded-sm ${
                selectedEvent.status === "success" && !selectedEvent.hasReportOnlyFailure
                  ? "bg-emerald-50 border-emerald-300 text-emerald-950"
                  : selectedEvent.status === "ca_blocked" || selectedEvent.errorCode !== 0
                  ? "bg-rose-50 border-rose-300 text-rose-950"
                  : "bg-amber-50 border-amber-300 text-amber-950"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider">
                  Status: {selectedEvent.status.toUpperCase()}
                </span>
                <span className="font-mono text-xs font-bold">
                  Error Code: {selectedEvent.errorCode}
                </span>
              </div>
              <p className="text-xs mt-1.5 font-medium leading-relaxed">
                {selectedEvent.failureReason || ERROR_CODE_TRANSLATIONS[selectedEvent.errorCode]?.explanation || "Authentication succeeded."}
              </p>
            </div>

            {/* User & Service Details */}
            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 border border-slate-200 text-xs">
              <div>
                <span className="text-slate-500 block text-[11px]">User (UPN):</span>
                <span className="font-mono font-semibold text-slate-900">{selectedEvent.userPrincipalName}</span>
                <span className="text-slate-600 block text-[11px]">{selectedEvent.userDisplayName}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px]">Service (App):</span>
                <span className="font-semibold text-slate-900">{selectedEvent.appDisplayName}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px]">Client & OS:</span>
                <span className="text-slate-800">{selectedEvent.clientApp} ({selectedEvent.deviceDetail.operatingSystem})</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px]">IP & Location:</span>
                <span className="font-mono text-slate-800">{selectedEvent.ipAddress}</span>
                <span className="text-slate-600 block text-[11px]">{selectedEvent.location.city}, {selectedEvent.location.country}</span>
              </div>
            </div>

            {/* CA Evaluation Chain */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 mb-2 flex items-center gap-1.5">
                <Layers size={13} />
                <span>Applied Conditional Access Policy Evaluations</span>
              </h4>

              {selectedEvent.appliedConditionalAccessPolicies.length === 0 ? (
                <div className="p-3 bg-slate-50 border border-slate-200 text-xs text-slate-500 rounded-sm">
                  No Conditional Access policies were evaluated for this session (e.g. legacy endpoint or excluded application).
                </div>
              ) : (
                <div className="space-y-2">
                  {selectedEvent.appliedConditionalAccessPolicies.map((pol, idx) => {
                    const isReportOnly = pol.result.startsWith("reportOnly");
                    const isFail = pol.result === "failure" || pol.result === "reportOnlyFailure";
                    const isSuccess = pol.result === "success" || pol.result === "reportOnlySuccess";

                    return (
                      <div
                        key={idx}
                        className={`p-2.5 border rounded-sm text-xs ${
                          isFail
                            ? "bg-rose-50 border-rose-300"
                            : isSuccess
                            ? "bg-emerald-50 border-emerald-200"
                            : "bg-slate-50 border-slate-200"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-900">{pol.displayName}</span>
                          <span
                            className={`px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase rounded-xs ${
                              isFail
                                ? "bg-rose-600 text-white"
                                : isSuccess
                                ? "bg-emerald-600 text-white"
                                : "bg-slate-300 text-slate-700"
                            }`}
                          >
                            {pol.result}
                          </span>
                        </div>
                        <div className="mt-1 text-[11px] text-slate-600 flex items-center justify-between">
                          <span>Mode: {isReportOnly ? "Report-Only (Simulation)" : "Enforced"}</span>
                          <span>Controls: {pol.enforcedGrantControls.join(", ") || "None"}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </Drawer>
      )}
    </div>
  );
};
