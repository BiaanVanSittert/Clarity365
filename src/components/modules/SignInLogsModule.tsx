import React, { useState } from "react";
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
} from "lucide-react";

interface SignInLogsModuleProps {
  snapshot: TenantSecuritySnapshot;
}

const ERROR_CODE_TRANSLATIONS: Record<number, { title: string; explanation: string }> = {
  0: { title: "Success", explanation: "Authentication succeeded and all evaluated Conditional Access policies passed." },
  50126: { title: "Invalid Credentials / Password Mismatch", explanation: "User entered an incorrect password, or basic/legacy authentication was attempted and rejected." },
  53003: { title: "Blocked by Conditional Access", explanation: "Access was blocked by an enforced Conditional Access policy (e.g., untrusted geography, uncompliant device, or missing MFA)." },
  50074: { title: "Strong Authentication Required", explanation: "User did not complete the required MFA challenge or failed number matching." },
  50076: { title: "Admin MFA Required", explanation: "User was required to perform MFA because of administrator role assignment." },
  50053: { title: "Account Locked Out", explanation: "Smart lockout triggered due to repeated failed sign-in attempts." },
  50058: { title: "Silent Session Expired", explanation: "User session cookie expired or continuous access evaluation revoked the token." },
};

export const SignInLogsModule: React.FC<SignInLogsModuleProps> = ({ snapshot }) => {
  const { signIns } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedEvent, setSelectedEvent] = useState<SignInEvent | null>(null);

  const filteredSignIns = signIns.filter((evt) => {
    const matchesSearch =
      evt.userPrincipalName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.userDisplayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.ipAddress.includes(searchQuery) ||
      evt.location.city.toLowerCase().includes(searchQuery.toLowerCase()) ||
      evt.clientApp.toLowerCase().includes(searchQuery.toLowerCase());

    if (statusFilter === "all") return matchesSearch;
    if (statusFilter === "success") return matchesSearch && evt.status === "success";
    if (statusFilter === "failed") return matchesSearch && evt.status === "failed";
    if (statusFilter === "ca_blocked") return matchesSearch && evt.status === "ca_blocked";
    if (statusFilter === "report_only_failed") return matchesSearch && evt.status === "report_only_failed";
    if (statusFilter === "risky") return matchesSearch && evt.isRisky;
    return matchesSearch;
  });

  const getStatusDisplay = (evt: SignInEvent) => {
    switch (evt.status) {
      case "success":
        return <StatusPill status="pass" label="Pass" size="sm" />;
      case "ca_blocked":
        return <StatusPill status="fail" label="CA Blocked" size="sm" />;
      case "failed":
        return <StatusPill status="fail" label={`Failed (${evt.errorCode})`} size="sm" />;
      case "report_only_failed":
        return <StatusPill status="warn" label="Report-Only Fail" size="sm" />;
      default:
        return <StatusPill status="info" label="Unknown" size="sm" />;
    }
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
            Real-time interactive log streamer with Conditional Access policy rule-chain inspection and error code translation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-xs font-semibold text-slate-700">Events Audited</div>
            <div className="text-lg font-bold font-mono text-slate-900 tabular-nums">
              {signIns.length} Logged
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search by User, UPN, IP, or Location..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
          >
            <option value="all">All Outcomes</option>
            <option value="success">Successful Logins</option>
            <option value="ca_blocked">Blocked by Conditional Access</option>
            <option value="report_only_failed">Failing Report-Only Policies</option>
            <option value="failed">Failed Logins (Bad Password / Auth)</option>
            <option value="risky">Flagged as Risky Login</option>
          </select>
        </div>
      </div>

      {/* Log Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            Entra ID Authentication & Session Audit Stream
          </h3>
          <span className="text-[11px] font-mono text-slate-500">
            {filteredSignIns.length} Records
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-36">Timestamp (UTC)</th>
                <th>User / Identity</th>
                <th>IP & Geo Location</th>
                <th>Client App & Device</th>
                <th>Target Cloud App</th>
                <th>CA Policy Result</th>
                <th className="w-24 text-right">Details</th>
              </tr>
            </thead>
            <tbody>
              {filteredSignIns.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-4 text-center text-xs text-slate-500">
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
                    <td className="font-mono text-[11px] text-slate-600">
                      {new Date(evt.createdDateTime).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </td>
                    <td>
                      <div className="font-semibold text-xs text-slate-900 flex items-center gap-1.5">
                        {evt.userDisplayName || evt.userPrincipalName}
                        {evt.isRisky && (
                          <span className="text-[9px] font-mono uppercase px-1 bg-red-100 text-red-800 border border-red-300 rounded-sm">
                            {evt.riskLevel} Risk
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500">{evt.userPrincipalName}</div>
                    </td>
                    <td className="text-xs">
                      <div className="font-mono text-slate-800">{evt.ipAddress}</div>
                      <div className="text-[11px] text-slate-500 flex items-center gap-1">
                        <MapPin size={11} />
                        <span>{evt.location.city}, {evt.location.country}</span>
                      </div>
                    </td>
                    <td className="text-xs">
                      <div className="font-medium text-slate-800">{evt.clientApp}</div>
                      <div className="text-[11px] text-slate-500 font-mono">
                        {evt.deviceDetail.operatingSystem} • {evt.deviceDetail.isCompliant ? "Compliant" : "Unmanaged"}
                      </div>
                    </td>
                    <td className="text-xs font-medium text-slate-800">
                      {evt.appDisplayName}
                    </td>
                    <td>{getStatusDisplay(evt)}</td>
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
              className={`p-3 border rounded-sm ${
                selectedEvent.status === "success"
                  ? "bg-emerald-50 border-emerald-300 text-emerald-900"
                  : selectedEvent.status === "ca_blocked" || selectedEvent.status === "failed"
                  ? "bg-red-50 border-red-300 text-red-900"
                  : "bg-amber-50 border-amber-300 text-amber-900"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wide">
                  Status: {selectedEvent.status.toUpperCase()}
                </span>
                <span className="font-mono text-xs font-bold">
                  Error Code: {selectedEvent.errorCode}
                </span>
              </div>
              <p className="text-xs mt-1 font-medium">
                {ERROR_CODE_TRANSLATIONS[selectedEvent.errorCode]?.title || "Authentication Result"}
              </p>
              <p className="text-[11px] mt-0.5 opacity-90">
                {selectedEvent.failureReason ||
                  ERROR_CODE_TRANSLATIONS[selectedEvent.errorCode]?.explanation ||
                  "No failure reason reported."}
              </p>
            </div>

            {/* User & Identity Details */}
            <div className="border border-[#CBD5E1] p-3 rounded-sm bg-white space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 border-b border-[#E2E8F0] pb-1">
                User Identity & Target Resource
              </h4>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-slate-500 block text-[11px]">Display Name</span>
                  <span className="font-semibold text-slate-900">{selectedEvent.userDisplayName}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">User Principal Name</span>
                  <span className="font-mono text-slate-900 text-[11px]">{selectedEvent.userPrincipalName}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Target Cloud Application</span>
                  <span className="font-semibold text-slate-900">{selectedEvent.appDisplayName}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Client Application</span>
                  <span className="font-mono text-slate-900">{selectedEvent.clientApp}</span>
                </div>
              </div>
            </div>

            {/* Device & Location */}
            <div className="border border-[#CBD5E1] p-3 rounded-sm bg-white space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 border-b border-[#E2E8F0] pb-1">
                Device State & IP Telemetry
              </h4>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-slate-500 block text-[11px]">IP Address</span>
                  <span className="font-mono font-bold text-slate-900">{selectedEvent.ipAddress}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Location</span>
                  <span>{selectedEvent.location.city}, {selectedEvent.location.country}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Device OS</span>
                  <span className="font-mono">{selectedEvent.deviceDetail.operatingSystem}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Compliance Status</span>
                  <StatusPill
                    status={selectedEvent.deviceDetail.isCompliant ? "pass" : "fail"}
                    label={selectedEvent.deviceDetail.isCompliant ? "Compliant" : "Non-Compliant"}
                    size="sm"
                  />
                </div>
              </div>
            </div>

            {/* Applied Conditional Access Policy Evaluation Chain */}
            <div className="border border-[#CBD5E1] p-3 rounded-sm bg-white space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 border-b border-[#E2E8F0] pb-1">
                Applied Conditional Access Evaluation Chain
              </h4>
              {selectedEvent.appliedConditionalAccessPolicies.length === 0 ? (
                <p className="text-xs text-slate-500 italic">No Conditional Access policies were evaluated on this session.</p>
              ) : (
                <div className="space-y-2">
                  {selectedEvent.appliedConditionalAccessPolicies.map((pol) => (
                    <div key={pol.id} className="p-2 border border-slate-200 rounded-sm bg-[#F8FAFC] flex items-center justify-between">
                      <div>
                        <div className="text-xs font-semibold text-slate-900">{pol.displayName}</div>
                        <div className="text-[11px] font-mono text-slate-500">
                          Controls: {pol.enforcedGrantControls.join(", ")}
                        </div>
                      </div>
                      <StatusPill
                        status={
                          pol.result === "success" || pol.result === "reportOnlySuccess"
                            ? "pass"
                            : pol.result === "failure"
                            ? "fail"
                            : "warn"
                        }
                        label={
                          pol.result === "success"
                            ? "Passed"
                            : pol.result === "failure"
                            ? "Failed / Blocked"
                            : pol.result === "reportOnlyFailure"
                            ? "Report-Only Failed"
                            : "Not Applied"
                        }
                        size="sm"
                      />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </Drawer>
      )}
    </div>
  );
};
