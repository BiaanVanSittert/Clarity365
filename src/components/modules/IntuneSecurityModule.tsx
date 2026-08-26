import React, { useState } from "react";
import { TenantSecuritySnapshot, IntuneDevice } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Drawer } from "../common/Drawer";
import { HardDrive, ShieldCheck, ShieldAlert, Laptop, Search, Filter, CheckCircle2, XCircle, Download, ChevronRight } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import { EmptyStateRow } from "../common/EmptyStateRow";

interface IntuneSecurityModuleProps {
  snapshot: TenantSecuritySnapshot;
}

function formatBytes(bytes: number | undefined): string {
  if (typeof bytes !== "number" || bytes <= 0) return "—";
  const gb = bytes / 1_073_741_824;
  return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(bytes / 1_048_576).toFixed(0)} MB`;
}

function formatDate(value: string | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  return isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export const IntuneSecurityModule: React.FC<IntuneSecurityModuleProps> = ({ snapshot }) => {
  const { intune } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [osFilter, setOsFilter] = useState<string>("all");
  const [selectedDevice, setSelectedDevice] = useState<IntuneDevice | null>(null);

  const devices = intune.devices;

  const filteredDevices = devices.filter((dev) => {
    const matchesSearch =
      dev.deviceName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      dev.userPrincipalName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      dev.osVersion.toLowerCase().includes(searchQuery.toLowerCase());

    if (osFilter === "all") return matchesSearch;
    return matchesSearch && dev.operatingSystem.toLowerCase() === osFilter.toLowerCase();
  });

  const handleExportCSV = () => {
    const headers = ["DeviceName", "UserPrincipalName", "OperatingSystem", "OsVersion", "Encrypted", "AntivirusStatus", "EdrOnboardingState", "ComplianceState"];
    const rows = filteredDevices.map((dev) => [
      dev.deviceName,
      dev.userPrincipalName,
      dev.operatingSystem,
      dev.osVersion,
      dev.isEncrypted ? "Yes" : "No",
      dev.antivirusStatus,
      dev.edrOnboardingState,
      dev.complianceState,
    ]);
    exportToCsv(csvFilename("IntuneDevices", snapshot.tenant.defaultDomainName), headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <HardDrive size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Module 10: Intune Endpoint Security (Antivirus & EDR Fleet Onboarding)
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Fleet compliance, BitLocker/FileVault encryption, Microsoft Defender Antivirus status, and EDR onboarding state.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-xs font-semibold text-slate-700 dark:text-slate-300">Fleet Compliance</div>
            <div className="text-lg font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums">
              {intune.totalDevices === 0 ? "0%" : `${Math.round((intune.compliantDevices / intune.totalDevices) * 100)}%`} ({intune.compliantDevices} / {intune.totalDevices})
            </div>
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold">Total Fleet Devices</div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">{intune.totalDevices}</div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Enrolled in Intune</div>
        </div>

        <div className="p-3 bg-[#ECFDF5] dark:bg-emerald-950 border border-[#10B981] dark:border-emerald-800 rounded-sm">
          <div className="text-[10px] uppercase font-mono text-[#065F46] dark:text-emerald-400 font-semibold">Compliant Endpoints</div>
          <div className="text-xl font-bold font-mono text-[#065F46] dark:text-emerald-400 tabular-nums mt-0.5">{intune.compliantDevices}</div>
          <div className="text-[11px] text-[#065F46] dark:text-emerald-400 mt-0.5">Passes compliance rules</div>
        </div>

        <div className="p-3 bg-[#FEF2F2] dark:bg-red-950 border border-[#EF4444] dark:border-red-800 rounded-sm">
          <div className="text-[10px] uppercase font-mono text-[#991B1B] dark:text-red-400 font-semibold">Non-Compliant Endpoints</div>
          <div className="text-xl font-bold font-mono text-[#991B1B] dark:text-red-400 tabular-nums mt-0.5">{intune.nonCompliantDevices}</div>
          <div className="text-[11px] text-[#991B1B] dark:text-red-400 mt-0.5">Failing baseline</div>
        </div>

        <div className="p-3 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold">EDR Policy Profiles</div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">{intune.edrPoliciesCount}</div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">{intune.antivirusPoliciesCount} AV Profiles Active</div>
        </div>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white dark:bg-slate-800 p-3 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            placeholder="Search device name, user, or OS..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500 dark:text-slate-400" />
          <select
            value={osFilter}
            onChange={(e) => setOsFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
          >
            <option value="all">All Platforms (Windows, macOS, iOS, Android, Linux)</option>
            <option value="windows">Windows</option>
            <option value="macos">macOS</option>
            <option value="ios">iOS</option>
            <option value="android">Android</option>
            <option value="linux">Linux</option>
          </select>

          <button
            onClick={handleExportCSV}
            title="Export filtered devices to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500 dark:text-slate-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Device Table */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Managed Endpoint Inventory & Telemetry Status
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{filteredDevices.length} Devices Listed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Device Hostname</th>
                <th>Primary User (UPN)</th>
                <th>Platform & OS Build</th>
                <th>Disk Encryption</th>
                <th>Defender Antivirus</th>
                <th>Defender EDR Status</th>
                <th className="w-28 text-right">Compliance</th>
                <th className="w-10"></th>
              </tr>
            </thead>
            <tbody>
              {filteredDevices.length === 0 ? (
                <EmptyStateRow colSpan={8} entityLabel="endpoint devices" isFiltered={searchQuery.trim().length > 0 || osFilter !== "all"} />
              ) : (
                filteredDevices.map((dev) => (
                  <tr
                    key={dev.id}
                    onClick={() => setSelectedDevice(dev)}
                    tabIndex={0}
                    role="button"
                    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), setSelectedDevice(dev))}
                    className={`cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors focus:outline focus:outline-2 focus:outline-slate-400 focus:-outline-offset-2 ${
                      dev.complianceState === "noncompliant" ? "bg-red-50/20 dark:bg-red-950" : ""
                    }`}
                  >
                    <td>
                      <div className="font-semibold text-xs text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                        <Laptop size={13} className="text-slate-500 dark:text-slate-400" />
                        <span>{dev.deviceName}</span>
                      </div>
                    </td>
                    <td className="font-mono text-[11px] text-slate-600 dark:text-slate-400">{dev.userPrincipalName}</td>
                    <td className="text-xs font-mono text-slate-700 dark:text-slate-300">
                      {dev.operatingSystem} ({dev.osVersion})
                    </td>
                    <td>
                      <StatusPill
                        status={dev.isEncrypted ? "pass" : "fail"}
                        label={dev.isEncrypted ? "BitLocker / Encrypted" : "Unencrypted"}
                        size="sm"
                      />
                    </td>
                    <td>
                      <StatusPill
                        status={dev.antivirusStatus === "active" ? "pass" : "fail"}
                        label={dev.antivirusStatus === "active" ? "Active" : "Out of Date"}
                        size="sm"
                      />
                    </td>
                    <td>
                      <StatusPill
                        status={dev.edrOnboardingState === "onboarded" ? "pass" : "warn"}
                        label={dev.edrOnboardingState === "onboarded" ? "Onboarded" : "Not Onboarded"}
                        size="sm"
                      />
                    </td>
                    <td className="text-right">
                      <StatusPill
                        status={dev.complianceState === "compliant" ? "pass" : "fail"}
                        label={dev.complianceState.toUpperCase()}
                        size="sm"
                      />
                    </td>
                    <td className="text-right">
                      <button
                        aria-label="View device details"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedDevice(dev);
                        }}
                        className="p-1 text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:text-slate-100 rounded-sm"
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

      {/* Device Detail Drawer */}
      {selectedDevice && (
        <Drawer
          isOpen={!!selectedDevice}
          onClose={() => setSelectedDevice(null)}
          title={selectedDevice.deviceName}
          subtitle={`${selectedDevice.userPrincipalName || "No assigned user"} • ${selectedDevice.operatingSystem} ${selectedDevice.osVersion}`}
          width="lg"
        >
          <div className="space-y-4">
            <div className="border border-[#CBD5E1] dark:border-slate-700 p-3 rounded-sm bg-[#F8FAFC] dark:bg-slate-900/50 space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Compliance & Security</h4>
              <div className="grid grid-cols-2 gap-2">
                <StatusPill
                  status={selectedDevice.complianceState === "compliant" ? "pass" : "fail"}
                  label={`Compliance: ${selectedDevice.complianceState.toUpperCase()}`}
                  size="sm"
                />
                <StatusPill
                  status={selectedDevice.isEncrypted ? "pass" : "fail"}
                  label={selectedDevice.isEncrypted ? "Encrypted" : "Unencrypted"}
                  size="sm"
                />
                <StatusPill
                  status={selectedDevice.antivirusStatus === "active" ? "pass" : "fail"}
                  label={selectedDevice.antivirusStatus === "active" ? "AV Active" : "AV Out of Date"}
                  size="sm"
                />
                <StatusPill
                  status={selectedDevice.edrOnboardingState === "onboarded" ? "pass" : "warn"}
                  label={selectedDevice.edrOnboardingState === "onboarded" ? "EDR Onboarded" : "EDR Not Onboarded"}
                  size="sm"
                />
              </div>
              {selectedDevice.jailBroken && selectedDevice.jailBroken.toLowerCase() === "true" && (
                <div className="text-[11px] font-semibold text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 p-1.5 rounded-sm">
                  This device is reported as jailbroken/rooted.
                </div>
              )}
              {selectedDevice.complianceState === "inGracePeriod" && (
                <div className="text-[11px] text-amber-800 dark:text-amber-400 bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 p-1.5 rounded-sm">
                  Grace period expires: {formatDate(selectedDevice.complianceGracePeriodExpirationDateTime)}
                </div>
              )}
            </div>

            <div className="border border-[#CBD5E1] dark:border-slate-700 p-3 rounded-sm bg-white dark:bg-slate-800 space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Hardware</h4>
              <dl className="grid grid-cols-2 gap-y-1.5 text-xs">
                <dt className="text-slate-500 dark:text-slate-400">Manufacturer</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-medium">{selectedDevice.manufacturer || "—"}</dd>
                <dt className="text-slate-500 dark:text-slate-400">Model</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-medium">{selectedDevice.model || "—"}</dd>
                <dt className="text-slate-500 dark:text-slate-400">Serial Number</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-mono">{selectedDevice.serialNumber || "—"}</dd>
                <dt className="text-slate-500 dark:text-slate-400">IMEI</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-mono">{selectedDevice.imei || "—"}</dd>
                <dt className="text-slate-500 dark:text-slate-400">Wi-Fi MAC</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-mono">{selectedDevice.wiFiMacAddress || "—"}</dd>
                <dt className="text-slate-500 dark:text-slate-400">Storage</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-medium">
                  {selectedDevice.freeStorageBytes !== undefined && selectedDevice.totalStorageBytes !== undefined
                    ? `${formatBytes(selectedDevice.freeStorageBytes)} free of ${formatBytes(selectedDevice.totalStorageBytes)}`
                    : "—"}
                </dd>
              </dl>
            </div>

            <div className="border border-[#CBD5E1] dark:border-slate-700 p-3 rounded-sm bg-[#F8FAFC] dark:bg-slate-900/50 space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Management & Enrollment</h4>
              <dl className="grid grid-cols-2 gap-y-1.5 text-xs">
                <dt className="text-slate-500 dark:text-slate-400">Enrollment Type</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-medium">{selectedDevice.deviceEnrollmentType || "—"}</dd>
                <dt className="text-slate-500 dark:text-slate-400">Management Agent</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-medium">{selectedDevice.managementAgent || "—"}</dd>
                <dt className="text-slate-500 dark:text-slate-400">Owner Type</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-medium capitalize">{selectedDevice.ownerType || "—"}</dd>
                <dt className="text-slate-500 dark:text-slate-400">Device Category</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-medium">{selectedDevice.deviceCategory || "—"}</dd>
                <dt className="text-slate-500 dark:text-slate-400">Azure AD Device ID</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-mono text-[10px] break-all">{selectedDevice.azureADDeviceId || "—"}</dd>
                <dt className="text-slate-500 dark:text-slate-400">Enrolled</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-medium">{formatDate(selectedDevice.enrolledDateTime)}</dd>
                <dt className="text-slate-500 dark:text-slate-400">Last Sync</dt>
                <dd className="text-slate-900 dark:text-slate-100 font-medium">{formatDate(selectedDevice.lastSyncDateTime)}</dd>
              </dl>
            </div>
          </div>
        </Drawer>
      )}
    </div>
  );
};
