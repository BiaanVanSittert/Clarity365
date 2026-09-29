import React, { useState, useMemo, useEffect } from "react";
import { TenantSecuritySnapshot, DefenderAvPolicySettings, EdrPolicySettings, BitLockerPolicySettings, RECOMMENDED_BITLOCKER_POLICY, IntuneAssignmentTarget } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { EmptyStateRow } from "../common/EmptyStateRow";
import { SyncErrorBanner } from "../common/SyncErrorBanner";
import { getSyncErrorsForPrefixes } from "@/lib/utils/sync-errors";
import { computeIntuneCoverageGaps } from "@/lib/services/intune-coverage-analyzer";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import {
  ShieldCheck,
  Search,
  Download,
  Info,
  CheckCircle2,
  XCircle,
  Lock,
  Unlock,
  Smartphone,
  Apple,
  MonitorSmartphone,
  Users,
  ShieldOff,
  Loader2,
  Rocket,
  Pencil,
  Sparkles,
  Copy,
  Check,
} from "lucide-react";

interface DefenderConfigurationModuleProps {
  snapshot: TenantSecuritySnapshot;
}

// A toggle row's display. Phase 1 was reporting-only; Phase 2 adds an
// optional edit affordance (onToggle) shown only when the caller passes it
// (write-enabled mode + the field is actually PATCH-able) - MdeConnectorSettings
// has no report-only concept, so a click here fires immediately, not a draft.
const SettingRow: React.FC<{
  label: string;
  enabled: boolean | undefined;
  hint?: string;
  onToggle?: () => void;
  saving?: boolean;
}> = ({ label, enabled, hint, onToggle, saving }) => (
  <div className="flex items-center justify-between gap-3 py-1.5 border-b border-slate-100 dark:border-slate-800 last:border-0">
    <div className="flex-1 min-w-0">
      <div className="text-xs text-slate-700 dark:text-slate-300">{label}</div>
      {hint && <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">{hint}</div>}
    </div>
    <div className="flex items-center gap-1.5 shrink-0">
      {enabled === undefined ? (
        <span className="text-[11px] text-slate-400 dark:text-slate-500 font-mono shrink-0">N/A</span>
      ) : (
        <span
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono font-semibold rounded-sm border shrink-0 ${
            enabled
              ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800"
              : "bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-300 dark:border-slate-700"
          }`}
        >
          {enabled ? <CheckCircle2 size={10} /> : <XCircle size={10} />}
          <span>{enabled ? "Enabled" : "Disabled"}</span>
        </span>
      )}
      {onToggle && (
        <button
          onClick={onToggle}
          disabled={saving}
          title="Toggle this MDE connector setting - takes effect immediately, tenant-wide (no report-only preview exists for this resource)"
          className="p-0.5 text-slate-400 hover:text-amber-600 dark:hover:text-amber-400 disabled:opacity-50"
        >
          {saving ? <Loader2 size={11} className="animate-spin" /> : <Pencil size={11} />}
        </button>
      )}
    </div>
  </div>
);

const ONBOARDING_STATE_LABEL: Record<string, { label: string; status: "pass" | "warn" | "fail" | "info" }> = {
  compliant: { label: "Onboarded", status: "pass" },
  remediated: { label: "Onboarded (Remediated)", status: "pass" },
  notApplicable: { label: "Not Applicable", status: "info" },
  nonCompliant: { label: "Not Onboarded", status: "warn" },
  notAssigned: { label: "Not Assigned", status: "warn" },
  error: { label: "Error", status: "fail" },
  conflict: { label: "Conflict", status: "fail" },
  unknown: { label: "Unknown", status: "info" },
};

// Labels are Microsoft's own Settings Catalog displayName strings, verbatim -
// read directly off a live tenant's catalog metadata (deviceManagement/
// configurationCategories + configurationSettings), not paraphrased, per an
// explicit user request to see exactly what each toggle actually is. See
// DEFENDER_AV_SETTING_DEFINITION_IDS in graph-client.ts for the settingDefinitionId
// each of these maps to.
const AV_SETTING_GROUPS: { label: string; fields: { key: keyof DefenderAvPolicySettings; label: string }[] }[] = [
  {
    label: "Real-time protection",
    fields: [
      { key: "allowRealtimeMonitoring", label: "Allow Realtime Monitoring" },
      { key: "allowBehaviorMonitoring", label: "Allow Behavior Monitoring" },
      { key: "allowCloudProtection", label: "Allow Cloud Protection" },
      { key: "allowIOAVProtection", label: "Allow scanning of all downloaded files and attachments" },
      { key: "allowScriptScanning", label: "Allow Script Scanning" },
      { key: "allowScanningNetworkFiles", label: "Allow Scanning Network Files" },
      { key: "allowEmailScanning", label: "Allow Email Scanning" },
    ],
  },
  {
    label: "Scan",
    fields: [
      { key: "allowArchiveScanning", label: "Allow Archive Scanning" },
      { key: "allowFullScanOnMappedNetworkDrives", label: "Allow Full Scan On Mapped Network Drives" },
      { key: "allowFullScanOnRemovableDrives", label: "Allow Full Scan Removable Drive Scanning" },
      { key: "enableLowCpuPriority", label: "Enable Low CPU Priority" },
      { key: "disableCatchupFullScan", label: "Disable Catchup Full Scan" },
      { key: "disableCatchupQuickScan", label: "Disable Catchup Quick Scan" },
      { key: "checkForSignaturesBeforeRunningScan", label: "Check For Signatures Before Running Scan" },
    ],
  },
  {
    label: "Updates",
    fields: [{ key: "allowUpdatesOnMeteredNetwork", label: "Metered Connection Updates" }],
  },
  {
    label: "Exclusions / Admin Merge",
    fields: [{ key: "disableLocalAdminMerge", label: "Disable Local Admin Merge" }],
  },
  {
    label: "User experience",
    fields: [{ key: "allowUserUIAccess", label: "Allow User UI Access" }],
  },
];

// Matches the Intune admin center's own Assignments picker wording
// verbatim ("Do Not Assign" / "Assign to All Users" / "Assign to All
// Devices" / "Assign to All Users and Devices"), per an explicit user
// request to see Microsoft's real option names - plus "a specific group",
// which the app already supported but the picker didn't previously expose
// as a distinct choice from "all licensed users".
const ASSIGNMENT_MODE_OPTIONS: { value: IntuneAssignmentTarget["mode"]; label: string }[] = [
  { value: "none", label: "Do Not Assign (recommended for a first deploy)" },
  { value: "allUsers", label: "Assign to All Users" },
  { value: "allDevices", label: "Assign to All Devices" },
  { value: "allUsersAndDevices", label: "Assign to All Users and Devices" },
  { value: "group", label: "A specific group" },
];

// Microsoft's own three real option labels for "Configure Recovery
// Password Rotation" - confirmed live against the setting's own choice
// option displayNames ("Refresh off (default)" / "Refresh on for Entra
// ID-joined devices" / "Refresh on for both Entra ID-joined and
// hybrid-joined devices"), reworded slightly tighter for a radio list.
const BITLOCKER_RECOVERY_ROTATION_OPTIONS: { value: BitLockerPolicySettings["recoveryPasswordRotation"]; label: string }[] = [
  { value: "off", label: "Off" },
  { value: "entraIdOnly", label: "On for Entra ID-joined devices (Microsoft's default when unset)" },
  { value: "entraIdAndHybrid", label: "On for Entra ID-joined and hybrid-joined devices" },
];

const EDR_ONBOARDING_LABEL: Record<string, string> = {
  onboarded: "Onboarded",
  canBeOnboarded: "Not Onboarded",
  unsupported: "Unsupported Platform",
  error: "Error",
};

export const DefenderConfigurationModule: React.FC<DefenderConfigurationModuleProps> = ({ snapshot }) => {
  const { intune, accountClassification, tenant } = snapshot;
  const defenderSyncErrors = getSyncErrorsForPrefixes(snapshot, [
    "MDE connector settings:",
    "MDE onboarding status:",
    "Intune Endpoint Security policies:",
    "Intune devices:",
  ]);
  const connector = intune.mdeConnectorSettings;
  const onboardingStates = intune.onboardingStates || [];

  const [onboardingSearch, setOnboardingSearch] = useState("");
  const [onboardingStatusFilter, setOnboardingStatusFilter] = useState<string>("all");
  const [savingMode, setSavingMode] = useState(false);
  const [copiedGapKey, setCopiedGapKey] = useState<string | null>(null);
  const [writeMode, setWriteMode] = useState<"read_only" | "write_enabled">(tenant.endpointSecurityWriteMode || "read_only");
  const writeEnabled = writeMode === "write_enabled";

  // Phase 2 write path - MDE connector settings have no report-only concept
  // at all (see plan/vault), so a toggle click here PATCHes immediately,
  // guarded by a confirm() rather than a draft/preview step.
  const [connectorFields, setConnectorFields] = useState(connector);
  useEffect(() => setConnectorFields(connector), [connector]);
  const [savingConnectorField, setSavingConnectorField] = useState<string | null>(null);

  const handleToggleConnectorField = async (field: keyof NonNullable<typeof connector>, label: string) => {
    if (!connectorFields || !connector) return;
    const currentValue = connectorFields[field];
    if (typeof currentValue !== "boolean") return;
    const nextValue = !currentValue;
    if (!window.confirm(`"${label}" will change to ${nextValue ? "Enabled" : "Disabled"} immediately, tenant-wide. Continue?`)) {
      return;
    }
    setSavingConnectorField(field as string);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/endpoint-security/mde-connector`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ connectorId: connector.id, patch: { [field]: nextValue } }),
      });
      const data = await res.json();
      if (data.success) {
        setConnectorFields((prev) => (prev ? { ...prev, [field]: nextValue } : prev));
      } else {
        window.alert(data.error || "Failed to update the connector setting.");
      }
    } catch (err: any) {
      window.alert(err.message || "Network error while updating the connector setting.");
    } finally {
      setSavingConnectorField(null);
    }
  };

  // Phase 2 write path - Defender Antivirus Settings Catalog policy.
  const [avPolicy, setAvPolicy] = useState<{ deployedPolicyId?: string; settings: DefenderAvPolicySettings } | null>(null);
  const [avLoading, setAvLoading] = useState(false);
  const [avDraft, setAvDraft] = useState<DefenderAvPolicySettings>({});
  const [avAssignmentMode, setAvAssignmentMode] = useState<IntuneAssignmentTarget["mode"]>("none");
  const [avGroupId, setAvGroupId] = useState("");
  const [avDeploying, setAvDeploying] = useState(false);
  const [avResult, setAvResult] = useState<{ success: boolean; message: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    setAvLoading(true);
    fetch(`/api/tenants/${tenant.id}/endpoint-security/defender-av-policy`)
      .then((res) => res.json())
      .then((data) => {
        if (cancelled) return;
        if (data.success) {
          setAvPolicy({ deployedPolicyId: data.deployedPolicyId, settings: data.settings || {} });
          setAvDraft(data.settings || {});
        }
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setAvLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [tenant.id]);

  const handleDeployAvPolicy = async () => {
    setAvDeploying(true);
    setAvResult(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/endpoint-security/defender-av-policy`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          settings: avDraft,
          assignment: { mode: avAssignmentMode, groupId: avGroupId || undefined } as IntuneAssignmentTarget,
        }),
      });
      const data = await res.json();
      setAvResult({ success: !!data.success, message: data.success ? data.message : data.error || "Deploy failed." });
      if (data.success) setAvPolicy({ deployedPolicyId: data.policyId, settings: avDraft });
    } catch (err: any) {
      setAvResult({ success: false, message: err.message || "Network error while deploying." });
    } finally {
      setAvDeploying(false);
    }
  };

  // Phase 2 write path - EDR policy ("Auto from connector" + Sample
  // Sharing). Mirrors the Defender Antivirus policy state/handlers above
  // exactly - see fetchEdrPolicy/deployEdrPolicy in graph-client.ts for the
  // confirmed Graph mechanics this reuses.
  const [edrPolicy, setEdrPolicy] = useState<{ deployedPolicyId?: string; settings: EdrPolicySettings } | null>(null);
  const [edrLoading, setEdrLoading] = useState(false);
  const [edrDraft, setEdrDraft] = useState<EdrPolicySettings>({});
  const [edrAssignmentMode, setEdrAssignmentMode] = useState<IntuneAssignmentTarget["mode"]>("none");
  const [edrGroupId, setEdrGroupId] = useState("");
  const [edrDeploying, setEdrDeploying] = useState(false);
  const [edrResult, setEdrResult] = useState<{ success: boolean; message: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    setEdrLoading(true);
    fetch(`/api/tenants/${tenant.id}/endpoint-security/edr-policy`)
      .then((res) => res.json())
      .then((data) => {
        if (cancelled) return;
        if (data.success) {
          setEdrPolicy({ deployedPolicyId: data.deployedPolicyId, settings: data.settings || {} });
          setEdrDraft(data.settings || {});
        }
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setEdrLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [tenant.id]);

  const handleDeployEdrPolicy = async () => {
    setEdrDeploying(true);
    setEdrResult(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/endpoint-security/edr-policy`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          settings: edrDraft,
          assignment: { mode: edrAssignmentMode, groupId: edrGroupId || undefined } as IntuneAssignmentTarget,
        }),
      });
      const data = await res.json();
      setEdrResult({ success: !!data.success, message: data.success ? data.message : data.error || "Deploy failed." });
      if (data.success) setEdrPolicy({ deployedPolicyId: data.policyId, settings: edrDraft });
    } catch (err: any) {
      setEdrResult({ success: false, message: err.message || "Network error while deploying." });
    } finally {
      setEdrDeploying(false);
    }
  };

  // Phase 2 write path - BitLocker policy (Require Device Encryption,
  // Allow Standard User Encryption, Allow Warning For Other Disk
  // Encryption, Configure Recovery Password Rotation). Mirrors the Defender
  // Antivirus/EDR policy state/handlers above exactly - see
  // fetchBitLockerPolicy/deployBitLockerPolicy in graph-client.ts for the
  // confirmed Graph mechanics this reuses.
  const [bitLockerPolicy, setBitLockerPolicy] = useState<{ deployedPolicyId?: string; settings: BitLockerPolicySettings } | null>(null);
  const [bitLockerLoading, setBitLockerLoading] = useState(false);
  const [bitLockerDraft, setBitLockerDraft] = useState<BitLockerPolicySettings>({});
  const [bitLockerAssignmentMode, setBitLockerAssignmentMode] = useState<IntuneAssignmentTarget["mode"]>("none");
  const [bitLockerGroupId, setBitLockerGroupId] = useState("");
  const [bitLockerDeploying, setBitLockerDeploying] = useState(false);
  const [bitLockerResult, setBitLockerResult] = useState<{ success: boolean; message: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    setBitLockerLoading(true);
    fetch(`/api/tenants/${tenant.id}/endpoint-security/bitlocker-policy`)
      .then((res) => res.json())
      .then((data) => {
        if (cancelled) return;
        if (data.success) {
          setBitLockerPolicy({ deployedPolicyId: data.deployedPolicyId, settings: data.settings || {} });
          setBitLockerDraft(data.settings || {});
        }
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setBitLockerLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [tenant.id]);

  const handleDeployBitLockerPolicy = async () => {
    setBitLockerDeploying(true);
    setBitLockerResult(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/endpoint-security/bitlocker-policy`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          settings: bitLockerDraft,
          assignment: { mode: bitLockerAssignmentMode, groupId: bitLockerGroupId || undefined } as IntuneAssignmentTarget,
        }),
      });
      const data = await res.json();
      setBitLockerResult({ success: !!data.success, message: data.success ? data.message : data.error || "Deploy failed." });
      if (data.success) setBitLockerPolicy({ deployedPolicyId: data.policyId, settings: bitLockerDraft });
    } catch (err: any) {
      setBitLockerResult({ success: false, message: err.message || "Network error while deploying." });
    } finally {
      setBitLockerDeploying(false);
    }
  };

  const coverageGaps = useMemo(
    () => computeIntuneCoverageGaps(accountClassification.users, intune.devices),
    [accountClassification.users, intune.devices]
  );

  const filteredOnboarding = useMemo(() => {
    return onboardingStates.filter((s) => {
      const q = onboardingSearch.toLowerCase();
      const matchesSearch =
        !q || s.deviceName.toLowerCase().includes(q) || (s.userPrincipalName || "").toLowerCase().includes(q);
      const matchesStatus = onboardingStatusFilter === "all" || s.state === onboardingStatusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [onboardingStates, onboardingSearch, onboardingStatusFilter]);

  const handleToggleWriteMode = async () => {
    const next = writeMode === "read_only" ? "write_enabled" : "read_only";
    setSavingMode(true);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ endpointSecurityWriteMode: next }),
      });
      const data = await res.json();
      if (data.success) setWriteMode(next);
    } finally {
      setSavingMode(false);
    }
  };

  const handleExportOnboardingCsv = () => {
    const headers = ["DeviceName", "UserPrincipalName", "Platform", "OnboardingState"];
    const rows = filteredOnboarding.map((s) => [s.deviceName, s.userPrincipalName || "", s.platformType || "", s.state]);
    exportToCsv(csvFilename("MdeOnboardingStatus", tenant.defaultDomainName), headers, rows);
  };

  const handleExportGapsCsv = () => {
    const headers = ["Category", "Identity", "Detail"];
    const rows: (string | number)[][] = [
      ...coverageGaps.usersWithoutIntuneDevice.map((u) => ["Missing from Intune", u.userPrincipalName, u.department]),
      ...coverageGaps.devicesWithoutEdr.map((d) => ["Missing EDR/AV", d.deviceName, `${d.userPrincipalName} - ${d.edrOnboardingState}`]),
    ];
    exportToCsv(csvFilename("IntuneCoverageGaps", tenant.defaultDomainName), headers, rows);
  };

  const handleCopyEmails = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedGapKey(key);
      setTimeout(() => setCopiedGapKey(null), 2000);
    } catch {
      // Clipboard write failed (e.g. permission denied) - don't show a
      // false "Copied" success state.
    }
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto select-none">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">Defender Configuration & Onboarding</h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Microsoft Defender for Endpoint connector settings, per-device onboarding status, and Intune/EDR coverage gaps.
          </p>
        </div>

        <button
          onClick={handleToggleWriteMode}
          disabled={savingMode}
          title="Deliberate per-tenant choice - deploy actions in a future release only appear when this is Write-Enabled AND the DeviceManagementConfiguration.ReadWrite.All permission is granted."
          className={`px-3 py-1.5 text-xs font-semibold rounded-sm flex items-center gap-1.5 transition-colors border shrink-0 ${
            writeMode === "write_enabled"
              ? "bg-amber-50 dark:bg-amber-950 text-amber-800 dark:text-amber-400 border-amber-300 dark:border-amber-800"
              : "bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-[#CBD5E1] dark:border-slate-700"
          }`}
        >
          {savingMode ? <Loader2 size={13} className="animate-spin" /> : writeMode === "write_enabled" ? <Unlock size={13} /> : <Lock size={13} />}
          <span>{writeMode === "write_enabled" ? "Write-Enabled" : "Read-Only"}</span>
        </button>
      </div>

      <SyncErrorBanner errors={defenderSyncErrors} title="Defender/Intune sync error - data below may be stale" />

      {/* Write-mode disclosure */}
      <div className="flex items-start gap-2 p-2.5 bg-sky-50 dark:bg-sky-950 border border-sky-300 dark:border-sky-800 rounded-sm text-[11px] text-sky-900 dark:text-sky-300">
        <Info size={13} className="text-sky-600 dark:text-sky-400 shrink-0 mt-0.5" />
        <span>
          {writeEnabled
            ? "Write-Enabled mode is on. MDE connector toggles below apply immediately (tenant-wide, no preview). Defender Antivirus policy changes deploy as a Settings Catalog policy you assign yourself - nothing is auto-assigned."
            : "This module is reporting live state only. Turn on Write-Enabled mode above (plus the DeviceManagementConfiguration.ReadWrite.All permission) to configure MDE connector settings and deploy a Defender Antivirus policy directly."}
        </span>
      </div>

      {/* MDE Connector Settings */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Microsoft Defender for Endpoint Connector Settings
          </h3>
        </div>

        {!connector || !connectorFields ? (
          <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400">
            <ShieldOff size={20} className="mx-auto text-slate-400 dark:text-slate-500 mb-1" />
            No MDE connector configured for this tenant yet (or this snapshot predates this feature - sync to refresh).
          </div>
        ) : (
          <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1.5">
                <ShieldCheck size={12} />
                <span>General</span>
              </div>
              {/* Confirmed verbatim against Microsoft's own Intune admin center + Learn docs (configure-integration.md). */}
              <SettingRow
                label="Allow Microsoft Defender for Endpoint to enforce Endpoint Security Configurations"
                enabled={connectorFields.microsoftDefenderForEndpointAttachEnabled}
                onToggle={writeEnabled ? () => handleToggleConnectorField("microsoftDefenderForEndpointAttachEnabled", "Allow Microsoft Defender for Endpoint to enforce Endpoint Security Configurations") : undefined}
                saving={savingConnectorField === "microsoftDefenderForEndpointAttachEnabled"}
              />
              {/* Not independently confirmed verbatim - closest available label. */}
              <SettingRow
                label="Block unsupported OS versions"
                enabled={connectorFields.partnerUnsupportedOsVersionBlocked}
                onToggle={writeEnabled ? () => handleToggleConnectorField("partnerUnsupportedOsVersionBlocked", "Block unsupported OS versions") : undefined}
                saving={savingConnectorField === "partnerUnsupportedOsVersionBlocked"}
              />
              <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-1.5">
                Partner state: <span className="font-mono">{connector.partnerState}</span>
                {connector.lastHeartbeatDateTime && ` · Last heartbeat: ${new Date(connector.lastHeartbeatDateTime).toLocaleString()}`}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1.5">
                <MonitorSmartphone size={12} />
                <span>Windows</span>
              </div>
              {/* "Connect Windows devices version 10.0.15063 and above to Microsoft Defender for
                  Endpoint (Compliance)" - confirmed verbatim against the live Intune admin center. */}
              <SettingRow
                label="Connect Windows devices version 10.0.15063 and above to Microsoft Defender for Endpoint (Compliance)"
                enabled={connectorFields.windowsEnabled}
                onToggle={writeEnabled ? () => handleToggleConnectorField("windowsEnabled", "Connect Windows devices to Microsoft Defender for Endpoint (Compliance)") : undefined}
                saving={savingConnectorField === "windowsEnabled"}
              />
              {/* Same base label, MAM variant - pattern-matched from the confirmed Compliance
                  label above, not independently confirmed on its own. */}
              <SettingRow
                label="Connect Windows devices version 10.0.15063 and above to Microsoft Defender for Endpoint (MAM)"
                enabled={connectorFields.windowsMobileApplicationManagementEnabled}
              />
              <SettingRow
                label="Block Windows devices version 10.0.15063 and above access to enterprise resources when the device compliance state is unavailable"
                enabled={connectorFields.windowsDeviceBlockedOnMissingPartnerData}
                onToggle={writeEnabled ? () => handleToggleConnectorField("windowsDeviceBlockedOnMissingPartnerData", "Block Windows access when Microsoft Defender for Endpoint reports as unavailable") : undefined}
                saving={savingConnectorField === "windowsDeviceBlockedOnMissingPartnerData"}
              />
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1.5">
                <Smartphone size={12} />
                <span>Android</span>
              </div>
              {/* "Connect Android devices to Defender for Endpoint" - confirmed verbatim
                  (Compliance policy evaluation section) against Microsoft Learn's
                  configure-integration.md; same label text repeats under App protection
                  policy evaluation for the MAM variant below. */}
              <SettingRow
                label="Connect Android devices to Defender for Endpoint"
                hint="Compliance policy evaluation"
                enabled={connectorFields.androidEnabled}
                onToggle={writeEnabled ? () => handleToggleConnectorField("androidEnabled", "Connect Android devices to Defender for Endpoint (Compliance policy evaluation)") : undefined}
                saving={savingConnectorField === "androidEnabled"}
              />
              <SettingRow
                label="Connect Android devices to Defender for Endpoint"
                hint="App protection policy evaluation"
                enabled={connectorFields.androidMobileApplicationManagementEnabled}
              />
              <SettingRow
                label="Block Android access when Microsoft Defender for Endpoint reports as unavailable"
                enabled={connectorFields.androidDeviceBlockedOnMissingPartnerData}
                onToggle={writeEnabled ? () => handleToggleConnectorField("androidDeviceBlockedOnMissingPartnerData", "Block Android access when Microsoft Defender for Endpoint reports as unavailable") : undefined}
                saving={savingConnectorField === "androidDeviceBlockedOnMissingPartnerData"}
              />
              <SettingRow
                label="Mobile Threat Defense role"
                enabled={undefined}
                hint="Not exposed via Microsoft Graph - configure in the Intune admin center directly."
              />
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1.5">
                <Apple size={12} />
                <span>iOS / iPadOS</span>
              </div>
              {/* "Connect iOS/iPadOS devices to Defender for Endpoint" - confirmed verbatim,
                  same pattern as Android above. */}
              <SettingRow
                label="Connect iOS/iPadOS devices to Defender for Endpoint"
                hint="Compliance policy evaluation"
                enabled={connectorFields.iosEnabled}
                onToggle={writeEnabled ? () => handleToggleConnectorField("iosEnabled", "Connect iOS/iPadOS devices to Defender for Endpoint (Compliance policy evaluation)") : undefined}
                saving={savingConnectorField === "iosEnabled"}
              />
              <SettingRow
                label="Connect iOS/iPadOS devices to Defender for Endpoint"
                hint="App protection policy evaluation"
                enabled={connectorFields.iosMobileApplicationManagementEnabled}
              />
              <SettingRow
                label="Block iOS access when Microsoft Defender for Endpoint reports as unavailable"
                enabled={connectorFields.iosDeviceBlockedOnMissingPartnerData}
                onToggle={writeEnabled ? () => handleToggleConnectorField("iosDeviceBlockedOnMissingPartnerData", "Block iOS access when Microsoft Defender for Endpoint reports as unavailable") : undefined}
                saving={savingConnectorField === "iosDeviceBlockedOnMissingPartnerData"}
              />
              {/* Both confirmed verbatim against configure-integration.md's "Additional iOS settings" tip. */}
              <SettingRow label="App Sync for iOS Devices" enabled={connectorFields.allowPartnerToCollectIOSApplicationMetadata} />
              <SettingRow label="Send full application inventory data on personally owned iOS/iPadOS Devices" enabled={connectorFields.allowPartnerToCollectIOSPersonalApplicationMetadata} />
              {/* Not independently confirmed - closest available label. */}
              <SettingRow label="Certificate Sync" enabled={connectorFields.allowPartnerToCollectIosCertificateMetadata} />
              <SettingRow label="Send full certificate inventory on personally-owned devices" enabled={connectorFields.allowPartnerToCollectIosPersonalCertificateMetadata} />
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1.5">
                <Apple size={12} />
                <span>macOS</span>
              </div>
              {/* Not independently confirmed - closest available label. */}
              <SettingRow
                label="Connect Mac devices to Defender for Endpoint"
                enabled={connectorFields.macEnabled}
                onToggle={writeEnabled ? () => handleToggleConnectorField("macEnabled", "Connect Mac devices to Defender for Endpoint") : undefined}
                saving={savingConnectorField === "macEnabled"}
              />
              <SettingRow label="Block Mac access when Microsoft Defender for Endpoint reports as unavailable" enabled={connectorFields.macDeviceBlockedOnMissingPartnerData} />
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1.5">
                <Info size={12} />
                <span>EDR Policy</span>
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed space-y-1.5">
                <div>
                  <strong className="text-slate-700 dark:text-slate-300">Microsoft Defender for Endpoint client configuration package type</strong> ("Auto
                  from connector") and <strong className="text-slate-700 dark:text-slate-300">Sample Sharing</strong> are real, deployable Intune
                  settings after all - see the <strong className="text-slate-700 dark:text-slate-300">EDR Policy</strong> section below. (An earlier
                  version of this module said both were non-configurable via Graph - that was wrong, corrected after a live catalog lookup.)
                </div>
                <div>
                  <strong className="text-slate-700 dark:text-slate-300">Mobile Threat Defense role</strong> (Android COBO/COPE) is genuinely not
                  exposed via Microsoft Graph - configure it in the Intune admin center directly.
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Defender Antivirus Policy (Phase 2 write path) */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Defender Antivirus Policy</h3>
          {avPolicy?.deployedPolicyId && (
            <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">Deployed policy: {avPolicy.deployedPolicyId}</span>
          )}
        </div>

        {avLoading ? (
          <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400 flex items-center justify-center gap-1.5">
            <Loader2 size={13} className="animate-spin" />
            <span>Loading current policy state...</span>
          </div>
        ) : !writeEnabled ? (
          <div className="p-4 text-xs text-slate-500 dark:text-slate-400">
            {avPolicy?.deployedPolicyId
              ? "A Clarity365-deployed Defender Antivirus policy exists (shown above). Turn on Write-Enabled mode to change it."
              : "No Clarity365-deployed Defender Antivirus policy found. Turn on Write-Enabled mode above (plus the DeviceManagementConfiguration.ReadWrite.All permission) to deploy one."}
          </div>
        ) : (
          <div className="p-4 space-y-4">
            {AV_SETTING_GROUPS.map((group) => (
              <div key={group.label}>
                <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">{group.label}</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6">
                  {group.fields.map(({ key, label }) => (
                    <label key={key} className="flex items-center gap-2 py-1 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={avDraft[key] === true}
                        onChange={(e) => setAvDraft((prev) => ({ ...prev, [key]: e.target.checked }))}
                      />
                      <span>{label}</span>
                    </label>
                  ))}
                </div>
              </div>
            ))}

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">Assignment</div>
              <div className="space-y-1.5">
                {ASSIGNMENT_MODE_OPTIONS.map((opt) => (
                  <label key={opt.value} className="flex items-center gap-2 text-[11px] text-slate-700 dark:text-slate-300 cursor-pointer">
                    <input
                      type="radio"
                      name="av-assignment-mode"
                      checked={avAssignmentMode === opt.value}
                      onChange={() => setAvAssignmentMode(opt.value)}
                    />
                    <span>{opt.label}</span>
                  </label>
                ))}
                {avAssignmentMode === "group" && (
                  <input
                    type="text"
                    placeholder="Entra group ID (GUID)"
                    value={avGroupId}
                    onChange={(e) => setAvGroupId(e.target.value)}
                    className="ml-6 mt-1 px-2 py-1 text-[11px] font-mono border border-[#CBD5E1] dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 w-full max-w-xs"
                  />
                )}
              </div>
            </div>

            {avResult && (
              <div
                className={`p-2.5 rounded-sm border text-[11px] ${
                  avResult.success
                    ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800"
                    : "bg-rose-50 dark:bg-red-950 text-rose-800 dark:text-red-300 border-rose-300 dark:border-red-800"
                }`}
              >
                {avResult.message}
              </div>
            )}

            <button
              onClick={handleDeployAvPolicy}
              disabled={avDeploying}
              className="px-3 py-2 text-xs font-semibold rounded-sm flex items-center justify-center gap-1.5 bg-amber-600 hover:bg-amber-700 disabled:opacity-60 text-white"
            >
              {avDeploying ? <Loader2 size={13} className="animate-spin" /> : <Rocket size={13} />}
              <span>{avDeploying ? "Deploying..." : avPolicy?.deployedPolicyId ? "Redeploy Policy" : "Deploy Policy"}</span>
            </button>
          </div>
        )}
      </div>

      {/* EDR Policy (Phase 2 write path) - "Microsoft Defender for Endpoint
          client configuration package type" (Auto from connector) and
          "Sample Sharing", both confirmed real, assignable Settings Catalog
          settings via a live tenant catalog lookup - see
          EDR_CONFIGURATION_TYPE_SETTING_ID/EDR_SAMPLE_SHARING_SETTING_ID in
          graph-client.ts. */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">EDR Policy</h3>
          {edrPolicy?.deployedPolicyId && (
            <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">Deployed policy: {edrPolicy.deployedPolicyId}</span>
          )}
        </div>

        {edrLoading ? (
          <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400 flex items-center justify-center gap-1.5">
            <Loader2 size={13} className="animate-spin" />
            <span>Loading current policy state...</span>
          </div>
        ) : !writeEnabled ? (
          <div className="p-4 text-xs text-slate-500 dark:text-slate-400">
            {edrPolicy?.deployedPolicyId
              ? "A Clarity365-deployed EDR policy exists (shown above). Turn on Write-Enabled mode to change it."
              : "No Clarity365-deployed EDR policy found. Turn on Write-Enabled mode above (plus the DeviceManagementConfiguration.ReadWrite.All permission) to deploy one."}
          </div>
        ) : (
          <div className="p-4 space-y-4">
            <label className="flex items-start gap-2 py-1 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={edrDraft.autoFromConnector === true}
                onChange={(e) => setEdrDraft((prev) => ({ ...prev, autoFromConnector: e.target.checked }))}
                className="mt-0.5"
              />
              <span>
                <span className="block">Microsoft Defender for Endpoint client configuration package type: Auto from connector</span>
                <span className="block text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                  Onboards Windows devices using the automatic package from the connected Defender for Endpoint tenant - the
                  recommended option. "Onboard"/"Offboard" (a manually pasted blob file) aren't supported here; use the Intune
                  admin center directly for those.
                </span>
              </span>
            </label>

            <label className="flex items-start gap-2 py-1 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={edrDraft.sampleSharingAll === true}
                onChange={(e) => setEdrDraft((prev) => ({ ...prev, sampleSharingAll: e.target.checked }))}
                className="mt-0.5"
              />
              <span>
                <span className="block">Sample Sharing: All</span>
                <span className="block text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                  Sends suspicious file samples to Microsoft for deep analysis. Leave unchecked to set Sample Sharing to None.
                </span>
              </span>
            </label>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">Assignment</div>
              <div className="space-y-1.5">
                {ASSIGNMENT_MODE_OPTIONS.map((opt) => (
                  <label key={opt.value} className="flex items-center gap-2 text-[11px] text-slate-700 dark:text-slate-300 cursor-pointer">
                    <input
                      type="radio"
                      name="edr-assignment-mode"
                      checked={edrAssignmentMode === opt.value}
                      onChange={() => setEdrAssignmentMode(opt.value)}
                    />
                    <span>{opt.label}</span>
                  </label>
                ))}
                {edrAssignmentMode === "group" && (
                  <input
                    type="text"
                    placeholder="Entra group ID (GUID)"
                    value={edrGroupId}
                    onChange={(e) => setEdrGroupId(e.target.value)}
                    className="ml-6 mt-1 px-2 py-1 text-[11px] font-mono border border-[#CBD5E1] dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 w-full max-w-xs"
                  />
                )}
              </div>
            </div>

            {edrResult && (
              <div
                className={`p-2.5 rounded-sm border text-[11px] ${
                  edrResult.success
                    ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800"
                    : "bg-rose-50 dark:bg-red-950 text-rose-800 dark:text-red-300 border-rose-300 dark:border-red-800"
                }`}
              >
                {edrResult.message}
              </div>
            )}

            <button
              onClick={handleDeployEdrPolicy}
              disabled={edrDeploying}
              className="px-3 py-2 text-xs font-semibold rounded-sm flex items-center justify-center gap-1.5 bg-amber-600 hover:bg-amber-700 disabled:opacity-60 text-white"
            >
              {edrDeploying ? <Loader2 size={13} className="animate-spin" /> : <Rocket size={13} />}
              <span>{edrDeploying ? "Deploying..." : edrPolicy?.deployedPolicyId ? "Redeploy Policy" : "Deploy Policy"}</span>
            </button>
          </div>
        )}
      </div>

      {/* BitLocker Policy (Phase 2 write path) - Require Device Encryption,
          Allow Standard User Encryption, Allow Warning For Other Disk
          Encryption, and Configure Recovery Password Rotation, all
          confirmed real, assignable Settings Catalog settings via a live
          tenant catalog lookup - see BITLOCKER_BOOLEAN_SETTING_DEFINITION_IDS/
          BITLOCKER_RECOVERY_ROTATION_SETTING_ID in graph-client.ts. Uses the
          direct BitLocker CSP category, not the separate "BitLocker Drive
          Encryption" Administrative Templates/GPO category. */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">BitLocker Policy</h3>
          {bitLockerPolicy?.deployedPolicyId && (
            <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">Deployed policy: {bitLockerPolicy.deployedPolicyId}</span>
          )}
        </div>

        {bitLockerLoading ? (
          <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400 flex items-center justify-center gap-1.5">
            <Loader2 size={13} className="animate-spin" />
            <span>Loading current policy state...</span>
          </div>
        ) : !writeEnabled ? (
          <div className="p-4 text-xs text-slate-500 dark:text-slate-400">
            {bitLockerPolicy?.deployedPolicyId
              ? "A Clarity365-deployed BitLocker policy exists (shown above). Turn on Write-Enabled mode to change it."
              : "No Clarity365-deployed BitLocker policy found. Turn on Write-Enabled mode above (plus the DeviceManagementConfiguration.ReadWrite.All permission) to deploy one."}
          </div>
        ) : (
          <div className="p-4 space-y-4">
            <button
              onClick={() => setBitLockerDraft(RECOMMENDED_BITLOCKER_POLICY)}
              title="Fills the form below with Clarity365's recommended BitLocker baseline - review before deploying, nothing is applied until you click Deploy Policy."
              className="px-2.5 py-1.5 text-xs font-medium text-indigo-800 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950 hover:bg-indigo-100 dark:hover:bg-indigo-900 border border-indigo-300 dark:border-indigo-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
            >
              <Sparkles size={13} />
              <span>Use Recommended Settings</span>
            </button>

            <label className="flex items-start gap-2 py-1 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={bitLockerDraft.requireDeviceEncryption === true}
                onChange={(e) => setBitLockerDraft((prev) => ({ ...prev, requireDeviceEncryption: e.target.checked }))}
                className="mt-0.5"
              />
              <span>
                <span className="block">Require Device Encryption</span>
                <span className="block text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                  The actual on/off switch for BitLocker device encryption. Disabling this later will not turn off encryption
                  already in place - it only stops prompting users to turn it on.
                </span>
              </span>
            </label>

            <label className="flex items-start gap-2 py-1 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={bitLockerDraft.allowStandardUserEncryption === true}
                onChange={(e) => setBitLockerDraft((prev) => ({ ...prev, allowStandardUserEncryption: e.target.checked }))}
                className="mt-0.5"
              />
              <span>
                <span className="block">Allow Standard User Encryption</span>
                <span className="block text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                  Lets Require Device Encryption succeed even when the currently signed-in user is a standard (non-admin)
                  user. Per Microsoft's own documentation this only takes effect when "Allow Warning For Other Disk
                  Encryption" below is also unchecked (silent encryption) - the two are functionally paired.
                </span>
              </span>
            </label>

            <label className="flex items-start gap-2 py-1 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={bitLockerDraft.allowWarningForOtherDiskEncryption === true}
                onChange={(e) => setBitLockerDraft((prev) => ({ ...prev, allowWarningForOtherDiskEncryption: e.target.checked }))}
                className="mt-0.5"
              />
              <span>
                <span className="block">Allow Warning For Other Disk Encryption</span>
                <span className="block text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                  Checked (Microsoft's own default when unset) shows the encryption notification/warning prompt to the user.
                  Leave unchecked for silent encryption with no user-facing prompts - required for "Allow Standard User
                  Encryption" above to actually work.
                </span>
              </span>
            </label>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">
                Configure Recovery Password Rotation
              </div>
              <div className="space-y-1.5">
                {BITLOCKER_RECOVERY_ROTATION_OPTIONS.map((opt) => (
                  <label key={opt.value} className="flex items-center gap-2 text-[11px] text-slate-700 dark:text-slate-300 cursor-pointer">
                    <input
                      type="radio"
                      name="bitlocker-recovery-rotation"
                      checked={bitLockerDraft.recoveryPasswordRotation === opt.value}
                      onChange={() => setBitLockerDraft((prev) => ({ ...prev, recoveryPasswordRotation: opt.value }))}
                    />
                    <span>{opt.label}</span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">Assignment</div>
              <div className="space-y-1.5">
                {ASSIGNMENT_MODE_OPTIONS.map((opt) => (
                  <label key={opt.value} className="flex items-center gap-2 text-[11px] text-slate-700 dark:text-slate-300 cursor-pointer">
                    <input
                      type="radio"
                      name="bitlocker-assignment-mode"
                      checked={bitLockerAssignmentMode === opt.value}
                      onChange={() => setBitLockerAssignmentMode(opt.value)}
                    />
                    <span>{opt.label}</span>
                  </label>
                ))}
                {bitLockerAssignmentMode === "group" && (
                  <input
                    type="text"
                    placeholder="Entra group ID (GUID)"
                    value={bitLockerGroupId}
                    onChange={(e) => setBitLockerGroupId(e.target.value)}
                    className="ml-6 mt-1 px-2 py-1 text-[11px] font-mono border border-[#CBD5E1] dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 w-full max-w-xs"
                  />
                )}
              </div>
            </div>

            {bitLockerResult && (
              <div
                className={`p-2.5 rounded-sm border text-[11px] ${
                  bitLockerResult.success
                    ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800"
                    : "bg-rose-50 dark:bg-red-950 text-rose-800 dark:text-red-300 border-rose-300 dark:border-red-800"
                }`}
              >
                {bitLockerResult.message}
              </div>
            )}

            <button
              onClick={handleDeployBitLockerPolicy}
              disabled={bitLockerDeploying}
              className="px-3 py-2 text-xs font-semibold rounded-sm flex items-center justify-center gap-1.5 bg-amber-600 hover:bg-amber-700 disabled:opacity-60 text-white"
            >
              {bitLockerDeploying ? <Loader2 size={13} className="animate-spin" /> : <Rocket size={13} />}
              <span>{bitLockerDeploying ? "Deploying..." : bitLockerPolicy?.deployedPolicyId ? "Redeploy Policy" : "Deploy Policy"}</span>
            </button>
          </div>
        )}
      </div>

      {/* Onboarding Status */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            MDE Onboarding Status by Device
          </h3>
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Search size={12} className="absolute left-2 top-1.5 text-slate-400 dark:text-slate-500" />
              <input
                type="text"
                placeholder="Search device or user..."
                value={onboardingSearch}
                onChange={(e) => setOnboardingSearch(e.target.value)}
                className="pl-6 pr-2 py-1 text-[11px] border border-[#CBD5E1] dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
              />
            </div>
            <select
              value={onboardingStatusFilter}
              onChange={(e) => setOnboardingStatusFilter(e.target.value)}
              className="px-2 py-1 text-[11px] border border-[#CBD5E1] dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
            >
              <option value="all">All States</option>
              {Object.keys(ONBOARDING_STATE_LABEL).map((s) => (
                <option key={s} value={s}>
                  {ONBOARDING_STATE_LABEL[s].label}
                </option>
              ))}
            </select>
            {onboardingStates.length > 0 && (
              <button
                onClick={handleExportOnboardingCsv}
                className="px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1"
              >
                <Download size={11} />
                <span>Export</span>
              </button>
            )}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>Device</th>
                <th>User</th>
                <th>Platform</th>
                <th className="text-right">Onboarding State</th>
              </tr>
            </thead>
            <tbody>
              {filteredOnboarding.length === 0 ? (
                <EmptyStateRow colSpan={4} entityLabel="onboarding records" isFiltered={onboardingSearch.trim().length > 0 || onboardingStatusFilter !== "all"} />
              ) : (
                filteredOnboarding.map((s, idx) => {
                  const meta = ONBOARDING_STATE_LABEL[s.state] || ONBOARDING_STATE_LABEL.unknown;
                  return (
                    <tr key={`${s.deviceName}-${idx}`} className="hover:bg-slate-50 dark:hover:bg-slate-700">
                      <td className="text-xs font-semibold text-slate-900 dark:text-slate-100">{s.deviceName}</td>
                      <td className="text-[11px] font-mono text-slate-600 dark:text-slate-400">{s.userPrincipalName || "-"}</td>
                      <td className="text-xs text-slate-700 dark:text-slate-300">{s.platformType || "-"}</td>
                      <td className="text-right">
                        <StatusPill status={meta.status} label={meta.label} size="sm" />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Coverage Gaps */}
      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-2xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">Intune & EDR Coverage Gaps</h3>
          {(coverageGaps.usersWithoutIntuneDevice.length > 0 || coverageGaps.devicesWithoutEdr.length > 0) && (
            <button
              onClick={handleExportGapsCsv}
              className="px-2 py-1 text-[11px] font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1"
            >
              <Download size={11} />
              <span>Export</span>
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-slate-200 dark:divide-slate-700">
          <div className="p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 flex items-center gap-1.5">
                <Users size={12} />
                <span>Licensed Users Missing from Intune ({coverageGaps.usersWithoutIntuneDevice.length})</span>
              </div>
              {coverageGaps.usersWithoutIntuneDevice.length > 0 && (
                <button
                  onClick={() =>
                    handleCopyEmails(coverageGaps.usersWithoutIntuneDevice.map((u) => u.userPrincipalName).join("; "), "all-users")
                  }
                  title="Copy all email addresses in this list (semicolon-separated, ready to paste into a To: field)"
                  className="px-1.5 py-0.5 text-[10px] font-medium text-slate-600 dark:text-slate-400 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1 shrink-0"
                >
                  {copiedGapKey === "all-users" ? <Check size={10} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={10} />}
                  <span>{copiedGapKey === "all-users" ? "Copied" : "Copy All"}</span>
                </button>
              )}
            </div>
            {coverageGaps.usersWithoutIntuneDevice.length === 0 ? (
              <div className="text-[11px] text-slate-400 dark:text-slate-500 italic">Every licensed, enabled user has at least one enrolled device.</div>
            ) : (
              <div className="space-y-1 max-h-72 overflow-y-auto">
                {coverageGaps.usersWithoutIntuneDevice.map((u) => (
                  <div
                    key={u.userId}
                    className="p-1.5 bg-amber-50/60 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 rounded-sm text-[11px] flex items-start justify-between gap-2"
                  >
                    <div>
                      <span className="font-semibold text-slate-900 dark:text-slate-100">{u.displayName}</span>{" "}
                      <span className="text-slate-500 dark:text-slate-400">({u.department})</span>
                      <div className="font-mono text-slate-600 dark:text-slate-400">{u.userPrincipalName}</div>
                    </div>
                    <button
                      onClick={() => handleCopyEmails(u.userPrincipalName, `user-${u.userId}`)}
                      title="Copy this user's email address"
                      className="p-1 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-white dark:hover:bg-slate-800 rounded-sm shrink-0"
                    >
                      {copiedGapKey === `user-${u.userId}` ? (
                        <Check size={12} className="text-emerald-600 dark:text-emerald-400" />
                      ) : (
                        <Copy size={12} />
                      )}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 flex items-center gap-1.5">
                <ShieldOff size={12} />
                <span>Devices Missing EDR/AV Coverage ({coverageGaps.devicesWithoutEdr.length})</span>
              </div>
              {coverageGaps.devicesWithoutEdr.length > 0 && (
                <button
                  onClick={() =>
                    handleCopyEmails(
                      [...new Set(coverageGaps.devicesWithoutEdr.map((d) => d.userPrincipalName).filter(Boolean))].join("; "),
                      "all-devices"
                    )
                  }
                  title="Copy all email addresses in this list (semicolon-separated, ready to paste into a To: field, deduplicated for devices sharing an owner)"
                  className="px-1.5 py-0.5 text-[10px] font-medium text-slate-600 dark:text-slate-400 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-[#CBD5E1] dark:border-slate-700 rounded-sm flex items-center gap-1 shrink-0"
                >
                  {copiedGapKey === "all-devices" ? <Check size={10} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={10} />}
                  <span>{copiedGapKey === "all-devices" ? "Copied" : "Copy All"}</span>
                </button>
              )}
            </div>
            {coverageGaps.devicesWithoutEdr.length === 0 ? (
              <div className="text-[11px] text-slate-400 dark:text-slate-500 italic">Every enrolled device (that can support MDE) is onboarded.</div>
            ) : (
              <div className="space-y-1 max-h-72 overflow-y-auto">
                {coverageGaps.devicesWithoutEdr.map((d) => (
                  <div
                    key={d.id}
                    className="p-1.5 bg-rose-50/60 dark:bg-red-950/40 border border-rose-200 dark:border-red-800 rounded-sm text-[11px] flex items-start justify-between gap-2"
                  >
                    <div>
                      <span className="font-semibold text-slate-900 dark:text-slate-100">{d.deviceName}</span>{" "}
                      <span className="text-slate-500 dark:text-slate-400">({d.operatingSystem})</span>
                      <div className="font-mono text-slate-600 dark:text-slate-400">
                        {d.userPrincipalName} - {EDR_ONBOARDING_LABEL[d.edrOnboardingState] || d.edrOnboardingState}
                      </div>
                    </div>
                    {d.userPrincipalName && (
                      <button
                        onClick={() => handleCopyEmails(d.userPrincipalName, `device-${d.id}`)}
                        title="Copy this device owner's email address"
                        className="p-1 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-white dark:hover:bg-slate-800 rounded-sm shrink-0"
                      >
                        {copiedGapKey === `device-${d.id}` ? (
                          <Check size={12} className="text-emerald-600 dark:text-emerald-400" />
                        ) : (
                          <Copy size={12} />
                        )}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
