import React, { useState, useEffect, useRef } from "react";
import { Modal } from "../common/Modal";
import { StatusPill } from "../common/StatusPill";
import { Tenant } from "@/lib/types";
import { TenantPermissionReport } from "@/lib/services/graph-client";
import { DeviceCodeStart, ExoConnectivityResult } from "@/lib/services/exo-client";
import { EXCHANGE_ROLE_LABEL, getExchangeAccess } from "@/lib/utils/exchange-access";
import { ShieldCheck, RefreshCw, AlertTriangle, CheckCircle, ExternalLink, Key, Mail, Copy, Check, Info } from "lucide-react";
import { getSecretExpiryStatus } from "@/lib/utils/credential-expiry";

interface PermissionsModalProps {
  isOpen: boolean;
  onClose: () => void;
  tenant: Tenant;
}

export const PermissionsModal: React.FC<PermissionsModalProps> = ({
  isOpen,
  onClose,
  tenant,
}) => {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<TenantPermissionReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Exchange Online: app-only access through this app registration
  // (Exchange.ManageAsApp + an Entra role, no sign-in) is the normal path; the
  // older device-code admin sign-in stays as an optional fallback. See
  // ai-context-vault/Optimization/Exchange App-Only Access Plan.md.
  const [exoDeviceInfo, setExoDeviceInfo] = useState<DeviceCodeStart | null>(null);
  const [exoPollStatus, setExoPollStatus] = useState<"idle" | "starting" | "pending" | "error" | "expired" | "declined">("idle");
  const [exoPollError, setExoPollError] = useState<string | null>(null);
  const [exoCodeCopied, setExoCodeCopied] = useState(false);
  const [exoTesting, setExoTesting] = useState(false);
  const [exoResult, setExoResult] = useState<ExoConnectivityResult | null>(null);
  const [showSignInFallback, setShowSignInFallback] = useState(false);
  // Off by default even when connected - see types/index.ts's TenantCredentials.exoWriteEnabled
  // comment for why this needs to be an explicit, separately-persisted opt-in
  // rather than something that turns on automatically once EXO is connected.
  const [exoWriteEnabled, setExoWriteEnabled] = useState(!!tenant.credentials.exoWriteEnabled);
  const [exoWriteSaving, setExoWriteSaving] = useState(false);
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pollDeadlineRef = useRef<number>(0);

  const stopPolling = () => {
    if (pollTimerRef.current) {
      clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  };

  const fetchPermissions = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/permissions`);
      const data = await res.json();
      if (data.success && data.report) {
        setReport(data.report);
      } else {
        setError(data.error || "Failed to retrieve permissions report");
      }
    } catch (err: any) {
      setError(err.message || "Network error while testing permissions");
    } finally {
      setLoading(false);
    }
  };

  const testExoConnectivity = async () => {
    setExoTesting(true);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/exo-permissions`);
      const data = await res.json();
      if (data.success && data.result) {
        setExoResult(data.result);
      } else {
        setExoResult({ connected: false, mode: "none", error: data.error || "Failed to check Exchange Online access", testedAt: new Date().toISOString() });
      }
    } catch (err: any) {
      setExoResult({ connected: false, mode: "none", error: err.message || "Network error while checking Exchange Online access", testedAt: new Date().toISOString() });
    } finally {
      setExoTesting(false);
    }
  };

  const pollExoConnect = async (deviceCode: string) => {
    if (Date.now() > pollDeadlineRef.current) {
      stopPolling();
      setExoPollStatus("expired");
      setExoPollError("The sign-in code expired before it was used.");
      return;
    }
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/exo-connect/poll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ deviceCode }),
      });
      const data = await res.json();
      const status = data.success ? data.result?.status : "error";

      if (status === "success") {
        stopPolling();
        setExoPollStatus("idle");
        setExoDeviceInfo(null);
        setShowSignInFallback(false);
        await testExoConnectivity();
      } else if (status === "pending") {
        setExoPollStatus("pending");
      } else {
        stopPolling();
        setExoPollStatus(status === "expired" || status === "declined" ? status : "error");
        setExoPollError(data.result?.error || data.error || "Exchange Online sign-in failed.");
      }
    } catch (err: any) {
      stopPolling();
      setExoPollStatus("error");
      setExoPollError(err.message || "Network error while checking sign-in status.");
    }
  };

  const startExoConnect = async () => {
    stopPolling();
    setExoPollStatus("starting");
    setExoPollError(null);
    setExoDeviceInfo(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/exo-connect/start`, { method: "POST" });
      const data = await res.json();
      if (!data.success || !data.result) {
        throw new Error(data.error || "Failed to start Exchange Online sign-in.");
      }
      const info: DeviceCodeStart = data.result;
      setExoDeviceInfo(info);
      setExoPollStatus("pending");
      pollDeadlineRef.current = Date.now() + info.expiresIn * 1000;
      pollTimerRef.current = setInterval(() => pollExoConnect(info.deviceCode), Math.max(info.interval, 5) * 1000);
    } catch (err: any) {
      setExoPollStatus("error");
      setExoPollError(err.message || "An unexpected error occurred.");
    }
  };

  const copyExoCode = async () => {
    if (!exoDeviceInfo) return;
    try {
      await navigator.clipboard.writeText(exoDeviceInfo.userCode);
      setExoCodeCopied(true);
      setTimeout(() => setExoCodeCopied(false), 2000);
    } catch {
      // Clipboard write failed - don't show a false "Copied" success state.
    }
  };

  const toggleExoWrite = async (next: boolean) => {
    setExoWriteSaving(true);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credentials: { exoWriteEnabled: next } }),
      });
      const data = await res.json();
      if (data.success) {
        setExoWriteEnabled(next);
      }
    } catch {
      // Leave the toggle in its previous state on failure.
    } finally {
      setExoWriteSaving(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchPermissions();
      setExoWriteEnabled(!!tenant.credentials.exoWriteEnabled);
      setExoDeviceInfo(null);
      setExoPollStatus("idle");
      setExoPollError(null);
      setExoResult(null);
      setShowSignInFallback(false);
      if (tenant.credentials.authMode !== "mock") {
        testExoConnectivity();
      }
    } else {
      stopPolling();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, tenant.id]);

  // Stop any in-flight polling if the modal unmounts entirely.
  useEffect(() => () => stopPolling(), []);

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Azure App Registration Permissions - ${tenant.displayName}`}
      maxWidth="3xl"
    >
      <div className="space-y-4">
        {/* Header Summary */}
        <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-slate-600 dark:text-slate-400" />
            <div>
              <span className="font-medium text-slate-700 dark:text-slate-300">Client ID: </span>
              <span className="font-mono text-slate-900 dark:text-slate-100">{tenant.credentials.clientId || "N/A (Simulated)"}</span>
              <span className="text-slate-400 dark:text-slate-500 mx-2">•</span>
              <span className="font-medium text-slate-700 dark:text-slate-300">Auth Mode: </span>
              <span className="uppercase text-slate-900 dark:text-slate-100 font-semibold">{tenant.credentials.authMode}</span>
              {(() => {
                const expiry = getSecretExpiryStatus(tenant.credentials);
                if (!expiry) return null;
                const tone = expiry.state === "expired" ? "text-rose-700 dark:text-red-400" : expiry.state === "expiring" ? "text-amber-700 dark:text-amber-400" : "text-slate-600 dark:text-slate-400";
                return (
                  <>
                    <span className="text-slate-400 dark:text-slate-500 mx-2">•</span>
                    <span title={expiry.detail} className={`font-medium ${tone}`}>
                      {expiry.label}
                    </span>
                  </>
                );
              })()}
            </div>
          </div>
          <button
            onClick={fetchPermissions}
            disabled={loading}
            className="flex items-center gap-1 px-2.5 py-1 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium rounded-sm disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Testing..." : "Re-Test Permissions"}
          </button>
        </div>

        {error && (
          <div className="p-3 bg-rose-50 dark:bg-red-950 border border-rose-200 dark:border-red-800 text-rose-800 dark:text-red-400 text-xs flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-rose-600 dark:text-red-400" />
            <div>
              <div className="font-semibold">Authentication Error</div>
              <div>{error}</div>
            </div>
          </div>
        )}

        {report && (() => {
          // Write-access permissions always render last, regardless of the
          // order testAppRegistrationPermissions returns them in - keeps the
          // "what does this let Clarity365 change, not just read" grouping
          // obvious without depending on source-array order. Stable sort:
          // relative order within the read-only group and within the
          // write-access group is otherwise preserved.
          const orderedPermissions = [...report.permissions].sort(
            (a, b) => Number(!!a.isWriteAccess) - Number(!!b.isWriteAccess)
          );

          return (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-600 dark:text-slate-400">
                Tested against Microsoft Graph API at:{" "}
                <span className="font-mono">{new Date(report.testedAt).toLocaleTimeString()}</span>
              </span>
              <div>
                {report.overallStatus === "all_granted" ? (
                  <StatusPill status="pass" label="All Required Permissions Granted" />
                ) : report.overallStatus === "partial" ? (
                  <StatusPill status="warn" label="Partial Permissions Allocated" />
                ) : (
                  <StatusPill status="fail" label="Permissions Missing / Denied" />
                )}
              </div>
            </div>

            {/* Write-access legend - only shown when at least one permission in this
                report actually grants write access, so a fully read-only app
                registration doesn't see an irrelevant warning. */}
            {report.permissions.some((p) => p.isWriteAccess) && (
              <div className="flex items-start gap-2 p-2.5 bg-amber-50 dark:bg-amber-950 border border-amber-300 dark:border-amber-800 rounded-sm text-[11px] text-amber-900 dark:text-amber-400">
                <AlertTriangle size={13} className="text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                <span>
                  Permissions outlined in amber below let Clarity365 create or modify data in Microsoft 365 -
                  not just read it. Review these before granting admin consent.
                </span>
              </div>
            )}

            {/* Per-optional-permission summary - makes the read-vs-write mode explicit
                at a glance, since "All Required Permissions Granted" above deliberately
                says nothing about optional ones either way. */}
            {orderedPermissions
              .filter((p) => p.optional)
              .map((p) => (
                <div
                  key={p.permission}
                  className={
                    p.status === "granted"
                      ? "flex items-start gap-2 p-2 bg-emerald-50 dark:bg-emerald-950 border border-emerald-200 dark:border-emerald-800 rounded-sm text-[11px] text-emerald-900 dark:text-emerald-400"
                      : "flex items-start gap-2 p-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm text-[11px] text-slate-600 dark:text-slate-400"
                  }
                >
                  {p.status === "granted" ? (
                    <CheckCircle size={13} className="text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <Info size={13} className="text-slate-400 dark:text-slate-500 shrink-0 mt-0.5" />
                  )}
                  <span>
                    {p.status === "granted" ? (
                      <>Write access enabled for <strong>{p.requiredFor.replace(/^Optional:\s*/, "")}</strong>.</>
                    ) : p.status === "unlicensed" ? (
                      <><strong>{p.requiredFor.replace(/^Optional:\s*/, "")}</strong> isn&apos;t available - not a permission issue, {p.errorMessage?.charAt(0).toLowerCase()}{p.errorMessage?.slice(1)}</>
                    ) : (
                      <>Running in read-only/reporting mode - <strong>{p.requiredFor.replace(/^Optional:\s*/, "")}</strong> isn&apos;t available. Grant <code className="bg-slate-200 dark:bg-slate-700 px-1 rounded font-mono">{p.permission}</code> in Entra to enable it.</>
                    )}
                  </span>
                </div>
              ))}

            {/* Permission Table */}
            <div className="border border-slate-200 dark:border-slate-700 overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse table-fixed">
                <thead className="bg-slate-100 dark:bg-slate-700 border-b border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-semibold uppercase text-[10px] tracking-wider">
                  <tr>
                    <th className="p-2.5 w-[38%]">Microsoft Graph Permission</th>
                    <th className="p-2.5 w-[12%]">Type</th>
                    <th className="p-2.5 w-[30%]">Required For</th>
                    <th className="p-2.5 w-[20%] text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                  {orderedPermissions.map((p, idx) => (
                    <tr
                      key={idx}
                      className={
                        p.isWriteAccess
                          ? "border-l-4 border-l-amber-500 bg-amber-50/60 dark:bg-amber-950 hover:bg-amber-100/70 dark:hover:bg-amber-900"
                          : "hover:bg-slate-50 dark:hover:bg-slate-700"
                      }
                    >
                      <td className="p-2.5 align-top">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="font-mono font-medium text-slate-900 dark:text-slate-100 break-words">{p.permission}</span>
                          {p.isWriteAccess && (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-amber-100 dark:bg-amber-950 text-amber-900 dark:text-amber-400 border border-amber-400 dark:border-amber-800 font-semibold text-[9px] uppercase tracking-wide rounded-sm">
                              <AlertTriangle size={9} /> Write Access{p.optional ? " (Optional)" : ""}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 break-words">{p.description}</div>
                        {p.isWriteAccess && !p.optional && (
                          <div className="text-[10px] text-amber-800 dark:text-amber-400 mt-1 break-words">
                            Grants Clarity365 the ability to create, modify, or delete data in Microsoft 365 using this permission - not just view it.
                          </div>
                        )}
                        {p.errorMessage && !(p.optional && p.status !== "granted") && (
                          <div className="text-[10px] font-mono text-rose-700 dark:text-red-400 mt-1 bg-rose-50 dark:bg-red-950 p-1 border border-rose-200 dark:border-red-800 break-words">
                            {p.errorMessage}
                          </div>
                        )}
                      </td>
                      <td className="p-2.5 align-top">
                        <span className="px-1.5 py-0.5 bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 font-mono text-[10px]">
                          {p.scope}
                        </span>
                      </td>
                      <td className="p-2.5 text-slate-600 dark:text-slate-400 align-top break-words">{p.requiredFor}</td>
                      <td className="p-2.5 text-right align-top">
                        {p.status === "granted" ? (
                          <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400 font-medium bg-emerald-50 dark:bg-emerald-950 px-2 py-0.5 border border-emerald-200 dark:border-emerald-800 text-[11px]">
                            <CheckCircle className="w-3.5 h-3.5" /> Granted
                          </span>
                        ) : p.status === "unlicensed" ? (
                          <span
                            title="Granting this permission in Azure AD will not fix this - the tenant needs to purchase the underlying license."
                            className="inline-flex items-center gap-1 text-amber-800 dark:text-amber-400 font-medium bg-amber-50 dark:bg-amber-950 px-2 py-0.5 border border-amber-300 dark:border-amber-800 text-[11px]"
                          >
                            <Info className="w-3.5 h-3.5" /> No License
                          </span>
                        ) : p.optional ? (
                          <span className="inline-flex items-center gap-1 text-slate-600 dark:text-slate-400 font-medium bg-slate-100 dark:bg-slate-700 px-2 py-0.5 border border-slate-300 dark:border-slate-600 text-[11px]">
                            Not Granted - Read-Only Mode
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-rose-700 dark:text-red-400 font-medium bg-rose-50 dark:bg-red-950 px-2 py-0.5 border border-rose-200 dark:border-red-800 text-[11px]">
                            <AlertTriangle className="w-3.5 h-3.5" /> Missing (HTTP {p.statusCode || 403})
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* No-license guidance - shown instead of (never alongside a claim
                that) the Azure Portal walkthrough below would help, since
                granting a Graph permission can't fix a missing license SKU. */}
            {report.permissions.some((p) => p.status === "unlicensed") && (
              <div className="p-3 bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 text-amber-900 dark:text-amber-400 text-xs space-y-1">
                <div className="font-semibold flex items-center gap-1.5">
                  <Info className="w-4 h-4 text-amber-700 dark:text-amber-400" />
                  Some features need a license this tenant doesn&apos;t have:
                </div>
                <ul className="text-[11px] text-amber-800 dark:text-amber-400 leading-relaxed list-disc pl-4 space-y-0.5">
                  {report.permissions
                    .filter((p) => p.status === "unlicensed")
                    .map((p) => (
                      <li key={p.permission}>{p.errorMessage}</li>
                    ))}
                </ul>
                <p className="text-[11px] text-amber-800 dark:text-amber-400 leading-relaxed pt-1">
                  No change in Azure AD / Entra will fix this - it requires purchasing the underlying Microsoft 365 license for {tenant.displayName}.
                </p>
              </div>
            )}

            {/* Guidance for genuinely missing/unconsented permissions - only
                shown when at least one required permission actually needs a
                consent grant, so this never co-appears as false advice for a
                tenant whose only failures are licensing gaps above. */}
            {report.permissions.some((p) => p.status === "missing" && !p.optional) && (
              <div className="p-3 bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 text-amber-900 dark:text-amber-400 text-xs space-y-1">
                <div className="font-semibold flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-amber-700 dark:text-amber-400" />
                  How to Grant Missing Permissions in Azure Portal:
                </div>
                <p className="text-[11px] text-amber-800 dark:text-amber-400 leading-relaxed">
                  1. Navigate to <strong>Microsoft Entra Admin Center</strong> &gt; <strong>App registrations</strong> &gt; Select your App Registration.
                  <br />
                  2. Go to <strong>API permissions</strong> &gt; <strong>Add a permission</strong> &gt; <strong>Microsoft Graph</strong> &gt; <strong>Application permissions</strong>.
                  <br />
                  3. Check all required permissions listed above and click <strong>Grant admin consent for {tenant.displayName}</strong>.
                </p>
              </div>
            )}
          </div>
          );
        })()}

        {/* Exchange Online - app-only access first, admin sign-in as a fallback */}
        {(() => {
          const access = exoResult
            ? getExchangeAccess({ exoAppAccess: exoResult.appAccess, exoRefreshToken: exoResult.mode === "delegated" ? "set" : undefined })
            : getExchangeAccess(tenant.credentials);
          const app = exoResult?.appAccess;
          const appOk = access.mode === "appOnly";
          const signInActive = exoPollStatus !== "idle";
          const btn =
            "flex items-center gap-1 px-2.5 py-1 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium rounded-sm disabled:opacity-50";
          return (
            <div className="border border-slate-200 dark:border-slate-700 p-3 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-800 dark:text-slate-200">
                  <Mail className="w-4 h-4 text-slate-600 dark:text-slate-400" />
                  <span>Exchange Online</span>
                </div>
                {tenant.credentials.authMode !== "mock" && !signInActive && (
                  <button onClick={testExoConnectivity} disabled={exoTesting} className={btn}>
                    <RefreshCw className={`w-3.5 h-3.5 ${exoTesting ? "animate-spin" : ""}`} />
                    {exoTesting ? "Checking..." : "Check again"}
                  </button>
                )}
              </div>

              {!exoResult && exoTesting ? (
                <span className="text-[11px] text-slate-400 dark:text-slate-500">Checking Exchange access...</span>
              ) : appOk ? (
                <div className="space-y-1.5">
                  <StatusPill status="pass" label="Connected - no sign-in needed" />
                  <p className="text-[11px] text-slate-600 dark:text-slate-300">
                    Role: <strong>{EXCHANGE_ROLE_LABEL[access.role || "otherRole"]}</strong>
                    {access.canWrite
                      ? " - reports and one-click fixes."
                      : " - reports only. For one-click fixes, assign Exchange Administrator to the app instead."}
                  </p>
                  {exoResult && !exoResult.connected && exoResult.error && (
                    <p className="text-[11px] text-rose-700 dark:text-red-400">Test command failed: {exoResult.error}</p>
                  )}
                </div>
              ) : (
                <div className="space-y-2">
                  {access.mode === "delegated" && <StatusPill status="warn" label="Connected through an admin sign-in (older method)" />}
                  <p className="text-[11px] font-semibold text-slate-700 dark:text-slate-300">
                    {access.mode === "delegated"
                      ? "Switch to access with no sign-in, in two steps:"
                      : "Set up in two steps (Entra admin center, on this app registration):"}
                  </p>
                  <ol className="list-decimal pl-5 text-[11px] text-slate-600 dark:text-slate-300 space-y-1">
                    <li>
                      <strong>API permissions</strong> → Add a permission → Office 365 Exchange Online → Application →{" "}
                      <code className="bg-slate-200 dark:bg-slate-700 px-1 rounded font-mono">Exchange.ManageAsApp</code> → Grant admin consent.
                    </li>
                    <li>
                      <strong>Roles and administrators</strong> → <strong>Exchange Administrator</strong> (or Global Reader for reports only) → Add
                      assignment → this app.
                    </li>
                  </ol>
                  {app && app.status !== "ok" && app.detail && <p className="text-[11px] text-amber-800 dark:text-amber-400">Missing: {app.detail}</p>}
                  {access.mode === "none" && !signInActive && (
                    <button onClick={() => setShowSignInFallback((v) => !v)} className="text-[11px] text-slate-500 dark:text-slate-400 underline">
                      Or connect with an admin sign-in instead
                    </button>
                  )}
                  {showSignInFallback && !signInActive && (
                    <button
                      onClick={startExoConnect}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      Sign in to Exchange Online
                    </button>
                  )}
                </div>
              )}

              {exoPollStatus === "starting" && <span className="text-[11px] text-slate-400 dark:text-slate-500">Starting sign-in...</span>}
              {exoPollStatus === "pending" && exoDeviceInfo && (
                <div className="space-y-2.5">
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Go to{" "}
                    <a href={exoDeviceInfo.verificationUri} target="_blank" rel="noopener noreferrer" className="text-slate-800 dark:text-slate-200 underline font-medium">
                      {exoDeviceInfo.verificationUri}
                    </a>{" "}
                    and enter this code as an Exchange admin:
                  </p>
                  <div className="flex items-center gap-2">
                    <span className="px-3 py-1.5 bg-slate-100 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-sm text-sm font-mono font-semibold tracking-widest text-slate-900 dark:text-slate-100">
                      {exoDeviceInfo.userCode}
                    </span>
                    <button onClick={copyExoCode} title="Copy code" className={btn}>
                      {exoCodeCopied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400">
                    <RefreshCw className="w-3 h-3 animate-spin" />
                    Waiting for you to approve access...
                  </div>
                </div>
              )}
              {(exoPollStatus === "error" || exoPollStatus === "expired" || exoPollStatus === "declined") && (
                <div className="space-y-2">
                  <div className="p-2 bg-rose-50 dark:bg-red-950 border border-rose-200 dark:border-red-800 text-rose-800 dark:text-red-400 text-[11px]">
                    {exoPollError || "Exchange Online sign-in failed."}
                  </div>
                  <button onClick={startExoConnect} className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm">
                    Try again
                  </button>
                </div>
              )}

              {access.available && access.canWrite && !signInActive && (
                <div className="border-t border-[#E2E8F0] dark:border-slate-700 pt-3">
                  <label className="flex items-start gap-2 cursor-pointer">
                    <input type="checkbox" checked={exoWriteEnabled} disabled={exoWriteSaving} onChange={(e) => toggleExoWrite(e.target.checked)} className="mt-0.5" />
                    <span className="text-xs text-slate-700 dark:text-slate-300">
                      <span className="font-medium">Allow Clarity365 to make changes in Exchange</span> (one-click fixes and Allow/Block List entries).
                      <span className="block text-[11px] text-slate-500 dark:text-slate-400">Off by default. When on, changes apply in Exchange immediately.</span>
                    </span>
                  </label>
                </div>
              )}
            </div>
          );
        })()}

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium rounded-sm"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
};
