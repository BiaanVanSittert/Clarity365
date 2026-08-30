import React, { useState } from "react";
import { Modal } from "../common/Modal";
import { ShieldAlert, AlertTriangle, KeyRound, UserX, Mail, RefreshCw, CheckCircle2, XCircle, Terminal, Copy, Check } from "lucide-react";
import { TenantSecuritySnapshot } from "@/lib/types";

interface CompromisedAccountModalProps {
  isOpen: boolean;
  onClose: () => void;
  tenantId: string;
  tenantName: string;
  targetUserUPN: string;
  targetUserId?: string;
  onSuccess?: () => void;
}

export const CompromisedAccountModal: React.FC<CompromisedAccountModalProps> = ({
  isOpen,
  onClose,
  tenantId,
  tenantName,
  targetUserUPN,
  targetUserId,
  onSuccess,
}) => {
  const [revokeTokens, setRevokeTokens] = useState(true);
  const [disableAccount, setDisableAccount] = useState(true);
  const [resetPassword, setResetPassword] = useState(true);
  const [purgeForwardingRules, setPurgeForwardingRules] = useState(true);
  const [reason, setReason] = useState("Suspected Account Compromise / Active BEC");
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<{
    success: boolean;
    actionsExecuted: string[];
    errors: string[];
  } | null>(null);
  const [copiedRollback, setCopiedRollback] = useState(false);

  const handleExecuteContainment = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(`/api/tenants/${tenantId}/incident-response/contain-user`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId: targetUserId,
          userPrincipalName: targetUserUPN,
          revokeTokens,
          disableAccount,
          resetPassword,
          purgeForwardingRules,
          reason,
        }),
      });
      const data = await res.json();
      setResults({
        success: data.success,
        actionsExecuted: data.actionsExecuted || [],
        errors: data.errors || (data.error ? [data.error] : []),
      });
      if (data.success && onSuccess) {
        onSuccess();
      }
    } catch (err: any) {
      setResults({
        success: false,
        actionsExecuted: [],
        errors: [err.message || "Failed to execute containment request"],
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyRollback = async () => {
    const rollbackScript = `# Rollback containment for ${targetUserUPN}
Connect-MgGraph -Scopes "User.ReadWrite.All"
# Re-enable user account
Update-MgUser -UserId "${targetUserUPN}" -AccountEnabled:$true
Write-Host "Account ${targetUserUPN} re-enabled." -ForegroundColor Green`;

    await navigator.clipboard.writeText(rollbackScript);
    setCopiedRollback(true);
    setTimeout(() => setCopiedRollback(false), 2000);
  };

  const handleClose = () => {
    setResults(null);
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Emergency Account Containment Playbook"
      subtitle={`Immediate threat containment for ${targetUserUPN} (${tenantName})`}
      maxWidth="xl"
    >
      <div className="space-y-4">
        {/* Warning Banner */}
        <div className="p-3 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800 text-red-950 dark:text-red-300 rounded-sm flex items-start gap-2.5">
          <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
          <div className="text-xs space-y-1">
            <div className="font-semibold text-red-900 dark:text-red-200">Incident Response Containment Mode</div>
            <p className="leading-relaxed">
              Executing this playbook immediately neutralizes attacker access. Active browser cookies and mobile sessions will be terminated instantly.
            </p>
          </div>
        </div>

        {results ? (
          /* Execution Results View */
          <div className="space-y-4">
            <div className={`p-4 border rounded-sm ${results.success ? "bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800" : "bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800"}`}>
              <div className="flex items-center gap-2 font-semibold text-xs mb-2">
                {results.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-600 dark:text-rose-400" />
                )}
                <span className={results.success ? "text-emerald-900 dark:text-emerald-200" : "text-rose-900 dark:text-rose-200"}>
                  {results.success ? "Containment Actions Executed Successfully" : "Containment Encountered Errors"}
                </span>
              </div>

              {results.actionsExecuted.length > 0 && (
                <div className="space-y-1 mt-2">
                  <div className="text-[11px] font-semibold text-slate-700 dark:text-slate-300 uppercase">Actions Applied:</div>
                  <ul className="list-disc list-inside text-xs text-slate-700 dark:text-slate-300 space-y-0.5">
                    {results.actionsExecuted.map((a, i) => (
                      <li key={i}>{a}</li>
                    ))}
                  </ul>
                </div>
              )}

              {results.errors.length > 0 && (
                <div className="space-y-1 mt-3 p-2.5 bg-rose-100 dark:bg-rose-900/50 rounded text-xs text-rose-900 dark:text-rose-200 font-mono">
                  {results.errors.map((e, i) => (
                    <div key={i}>• {e}</div>
                  ))}
                </div>
              )}
            </div>

            {/* Rollback Guide */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
                <span className="flex items-center gap-1.5">
                  <Terminal size={13} className="text-slate-500" />
                  <span>PowerShell Rollback Procedure</span>
                </span>
                <button
                  onClick={handleCopyRollback}
                  className="flex items-center gap-1 text-[11px] px-2 py-0.5 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 rounded border border-slate-300 dark:border-slate-600 transition-colors"
                >
                  {copiedRollback ? <Check size={11} className="text-emerald-500" /> : <Copy size={11} />}
                  <span>{copiedRollback ? "Copied" : "Copy Rollback"}</span>
                </button>
              </div>
              <pre className="p-3 bg-slate-950 text-slate-200 font-mono text-[11px] rounded-sm overflow-x-auto">
                <code>{`Update-MgUser -UserId "${targetUserUPN}" -AccountEnabled:$true`}</code>
              </pre>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-200 dark:border-slate-700">
              <button
                onClick={handleClose}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm"
              >
                Close & Return to Incident Queue
              </button>
            </div>
          </div>
        ) : (
          /* Playbook Action Checkboxes */
          <div className="space-y-4">
            <div className="space-y-2.5 border border-slate-200 dark:border-slate-700 p-3 rounded-sm bg-white dark:bg-slate-800">
              <div className="text-[11px] uppercase font-mono font-semibold text-slate-500 dark:text-slate-400">
                Select Containment Actions:
              </div>

              <label className="flex items-start gap-2.5 cursor-pointer p-1.5 hover:bg-slate-50 dark:hover:bg-slate-700/50 rounded">
                <input
                  type="checkbox"
                  checked={revokeTokens}
                  onChange={(e) => setRevokeTokens(e.target.checked)}
                  className="mt-0.5 rounded border-slate-300 text-slate-900"
                />
                <div className="text-xs">
                  <div className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                    <KeyRound size={13} className="text-slate-600 dark:text-slate-400" />
                    <span>Revoke All Active Sign-In Sessions & Refresh Tokens</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Immediately invalidates OAuth tokens across web apps, Teams, Outlook, and mobile devices (`revokeSignInSessions`).
                  </p>
                </div>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer p-1.5 hover:bg-slate-50 dark:hover:bg-slate-700/50 rounded">
                <input
                  type="checkbox"
                  checked={disableAccount}
                  onChange={(e) => setDisableAccount(e.target.checked)}
                  className="mt-0.5 rounded border-slate-300 text-slate-900"
                />
                <div className="text-xs">
                  <div className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                    <UserX size={13} className="text-slate-600 dark:text-slate-400" />
                    <span>Disable Account in Microsoft Entra ID</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Blocks all incoming authentication attempts by setting `accountEnabled: false`.
                  </p>
                </div>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer p-1.5 hover:bg-slate-50 dark:hover:bg-slate-700/50 rounded">
                <input
                  type="checkbox"
                  checked={resetPassword}
                  onChange={(e) => setResetPassword(e.target.checked)}
                  className="mt-0.5 rounded border-slate-300 text-slate-900"
                />
                <div className="text-xs">
                  <div className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                    <RefreshCw size={13} className="text-slate-600 dark:text-slate-400" />
                    <span>Enforce Password Reset at Next Sign-In</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Requires legitimate user to establish new credentials before regaining access (`forceChangePasswordNextSignIn`).
                  </p>
                </div>
              </label>

              <label className="flex items-start gap-2.5 cursor-pointer p-1.5 hover:bg-slate-50 dark:hover:bg-slate-700/50 rounded">
                <input
                  type="checkbox"
                  checked={purgeForwardingRules}
                  onChange={(e) => setPurgeForwardingRules(e.target.checked)}
                  className="mt-0.5 rounded border-slate-300 text-slate-900"
                />
                <div className="text-xs">
                  <div className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                    <Mail size={13} className="text-slate-600 dark:text-slate-400" />
                    <span>Scan & Purge Inbox Forwarding Rules</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Removes automated mailbox forwarding rules commonly planted during Business Email Compromise (BEC).
                  </p>
                </div>
              </label>
            </div>

            {/* Incident Reason Note */}
            <div>
              <label className="block text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1">
                Incident Response Reason / Ticket Reference:
              </label>
              <input
                type="text"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                className="w-full px-3 py-1.5 text-xs border border-slate-300 dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-800"
              />
            </div>

            {/* Modal Actions */}
            <div className="flex items-center justify-between pt-3 border-t border-slate-200 dark:border-slate-700">
              <button
                type="button"
                onClick={handleClose}
                disabled={isLoading}
                className="px-3.5 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-sm"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleExecuteContainment}
                disabled={isLoading || (!revokeTokens && !disableAccount && !resetPassword && !purgeForwardingRules)}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-sm flex items-center gap-1.5 shadow-sm transition-colors"
              >
                {isLoading && <RefreshCw size={13} className="animate-spin" />}
                <span>{isLoading ? "Executing Containment..." : "Execute Containment Playbook"}</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};
