import React, { useState } from "react";
import { Modal } from "../common/Modal";
import {
  ShieldAlert,
  KeyRound,
  UserX,
  UserCheck,
  Mail,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Terminal,
  Copy,
  Check,
  Key,
  ShieldCheck,
  Lock,
} from "lucide-react";

interface CompromisedAccountModalProps {
  isOpen: boolean;
  onClose: () => void;
  tenantId: string;
  tenantName: string;
  targetUserUPN: string;
  targetUserId?: string;
  initialMode?: "contain" | "restore";
  onSuccess?: () => void;
}

export const CompromisedAccountModal: React.FC<CompromisedAccountModalProps> = ({
  isOpen,
  onClose,
  tenantId,
  tenantName,
  targetUserUPN,
  targetUserId,
  initialMode = "contain",
  onSuccess,
}) => {
  const [mode, setMode] = useState<"contain" | "restore">(initialMode);
  const [revokeTokens, setRevokeTokens] = useState(true);
  const [disableAccount, setDisableAccount] = useState(true);
  const [resetPassword, setResetPassword] = useState(true);
  const [purgeForwardingRules, setPurgeForwardingRules] = useState(true);
  const [reason, setReason] = useState("Suspected Account Compromise / Active BEC");
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<{
    success: boolean;
    temporaryPassword?: string;
    actionsExecuted: string[];
    errors: string[];
  } | null>(null);
  const [copiedRollback, setCopiedRollback] = useState(false);
  const [copiedPassword, setCopiedPassword] = useState(false);

  const handleExecuteAction = async () => {
    setIsLoading(true);
    try {
      const res = await fetch(`/api/tenants/${tenantId}/incident-response/contain-user`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: mode,
          userId: targetUserId,
          userPrincipalName: targetUserUPN,
          revokeTokens: mode === "contain" ? revokeTokens : false,
          disableAccount: mode === "contain" ? disableAccount : false,
          resetPassword: mode === "contain" ? resetPassword : false,
          purgeForwardingRules: mode === "contain" ? purgeForwardingRules : false,
          reason,
        }),
      });
      const data = await res.json();
      setResults({
        success: data.success,
        temporaryPassword: data.temporaryPassword,
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
        errors: [err.message || `Failed to execute ${mode} request`],
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

  const handleCopyPassword = async () => {
    if (!results?.temporaryPassword) return;
    await navigator.clipboard.writeText(results.temporaryPassword);
    setCopiedPassword(true);
    setTimeout(() => setCopiedPassword(false), 2000);
  };

  const handleClose = () => {
    setResults(null);
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title={mode === "contain" ? "Emergency Account Containment Playbook" : "Restore & Re-Enable User Account"}
      subtitle={`${mode === "contain" ? "Immediate threat containment" : "Post-incident recovery"} for ${targetUserUPN} (${tenantName})`}
      maxWidth="xl"
    >
      <div className="space-y-4">
        {/* Mode Selector Tabs */}
        {!results && (
          <div className="grid grid-cols-2 gap-2 border-b border-slate-200 dark:border-slate-700 pb-2">
            <button
              type="button"
              onClick={() => { setMode("contain"); setReason("Suspected Account Compromise / Active BEC"); }}
              className={`py-2 text-xs font-semibold rounded flex items-center justify-center gap-1.5 transition-all ${
                mode === "contain"
                  ? "bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300 border border-red-300 dark:border-red-800"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
              }`}
            >
              <UserX size={14} />
              <span>🚨 Contain & Neutralize</span>
            </button>

            <button
              type="button"
              onClick={() => { setMode("restore"); setReason("Incident Resolved - Restoring Legitimate User Access"); }}
              className={`py-2 text-xs font-semibold rounded flex items-center justify-center gap-1.5 transition-all ${
                mode === "restore"
                  ? "bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
              }`}
            >
              <UserCheck size={14} />
              <span>♻️ Restore & Re-Enable</span>
            </button>
          </div>
        )}

        {/* Banner */}
        {mode === "contain" ? (
          <div className="p-3 bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800 text-red-950 dark:text-red-300 rounded-sm flex items-start gap-2.5">
            <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <div className="font-semibold text-red-900 dark:text-red-200">Incident Response Containment Mode</div>
              <p className="leading-relaxed">
                Executing this playbook immediately terminates attacker access across web apps, Teams, and Outlook mobile sessions.
              </p>
            </div>
          </div>
        ) : (
          <div className="p-3 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 text-emerald-950 dark:text-emerald-300 rounded-sm flex items-start gap-2.5">
            <ShieldCheck className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <div className="font-semibold text-emerald-900 dark:text-emerald-200">Post-Remediation User Recovery</div>
              <p className="leading-relaxed">
                Restores the user account to active status in Microsoft Entra ID (`accountEnabled: true`) once threat analysis and password rotation are completed.
              </p>
            </div>
          </div>
        )}

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
                  {results.success ? `${mode === "contain" ? "Containment" : "Restoration"} Actions Executed Successfully` : "Action Encountered Errors"}
                </span>
              </div>

              {/* Temporary One-Time Password Showcase Card */}
              {results.temporaryPassword && (
                <div className="my-3 p-3.5 bg-white dark:bg-slate-900 border-2 border-amber-400 dark:border-amber-600 rounded-sm shadow-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-xs font-bold text-amber-900 dark:text-amber-300">
                      <Key size={14} className="text-amber-600" />
                      <span>Temporary One-Time Password (OTP) Generated</span>
                    </div>
                    <button
                      onClick={handleCopyPassword}
                      className="flex items-center gap-1 text-[11px] font-semibold px-2.5 py-1 bg-amber-100 dark:bg-amber-950/80 hover:bg-amber-200 dark:hover:bg-amber-900 text-amber-900 dark:text-amber-200 rounded border border-amber-300 dark:border-amber-700 transition-colors"
                    >
                      {copiedPassword ? <Check size={12} className="text-emerald-600" /> : <Copy size={12} />}
                      <span>{copiedPassword ? "Copied Password" : "Copy Password"}</span>
                    </button>
                  </div>
                  <div className="p-2 bg-slate-950 text-amber-400 font-mono text-sm tracking-wider font-bold rounded text-center select-all">
                    {results.temporaryPassword}
                  </div>
                  <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-tight">
                    Provide this temporary credential to the user or use it to sign in for forensic investigation. The user will be <strong>forced to establish a new password</strong> immediately upon sign-in.
                  </p>
                </div>
              )}

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

            {/* Rollback Guide if contained */}
            {mode === "contain" && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs font-semibold text-slate-800 dark:text-slate-200">
                  <span className="flex items-center gap-1.5">
                    <Terminal size={13} className="text-slate-500" />
                    <span>PowerShell Re-enable Procedure</span>
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
            )}

            <div className="flex justify-end pt-2 border-t border-slate-200 dark:border-slate-700">
              <button
                onClick={handleClose}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm"
              >
                Close & Return to Incident Queue
              </button>
            </div>
          </div>
        ) : mode === "contain" ? (
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
                    <span>Generate Temporary Password & Enforce Reset on Next Sign-In</span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Generates a secure temporary One-Time Password for admin retrieval and forces user to rotate it upon sign-in.
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
                onClick={handleExecuteAction}
                disabled={isLoading || (!revokeTokens && !disableAccount && !resetPassword && !purgeForwardingRules)}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-sm flex items-center gap-1.5 shadow-sm transition-colors"
              >
                {isLoading && <RefreshCw size={13} className="animate-spin" />}
                <span>{isLoading ? "Executing Containment..." : "Execute Containment Playbook"}</span>
              </button>
            </div>
          </div>
        ) : (
          /* Restore User Account View */
          <div className="space-y-4">
            <div className="p-3 border border-slate-200 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-800 space-y-2">
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                <UserCheck size={14} className="text-emerald-600" />
                <span>Re-enable Entra ID Account Status</span>
              </div>
              <p className="text-[11px] text-slate-600 dark:text-slate-400">
                This will set <code>accountEnabled: true</code> for <strong>{targetUserUPN}</strong> in Microsoft Entra ID. The user will be able to sign in normally with their credentials.
              </p>
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1">
                Restoration Reason / Verification Reference:
              </label>
              <input
                type="text"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                className="w-full px-3 py-1.5 text-xs border border-slate-300 dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-800"
              />
            </div>

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
                onClick={handleExecuteAction}
                disabled={isLoading}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 rounded-sm flex items-center gap-1.5 shadow-sm transition-colors"
              >
                {isLoading && <RefreshCw size={13} className="animate-spin" />}
                <span>{isLoading ? "Restoring Account..." : "Restore User Account"}</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};
