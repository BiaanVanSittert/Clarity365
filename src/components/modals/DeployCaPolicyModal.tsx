import React, { useState } from "react";
import { Modal } from "../common/Modal";
import { CABaselinePolicyDefinition } from "@/lib/data/baseline-definitions";
import { Copy, Check, Terminal, AlertTriangle, Info, ShieldAlert, Zap, RefreshCw, CheckCircle2, Key } from "lucide-react";

interface DeployCaPolicyModalProps {
  isOpen: boolean;
  onClose: () => void;
  policy: CABaselinePolicyDefinition | null;
  tenantId: string;
  tenantName: string;
  tenantDomain: string;
  hasEntraP2?: boolean;
  onPolicyDeployed?: () => void;
}

export const DeployCaPolicyModal: React.FC<DeployCaPolicyModalProps> = ({
  isOpen,
  onClose,
  policy,
  tenantId,
  tenantName,
  tenantDomain,
  hasEntraP2 = false,
  onPolicyDeployed,
}) => {
  const [copied, setCopied] = useState(false);
  const [showConfirmDeploy, setShowConfirmDeploy] = useState(false);
  const [isDeploying, setIsDeploying] = useState(false);
  const [deployError, setDeployError] = useState<string | null>(null);
  const [deploySuccess, setDeploySuccess] = useState<string | null>(null);

  if (!policy) return null;

  const script = policy.powershellTemplate(tenantDomain);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(script);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Clipboard write failed (e.g. permission denied) - don't show a
      // false "Copied" success state.
    }
  };

  const handleExecuteAutoDeploy = async () => {
    setIsDeploying(true);
    setDeployError(null);
    setDeploySuccess(null);

    try {
      const res = await fetch(`/api/tenants/${tenantId}/deploy-ca`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ baselineCode: policy.code }),
      });

      const data = await res.json();
      if (data.success) {
        setDeploySuccess(`Policy '${policy.code}: ${policy.name}' successfully deployed to ${tenantName} in Report-Only mode!`);
        setShowConfirmDeploy(false);
        if (onPolicyDeployed) {
          onPolicyDeployed();
        }
        setTimeout(() => {
          onClose();
          setDeploySuccess(null);
        }, 2200);
      } else {
        setDeployError(data.error || "Failed to auto-deploy policy to Microsoft Graph.");
      }
    } catch (err: any) {
      setDeployError(err.message || "Network error while calling auto-deploy API.");
    } finally {
      setIsDeploying(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={() => {
        setShowConfirmDeploy(false);
        setDeployError(null);
        setDeploySuccess(null);
        onClose();
      }}
      title={`Deploy Conditional Access Baseline: ${policy.code} - ${policy.name}`}
      maxWidth="3xl"
    >
      <div className="space-y-4">
        {/* Success Alert */}
        {deploySuccess && (
          <div className="p-3 bg-emerald-50 dark:bg-emerald-950 border border-emerald-300 dark:border-emerald-800 text-emerald-950 text-xs rounded-sm flex items-center gap-2 font-medium">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
            <span>{deploySuccess}</span>
          </div>
        )}

        {/* Error Alert */}
        {deployError && (
          <div className="p-3 bg-rose-50 dark:bg-red-950 border border-rose-300 dark:border-red-800 text-rose-950 dark:text-red-400 text-xs rounded-sm space-y-1">
            <div className="flex items-center gap-2 font-semibold text-rose-900 dark:text-red-400">
              <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-red-400 flex-shrink-0" />
              <span>Auto-Deployment Failed</span>
            </div>
            <div className="text-[11px] font-mono bg-white dark:bg-slate-800 p-1.5 border border-rose-200 dark:border-red-800 text-rose-800 dark:text-red-400">
              {deployError}
            </div>
            <p className="text-[10px] text-rose-700 dark:text-red-400 mt-1">
              Ensure your App Registration has been granted <strong>Policy.ReadWrite.ConditionalAccess</strong> with <strong>Admin Consent</strong> in Microsoft Entra Admin Center.
            </p>
          </div>
        )}

        {/* Critical Notice Banner */}
        <div className="p-3.5 bg-amber-50 dark:bg-amber-950 border border-amber-300 dark:border-amber-800 text-amber-950 dark:text-amber-400 text-xs rounded-sm space-y-1.5">
          <div className="flex items-center gap-2 font-semibold text-amber-900 dark:text-amber-400">
            <AlertTriangle className="w-4 h-4 text-amber-700 dark:text-amber-400 flex-shrink-0" />
            <span>Important Deployment Safety Rule: Report-Only Mode</span>
          </div>
          <p className="text-[11px] leading-relaxed text-amber-900 dark:text-amber-400">
            This deployment will create the policy strictly in <strong>Report-only</strong> mode (<code>state = &quot;enabledForReportingButNotEnforced&quot;</code>). 
            It will <strong>NOT</strong> block or challenge users immediately. You must review the Entra ID Sign-In logs over 7–14 days to confirm expected rule evaluations before manually switching the policy state to <strong>On (Enabled)</strong> in the Microsoft Entra Admin Center.
          </p>
        </div>

        {/* Auto-Deploy Confirmation Warning Step */}
        {showConfirmDeploy ? (
          <div className="p-4 bg-slate-900 text-white rounded-sm space-y-3 border border-slate-800 animate-in fade-in duration-200">
            <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs">
              <Zap className="w-4 h-4" />
              <span>Confirm Direct Graph API Auto-Deployment to {tenantName}</span>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Clarity365 will connect directly via Microsoft Graph API to create <strong>{policy.code}: {policy.name}</strong> in <strong>Report-Only mode</strong>.
            </p>
            <div className="p-2.5 bg-slate-950 border border-slate-800 text-[11px] space-y-1 text-slate-300 rounded-sm">
              <div className="flex items-center gap-1 text-amber-300 font-medium">
                <Key className="w-3.5 h-3.5" />
                Required Azure App Registration Permission:
              </div>
              <p>
                <strong>Policy.ReadWrite.ConditionalAccess</strong> (Application type with Admin Consent granted).
              </p>
            </div>
            <div className="flex items-center justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setShowConfirmDeploy(false)}
                disabled={isDeploying}
                className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-sm transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleExecuteAutoDeploy}
                disabled={isDeploying}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-700 dark:bg-emerald-700 dark:hover:bg-emerald-600 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                {isDeploying ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                <span>{isDeploying ? "Deploying Policy..." : "Confirm & Auto-Deploy (Report-Only)"}</span>
              </button>
            </div>
          </div>
        ) : (
          /* Entra ID P2 Requirement Banner if applicable */
          policy.requiresEntraP2 && (
            <div className={`p-3 border text-xs rounded-sm ${hasEntraP2 ? "bg-blue-50 border-blue-200 text-blue-900" : "bg-rose-50 dark:bg-red-950 border-rose-300 dark:border-red-800 text-rose-950 dark:text-red-400"}`}>
              <div className="flex items-center gap-2 font-semibold">
                <ShieldAlert className={`w-4 h-4 flex-shrink-0 ${hasEntraP2 ? "text-blue-700" : "text-rose-600 dark:text-red-400"}`} />
                <span>License Dependency: Microsoft Entra ID Plan 2 Required</span>
              </div>
              <p className="text-[11px] mt-1 leading-relaxed">
                <strong>{policy.code}</strong> relies on Entra Identity Protection risk machine learning. 
                {hasEntraP2 ? (
                  <span> Entra ID P2 capability detected in this tenant.</span>
                ) : (
                  <span> <strong>Recommendation:</strong> This tenant does not currently appear to have an active Entra ID Plan 2 SKU. Please obtain at least one Entra ID Plan 2 license for your tenant before enabling this policy in production.</span>
                )}
              </p>
            </div>
          )
        )}

        {/* Policy Metadata Summary */}
        <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs">
          <div>
            <span className="text-slate-500 dark:text-slate-400 block text-[11px]">Target Scope:</span>
            <span className="font-medium text-slate-800 dark:text-slate-200">{policy.targetScope}</span>
          </div>
          <div>
            <span className="text-slate-500 dark:text-slate-400 block text-[11px]">Risk Mitigated:</span>
            <span className="font-medium text-slate-800 dark:text-slate-200">{policy.riskMitigated}</span>
          </div>
        </div>

        {/* PowerShell Script Block & Action Buttons */}
        <div>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300">
              <Terminal className="w-3.5 h-3.5 text-slate-600 dark:text-slate-400" />
              <span>Microsoft Graph PowerShell Script or Direct Auto-Deploy</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 px-3 py-1 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-medium rounded-sm transition-colors shadow-2xs"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? "Copied Script!" : "Copy PowerShell Script"}
              </button>

              <button
                onClick={() => {
                  setDeployError(null);
                  setShowConfirmDeploy(true);
                }}
                className="flex items-center gap-1.5 px-3 py-1 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded-sm transition-colors shadow-sm"
              >
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                <span>Auto-Deploy to Tenant</span>
              </button>
            </div>
          </div>

          <pre className="p-3.5 bg-slate-950 text-slate-100 font-mono text-[11px] leading-relaxed overflow-x-auto border border-slate-800 max-h-60 rounded-sm select-all">
            {script}
          </pre>
        </div>

        {/* Instructions */}
        <div className="p-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs text-slate-600 dark:text-slate-400 space-y-1">
          <div className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1">
            <Info className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
            Deployment Options:
          </div>
          <p className="text-[11px]">
            • <strong>Option A (Auto-Deploy):</strong> Click <em>Auto-Deploy to Tenant</em> to create the policy directly in Microsoft Graph without opening a terminal.
            <br />
            • <strong>Option B (Manual PowerShell):</strong> Copy the script above and run it in PowerShell 7 as Administrator.
          </p>
        </div>

        <div className="flex justify-end pt-1">
          <button
            onClick={() => {
              setShowConfirmDeploy(false);
              setDeployError(null);
              setDeploySuccess(null);
              onClose();
            }}
            className="px-4 py-1.5 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-800 dark:text-slate-200 text-xs font-medium rounded-sm"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
};
