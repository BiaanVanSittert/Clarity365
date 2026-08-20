import React, { useState } from "react";
import { Modal } from "../common/Modal";
import { CABaselinePolicyDefinition } from "@/lib/data/baseline-definitions";
import { Copy, Check, Terminal, AlertTriangle, Info, ShieldAlert } from "lucide-react";

interface DeployCaPolicyModalProps {
  isOpen: boolean;
  onClose: () => void;
  policy: CABaselinePolicyDefinition | null;
  tenantDomain: string;
  hasEntraP2?: boolean;
}

export const DeployCaPolicyModal: React.FC<DeployCaPolicyModalProps> = ({
  isOpen,
  onClose,
  policy,
  tenantDomain,
  hasEntraP2 = false,
}) => {
  const [copied, setCopied] = useState(false);

  if (!policy) return null;

  const script = policy.powershellTemplate(tenantDomain);

  const handleCopy = () => {
    navigator.clipboard.writeText(script);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Deploy Conditional Access Baseline: ${policy.code} — ${policy.name}`}
      maxWidth="max-w-3xl"
    >
      <div className="space-y-4">
        {/* Critical Notice Banner */}
        <div className="p-3.5 bg-amber-50 border border-amber-300 text-amber-950 text-xs rounded-sm space-y-1.5">
          <div className="flex items-center gap-2 font-semibold text-amber-900">
            <AlertTriangle className="w-4 h-4 text-amber-700 flex-shrink-0" />
            <span>Important Deployment Safety Rule: Report-Only Mode</span>
          </div>
          <p className="text-[11px] leading-relaxed text-amber-900">
            This script will create the policy strictly in <strong>Report-only</strong> mode (<code>state = &quot;enabledForReportingButNotEnforced&quot;</code>). 
            It will <strong>NOT</strong> block or challenge users immediately. You must review the Entra ID Sign-In logs over 7–14 days to confirm expected rule evaluations before manually switching the policy state to <strong>On (Enabled)</strong> in the Microsoft Entra Admin Center.
          </p>
        </div>

        {/* Entra ID P2 Requirement Banner if applicable */}
        {policy.requiresEntraP2 && (
          <div className={`p-3 border text-xs rounded-sm ${hasEntraP2 ? "bg-blue-50 border-blue-200 text-blue-900" : "bg-rose-50 border-rose-300 text-rose-950"}`}>
            <div className="flex items-center gap-2 font-semibold">
              <ShieldAlert className={`w-4 h-4 flex-shrink-0 ${hasEntraP2 ? "text-blue-700" : "text-rose-600"}`} />
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
        )}

        {/* Policy Metadata Summary */}
        <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 border border-slate-200 text-xs">
          <div>
            <span className="text-slate-500 block text-[11px]">Target Scope:</span>
            <span className="font-medium text-slate-800">{policy.targetScope}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[11px]">Risk Mitigated:</span>
            <span className="font-medium text-slate-800">{policy.riskMitigated}</span>
          </div>
        </div>

        {/* PowerShell Script Block */}
        <div>
          <div className="flex items-center justify-between pb-1.5">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700">
              <Terminal className="w-3.5 h-3.5 text-slate-600" />
              <span>Automated Microsoft Graph PowerShell Deployment Command</span>
            </div>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1 bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium rounded-sm transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? "Copied to Clipboard!" : "Copy PowerShell Script"}
            </button>
          </div>

          <pre className="p-3.5 bg-slate-950 text-slate-100 font-mono text-[11px] leading-relaxed overflow-x-auto border border-slate-800 max-h-72 rounded-sm select-all">
            {script}
          </pre>
        </div>

        {/* Instructions */}
        <div className="p-3 bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1">
          <div className="font-semibold text-slate-800 flex items-center gap-1">
            <Info className="w-3.5 h-3.5 text-slate-500" />
            Execution Steps:
          </div>
          <ol className="list-decimal list-inside space-y-0.5 text-[11px]">
            <li>Open PowerShell 7 (x64) as Administrator.</li>
            <li>Run <code>Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser</code> if not already installed.</li>
            <li>Paste and execute the script above. Authenticate with your tenant Global Admin account.</li>
            <li>Verify in Entra ID Portal that the policy is listed with state <strong>Report-only</strong>.</li>
          </ol>
        </div>

        <div className="flex justify-end pt-1">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-200 hover:bg-slate-300 text-slate-800 text-xs font-medium rounded-sm"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
};
