import React, { useState } from "react";
import { Drawer } from "../common/Drawer";
import { RemediationPlan } from "@/lib/services/remediation-generator";
import { Terminal, Copy, Check, ShieldAlert, FileText, Undo2 } from "lucide-react";
import { StatusPill } from "../common/StatusPill";

interface RemediationDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  plans: RemediationPlan[];
  tenantName: string;
}

export const RemediationDrawer: React.FC<RemediationDrawerProps> = ({
  isOpen,
  onClose,
  plans,
  tenantName,
}) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleCopyScript = (script: string, idx: number) => {
    navigator.clipboard.writeText(script);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      title="Automated Remediation & PowerShell Playbooks"
      subtitle={`Generated security remediation plans for ${tenantName}`}
      width="2xl"
    >
      <div className="space-y-6">
        {plans.length === 0 ? (
          <div className="p-8 text-center border border-dashed border-[#CBD5E1] rounded-sm bg-[#F8FAFC]">
            <p className="text-xs text-slate-500">No critical remediation actions pending for this category.</p>
          </div>
        ) : (
          plans.map((plan, idx) => (
            <div key={idx} className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden space-y-3">
              {/* Plan Header */}
              <div className="p-3.5 bg-[#F8FAFC] border-b border-[#E2E8F0] flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <StatusPill status={plan.severity} label={plan.severity.toUpperCase()} />
                    <span className="text-[11px] font-mono text-slate-500 uppercase">{plan.category}</span>
                  </div>
                  <h4 className="text-xs font-semibold text-slate-900">{plan.title}</h4>
                </div>
              </div>

              {/* Summary */}
              <div className="px-3.5 text-xs text-slate-700 leading-relaxed">
                {plan.summary}
              </div>

              {/* Steps */}
              <div className="px-3.5 space-y-1.5">
                <div className="text-[11px] font-semibold text-slate-900 uppercase tracking-wide flex items-center gap-1.5">
                  <FileText size={12} className="text-slate-600" />
                  <span>Execution Checklist</span>
                </div>
                <ol className="list-decimal list-inside text-xs text-slate-600 space-y-1 pl-1">
                  {plan.steps.map((step, sIdx) => (
                    <li key={sIdx} className="leading-snug">{step}</li>
                  ))}
                </ol>
              </div>

              {/* PowerShell Snippet */}
              <div className="px-3.5">
                <div className="flex items-center justify-between bg-slate-900 px-3 py-1.5 rounded-t-sm border border-slate-800">
                  <div className="flex items-center gap-2 text-[11px] font-mono text-slate-300">
                    <Terminal size={13} className="text-emerald-400" />
                    <span>PowerShell Execution Script</span>
                  </div>
                  <button
                    onClick={() => handleCopyScript(plan.powershellScript, idx)}
                    className="flex items-center gap-1 text-[11px] text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 px-2 py-0.5 rounded-sm transition-colors"
                  >
                    {copiedIndex === idx ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    <span>{copiedIndex === idx ? "Copied" : "Copy Code"}</span>
                  </button>
                </div>
                <pre className="p-3 bg-slate-950 text-slate-200 font-mono text-[11px] overflow-x-auto rounded-b-sm border-x border-b border-slate-800 leading-relaxed max-h-48">
                  <code>{plan.powershellScript}</code>
                </pre>
              </div>

              {/* Rollback */}
              <div className="px-3.5 pb-3.5">
                <div className="p-2 bg-slate-50 border border-slate-200 rounded-sm flex items-start gap-2 text-[11px] text-slate-600">
                  <Undo2 size={13} className="text-slate-500 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-slate-800">Rollback Procedure: </span>
                    <span>{plan.rollbackPlan}</span>
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </Drawer>
  );
};
