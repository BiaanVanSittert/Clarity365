import React from "react";
import { Modal } from "../common/Modal";
import {
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Zap,
  RefreshCw,
  Info,
  Eye,
  ShieldCheck,
  ChevronRight,
  ArrowRight,
} from "lucide-react";

export interface ChangeItemSummary {
  tenantName: string;
  targetComponent: string;
  actionDescription: string;
  beforeState?: string;
  afterState: string;
  isReportOnly?: boolean;
}

interface ChangeConfirmationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void | Promise<void>;
  title: string;
  warningMessage?: string;
  isAuditMode?: boolean;
  changes: ChangeItemSummary[];
  confirmButtonText?: string;
  isExecuting?: boolean;
  error?: string | null;
}

export const ChangeConfirmationModal: React.FC<ChangeConfirmationModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  warningMessage,
  isAuditMode = true,
  changes,
  confirmButtonText = "Confirm & Apply Changes",
  isExecuting = false,
  error = null,
}) => {
  if (!isOpen) return null;

  return (
    <Modal
      isOpen={isOpen}
      onClose={() => {
        if (!isExecuting) onClose();
      }}
      title={title}
      maxWidth="3xl"
    >
      <div className="space-y-4 text-xs select-none font-sans">
        {/* Error Alert if any */}
        {error && (
          <div className="p-3 bg-rose-50 dark:bg-red-950 border border-rose-300 dark:border-red-800 text-rose-950 dark:text-red-400 rounded-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Warning Banner */}
        <div className="p-3.5 bg-amber-50 dark:bg-amber-950/70 border border-amber-300 dark:border-amber-800 text-amber-950 dark:text-amber-300 rounded-sm space-y-1.5">
          <div className="flex items-center gap-2 font-bold text-xs text-amber-900 dark:text-amber-300">
            <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
            <span>Review Pending Tenant Configuration Changes</span>
          </div>
          <p className="text-[11px] text-amber-900 dark:text-amber-300 leading-relaxed">
            {warningMessage ||
              "You are about to modify live Microsoft 365 security settings across one or more customer organizations. Please carefully review the proposed changes below before confirming."}
          </p>
        </div>

        {/* Audit Mode / Report-Only Safety Assurance Badge */}
        {isAuditMode && (
          <div className="p-3 bg-blue-50 dark:bg-blue-950/60 border border-blue-300 dark:border-blue-800 text-blue-950 dark:text-blue-300 rounded-sm flex items-start gap-2.5">
            <div className="p-1 bg-blue-100 dark:bg-blue-900 rounded-sm mt-0.5 text-blue-700 dark:text-blue-300 shrink-0">
              <Eye className="w-3.5 h-3.5" />
            </div>
            <div className="space-y-0.5">
              <div className="flex items-center gap-1.5 font-bold text-xs text-blue-950 dark:text-blue-200">
                <span>Staged in Audit / Report-Only Mode</span>
                <span className="text-[9px] px-1.5 py-0.2 bg-blue-200 dark:bg-blue-900 text-blue-900 dark:text-blue-200 font-mono rounded-sm">
                  state: enabledForReportingButNotEnforced
                </span>
              </div>
              <p className="text-[11px] text-blue-800 dark:text-blue-300 leading-relaxed">
                All applicable policies will be deployed in <strong>Audit / Report-Only Mode</strong> first. Sign-in events and access requests will be logged and evaluated against the policy rules without challenging or locking out end users.
              </p>
            </div>
          </div>
        )}

        {/* Detailed Proposed Changes Breakdown */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">
              Outline of Proposed Changes ({changes.length} Action{changes.length === 1 ? "" : "s"})
            </span>
            <span className="text-[10px] text-slate-400">Target Tenant & Component</span>
          </div>

          <div className="border border-[#CBD5E1] dark:border-slate-700 rounded-sm overflow-hidden divide-y divide-slate-200 dark:divide-slate-800 max-h-64 overflow-y-auto bg-white dark:bg-slate-900">
            {changes.map((c, idx) => (
              <div key={idx} className="p-3 space-y-1.5 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-900 dark:text-slate-100">{c.tenantName}</span>
                    <span className="text-slate-400 font-mono text-[10px]">({c.targetComponent})</span>
                  </div>
                  {c.isReportOnly !== false && (
                    <span className="text-[9px] font-bold px-1.5 py-0.5 bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border border-emerald-300 rounded-sm whitespace-nowrap inline-flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3 text-emerald-600" />
                      <span>Audit / Report-Only</span>
                    </span>
                  )}
                </div>

                <div className="text-[11px] font-medium text-slate-700 dark:text-slate-300">
                  {c.actionDescription}
                </div>

                {(c.beforeState || c.afterState) && (
                  <div className="flex items-center gap-2 font-mono text-[10px] bg-slate-50 dark:bg-slate-950 p-1.5 rounded-sm border border-slate-200 dark:border-slate-800">
                    {c.beforeState && (
                      <span className="text-rose-600 dark:text-rose-400 line-through">
                        {c.beforeState}
                      </span>
                    )}
                    {c.beforeState && <ArrowRight className="w-3 h-3 text-slate-400 shrink-0" />}
                    <span className="text-emerald-600 dark:text-emerald-400 font-bold">
                      {c.afterState}
                    </span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-200 dark:border-slate-700">
          <button
            type="button"
            onClick={onClose}
            disabled={isExecuting}
            className="px-3.5 py-1.5 text-xs text-slate-600 dark:text-slate-300 hover:text-slate-900 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-sm transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={isExecuting || changes.length === 0}
            className="px-4 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 dark:bg-emerald-600 dark:hover:bg-emerald-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-xs disabled:opacity-50"
          >
            {isExecuting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5 text-amber-400" />}
            <span>{isExecuting ? "Applying Changes..." : confirmButtonText}</span>
          </button>
        </div>
      </div>
    </Modal>
  );
};
