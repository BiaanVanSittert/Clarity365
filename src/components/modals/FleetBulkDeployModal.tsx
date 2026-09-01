import React, { useState } from "react";
import { Modal } from "../common/Modal";
import { Tenant, FleetBulkDeployResult } from "@/lib/types";
import { CA_BASELINE_STANDARDS } from "@/lib/data/baseline-definitions";
import {
  Zap,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Layers,
  ChevronRight,
  Info,
} from "lucide-react";

interface FleetBulkDeployModalProps {
  isOpen: boolean;
  onClose: () => void;
  selectedBaselineCodes: string[];
  selectedTenants: Tenant[];
  onDeployComplete?: () => void;
}

export const FleetBulkDeployModal: React.FC<FleetBulkDeployModalProps> = ({
  isOpen,
  onClose,
  selectedBaselineCodes,
  selectedTenants,
  onDeployComplete,
}) => {
  const [isExecuting, setIsExecuting] = useState(false);
  const [deployResult, setDeployResult] = useState<FleetBulkDeployResult | null>(null);
  const [deployError, setDeployError] = useState<string | null>(null);

  if (!isOpen) return null;

  const baselineDefs = CA_BASELINE_STANDARDS.filter((b) =>
    selectedBaselineCodes.includes(b.code)
  );

  const hasP2Baselines = baselineDefs.some((b) => b.requiresEntraP2);

  const handleExecuteBulkDeploy = async () => {
    setIsExecuting(true);
    setDeployError(null);
    setDeployResult(null);

    try {
      const res = await fetch("/api/fleet/bulk-deploy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          baselineCodes: selectedBaselineCodes,
          targetTenantIds: selectedTenants.map((t) => t.id),
          mode: "reportOnly",
        }),
      });

      const data = await res.json();
      if (data.success && data.result) {
        setDeployResult(data.result);
        if (onDeployComplete) {
          onDeployComplete();
        }
      } else {
        setDeployError(data.error || "Failed to execute fleet rollout.");
      }
    } catch (err: any) {
      setDeployError(err.message || "Network error communicating with Fleet Rollout API.");
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={() => {
        if (!isExecuting) {
          setDeployResult(null);
          setDeployError(null);
          onClose();
        }
      }}
      title={`Fleet Baseline Rollout: ${selectedBaselineCodes.length} Baseline(s) across ${selectedTenants.length} Tenant(s)`}
      maxWidth="3xl"
    >
      <div className="space-y-4 text-xs select-none font-sans">
        {/* Error Alert */}
        {deployError && (
          <div className="p-3 bg-rose-50 dark:bg-red-950 border border-rose-300 dark:border-red-800 text-rose-950 dark:text-red-400 rounded-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-red-400 shrink-0" />
            <span>{deployError}</span>
          </div>
        )}

        {/* Results Screen if complete */}
        {deployResult ? (
          <div className="space-y-3">
            <div className="p-3.5 bg-emerald-50 dark:bg-emerald-950/70 border border-emerald-300 dark:border-emerald-800 text-emerald-950 dark:text-emerald-300 rounded-sm space-y-1">
              <div className="flex items-center gap-2 font-bold text-sm">
                <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                <span>Fleet Baseline Rollout Completed</span>
              </div>
              <p className="text-[11px] text-emerald-800 dark:text-emerald-300">
                {deployResult.successCount} policy deployments successful (Report-Only mode), {deployResult.skippedCount} skipped (already active), {deployResult.failedCount} failed.
              </p>
            </div>

            <div className="border border-[#CBD5E1] dark:border-slate-700 max-h-64 overflow-y-auto divide-y divide-slate-200 dark:divide-slate-800 rounded-sm">
              {deployResult.results.map((r, idx) => (
                <div key={idx} className="p-2.5 flex items-center justify-between text-[11px] bg-white dark:bg-slate-900">
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        r.status === "success"
                          ? "bg-emerald-500"
                          : r.status === "skipped"
                          ? "bg-blue-500"
                          : "bg-rose-500"
                      }`}
                    />
                    <div>
                      <span className="font-bold text-slate-900 dark:text-slate-100">{r.tenantName}</span>
                      <span className="text-slate-400 mx-1.5">—</span>
                      <span className="font-mono text-slate-700 dark:text-slate-300">{r.baselineCode}: {r.policyName}</span>
                    </div>
                  </div>
                  <span className="text-slate-500 dark:text-slate-400 text-[10px]">{r.message}</span>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => {
                  setDeployResult(null);
                  onClose();
                }}
                className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded-sm transition-colors"
              >
                Close Summary
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Safety Notice */}
            <div className="p-3 bg-amber-50 dark:bg-amber-950/60 border border-amber-300 dark:border-amber-800 text-amber-950 dark:text-amber-300 rounded-sm space-y-1">
              <div className="flex items-center gap-2 font-semibold">
                <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                <span>Standard Multi-Tenant Safety Policy: Report-Only Enforcement</span>
              </div>
              <p className="text-[11px] text-amber-900 dark:text-amber-300 leading-relaxed">
                All selected baseline policies will be created across target tenants strictly in <strong>Report-Only</strong> mode (<code>state = &quot;enabledForReportingButNotEnforced&quot;</code>). This will evaluate policy hit rates and logs without challenging or locking out end users.
              </p>
            </div>

            {/* Target Baselines Summary */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-mono uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">
                Selected Baselines to Deploy ({baselineDefs.length})
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {baselineDefs.map((b) => (
                  <div
                    key={b.code}
                    className="p-2 bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded-sm space-y-0.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-slate-900 dark:text-slate-100">{b.code}</span>
                      {b.requiresEntraP2 && (
                        <span className="text-[9px] font-bold px-1.5 py-0.2 bg-indigo-50 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800 rounded-sm">
                          Requires P2
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-700 dark:text-slate-300 font-medium truncate">{b.name}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Target Tenants Summary */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-mono uppercase font-bold text-slate-500 dark:text-slate-400 tracking-wider">
                Target Customer Tenants ({selectedTenants.length})
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {selectedTenants.map((t) => {
                  const hasP2 = t.tier === "M365_E5" || (t.tier as string) === "Microsoft 365 E5";
                  return (
                    <div
                      key={t.id}
                      className="p-2 bg-slate-50 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded-sm flex items-center justify-between"
                    >
                      <div>
                        <div className="font-bold text-slate-900 dark:text-slate-100">{t.displayName}</div>
                        <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400">{t.tier.replace("_", " ")}</div>
                      </div>
                      {hasP2Baselines && (
                        <span
                          className={`text-[9px] font-bold px-1.5 py-0.5 rounded-sm border whitespace-nowrap inline-flex items-center gap-1 ${
                            hasP2
                              ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border-emerald-300"
                              : "bg-rose-50 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border-rose-300"
                          }`}
                        >
                          {hasP2 ? <ShieldCheck className="w-3 h-3 text-emerald-600" /> : <ShieldAlert className="w-3 h-3 text-rose-600" />}
                          <span>{hasP2 ? "P2 Ready" : "P2 Missing"}</span>
                        </span>
                      )}
                    </div>
                  );
                })}
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
                onClick={handleExecuteBulkDeploy}
                disabled={isExecuting || selectedBaselineCodes.length === 0 || selectedTenants.length === 0}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 dark:bg-emerald-600 dark:hover:bg-emerald-700 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                {isExecuting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5 text-amber-400" />}
                <span>
                  {isExecuting
                    ? "Executing Multi-Tenant Rollout..."
                    : `Deploy ${selectedBaselineCodes.length * selectedTenants.length} Policy Target(s) (Report-Only)`}
                </span>
              </button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};
