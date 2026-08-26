import React, { useState } from "react";
import { TenantSecuritySnapshot } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Modal } from "../common/Modal";
import { evaluateMailflowBaseline } from "@/lib/services/mailflow-baseline-matcher";
import { MAILFLOW_BASELINE_STANDARDS } from "@/lib/data/mailflow-baseline-definitions";
import { GitBranch, AlertTriangle, Wrench, ExternalLink, Mail } from "lucide-react";

interface MailflowRulesModuleProps {
  snapshot: TenantSecuritySnapshot;
  onLocalRefresh: () => void;
  onOpenPermissions: () => void;
}

export const MailflowRulesModule: React.FC<MailflowRulesModuleProps> = ({
  snapshot,
  onLocalRefresh,
  onOpenPermissions,
}) => {
  const { mailflowTransportRules, mailflowConnectors, mdoThreat, tenant, remoteDomainAutoForwardBlocked, externalSenderTagEnabled } = snapshot;

  const exoConnected = !!tenant.credentials.exoRefreshToken;
  const exoWriteEnabled = !!tenant.credentials.exoWriteEnabled;
  const mailflowSyncErrors = (snapshot.syncHealth?.errors || []).filter((e) => e.startsWith("Mailflow:"));

  const { results, coveragePercent } = evaluateMailflowBaseline({
    transportRules: mailflowTransportRules,
    policies: mdoThreat.policies,
    connectors: mailflowConnectors,
    remoteDomainAutoForwardBlocked,
    externalSenderTagEnabled,
  });
  const checksBelowCount = results.filter((r) => !r.met).length;
  const resultFor = (code: string) => results.find((r) => r.code === code)!;

  // ---- Fix confirm modal (handles both per-rule and tenant-wide fixes) ----
  const [fixTarget, setFixTarget] = useState<{ code: string; ruleId?: string; ruleName?: string } | null>(null);
  const [isFixing, setIsFixing] = useState(false);
  const [fixError, setFixError] = useState<string | null>(null);
  const fixStandard = fixTarget ? MAILFLOW_BASELINE_STANDARDS.find((s) => s.code === fixTarget.code) : undefined;

  const closeFixModal = () => {
    setFixTarget(null);
    setFixError(null);
  };

  const applyFix = async () => {
    if (!fixTarget) return;
    setIsFixing(true);
    setFixError(null);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}/mailflow-baseline-fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: fixTarget.code, ruleId: fixTarget.ruleId }),
      });
      const data = await res.json();
      if (data.success) {
        closeFixModal();
        onLocalRefresh();
      } else {
        setFixError(data.error || "Failed to apply fix.");
      }
    } catch (err: any) {
      setFixError(err.message || "Network error while applying fix.");
    } finally {
      setIsFixing(false);
    }
  };

  const renderAction = (standard: (typeof MAILFLOW_BASELINE_STANDARDS)[number]) => {
    const result = resultFor(standard.code);
    if (result.met) {
      return <span className="text-[11px] text-slate-400 dark:text-slate-500">No action needed</span>;
    }
    if (!standard.remediation) {
      return <span className="text-[11px] text-slate-500 dark:text-slate-400">Manual review required</span>;
    }
    if (!exoConnected) {
      return (
        <button
          onClick={onOpenPermissions}
          title="Connect Exchange Online to enable one-click fixes"
          className="text-[11px] text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 inline-flex items-center gap-1 underline decoration-dotted"
        >
          <ExternalLink size={11} />
          <span>Connect EXO to fix</span>
        </button>
      );
    }
    if (!exoWriteEnabled) {
      return (
        <span className="text-[11px] text-slate-400 dark:text-slate-500" title="Enable live Exchange Online writes in the Permissions check to use one-click fixes">
          Enable write access to fix
        </span>
      );
    }

    // MF04/07/08 are single tenant-wide settings - one fix button. MF01/02
    // can have several offending rules - one fix button per rule, since each
    // is independently safe to disable regardless of the others. MF05/06
    // (connectors) have no remediation defined at all, so they never reach
    // this function past the !standard.remediation check above.
    if (standard.code === "MF04" || standard.code === "MF07" || standard.code === "MF08") {
      return (
        <button
          onClick={() => {
            setFixError(null);
            setFixTarget({ code: standard.code });
          }}
          className="px-2.5 py-1 text-[11px] font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm inline-flex items-center gap-1"
        >
          <Wrench size={11} />
          <span>Fix This</span>
        </button>
      );
    }

    const offendingIds = result.offendingRuleIds || [];
    const offendingNames = result.offendingRuleNames || [];
    return (
      <div className="space-y-1">
        {offendingIds.map((id, i) => (
          <button
            key={id}
            onClick={() => {
              setFixError(null);
              setFixTarget({ code: standard.code, ruleId: id, ruleName: offendingNames[i] });
            }}
            title={offendingNames[i]}
            className="px-2.5 py-1 text-[11px] font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm inline-flex items-center gap-1 w-full justify-center"
          >
            <Wrench size={11} />
            <span className="truncate max-w-[140px]">Disable "{offendingNames[i]}"</span>
          </button>
        ))}
      </div>
    );
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <GitBranch size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Transport & Mail Flow Rules Baseline
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Score every org-wide transport rule against known abuse patterns (external redirects, spam-filter bypasses,
            unscoped permanent rules) and confirm the tenant-wide auto-forwarding kill switch is on.
          </p>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="p-3 bg-white dark:bg-slate-800 border border-[#CBD5E1] dark:border-slate-700 rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400 font-semibold">Baseline Coverage</div>
          <div className="text-xl font-bold font-mono text-slate-900 dark:text-slate-100 tabular-nums mt-0.5">{coveragePercent}%</div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            {results.length - checksBelowCount} / {results.length} checks met
          </div>
        </div>
        <div className={`p-3 border rounded-sm ${checksBelowCount > 0 ? "bg-[#FEF2F2] dark:bg-red-950 border-[#EF4444] dark:border-red-800" : "bg-white dark:bg-slate-800 border-[#CBD5E1] dark:border-slate-700"}`}>
          <div className={`text-[10px] uppercase font-mono font-semibold ${checksBelowCount > 0 ? "text-[#991B1B] dark:text-red-400" : "text-slate-500 dark:text-slate-400"}`}>
            Checks Below Recommended
          </div>
          <div className={`text-xl font-bold font-mono tabular-nums mt-0.5 ${checksBelowCount > 0 ? "text-[#991B1B] dark:text-red-400" : "text-slate-900 dark:text-slate-100"}`}>
            {checksBelowCount}
          </div>
          <div className={`text-[11px] mt-0.5 ${checksBelowCount > 0 ? "text-[#991B1B] dark:text-red-400" : "text-slate-500 dark:text-slate-400"}`}>Out of {results.length} checks</div>
        </div>
      </div>

      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Mail Flow Rule Baseline Specification & Configuration Alignment
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
            {coveragePercent}% ({results.length - checksBelowCount}/{results.length})
          </span>
        </div>

        {!exoConnected ? (
          <div className="p-6 text-center space-y-2">
            <Mail className="w-6 h-6 text-slate-300 mx-auto" />
            <p className="text-xs text-slate-500 dark:text-slate-400">Connect Exchange Online to score your tenant's mail flow rule configuration.</p>
            <button
              onClick={onOpenPermissions}
              className="px-3 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm inline-flex items-center gap-1.5"
            >
              <ExternalLink size={13} />
              <span>Connect Exchange Online</span>
            </button>
          </div>
        ) : (
          <>
            {mailflowSyncErrors.length > 0 && (
              <div className="m-3 p-3 bg-rose-50 dark:bg-red-950 border border-rose-300 dark:border-red-800 text-rose-900 dark:text-red-300 text-xs rounded-sm space-y-1.5">
                <div className="flex items-center gap-2 font-semibold">
                  <AlertTriangle size={14} className="text-rose-600 dark:text-red-400" />
                  <span>Exchange Online sync error</span>
                </div>
                {mailflowSyncErrors.map((err, i) => (
                  <div key={i} className="text-[11px] font-mono bg-white/70 dark:bg-slate-900/50 p-1.5 border border-rose-200 dark:border-red-800 rounded-sm">
                    {err}
                  </div>
                ))}
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse table-dense">
                <thead>
                  <tr>
                    <th className="w-16">Code</th>
                    <th>Baseline Check</th>
                    <th className="w-32">Status</th>
                    <th className="w-56 text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {MAILFLOW_BASELINE_STANDARDS.map((standard) => {
                    const result = resultFor(standard.code);
                    return (
                      <tr key={standard.code}>
                        <td className="font-mono font-bold text-xs text-slate-900 dark:text-slate-100">{standard.code}</td>
                        <td>
                          <div className="font-semibold text-xs text-slate-900 dark:text-slate-100">{standard.name}</div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">{standard.description}</div>
                          <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">Mitigates: {standard.riskMitigated}</div>
                        </td>
                        <td>
                          {result.met ? (
                            <StatusPill status="pass" label="Met" size="sm" />
                          ) : (
                            <StatusPill
                              status="fail"
                              label={result.offendingRuleNames ? `${result.offendingRuleNames.length} item(s) flagged` : "Below Recommended"}
                              size="sm"
                            />
                          )}
                        </td>
                        <td className="text-right">{renderAction(standard)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      {/* Confirm Remediation Modal */}
      <Modal
        isOpen={!!fixTarget}
        onClose={closeFixModal}
        title="Confirm Remediation"
        subtitle={fixStandard ? `${fixStandard.code}: ${fixStandard.name}` : undefined}
        maxWidth="md"
      >
        {fixStandard?.remediation && (
          <div className="space-y-3">
            <div className="p-3.5 bg-slate-900 text-white rounded-sm space-y-2.5 border border-slate-800">
              <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs">
                <AlertTriangle className="w-4 h-4" />
                <span>Confirm Live Write to Exchange Online</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {fixTarget?.ruleName ? (
                  <>
                    This will immediately disable the rule <strong>{fixTarget.ruleName}</strong>.
                  </>
                ) : (
                  fixStandard.remediation.summary
                )}{" "}
                This takes effect right away - there is no undo from here.
              </p>
              <div className="p-2 bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 rounded-sm">
                {fixStandard.remediation.cmdlet}
                {fixTarget?.ruleName ? ` -Identity "${fixTarget.ruleName}"` : ""}
              </div>
              {fixError && (
                <div className="p-2 bg-rose-950 border border-rose-800 text-rose-200 text-[11px] rounded-sm">{fixError}</div>
              )}
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={closeFixModal}
                  disabled={isFixing}
                  className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-sm transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={applyFix}
                  disabled={isFixing}
                  className="px-4 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-700 dark:bg-emerald-700 dark:hover:bg-emerald-600 rounded-sm transition-colors disabled:opacity-50"
                >
                  {isFixing ? "Applying..." : "Confirm & Apply Fix"}
                </button>
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
