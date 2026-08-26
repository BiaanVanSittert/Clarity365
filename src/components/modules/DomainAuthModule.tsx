import React from "react";
import { TenantSecuritySnapshot, DomainAuthCheck } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { Fingerprint, ExternalLink, Mail, AlertTriangle } from "lucide-react";

interface DomainAuthModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenPermissions: () => void;
}

function statusToPillStatus(status: DomainAuthCheck["status"]): "pass" | "warn" | "fail" | "info" {
  if (status === "pass") return "pass";
  if (status === "warn") return "warn";
  if (status === "fail") return "fail";
  return "info";
}

const CheckCell: React.FC<{ check: DomainAuthCheck }> = ({ check }) => (
  <td className="align-top">
    <div className="space-y-1">
      <StatusPill status={statusToPillStatus(check.status)} label={check.status.toUpperCase()} size="sm" />
      <div className="text-[11px] text-slate-500 dark:text-slate-400 max-w-xs">{check.detail}</div>
      {check.recommendation && (
        <div className="text-[10px] font-mono bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700 p-1.5 rounded-sm text-slate-700 dark:text-slate-300 max-w-sm break-words">
          {check.recommendation}
        </div>
      )}
    </div>
  </td>
);

export const DomainAuthModule: React.FC<DomainAuthModuleProps> = ({ snapshot, onOpenPermissions }) => {
  const { domainAuth, tenant } = snapshot;
  const exoConnected = !!tenant.credentials.exoRefreshToken;
  const domainAuthSyncErrors = (snapshot.syncHealth?.errors || []).filter((e) => e.startsWith("Domain Auth:"));

  const fullyPassingCount = domainAuth.filter((d) => d.dkim.status === "pass" && d.spf.status === "pass" && d.dmarc.status === "pass").length;

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] dark:bg-slate-900/50 border border-[#CBD5E1] dark:border-slate-700 p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Fingerprint size={18} className="text-slate-800 dark:text-slate-200" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
              Domain Authentication (SPF / DKIM / DMARC)
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            The primary defense against someone spoofing your own domain to phish your customers and partners.
            SPF/DMARC live in public DNS, so fixes here are exact record text to publish at your domain registrar,
            not a button.
          </p>
        </div>
        {domainAuth.length > 0 && (
          <div className={`p-2.5 border rounded-sm flex items-center gap-2 text-xs ${fullyPassingCount === domainAuth.length ? "bg-emerald-50 dark:bg-emerald-950 border-emerald-300 dark:border-emerald-800 text-emerald-900 dark:text-emerald-400" : "bg-amber-50 dark:bg-amber-950 border-amber-300 dark:border-amber-800 text-amber-900 dark:text-amber-400"}`}>
            <span>
              <strong>{fullyPassingCount}</strong> / {domainAuth.length} domains fully passing all three checks
            </span>
          </div>
        )}
      </div>

      <div className="border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] dark:bg-slate-900/50 border-b border-[#CBD5E1] dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            Accepted Domain Authentication Status
          </h3>
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">{domainAuth.length} Domains</span>
        </div>

        {!exoConnected ? (
          <div className="p-6 text-center space-y-2">
            <Mail className="w-6 h-6 text-slate-300 mx-auto" />
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Connect Exchange Online to enumerate accepted domains and check their DKIM/SPF/DMARC status.
            </p>
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
            {domainAuthSyncErrors.length > 0 && (
              <div className="m-3 p-3 bg-rose-50 dark:bg-red-950 border border-rose-300 dark:border-red-800 text-rose-900 dark:text-red-300 text-xs rounded-sm space-y-1.5">
                <div className="flex items-center gap-2 font-semibold">
                  <AlertTriangle size={14} className="text-rose-600 dark:text-red-400" />
                  <span>Sync error</span>
                </div>
                {domainAuthSyncErrors.map((err, i) => (
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
                    <th className="w-48">Domain</th>
                    <th>DKIM</th>
                    <th>SPF</th>
                    <th>DMARC</th>
                  </tr>
                </thead>
                <tbody>
                  {domainAuth.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="p-4 text-center text-xs text-slate-500 dark:text-slate-400">
                        {domainAuthSyncErrors.length > 0
                          ? "Domains couldn't be loaded due to the sync error above."
                          : "No accepted domains found for this tenant."}
                      </td>
                    </tr>
                  ) : (
                    domainAuth.map((d) => (
                      <tr key={d.domain}>
                        <td className="align-top">
                          <div className="font-semibold text-xs text-slate-900 dark:text-slate-100">{d.domain}</div>
                          {d.isDefaultDomain && (
                            <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono uppercase mt-0.5">Default domain</div>
                          )}
                        </td>
                        <CheckCell check={d.dkim} />
                        <CheckCell check={d.spf} />
                        <CheckCell check={d.dmarc} />
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
