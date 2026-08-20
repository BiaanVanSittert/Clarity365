import React, { useState, useEffect } from "react";
import { Modal } from "../common/Modal";
import { StatusPill } from "../common/StatusPill";
import { Tenant } from "@/lib/types";
import { TenantPermissionReport } from "@/lib/services/graph-client";
import { ShieldCheck, RefreshCw, AlertTriangle, CheckCircle, ExternalLink, Key } from "lucide-react";

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

  useEffect(() => {
    if (isOpen) {
      fetchPermissions();
    }
  }, [isOpen, tenant.id]);

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={`Azure App Registration Permissions — ${tenant.displayName}`}
      maxWidth="max-w-3xl"
    >
      <div className="space-y-4">
        {/* Header Summary */}
        <div className="flex items-center justify-between p-3 bg-slate-50 border border-slate-200 text-xs">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-slate-600" />
            <div>
              <span className="font-medium text-slate-700">Client ID: </span>
              <span className="font-mono text-slate-900">{tenant.credentials.clientId || "N/A (Simulated)"}</span>
              <span className="text-slate-400 mx-2">•</span>
              <span className="font-medium text-slate-700">Auth Mode: </span>
              <span className="uppercase text-slate-900 font-semibold">{tenant.credentials.authMode}</span>
            </div>
          </div>
          <button
            onClick={fetchPermissions}
            disabled={loading}
            className="flex items-center gap-1 px-2.5 py-1 bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 text-xs font-medium rounded-sm disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Testing..." : "Re-Test Permissions"}
          </button>
        </div>

        {error && (
          <div className="p-3 bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-rose-600" />
            <div>
              <div className="font-semibold">Authentication Error</div>
              <div>{error}</div>
            </div>
          </div>
        )}

        {report && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-600">
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

            {/* Permission Table */}
            <div className="border border-slate-200 overflow-hidden">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-slate-100 border-b border-slate-200 text-slate-700 font-semibold uppercase text-[10px] tracking-wider">
                  <tr>
                    <th className="p-2.5">Microsoft Graph Permission</th>
                    <th className="p-2.5">Type</th>
                    <th className="p-2.5">Required For</th>
                    <th className="p-2.5 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {report.permissions.map((p, idx) => (
                    <tr key={idx} className="hover:bg-slate-50">
                      <td className="p-2.5">
                        <div className="font-mono font-medium text-slate-900">{p.permission}</div>
                        <div className="text-[11px] text-slate-500">{p.description}</div>
                        {p.errorMessage && (
                          <div className="text-[10px] font-mono text-rose-700 mt-1 bg-rose-50 p-1 border border-rose-200">
                            {p.errorMessage}
                          </div>
                        )}
                      </td>
                      <td className="p-2.5">
                        <span className="px-1.5 py-0.5 bg-slate-100 text-slate-700 border border-slate-200 font-mono text-[10px]">
                          {p.scope}
                        </span>
                      </td>
                      <td className="p-2.5 text-slate-600">{p.requiredFor}</td>
                      <td className="p-2.5 text-right">
                        {p.status === "granted" ? (
                          <span className="inline-flex items-center gap-1 text-emerald-700 font-medium bg-emerald-50 px-2 py-0.5 border border-emerald-200 text-[11px]">
                            <CheckCircle className="w-3.5 h-3.5" /> Granted
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-rose-700 font-medium bg-rose-50 px-2 py-0.5 border border-rose-200 text-[11px]">
                            <AlertTriangle className="w-3.5 h-3.5" /> Missing (HTTP {p.statusCode || 403})
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Guidance for missing permissions */}
            <div className="p-3 bg-amber-50 border border-amber-200 text-amber-900 text-xs space-y-1">
              <div className="font-semibold flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-amber-700" />
                How to Grant Missing Permissions in Azure Portal:
              </div>
              <p className="text-[11px] text-amber-800 leading-relaxed">
                1. Navigate to <strong>Microsoft Entra Admin Center</strong> &gt; <strong>App registrations</strong> &gt; Select your App Registration.
                <br />
                2. Go to <strong>API permissions</strong> &gt; <strong>Add a permission</strong> &gt; <strong>Microsoft Graph</strong> &gt; <strong>Application permissions</strong>.
                <br />
                3. Check all required permissions listed above and click <strong>Grant admin consent for {tenant.displayName}</strong>.
              </p>
            </div>
          </div>
        )}

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
