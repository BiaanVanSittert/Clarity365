import React, { useState } from "react";
import { Modal } from "../common/Modal";
import { ShieldAlert, Laptop, Radio, Scan, RefreshCw, CheckCircle2, XCircle } from "lucide-react";

interface DeviceIsolationModalProps {
  isOpen: boolean;
  onClose: () => void;
  tenantId: string;
  tenantName: string;
  deviceId: string;
  deviceName: string;
  onSuccess?: () => void;
}

export const DeviceIsolationModal: React.FC<DeviceIsolationModalProps> = ({
  isOpen,
  onClose,
  tenantId,
  tenantName,
  deviceId,
  deviceName,
  onSuccess,
}) => {
  const [actionType, setActionType] = useState<"isolate" | "scan">("isolate");
  const [scanType, setScanType] = useState<"quickScan" | "fullScan">("fullScan");
  const [comment, setComment] = useState("Isolated by Clarity365 Incident Response due to suspected malware/c2 activity.");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message?: string; error?: string } | null>(null);

  const handleExecute = async () => {
    setIsLoading(true);
    try {
      if (actionType === "isolate") {
        const res = await fetch(`/api/tenants/${tenantId}/incident-response/isolate-device`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ deviceId, deviceName, comment }),
        });
        const data = await res.json();
        setResult({
          success: data.success,
          message: data.success ? `Device '${deviceName}' isolated from network.` : undefined,
          error: data.error,
        });
      } else {
        const res = await fetch(`/api/tenants/${tenantId}/incident-response/scan-device`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ deviceId, deviceName, scanType }),
        });
        const data = await res.json();
        setResult({
          success: data.success,
          message: data.success ? `Triggered ${scanType} Defender scan on '${deviceName}'.` : undefined,
          error: data.error,
        });
      }
      if (onSuccess) onSuccess();
    } catch (err: any) {
      setResult({ success: false, error: err.message || "Failed to execute device action" });
    } finally {
      setIsLoading(false);
    }
  };

  const handleClose = () => {
    setResult(null);
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Endpoint Remote Containment & Security Actions"
      subtitle={`Defender for Endpoint response actions for ${deviceName} (${tenantName})`}
      maxWidth="lg"
    >
      <div className="space-y-4">
        {/* Banner */}
        <div className="p-3 bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800 text-amber-950 dark:text-amber-300 rounded-sm flex items-start gap-2.5">
          <ShieldAlert className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs space-y-1">
            <div className="font-semibold text-amber-900 dark:text-amber-200">Defender Endpoint Containment</div>
            <p className="leading-relaxed">
              Isolating a device cuts off all incoming/outgoing network communication except connectivity with Microsoft Defender cloud services and Intune.
            </p>
          </div>
        </div>

        {result ? (
          <div className="space-y-4">
            <div className={`p-4 border rounded-sm ${result.success ? "bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800" : "bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800"}`}>
              <div className="flex items-center gap-2 font-semibold text-xs mb-1">
                {result.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-600 dark:text-rose-400" />
                )}
                <span className={result.success ? "text-emerald-900 dark:text-emerald-200" : "text-rose-900 dark:text-rose-200"}>
                  {result.success ? "Command Dispatched Successfully" : "Action Failed"}
                </span>
              </div>
              <p className="text-xs text-slate-700 dark:text-slate-300 mt-1">
                {result.message || result.error}
              </p>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-200 dark:border-slate-700">
              <button
                onClick={handleClose}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm"
              >
                Close
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Action Type Selection */}
            <div className="grid grid-cols-2 gap-2.5">
              <button
                type="button"
                onClick={() => setActionType("isolate")}
                className={`p-3 border text-left rounded-sm transition-all ${
                  actionType === "isolate"
                    ? "bg-red-50 dark:bg-red-950/40 border-red-400 dark:border-red-700 font-semibold"
                    : "bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 hover:border-slate-400"
                }`}
              >
                <div className="flex items-center gap-2 text-xs text-red-700 dark:text-red-400 mb-1">
                  <Radio size={14} />
                  <span>Network Isolation</span>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 font-normal">
                  Cut off device from local network & internet.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setActionType("scan")}
                className={`p-3 border text-left rounded-sm transition-all ${
                  actionType === "scan"
                    ? "bg-blue-50 dark:bg-blue-950/40 border-blue-400 dark:border-blue-700 font-semibold"
                    : "bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 hover:border-slate-400"
                }`}
              >
                <div className="flex items-center gap-2 text-xs text-blue-700 dark:text-blue-400 mb-1">
                  <Scan size={14} />
                  <span>Defender Antivirus Scan</span>
                </div>
                <p className="text-[11px] text-slate-500 dark:text-slate-400 font-normal">
                  Trigger on-demand background malware scan.
                </p>
              </button>
            </div>

            {actionType === "isolate" ? (
              <div>
                <label className="block text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Isolation Justification / Audit Comment:
                </label>
                <textarea
                  rows={2}
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs border border-slate-300 dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-800"
                />
              </div>
            ) : (
              <div className="space-y-2">
                <label className="block text-[11px] font-semibold text-slate-700 dark:text-slate-300">
                  Select Scan Depth:
                </label>
                <div className="flex gap-4 text-xs">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="scanType"
                      checked={scanType === "fullScan"}
                      onChange={() => setScanType("fullScan")}
                    />
                    <span>Full Antivirus Scan (Thorough)</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="scanType"
                      checked={scanType === "quickScan"}
                      onChange={() => setScanType("quickScan")}
                    />
                    <span>Quick Scan (Processes & Memory)</span>
                  </label>
                </div>
              </div>
            )}

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
                onClick={handleExecute}
                disabled={isLoading}
                className={`px-4 py-1.5 text-xs font-semibold text-white rounded-sm flex items-center gap-1.5 shadow-sm transition-colors ${
                  actionType === "isolate" ? "bg-red-600 hover:bg-red-700" : "bg-blue-600 hover:bg-blue-700"
                }`}
              >
                {isLoading && <RefreshCw size={13} className="animate-spin" />}
                <span>
                  {isLoading
                    ? "Dispatching..."
                    : actionType === "isolate"
                    ? "Isolate Endpoint"
                    : "Trigger Defender Scan"}
                </span>
              </button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
};
