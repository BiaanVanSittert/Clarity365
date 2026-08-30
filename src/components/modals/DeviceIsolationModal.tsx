import React, { useState } from "react";
import { Modal } from "../common/Modal";
import { ShieldAlert, Laptop, Radio, Scan, RefreshCw, CheckCircle2, XCircle, ShieldCheck, Wifi, WifiOff } from "lucide-react";

interface DeviceIsolationModalProps {
  isOpen: boolean;
  onClose: () => void;
  tenantId: string;
  tenantName: string;
  deviceId: string;
  deviceName: string;
  isCurrentlyIsolated?: boolean;
  onSuccess?: () => void;
}

export const DeviceIsolationModal: React.FC<DeviceIsolationModalProps> = ({
  isOpen,
  onClose,
  tenantId,
  tenantName,
  deviceId,
  deviceName,
  isCurrentlyIsolated = false,
  onSuccess,
}) => {
  const [actionType, setActionType] = useState<"isolate" | "unisolate" | "scan">(
    isCurrentlyIsolated ? "unisolate" : "isolate"
  );
  const [scanType, setScanType] = useState<"quickScan" | "fullScan">("fullScan");
  const [comment, setComment] = useState(
    isCurrentlyIsolated
      ? "Threat eradicated. Released from isolation by Clarity365 Incident Response."
      : "Isolated by Clarity365 Incident Response due to suspected malware/C2 activity."
  );
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message?: string; error?: string } | null>(null);

  const handleExecute = async () => {
    setIsLoading(true);
    try {
      if (actionType === "isolate") {
        const res = await fetch(`/api/tenants/${tenantId}/incident-response/isolate-device`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "isolate", deviceId, deviceName, comment }),
        });
        const data = await res.json();
        setResult({
          success: data.success,
          message: data.success ? `Device '${deviceName}' isolated from network.` : undefined,
          error: data.error,
        });
      } else if (actionType === "unisolate") {
        const res = await fetch(`/api/tenants/${tenantId}/incident-response/isolate-device`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "unisolate", deviceId, deviceName, comment }),
        });
        const data = await res.json();
        setResult({
          success: data.success,
          message: data.success ? `Device '${deviceName}' released from network isolation.` : undefined,
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
        {actionType === "unisolate" ? (
          <div className="p-3 bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-800 text-emerald-950 dark:text-emerald-300 rounded-sm flex items-start gap-2.5">
            <ShieldCheck className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <div className="font-semibold text-emerald-900 dark:text-emerald-200">Release Endpoint from Network Isolation</div>
              <p className="leading-relaxed">
                Restores full corporate and internet network connectivity to <strong>{deviceName}</strong> once malware remediation is verified.
              </p>
            </div>
          </div>
        ) : actionType === "isolate" ? (
          <div className="p-3 bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-800 text-red-950 dark:text-red-300 rounded-sm flex items-start gap-2.5">
            <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <div className="font-semibold text-red-900 dark:text-red-200">Defender Endpoint Network Isolation</div>
              <p className="leading-relaxed">
                Isolating a device terminates all incoming/outgoing network communication except connectivity with Microsoft Defender cloud services and Intune.
              </p>
            </div>
          </div>
        ) : (
          <div className="p-3 bg-blue-50 dark:bg-blue-950/50 border border-blue-200 dark:border-blue-800 text-blue-950 dark:text-blue-300 rounded-sm flex items-start gap-2.5">
            <Scan className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <div className="font-semibold text-blue-900 dark:text-blue-200">On-Demand Antivirus Scan</div>
              <p className="leading-relaxed">
                Dispatches a cloud-managed Microsoft Defender Antivirus scan across processes, memory, and local disks.
              </p>
            </div>
          </div>
        )}

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
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => {
                  setActionType("isolate");
                  setComment("Isolated by Clarity365 Incident Response due to suspected malware/C2 activity.");
                }}
                className={`p-2.5 border text-left rounded-sm transition-all ${
                  actionType === "isolate"
                    ? "bg-red-50 dark:bg-red-950/40 border-red-400 dark:border-red-700 font-semibold"
                    : "bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 hover:border-slate-400"
                }`}
              >
                <div className="flex items-center gap-1.5 text-xs text-red-700 dark:text-red-400 mb-0.5">
                  <WifiOff size={13} />
                  <span>Isolate</span>
                </div>
                <p className="text-[10px] text-slate-500 dark:text-slate-400 font-normal">
                  Cut off network access.
                </p>
              </button>

              <button
                type="button"
                onClick={() => {
                  setActionType("unisolate");
                  setComment("Threat eradicated. Released from isolation by Clarity365 Incident Response.");
                }}
                className={`p-2.5 border text-left rounded-sm transition-all ${
                  actionType === "unisolate"
                    ? "bg-emerald-50 dark:bg-emerald-950/40 border-emerald-400 dark:border-emerald-700 font-semibold"
                    : "bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 hover:border-slate-400"
                }`}
              >
                <div className="flex items-center gap-1.5 text-xs text-emerald-700 dark:text-emerald-400 mb-0.5">
                  <Wifi size={13} />
                  <span>Release</span>
                </div>
                <p className="text-[10px] text-slate-500 dark:text-slate-400 font-normal">
                  Restore connectivity.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setActionType("scan")}
                className={`p-2.5 border text-left rounded-sm transition-all ${
                  actionType === "scan"
                    ? "bg-blue-50 dark:bg-blue-950/40 border-blue-400 dark:border-blue-700 font-semibold"
                    : "bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 hover:border-slate-400"
                }`}
              >
                <div className="flex items-center gap-1.5 text-xs text-blue-700 dark:text-blue-400 mb-0.5">
                  <Scan size={13} />
                  <span>Defender Scan</span>
                </div>
                <p className="text-[10px] text-slate-500 dark:text-slate-400 font-normal">
                  Trigger AV scan.
                </p>
              </button>
            </div>

            {actionType !== "scan" ? (
              <div>
                <label className="block text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  {actionType === "isolate" ? "Isolation Reason / Justification:" : "Release from Isolation Verification Note:"}
                </label>
                <textarea
                  rows={2}
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs border border-slate-300 dark:border-slate-600 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-slate-800"
                />
              </div>
            ) : (
              <div className="space-y-2 p-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-sm">
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
                    <span>Full Antivirus Scan (Thorough Disk Scan)</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="scanType"
                      checked={scanType === "quickScan"}
                      onChange={() => setScanType("quickScan")}
                    />
                    <span>Quick Scan (Memory & Active Processes)</span>
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
                  actionType === "isolate"
                    ? "bg-red-600 hover:bg-red-700"
                    : actionType === "unisolate"
                    ? "bg-emerald-600 hover:bg-emerald-700"
                    : "bg-blue-600 hover:bg-blue-700"
                }`}
              >
                {isLoading && <RefreshCw size={13} className="animate-spin" />}
                <span>
                  {isLoading
                    ? "Dispatching..."
                    : actionType === "isolate"
                    ? "Isolate Endpoint"
                    : actionType === "unisolate"
                    ? "Release from Isolation"
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
