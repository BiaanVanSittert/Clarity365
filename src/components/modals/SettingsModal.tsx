import React, { useState, useEffect } from "react";
import { Modal } from "../common/Modal";
import { SystemSettings } from "@/lib/types";
import { Settings, Cpu, Shield, Database, Check, RefreshCw } from "lucide-react";
import { StatusPill } from "../common/StatusPill";

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose }) => {
  const [settings, setSettings] = useState<SystemSettings>({
    enableMcpServer: true,
    mcpServerPort: 8365,
    allowToolExecution: true,
    autoSyncIntervalMinutes: 30,
    auditLogRetentionDays: 90,
    defaultTheme: "light",
    tableDensity: "compact",
  });
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetchSettings();
    }
  }, [isOpen]);

  const fetchSettings = async () => {
    setIsLoading(true);
    try {
      const res = await fetch("/api/settings");
      const data = await res.json();
      if (data.success && data.settings) {
        setSettings(data.settings);
      }
    } catch (err) {
      console.error("Failed to fetch settings", err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setSavedSuccess(false);

    try {
      const res = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      });
      const data = await res.json();
      if (data.success) {
        setSavedSuccess(true);
        setTimeout(() => {
          setSavedSuccess(false);
          onClose();
        }, 800);
      }
    } catch (err) {
      console.error("Failed to save settings", err);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Clarity365 Platform & Security Settings"
      subtitle="Configure internal MCP server, localhost binding, and multi-tenant synchronization parameters"
      maxWidth="xl"
    >
      <form onSubmit={handleSave} className="space-y-4">
        {/* Localhost Security Notice */}
        <div className="p-3 bg-slate-50 border border-slate-200 rounded-sm flex items-start gap-2.5">
          <Shield size={16} className="text-slate-700 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-700">
            <p className="font-semibold text-slate-900">Local Security Isolation Enforced</p>
            <p className="text-slate-600 mt-0.5">
              Clarity365 is bound strictly to <code className="bg-slate-200 px-1 py-0.5 rounded font-mono text-[11px]">127.0.0.1:3000</code>. No network listeners are exposed to the public Internet or local LAN.
            </p>
          </div>
        </div>

        {/* Model Context Protocol (MCP) Server Configuration */}
        <div className="border border-[#CBD5E1] p-3.5 bg-white rounded-sm space-y-3">
          <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2">
            <div className="flex items-center gap-2">
              <Cpu size={16} className="text-slate-700" />
              <h4 className="text-xs font-semibold text-slate-900">Model Context Protocol (MCP) Integration</h4>
            </div>
            <StatusPill
              status={settings.enableMcpServer ? "pass" : "disabled"}
              label={settings.enableMcpServer ? "Internal MCP Active" : "Disabled"}
            />
          </div>

          <p className="text-xs text-slate-600">
            Expose Clarity365's internal tools (<code className="font-mono text-[11px]">audit_conditional_access</code>, <code className="font-mono text-[11px]">query_signin_logs</code>, <code className="font-mono text-[11px]">manage_tabl</code>, <code className="font-mono text-[11px]">generate_remediation_plan</code>) to local AI agents or testing tools.
          </p>

          <div className="grid grid-cols-2 gap-3 pt-1">
            <label className="flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={settings.enableMcpServer}
                onChange={(e) => setSettings({ ...settings, enableMcpServer: e.target.checked })}
                className="rounded-sm border-slate-300 text-slate-900 focus:ring-0"
              />
              <span>Enable In-House MCP Server</span>
            </label>

            <label className="flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={settings.allowToolExecution}
                onChange={(e) => setSettings({ ...settings, allowToolExecution: e.target.checked })}
                className="rounded-sm border-slate-300 text-slate-900 focus:ring-0"
              />
              <span>Allow Autonomous Tool Execution</span>
            </label>
          </div>

          <div>
            <label className="block text-[11px] font-medium text-slate-600 mb-1">
              Internal MCP Standalone Port (Localhost)
            </label>
            <input
              type="number"
              value={settings.mcpServerPort}
              onChange={(e) => setSettings({ ...settings, mcpServerPort: parseInt(e.target.value) || 8365 })}
              className="w-40 px-2.5 py-1 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-mono"
            />
          </div>
        </div>

        {/* Sync & Retention */}
        <div className="border border-[#CBD5E1] p-3.5 bg-white rounded-sm space-y-3">
          <div className="flex items-center gap-2 border-b border-[#E2E8F0] pb-2">
            <Database size={16} className="text-slate-700" />
            <h4 className="text-xs font-semibold text-slate-900">Tenant Telemetry & Caching</h4>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Auto-Sync Interval (Minutes)
              </label>
              <select
                value={settings.autoSyncIntervalMinutes}
                onChange={(e) => setSettings({ ...settings, autoSyncIntervalMinutes: parseInt(e.target.value) })}
                className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
              >
                <option value={15}>15 Minutes</option>
                <option value={30}>30 Minutes (Recommended)</option>
                <option value={60}>60 Minutes</option>
                <option value={360}>Every 6 Hours</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Audit Log Retention Window
              </label>
              <select
                value={settings.auditLogRetentionDays}
                onChange={(e) => setSettings({ ...settings, auditLogRetentionDays: parseInt(e.target.value) })}
                className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
              >
                <option value={30}>30 Days</option>
                <option value={90}>90 Days (Enterprise Standard)</option>
                <option value={180}>180 Days</option>
                <option value={365}>365 Days</option>
              </select>
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2 border-t border-[#E2E8F0]">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 border border-[#CBD5E1] bg-white rounded-sm hover:bg-slate-50 transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isSaving}
            className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            {savedSuccess ? <Check size={14} /> : <Settings size={14} />}
            <span>{isSaving ? "Saving..." : savedSuccess ? "Settings Saved" : "Save Preferences"}</span>
          </button>
        </div>
      </form>
    </Modal>
  );
};
