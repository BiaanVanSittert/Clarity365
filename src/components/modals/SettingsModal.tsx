import React, { useState, useEffect } from "react";
import { Modal } from "../common/Modal";
import { SystemSettings } from "@/lib/types";
import { Settings, Cpu, Shield, Database, Check, RefreshCw, KeyRound } from "lucide-react";
import { StatusPill } from "../common/StatusPill";

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose }) => {
  const [settings, setSettings] = useState<SystemSettings>({
    enableMcpServer: true,
    allowToolExecution: true,
    autoSyncIntervalMinutes: 30,
    auditLogRetentionDays: 90,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [settingsError, setSettingsError] = useState<string | null>(null);

  // Change Password
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordSuccess, setPasswordSuccess] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetchSettings();
      setCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
      setPasswordError(null);
      setPasswordSuccess(false);
      setSettingsError(null);
      setSavedSuccess(false);
    }
  }, [isOpen]);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError(null);
    setPasswordSuccess(false);
    setIsChangingPassword(true);

    try {
      const res = await fetch("/api/auth/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword, newPassword, confirmPassword: confirmNewPassword }),
      });
      const data = await res.json();
      if (!data.success) {
        throw new Error(data.error || "Failed to change password.");
      }
      setPasswordSuccess(true);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
      setTimeout(() => setPasswordSuccess(false), 2500);
    } catch (err: any) {
      setPasswordError(err.message || "An unexpected error occurred.");
    } finally {
      setIsChangingPassword(false);
    }
  };

  const fetchSettings = async () => {
    setIsLoading(true);
    setSettingsError(null);
    try {
      const res = await fetch("/api/settings");
      const data = await res.json();
      if (data.success && data.settings) {
        setSettings(data.settings);
      } else {
        setSettingsError(data.error || "Failed to load current settings - showing defaults, which may not reflect what's actually saved.");
      }
    } catch (err) {
      console.error("Failed to fetch settings", err);
      setSettingsError("Failed to load current settings - showing defaults, which may not reflect what's actually saved.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setSavedSuccess(false);
    setSettingsError(null);

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
      } else {
        setSettingsError(data.error || "Failed to save settings.");
      }
    } catch (err: any) {
      console.error("Failed to save settings", err);
      setSettingsError(err.message || "Failed to reach the server while saving settings.");
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
      <div className="space-y-4">
      <form onSubmit={handleSave} className="space-y-4">
        {settingsError && (
          <div className="p-2.5 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-xs rounded-sm">
            {settingsError}
          </div>
        )}

        {/* Localhost Security Notice */}
        <div className="p-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm flex items-start gap-2.5">
          <Shield size={16} className="text-slate-700 dark:text-slate-300 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-700 dark:text-slate-300">
            <p className="font-semibold text-slate-900 dark:text-slate-100">Local Security Isolation Enforced</p>
            <p className="text-slate-600 dark:text-slate-400 mt-0.5">
              Clarity365 is bound strictly to <code className="bg-slate-200 dark:bg-slate-700 px-1 py-0.5 rounded font-mono text-[11px]">127.0.0.1:3000</code>. No network listeners are exposed to the public Internet or local LAN.
            </p>
          </div>
        </div>

        {/* Model Context Protocol (MCP) Server Configuration */}
        <div className="border border-[#CBD5E1] dark:border-slate-700 p-3.5 bg-white dark:bg-slate-800 rounded-sm space-y-3">
          <div className="flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-700 pb-2">
            <div className="flex items-center gap-2">
              <Cpu size={16} className="text-slate-700 dark:text-slate-300" />
              <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">Model Context Protocol (MCP) Integration</h4>
            </div>
            <StatusPill
              status={settings.enableMcpServer ? "pass" : "disabled"}
              label={settings.enableMcpServer ? "Internal MCP Active" : "Disabled"}
            />
          </div>

          <p className="text-xs text-slate-600 dark:text-slate-400">
            Expose Clarity365&apos;s internal tools (<code className="font-mono text-[11px]">audit_conditional_access</code>, <code className="font-mono text-[11px]">query_signin_logs</code>, <code className="font-mono text-[11px]">manage_tabl</code>, <code className="font-mono text-[11px]">generate_remediation_plan</code>) to local AI agents or testing tools.
          </p>

          <div className="grid grid-cols-2 gap-3 pt-1">
            <label className="flex items-center gap-2 text-xs font-medium text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={settings.enableMcpServer}
                onChange={(e) => setSettings({ ...settings, enableMcpServer: e.target.checked })}
                className="rounded-sm border-slate-300 dark:border-slate-600 text-slate-900 dark:text-slate-100 focus:ring-0"
              />
              <span>Enable In-House MCP Server</span>
            </label>

            <label className="flex items-center gap-2 text-xs font-medium text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={settings.allowToolExecution}
                onChange={(e) => setSettings({ ...settings, allowToolExecution: e.target.checked })}
                className="rounded-sm border-slate-300 dark:border-slate-600 text-slate-900 dark:text-slate-100 focus:ring-0"
              />
              <span>Allow Autonomous Tool Execution</span>
            </label>
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            When disabled, MCP agents can still read tenant data but cannot modify the Tenant Allow/Block List.
          </p>
        </div>

        {/* Sync & Retention */}
        <div className="border border-[#CBD5E1] dark:border-slate-700 p-3.5 bg-white dark:bg-slate-800 rounded-sm space-y-3">
          <div className="flex items-center gap-2 border-b border-[#E2E8F0] dark:border-slate-700 pb-2">
            <Database size={16} className="text-slate-700 dark:text-slate-300" />
            <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">Tenant Telemetry & Caching</h4>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Auto-Sync Interval (Minutes)
              </label>
              <select
                value={settings.autoSyncIntervalMinutes}
                onChange={(e) => setSettings({ ...settings, autoSyncIntervalMinutes: parseInt(e.target.value) })}
                className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
              >
                <option value={15}>15 Minutes</option>
                <option value={30}>30 Minutes (Recommended)</option>
                <option value={60}>60 Minutes</option>
                <option value={360}>Every 6 Hours</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Audit Log Retention Window
              </label>
              <select
                value={settings.auditLogRetentionDays}
                onChange={(e) => setSettings({ ...settings, auditLogRetentionDays: parseInt(e.target.value) })}
                className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
              >
                <option value={30}>30 Days</option>
                <option value={90}>90 Days (Enterprise Standard)</option>
                <option value={180}>180 Days</option>
                <option value={365}>365 Days</option>
              </select>
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-2 border-t border-[#E2E8F0] dark:border-slate-700">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
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

      {/* Change Operator Password */}
      <form onSubmit={handleChangePassword} className="border border-[#CBD5E1] dark:border-slate-700 p-3.5 bg-white dark:bg-slate-800 rounded-sm space-y-3">
        <div className="flex items-center gap-2 border-b border-[#E2E8F0] dark:border-slate-700 pb-2">
          <KeyRound size={16} className="text-slate-700 dark:text-slate-300" />
          <h4 className="text-xs font-semibold text-slate-900 dark:text-slate-100">Change Operator Password</h4>
        </div>

        {passwordError && (
          <div className="p-2.5 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-xs rounded-sm">
            {passwordError}
          </div>
        )}

        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">Current Password</label>
            <input
              type="password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
            />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">New Password</label>
            <input
              type="password"
              required
              minLength={8}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
            />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">Confirm New Password</label>
            <input
              type="password"
              required
              minLength={8}
              value={confirmNewPassword}
              onChange={(e) => setConfirmNewPassword(e.target.value)}
              className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
            />
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={isChangingPassword}
            className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            {passwordSuccess ? <Check size={14} /> : <KeyRound size={14} />}
            <span>{isChangingPassword ? "Updating..." : passwordSuccess ? "Password Updated" : "Update Password"}</span>
          </button>
        </div>
      </form>
      </div>
    </Modal>
  );
};
