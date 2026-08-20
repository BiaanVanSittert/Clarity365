import React, { useState } from "react";
import { Modal } from "../common/Modal";
import { TenantLicenseType } from "@/lib/types";
import { ShieldCheck, Plus, Key, Globe, Server, Check } from "lucide-react";

interface AddTenantModalProps {
  isOpen: boolean;
  onClose: () => void;
  onTenantAdded: () => void;
}

export const AddTenantModal: React.FC<AddTenantModalProps> = ({ isOpen, onClose, onTenantAdded }) => {
  const [mode, setMode] = useState<"demo" | "live">("live");
  const [displayName, setDisplayName] = useState("");
  const [defaultDomainName, setDefaultDomainName] = useState("");
  const [organizationId, setOrganizationId] = useState("");
  const [primaryContact, setPrimaryContact] = useState("");
  const [tier, setTier] = useState<TenantLicenseType>("M365_E5");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      const payload = {
        displayName: displayName.trim(),
        defaultDomainName: defaultDomainName.trim().toLowerCase(),
        organizationId: organizationId.trim() || undefined,
        primaryContact: primaryContact.trim() || undefined,
        tier,
        isDemo: mode === "demo",
        credentials: {
          tenantId: organizationId.trim() || crypto.randomUUID(),
          clientId: clientId.trim() || undefined,
          clientSecret: clientSecret.trim() || undefined,
          authMode: mode === "live" && clientId ? "secret" : "mock",
          status: "connected",
        },
      };

      const res = await fetch("/api/tenants", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!data.success) {
        throw new Error(data.error || "Failed to create tenant");
      }

      onTenantAdded();
      onClose();
      // Reset form
      setDisplayName("");
      setDefaultDomainName("");
      setOrganizationId("");
      setPrimaryContact("");
      setClientId("");
      setClientSecret("");
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Add Customer Tenant / Organization"
      subtitle="Register an M365 tenant with Microsoft Graph credentials or deploy an instant demo environment"
      maxWidth="xl"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="p-2.5 bg-red-50 border border-red-200 text-red-700 text-xs rounded-sm">
            {error}
          </div>
        )}

        <div className="flex border border-[#CBD5E1] p-1 bg-[#F8FAFC] rounded-sm text-xs font-medium">
          <button
            type="button"
            onClick={() => setMode("live")}
            className={`flex-1 py-1.5 px-3 rounded-sm flex items-center justify-center gap-1.5 transition-colors ${
              mode === "live" ? "bg-white border border-[#CBD5E1] text-slate-900 shadow-sm" : "text-slate-500 hover:text-slate-800"
            }`}
          >
            <Server size={14} />
            <span>Live Azure App Registration</span>
          </button>
          <button
            type="button"
            onClick={() => setMode("demo")}
            className={`flex-1 py-1.5 px-3 rounded-sm flex items-center justify-center gap-1.5 transition-colors ${
              mode === "demo" ? "bg-white border border-[#CBD5E1] text-slate-900 shadow-sm" : "text-slate-500 hover:text-slate-800"
            }`}
          >
            <Globe size={14} />
            <span>Simulated / Demo Environment</span>
          </button>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Organization / Company Name <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              required
              placeholder="e.g. Acme Health Corp"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Default Domain Name <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              required
              placeholder="e.g. acmehealth.onmicrosoft.com"
              value={defaultDomainName}
              onChange={(e) => setDefaultDomainName(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-mono"
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">Primary License SKU Tier</label>
            <select
              value={tier}
              onChange={(e) => setTier(e.target.value as TenantLicenseType)}
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
            >
              <option value="M365_E5">Microsoft 365 E5 (Full Security Suite)</option>
              <option value="M365_E3">Microsoft 365 E3</option>
              <option value="M365_BP">Microsoft 365 Business Premium</option>
              <option value="M365_F3">Microsoft 365 F3 (Frontline)</option>
              <option value="A5_EDU">Microsoft 365 A5 (Education)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">Primary Security Contact</label>
            <input
              type="email"
              placeholder="secops@acmehealth.com"
              value={primaryContact}
              onChange={(e) => setPrimaryContact(e.target.value)}
              className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
            />
          </div>
        </div>

        {mode === "live" && (
          <div className="border border-[#E2E8F0] bg-[#F8FAFC] p-3 rounded-sm space-y-3">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-800">
              <Key size={14} className="text-slate-600" />
              <span>Microsoft Entra ID App Registration Credentials</span>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-600 mb-1">
                Directory (Tenant) ID
              </label>
              <input
                type="text"
                placeholder="00000000-0000-0000-0000-000000000000"
                value={organizationId}
                onChange={(e) => setOrganizationId(e.target.value)}
                className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-mono"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[11px] font-medium text-slate-600 mb-1">
                  Application (Client) ID
                </label>
                <input
                  type="text"
                  placeholder="Application ID"
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-mono"
                />
              </div>

              <div>
                <label className="block text-[11px] font-medium text-slate-600 mb-1">
                  Client Secret Value
                </label>
                <input
                  type="password"
                  placeholder="Secret Value"
                  value={clientSecret}
                  onChange={(e) => setClientSecret(e.target.value)}
                  className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-mono"
                />
              </div>
            </div>

            <p className="text-[11px] text-slate-500">
              Required Graph Permissions: <code className="bg-slate-200 px-1 py-0.5 rounded font-mono">Policy.Read.All</code>, <code className="bg-slate-200 px-1 py-0.5 rounded font-mono">AuditLog.Read.All</code>, <code className="bg-slate-200 px-1 py-0.5 rounded font-mono">User.Read.All</code>.
            </p>
          </div>
        )}

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
            disabled={isSubmitting}
            className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Plus size={14} />
            <span>{isSubmitting ? "Registering..." : "Add Organization"}</span>
          </button>
        </div>
      </form>
    </Modal>
  );
};
