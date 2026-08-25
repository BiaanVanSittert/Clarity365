import React, { useEffect, useState } from "react";
import { Modal } from "../common/Modal";
import { TenantLicenseType } from "@/lib/types";
import { ShieldCheck, Plus, Key, Globe, Server, Check } from "lucide-react";

interface AddTenantModalProps {
  isOpen: boolean;
  onClose: () => void;
  onTenantAdded: () => void;
}

const GUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const INITIAL_STATE = {
  mode: "live" as "demo" | "live",
  displayName: "",
  defaultDomainName: "",
  organizationId: "",
  primaryContact: "",
  tier: "M365_E5" as TenantLicenseType,
  clientId: "",
  clientSecret: "",
};

export const AddTenantModal: React.FC<AddTenantModalProps> = ({ isOpen, onClose, onTenantAdded }) => {
  const [mode, setMode] = useState(INITIAL_STATE.mode);
  const [displayName, setDisplayName] = useState(INITIAL_STATE.displayName);
  const [defaultDomainName, setDefaultDomainName] = useState(INITIAL_STATE.defaultDomainName);
  const [organizationId, setOrganizationId] = useState(INITIAL_STATE.organizationId);
  const [primaryContact, setPrimaryContact] = useState(INITIAL_STATE.primaryContact);
  const [tier, setTier] = useState<TenantLicenseType>(INITIAL_STATE.tier);
  const [clientId, setClientId] = useState(INITIAL_STATE.clientId);
  const [clientSecret, setClientSecret] = useState(INITIAL_STATE.clientSecret);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset all form state whenever the modal is (re)opened, so a previous
  // failed attempt's error banner and typed values don't linger.
  useEffect(() => {
    if (isOpen) {
      setMode(INITIAL_STATE.mode);
      setDisplayName(INITIAL_STATE.displayName);
      setDefaultDomainName(INITIAL_STATE.defaultDomainName);
      setOrganizationId(INITIAL_STATE.organizationId);
      setPrimaryContact(INITIAL_STATE.primaryContact);
      setTier(INITIAL_STATE.tier);
      setClientId(INITIAL_STATE.clientId);
      setClientSecret(INITIAL_STATE.clientSecret);
      setIsSubmitting(false);
      setError(null);
    }
  }, [isOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (mode === "live") {
      if (!organizationId.trim() || !clientId.trim() || !clientSecret.trim()) {
        setError("Directory (Tenant) ID, Application (Client) ID, and Client Secret are all required to connect a live tenant.");
        return;
      }
      if (!GUID_REGEX.test(organizationId.trim())) {
        setError("Directory (Tenant) ID must be a valid GUID (e.g. 00000000-0000-0000-0000-000000000000).");
        return;
      }
      if (!GUID_REGEX.test(clientId.trim())) {
        setError("Application (Client) ID must be a valid GUID.");
        return;
      }
    }

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
          tenantId: mode === "live" ? organizationId.trim() : organizationId.trim() || crypto.randomUUID(),
          clientId: clientId.trim() || undefined,
          clientSecret: clientSecret.trim() || undefined,
          authMode: mode === "live" ? "secret" : "mock",
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
                Directory (Tenant) ID <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                required={mode === "live"}
                placeholder="00000000-0000-0000-0000-000000000000"
                value={organizationId}
                onChange={(e) => setOrganizationId(e.target.value)}
                className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-mono"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="block text-[11px] font-medium text-slate-600 mb-1">
                  Application (Client) ID <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  required={mode === "live"}
                  placeholder="Application ID"
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-mono"
                />
              </div>

              <div>
                <label className="block text-[11px] font-medium text-slate-600 mb-1">
                  Client Secret Value <span className="text-red-500">*</span>
                </label>
                <input
                  type="password"
                  required={mode === "live"}
                  placeholder="Secret Value"
                  value={clientSecret}
                  onChange={(e) => setClientSecret(e.target.value)}
                  className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-mono"
                />
              </div>
            </div>

            <p className="text-[11px] text-slate-500">
              Required Graph Application Permissions:{" "}
              {[
                "Policy.Read.All",
                "Policy.ReadWrite.ConditionalAccess",
                "User.Read.All",
                "AuditLog.Read.All",
                "Reports.Read.All",
                "UserAuthenticationMethod.Read.All",
                "Organization.Read.All",
                "DeviceManagementManagedDevices.Read.All",
                "SecurityEvents.Read.All",
                "SecurityAlert.Read.All",
              ].map((perm, i, arr) => (
                <React.Fragment key={perm}>
                  <code className="bg-slate-200 px-1 py-0.5 rounded font-mono">{perm}</code>
                  {i < arr.length - 1 ? ", " : "."}
                </React.Fragment>
              ))}
              {" "}Use the Permissions check after adding this tenant to confirm every scope is granted.
            </p>
            <p className="text-[11px] text-slate-500">
              Defender for Office 365 policy sync (MDO Policies) needs a separate one-time Exchange Online sign-in, not a
              Graph permission — connect it from the Permissions check after adding this tenant.
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
