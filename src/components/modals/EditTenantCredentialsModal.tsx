import React, { useEffect, useState } from "react";
import { Modal } from "../common/Modal";
import { Tenant } from "@/lib/types";
import { Key, Save } from "lucide-react";

interface EditTenantCredentialsModalProps {
  isOpen: boolean;
  onClose: () => void;
  tenant: Tenant | null;
  onUpdated: () => void;
}

const GUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// The masked placeholder tenant-store.ts's sanitizeTenant() sends in place of
// the real (encrypted) secret - typing over it is how a rotation is
// signaled; leaving it untouched means "keep the existing secret" (see
// updateTenant()'s keepExistingSecret check).
const SECRET_MASK = "••••••••";

// Rotating a live tenant's Entra app registration credentials - e.g. after a
// client secret was rotated/expired on the client's own tenant and every
// Graph call started failing with "Lifetime validation failed, the token is
// expired" regardless of which endpoint. The backend (tenant-store.ts's
// updateTenant()) already fully supported this via PUT /api/tenants/[id];
// this modal was the missing piece - there was previously no UI anywhere in
// the app to update credentials for a tenant that already exists, only to
// set them once at creation time in AddTenantModal.tsx.
export const EditTenantCredentialsModal: React.FC<EditTenantCredentialsModalProps> = ({
  isOpen,
  onClose,
  tenant,
  onUpdated,
}) => {
  const [organizationId, setOrganizationId] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  // Deliberately keyed on `isOpen` alone, not `tenant` - a successful save
  // triggers onUpdated() -> fetchTenants(), which hands this modal a new
  // `tenant` object reference while it's still open. Depending on `tenant`
  // here would re-run this reset on that refresh and instantly clear the
  // success banner right after it appeared.
  useEffect(() => {
    if (isOpen && tenant) {
      setOrganizationId(tenant.credentials.tenantId || "");
      setClientId(tenant.credentials.clientId || "");
      // Prefilled with the mask, never the real secret - the sanitized
      // tenant this modal receives never carries the real value at all.
      setClientSecret(tenant.credentials.clientSecret ? SECRET_MASK : "");
      setIsSubmitting(false);
      setError(null);
      setSuccess(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  if (!tenant) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!organizationId.trim() || !clientId.trim() || !clientSecret.trim()) {
      setError("Directory (Tenant) ID, Application (Client) ID, and Client Secret are all required.");
      return;
    }
    if (!GUID_REGEX.test(organizationId.trim())) {
      setError("Directory (Tenant) ID must be a valid GUID.");
      return;
    }
    if (!GUID_REGEX.test(clientId.trim())) {
      setError("Application (Client) ID must be a valid GUID.");
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await fetch(`/api/tenants/${tenant.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credentials: {
            tenantId: organizationId.trim(),
            clientId: clientId.trim(),
            // Sent as-is - the backend treats an unchanged mask (or an empty
            // value) as "keep the existing secret," so this is safe whether
            // or not the operator actually edited the field.
            clientSecret: clientSecret.trim(),
          },
        }),
      });
      const data = await res.json();
      if (!data.success) {
        throw new Error(data.error || "Failed to update credentials");
      }
      setSuccess(true);
      onUpdated();
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
      title="Edit App Registration Credentials"
      subtitle={`Rotate or correct ${tenant.displayName}'s Microsoft Entra ID credentials`}
      maxWidth="lg"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="p-2.5 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-xs rounded-sm">
            {error}
          </div>
        )}
        {success && (
          <div className="p-2.5 bg-emerald-50 dark:bg-emerald-950 border border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 text-xs rounded-sm">
            Credentials updated. Run the Permissions check to confirm Microsoft Graph accepts them.
          </div>
        )}

        <div className="border border-[#E2E8F0] dark:border-slate-700 bg-[#F8FAFC] dark:bg-slate-900/50 p-3 rounded-sm space-y-3">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-800 dark:text-slate-200">
            <Key size={14} className="text-slate-600 dark:text-slate-400" />
            <span>Microsoft Entra ID App Registration Credentials</span>
          </div>

          <div>
            <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
              Directory (Tenant) ID <span className="text-red-500 dark:text-red-400">*</span>
            </label>
            <input
              type="text"
              required
              value={organizationId}
              onChange={(e) => setOrganizationId(e.target.value)}
              className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-mono"
            />
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
                Application (Client) ID <span className="text-red-500 dark:text-red-400">*</span>
              </label>
              <input
                type="text"
                required
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-mono"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-600 dark:text-slate-400 mb-1">
                Client Secret Value <span className="text-red-500 dark:text-red-400">*</span>
              </label>
              <input
                type="password"
                required
                placeholder="Secret Value"
                value={clientSecret}
                onFocus={() => {
                  // Clear the mask on focus so the operator types a real new
                  // value rather than accidentally appending to the dots -
                  // leaving the field empty on blur restores "keep existing."
                  if (clientSecret === SECRET_MASK) setClientSecret("");
                }}
                onBlur={() => {
                  if (!clientSecret.trim()) setClientSecret(SECRET_MASK);
                }}
                onChange={(e) => setClientSecret(e.target.value)}
                className="w-full px-2.5 py-1 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-mono"
              />
            </div>
          </div>

          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            Leave the Client Secret as {SECRET_MASK} to keep the current stored value - only type a new one when rotating
            it (e.g. after generating a fresh secret in Entra because the old one expired or was revoked).
          </p>
        </div>

        <div className="flex justify-end gap-2 pt-2 border-t border-[#E2E8F0] dark:border-slate-700">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-slate-100 border border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
          >
            Close
          </button>
          <button
            type="submit"
            disabled={isSubmitting}
            className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Save size={14} />
            <span>{isSubmitting ? "Saving..." : "Save Credentials"}</span>
          </button>
        </div>
      </form>
    </Modal>
  );
};
