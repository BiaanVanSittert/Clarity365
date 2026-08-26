import React, { useEffect, useState } from "react";
import { Modal } from "../common/Modal";
import { Trash2, AlertTriangle } from "lucide-react";
import { Tenant } from "@/lib/types";

interface DeleteTenantModalProps {
  isOpen: boolean;
  onClose: () => void;
  tenant: Tenant | null;
  onTenantDeleted: () => void;
}

export const DeleteTenantModal: React.FC<DeleteTenantModalProps> = ({
  isOpen,
  onClose,
  tenant,
  onTenantDeleted,
}) => {
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState("");

  // Reset confirmation state whenever the modal is (re)opened - otherwise a
  // previous failed attempt's error banner (or a typed confirmation for a
  // different tenant) could linger into the next open.
  useEffect(() => {
    if (isOpen) {
      setIsDeleting(false);
      setError(null);
      setConfirmText("");
    }
  }, [isOpen]);

  if (!tenant) return null;

  const isConfirmed = confirmText.trim() === tenant.displayName;

  const handleDelete = async () => {
    if (!isConfirmed) return;
    setIsDeleting(true);
    setError(null);
    try {
      const res = await fetch(`/api/tenants?id=${encodeURIComponent(tenant.id)}`, {
        method: "DELETE",
      });
      const data = await res.json();
      if (!data.success) {
        throw new Error(data.error || "Failed to delete tenant");
      }
      onTenantDeleted();
      onClose();
    } catch (err: any) {
      setError(err.message || "Failed to delete tenant");
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Remove Tenant Environment"
      maxWidth="md"
    >
      <div className="space-y-4">
        {error && (
          <div className="p-2.5 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 text-xs rounded-sm">
            {error}
          </div>
        )}

        <div className="flex items-start gap-3 p-3 bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-sm">
          <AlertTriangle size={18} className="text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs text-amber-800 dark:text-amber-400 space-y-1">
            <p className="font-semibold">Are you sure you want to disconnect this tenant?</p>
            <p>
              This will remove <strong>{tenant.displayName}</strong> (<code className="font-mono text-[11px]">{tenant.defaultDomainName}</code>) and clear all cached telemetry and snapshots from Clarity365. This action cannot be undone.
            </p>
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
            Type <span className="font-mono text-slate-900 dark:text-slate-100">{tenant.displayName}</span> to confirm
          </label>
          <input
            type="text"
            autoFocus
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            placeholder={tenant.displayName}
            className="w-full px-2.5 py-1.5 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-red-500 dark:focus:border-red-400 dark:border-red-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
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
            type="button"
            onClick={handleDelete}
            disabled={isDeleting || !isConfirmed}
            title={!isConfirmed ? "Type the tenant name exactly to enable removal" : undefined}
            className="px-3.5 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Trash2 size={14} />
            <span>{isDeleting ? "Removing..." : "Confirm Removal"}</span>
          </button>
        </div>
      </div>
    </Modal>
  );
};
