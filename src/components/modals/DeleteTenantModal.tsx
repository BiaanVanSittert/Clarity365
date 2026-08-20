import React, { useState } from "react";
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

  if (!tenant) return null;

  const handleDelete = async () => {
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
          <div className="p-2.5 bg-red-50 border border-red-200 text-red-700 text-xs rounded-sm">
            {error}
          </div>
        )}

        <div className="flex items-start gap-3 p-3 bg-amber-50 border border-amber-200 rounded-sm">
          <AlertTriangle size={18} className="text-amber-600 shrink-0 mt-0.5" />
          <div className="text-xs text-amber-800 space-y-1">
            <p className="font-semibold">Are you sure you want to disconnect this tenant?</p>
            <p>
              This will remove <strong>{tenant.displayName}</strong> (<code className="font-mono text-[11px]">{tenant.defaultDomainName}</code>) and clear all cached telemetry and snapshots from Clarity365.
            </p>
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
            type="button"
            onClick={handleDelete}
            disabled={isDeleting}
            className="px-3.5 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-700 rounded-sm flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <Trash2 size={14} />
            <span>{isDeleting ? "Removing..." : "Confirm Removal"}</span>
          </button>
        </div>
      </div>
    </Modal>
  );
};
