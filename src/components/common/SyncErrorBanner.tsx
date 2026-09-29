import React from "react";
import { AlertTriangle } from "lucide-react";

interface SyncErrorBannerProps {
  errors: string[];
  // Defaults to a generic message - pass a module-specific one (e.g. "ASR
  // configuration sync error - rule states below may be incomplete") so the
  // warning names what's actually stale, not just "something".
  title?: string;
  // Layout-only override (e.g. "m-3" to match a specific spot's spacing) -
  // never used to change the warning's own colors/severity, so every
  // instance of this banner still reads as the same thing everywhere.
  className?: string;
  // Extra context appended after the raw error list - e.g. a specific
  // permission-grant hint when the error is known to usually mean one
  // missing scope, rather than a generic "sync failed."
  children?: React.ReactNode;
}

// Extracted after a live incident: a tenant's CA10 policy was deleted in
// Entra, but Clarity365 kept showing it as deployed even after a Sync Tenant
// click and a page refresh - because the sync itself was failing outright
// (a Graph token quirk), and nothing told the admin the data on screen
// predated that failure. Only ASR/MDO/Mailflow/DomainAuth had this warning
// before that incident; every other module - including the one the
// incident actually happened in - had none. This one component is now the
// only place this banner is defined, so a module can't silently ship
// without it the way ConditionalAccessModule did. Pair with
// getSyncErrorsForPrefixes() (src/lib/utils/sync-errors.ts) to build the
// `errors` prop from snapshot.syncHealth.errors.
export const SyncErrorBanner: React.FC<SyncErrorBannerProps> = ({ errors, title, className, children }) => {
  if (errors.length === 0) return null;
  return (
    <div
      className={`p-3 bg-rose-50 dark:bg-red-950 border border-rose-300 dark:border-red-800 text-rose-900 dark:text-red-300 text-xs rounded-sm space-y-1.5 ${className || ""}`}
    >
      <div className="flex items-center gap-2 font-semibold">
        <AlertTriangle size={14} className="text-rose-600 dark:text-red-400 shrink-0" />
        <span>{title || "Sync error - data below may be stale"}</span>
      </div>
      {errors.map((err, i) => (
        <div
          key={i}
          className="text-[11px] font-mono bg-white/70 dark:bg-slate-900/50 p-1.5 border border-rose-200 dark:border-red-800 rounded-sm"
        >
          {err}
        </div>
      ))}
      {children}
    </div>
  );
};
