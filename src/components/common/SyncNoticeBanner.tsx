import React from "react";
import { Info } from "lucide-react";

// Companion to SyncErrorBanner for deliberate sync limits ("capped at the
// first 250 groups"): the data shown is current, but not all of it was read.
// Amber and informational, never "sync error" - pair with
// getSyncNoticesForPrefixes() (src/lib/utils/sync-errors.ts).
export const SyncNoticeBanner: React.FC<{ notices: string[]; className?: string }> = ({ notices, className }) => {
  if (notices.length === 0) return null;
  return (
    <div className={`p-2.5 bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800 text-amber-900 dark:text-amber-300 text-xs rounded-sm space-y-1 ${className || ""}`}>
      <div className="flex items-center gap-2 font-semibold">
        <Info size={13} className="shrink-0" />
        <span>Partial data - this tenant has more than the sync reads</span>
      </div>
      {notices.map((n, i) => (
        <div key={i} className="text-[11px]">
          {n.replace(/^[^:]+:\s*/, "")}
        </div>
      ))}
    </div>
  );
};
