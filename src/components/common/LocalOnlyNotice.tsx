import React from "react";
import { Info } from "lucide-react";

// Groups, TABL, and SharePoint sharing-tier edits are persisted to
// Clarity365's own cache but never pushed to the real tenant via Microsoft
// Graph - this notice keeps that clear at the point of action rather than
// implying the change reaches Microsoft 365 immediately.
export const LocalOnlyNotice: React.FC<{ className?: string }> = ({ className = "" }) => (
  <div className={`flex items-start gap-2 p-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm text-[11px] text-slate-600 dark:text-slate-400 ${className}`}>
    <Info size={13} className="text-slate-400 dark:text-slate-500 shrink-0 mt-0.5" />
    <span>Tracked in Clarity365 - not yet pushed to Microsoft 365.</span>
  </div>
);
