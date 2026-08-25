import React from "react";

interface EmptyStateRowProps {
  colSpan: number;
  entityLabel: string;
  // true when the emptiness is a result of an active search/filter (so the
  // copy should point at adjusting filters); false when the underlying
  // dataset is genuinely empty (e.g. a freshly-synced/blank tenant), where
  // "no matches" copy would be misleading — the fix there is to sync, not filter.
  isFiltered: boolean;
}

export const EmptyStateRow: React.FC<EmptyStateRowProps> = ({ colSpan, entityLabel, isFiltered }) => (
  <tr>
    <td colSpan={colSpan} className="p-4 text-center text-xs text-slate-500">
      {isFiltered
        ? `No ${entityLabel} found — try adjusting your filters.`
        : `No ${entityLabel} yet — sync this tenant to pull live data.`}
    </td>
  </tr>
);
