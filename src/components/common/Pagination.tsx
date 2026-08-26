import React from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";

interface PaginationProps {
  page: number;
  pageSize: number;
  totalItems: number;
  onPageChange: (page: number) => void;
}

// Purely client-side pagination — the caller is expected to already have the
// full (filtered) array in memory and slice it using `page`/`pageSize`; this
// component only renders the Prev/Next controls and a "X-Y of N" indicator.
export const Pagination: React.FC<PaginationProps> = ({ page, pageSize, totalItems, onPageChange }) => {
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const rangeStart = totalItems === 0 ? 0 : (page - 1) * pageSize + 1;
  const rangeEnd = Math.min(page * pageSize, totalItems);

  if (totalItems === 0) return null;

  return (
    <div className="flex items-center justify-between px-4 py-2 border-t border-[#E2E8F0] dark:border-slate-700 bg-[#F8FAFC] dark:bg-slate-900/50 text-[11px] text-slate-600 dark:text-slate-400">
      <span>
        Showing <span className="font-semibold text-slate-900 dark:text-slate-100">{rangeStart}-{rangeEnd}</span> of{" "}
        <span className="font-semibold text-slate-900 dark:text-slate-100">{totalItems}</span>
      </span>
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={() => onPageChange(Math.max(1, page - 1))}
          disabled={page <= 1}
          aria-label="Previous page"
          className="p-1 border border-[#CBD5E1] dark:border-slate-700 rounded-sm bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <ChevronLeft size={13} />
        </button>
        <span className="font-mono px-1.5">
          Page {page} / {totalPages}
        </span>
        <button
          type="button"
          onClick={() => onPageChange(Math.min(totalPages, page + 1))}
          disabled={page >= totalPages}
          aria-label="Next page"
          className="p-1 border border-[#CBD5E1] dark:border-slate-700 rounded-sm bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <ChevronRight size={13} />
        </button>
      </div>
    </div>
  );
};
