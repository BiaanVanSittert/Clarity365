import React from "react";

interface SkeletonProps {
  className?: string;
  variant?: "text" | "rect" | "circle" | "card" | "row";
  rows?: number;
}

export const Skeleton: React.FC<SkeletonProps> = ({
  className = "",
  variant = "rect",
  rows = 1,
}) => {
  const baseClasses = "animate-pulse bg-[#E2E8F0] dark:bg-slate-700 rounded-sm";

  if (variant === "circle") {
    return <div className={`${baseClasses} rounded-full ${className}`} />;
  }

  if (variant === "text") {
    return <div className={`${baseClasses} h-4 ${className}`} />;
  }

  if (variant === "card") {
    return (
      <div className={`p-4 border border-[#E2E8F0] dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm space-y-3 ${className}`}>
        <div className="flex justify-between items-center">
          <div className="h-4 w-1/3 bg-[#E2E8F0] dark:bg-slate-700 rounded-sm animate-pulse" />
          <div className="h-4 w-12 bg-[#E2E8F0] dark:bg-slate-700 rounded-sm animate-pulse" />
        </div>
        <div className="h-8 w-24 bg-[#E2E8F0] dark:bg-slate-700 rounded-sm animate-pulse" />
        <div className="h-3 w-full bg-[#E2E8F0] dark:bg-slate-700 rounded-sm animate-pulse" />
      </div>
    );
  }

  if (variant === "row") {
    return (
      <div className="space-y-2">
        {Array.from({ length: rows }).map((_, idx) => (
          <div key={idx} className={`h-9 w-full bg-[#F1F5F9] dark:bg-slate-800 border-b border-[#E2E8F0] dark:border-slate-700 animate-pulse flex items-center px-3 space-x-4 ${className}`}>
            <div className="h-3.5 w-1/4 bg-[#E2E8F0] dark:bg-slate-700 rounded-sm" />
            <div className="h-3.5 w-1/3 bg-[#E2E8F0] dark:bg-slate-700 rounded-sm" />
            <div className="h-3.5 w-1/6 bg-[#E2E8F0] dark:bg-slate-700 rounded-sm" />
            <div className="h-3.5 w-1/6 bg-[#E2E8F0] dark:bg-slate-700 rounded-sm ml-auto" />
          </div>
        ))}
      </div>
    );
  }

  return <div className={`${baseClasses} ${className}`} />;
};

// Full-module loading state used as the <Suspense> fallback while a lazy-loaded
// module chunk is being fetched (see AppShell.tsx). Distinct from the generic
// Skeleton primitive above - this composes it into a layout that approximates
// a typical module's shape (header + stat cards + a data table).
export const SkeletonLoader: React.FC = () => (
  <div className="p-6 space-y-4">
    <div className="flex items-center justify-between">
      <Skeleton variant="text" className="w-48" />
      <Skeleton variant="text" className="w-24" />
    </div>
    <div className="grid grid-cols-4 gap-4">
      <Skeleton variant="card" />
      <Skeleton variant="card" />
      <Skeleton variant="card" />
      <Skeleton variant="card" />
    </div>
    <Skeleton variant="row" rows={8} />
  </div>
);
