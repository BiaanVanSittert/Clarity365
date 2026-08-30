import React, { useState, useEffect, useRef, useMemo } from "react";
import { FleetSearchResultItem, TrafficStatus } from "@/lib/types";
import { StatusPill } from "./StatusPill";
import {
  Search,
  X,
  Building2,
  Users,
  Flame,
  Globe,
  HardDrive,
  Server,
  Share2,
  ShieldAlert,
  Layers,
  ChevronRight,
  ArrowRight,
  Filter,
} from "lucide-react";

interface GlobalFleetSearchDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectResult: (tenantId: string, targetModule: string, targetEntityId?: string) => void;
}

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  user: Users,
  incident: Flame,
  ip_address: Globe,
  device: HardDrive,
  app_registration: Server,
  forwarding_rule: Share2,
  file_hash: ShieldAlert,
  tabl: Layers,
};

const CATEGORIES = [
  { id: "all", label: "All Indicators" },
  { id: "user", label: "Users & Identities" },
  { id: "incident", label: "Security Incidents" },
  { id: "ip_address", label: "IP Addresses / Sign-Ins" },
  { id: "device", label: "Intune Devices" },
  { id: "app_registration", label: "OAuth App Registrations" },
  { id: "forwarding_rule", label: "Forwarding Rules" },
  { id: "tabl", label: "TABL & Hashes" },
];

export const GlobalFleetSearchDialog: React.FC<GlobalFleetSearchDialogProps> = ({
  isOpen,
  onClose,
  onSelectResult,
}) => {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const [results, setResults] = useState<FleetSearchResultItem[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);

  const inputRef = useRef<HTMLInputElement>(null);

  // Focus input when dialog opens
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
      setQuery("");
      setResults([]);
      setSelectedIndex(0);
    }
  }, [isOpen]);

  // Execute search when query or category changes
  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      setIsLoading(false);
      return;
    }

    const timer = setTimeout(async () => {
      setIsLoading(true);
      try {
        const catParam = category !== "all" ? `&category=${category}` : "";
        const res = await fetch(`/api/fleet/search?q=${encodeURIComponent(query)}${catParam}`);
        const data = await res.json();
        if (data.success && Array.isArray(data.results)) {
          setResults(data.results);
          setSelectedIndex(0);
        }
      } catch (err) {
        console.error("Fleet search error:", err);
      } finally {
        setIsLoading(false);
      }
    }, 150);

    return () => clearTimeout(timer);
  }, [query, category]);

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((prev) => (results.length > 0 ? (prev + 1) % results.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((prev) => (results.length > 0 ? (prev - 1 + results.length) % results.length : 0));
    } else if (e.key === "Enter" && results[selectedIndex]) {
      e.preventDefault();
      const item = results[selectedIndex];
      onSelectResult(item.tenantId, item.targetModule, item.id || item.title);
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/60 backdrop-blur-xs select-none">
      <div
        className="w-full max-w-3xl bg-white dark:bg-slate-900 border border-[#CBD5E1] dark:border-slate-700 rounded-sm shadow-2xl overflow-hidden flex flex-col max-h-[80vh] animate-in fade-in zoom-in-95 duration-100"
        onKeyDown={handleKeyDown}
      >
        {/* Search Header */}
        <div className="p-3.5 border-b border-[#CBD5E1] dark:border-slate-700 bg-[#F8FAFC] dark:bg-slate-800/80 flex items-center gap-3">
          <Search size={16} className="text-slate-400 dark:text-slate-500 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Search users, incidents, IPs, file hashes, or devices across all customer tenants..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-transparent text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none font-sans"
          />
          {isLoading && (
            <div className="h-4 w-4 border-2 border-slate-300 border-t-slate-600 rounded-full animate-spin shrink-0" />
          )}
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* Category Filters Bar */}
        <div className="px-3 py-2 border-b border-[#CBD5E1] dark:border-slate-700 bg-white dark:bg-slate-900 flex items-center gap-1.5 overflow-x-auto text-xs scrollbar-none">
          {CATEGORIES.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setCategory(cat.id)}
              className={`px-2.5 py-1 rounded-sm text-[11px] font-medium whitespace-nowrap transition-colors border ${
                category === cat.id
                  ? "bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 border-slate-900 dark:border-slate-100 font-semibold"
                  : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700"
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Results Container */}
        <div className="overflow-y-auto p-2 space-y-1.5 flex-1 max-h-[480px]">
          {!query.trim() ? (
            <div className="py-12 text-center text-slate-400 dark:text-slate-500 text-xs">
              <Building2 size={24} className="mx-auto mb-2 opacity-50" />
              <p className="font-semibold text-slate-600 dark:text-slate-400">
                Universal Fleet Indicator Search
              </p>
              <p className="text-[11px] mt-1 text-slate-400">
                Type an IP address (e.g. <code>194.26.29.112</code>), user email, device name, or incident keyword.
              </p>
            </div>
          ) : results.length === 0 && !isLoading ? (
            <div className="py-12 text-center text-slate-400 dark:text-slate-500 text-xs">
              No cross-tenant indicators found matching &quot;{query}&quot;.
            </div>
          ) : (
            results.map((item, idx) => {
              const Icon = CATEGORY_ICONS[item.category] || Building2;
              const isSelected = idx === selectedIndex;
              return (
                <div
                  key={item.id}
                  onClick={() => {
                    onSelectResult(item.tenantId, item.targetModule, item.id || item.title);
                    onClose();
                  }}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`p-2.5 rounded-sm border cursor-pointer transition-colors flex items-center justify-between gap-3 ${
                    isSelected
                      ? "bg-slate-100 dark:bg-slate-800 border-slate-400 dark:border-slate-500 shadow-xs"
                      : "bg-white dark:bg-slate-900/60 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <div className={`p-2 rounded-sm shrink-0 ${
                      item.category === "incident"
                        ? "bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300"
                        : item.category === "user"
                        ? "bg-indigo-100 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300"
                        : item.category === "device"
                        ? "bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300"
                        : "bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300"
                    }`}>
                      <Icon size={16} />
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">
                          {item.title}
                        </span>
                        {item.statusPill && (
                          <StatusPill
                            status={item.statusPill.status}
                            label={item.statusPill.label}
                            size="sm"
                          />
                        )}
                      </div>
                      <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate mt-0.5">
                        {item.subtitle}
                      </div>
                    </div>
                  </div>

                  {/* Tenant Tag & Action */}
                  <div className="text-right shrink-0 flex items-center gap-3">
                    <div className="text-right">
                      <div className="text-[10px] font-mono uppercase font-semibold text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                        {item.tenantName}
                      </div>
                      <div className="text-[10px] text-slate-400 capitalize mt-0.5">
                        Module: {item.targetModule.replace(/_/g, " ")}
                      </div>
                    </div>

                    <ChevronRight size={14} className={`text-slate-400 transition-transform ${isSelected ? "translate-x-0.5 text-slate-900 dark:text-slate-100" : ""}`} />
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer Hints */}
        <div className="px-3.5 py-2 border-t border-[#CBD5E1] dark:border-slate-700 bg-[#F8FAFC] dark:bg-slate-800/60 text-[11px] text-slate-500 dark:text-slate-400 flex items-center justify-between font-mono">
          <div className="flex items-center gap-3">
            <span><kbd className="px-1 py-0.5 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded text-[10px]">↑↓</kbd> Navigate</span>
            <span><kbd className="px-1 py-0.5 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded text-[10px]">Enter</kbd> Open & Switch Tenant</span>
            <span><kbd className="px-1 py-0.5 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded text-[10px]">Esc</kbd> Close</span>
          </div>
          <div>
            {results.length > 0 && <span>{results.length} cross-tenant results</span>}
          </div>
        </div>
      </div>
    </div>
  );
};
