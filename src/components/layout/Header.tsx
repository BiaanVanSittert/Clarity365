import React, { useState } from "react";
import { Tenant, TenantSecuritySnapshot } from "@/lib/types";
import { ChevronDown, Plus, Trash2, Search, Settings, RefreshCw, ShieldCheck, Check, Globe, Server, LogOut } from "lucide-react";
import { StatusPill } from "../common/StatusPill";

interface HeaderProps {
  tenants: Tenant[];
  activeTenant: Tenant | null;
  activeSnapshot: TenantSecuritySnapshot | null;
  onSelectTenant: (tenantId: string) => void;
  onOpenAddTenant: () => void;
  onOpenDeleteTenant: () => void;
  onOpenSettings: () => void;
  onOpenSearch: () => void;
  onOpenPermissions: () => void;
  onRefresh: () => void;
  isRefreshing: boolean;
  onLogout: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  tenants,
  activeTenant,
  activeSnapshot,
  onSelectTenant,
  onOpenAddTenant,
  onOpenDeleteTenant,
  onOpenSettings,
  onOpenSearch,
  onOpenPermissions,
  onRefresh,
  isRefreshing,
  onLogout,
}) => {
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const formatTimestamp = (ts?: string) => {
    if (!ts) return "Just now";
    try {
      const date = new Date(ts);
      return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch {
      return ts;
    }
  };

  return (
    <header className="h-12 border-b border-[#CBD5E1] bg-white px-4 flex items-center justify-between select-none z-20">
      {/* Left: Brand & Tenant Switcher */}
      <div className="flex items-center gap-3">
        {/* Brand */}
        <div className="flex items-center gap-2 pr-3 border-r border-[#E2E8F0]">
          <div className="h-6 w-6 bg-slate-900 text-white rounded-sm flex items-center justify-center font-mono font-bold text-xs">
            C
          </div>
          <span className="text-xs font-bold tracking-tight text-slate-900">Clarity365</span>
          <span className="text-[10px] font-mono uppercase bg-slate-100 text-slate-600 px-1 py-0.5 rounded-sm border border-slate-200">
            v1.0
          </span>
        </div>

        {/* Global Persistent Tenant Switcher */}
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-2 px-2.5 py-1 text-xs border border-[#CBD5E1] bg-[#F8FAFC] hover:bg-[#F1F5F9] text-slate-900 rounded-sm transition-colors"
          >
            {activeTenant?.isDemo ? (
              <Globe size={13} className="text-slate-500" />
            ) : (
              <Server size={13} className="text-emerald-600" />
            )}
            <span className="font-semibold">{activeTenant?.displayName || "Select Organization"}</span>
            <span className="text-slate-400 text-[11px] font-mono hidden sm:inline">
              ({activeTenant?.defaultDomainName})
            </span>
            <ChevronDown size={13} className="text-slate-500 ml-0.5" />
          </button>

          {dropdownOpen && (
            <>
              <div className="fixed inset-0 z-20" onClick={() => setDropdownOpen(false)} />
              <div className="absolute left-0 mt-1 w-80 bg-white border border-[#CBD5E1] shadow-lg rounded-sm py-1 z-30 divide-y divide-slate-100">
                <div className="px-3 py-1.5 text-[10px] font-mono uppercase text-slate-400 bg-slate-50">
                  Managed M365 Customer Tenants ({tenants.length})
                </div>

                <div className="max-h-60 overflow-y-auto">
                  {tenants.map((t) => {
                    const isSelected = t.id === activeTenant?.id;
                    return (
                      <button
                        key={t.id}
                        onClick={() => {
                          onSelectTenant(t.id);
                          setDropdownOpen(false);
                        }}
                        className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-slate-50 transition-colors ${
                          isSelected ? "bg-slate-50 font-semibold text-slate-900" : "text-slate-700"
                        }`}
                      >
                        <div className="truncate pr-2">
                          <div className="flex items-center gap-1.5">
                            {t.isDemo ? (
                              <span className="text-[9px] font-mono uppercase px-1 bg-slate-100 text-slate-600 border border-slate-200 rounded-sm">
                                DEMO
                              </span>
                            ) : (
                              <span className="text-[9px] font-mono uppercase px-1 bg-emerald-50 text-emerald-700 border border-emerald-300 rounded-sm">
                                LIVE
                              </span>
                            )}
                            <span className="truncate">{t.displayName}</span>
                          </div>
                          <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                            {t.defaultDomainName} • {t.tier}
                          </div>
                        </div>
                        {isSelected && <Check size={14} className="text-slate-900 shrink-0" />}
                      </button>
                    );
                  })}
                </div>

                <div className="p-1 bg-slate-50 flex items-center justify-between">
                  <button
                    onClick={() => {
                      setDropdownOpen(false);
                      onOpenAddTenant();
                    }}
                    className="flex-1 text-left px-2.5 py-1.5 text-xs text-slate-800 hover:text-black font-medium flex items-center gap-1.5 hover:bg-slate-200/60 rounded-sm transition-colors"
                  >
                    <Plus size={13} />
                    <span>Add New Tenant...</span>
                  </button>

                  {activeTenant && (
                    <button
                      onClick={() => {
                        setDropdownOpen(false);
                        onOpenDeleteTenant();
                      }}
                      title="Remove active tenant"
                      className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-sm transition-colors"
                    >
                      <Trash2 size={13} />
                    </button>
                  )}
                </div>
              </div>
            </>
          )}
        </div>

        {/* Tenant Connection Status Badge */}
        {activeTenant && (
          <div className="hidden md:flex items-center gap-2">
            <StatusPill
              status={activeTenant.connectionStatus === "healthy" ? "pass" : activeTenant.connectionStatus === "degraded" ? "warn" : "fail"}
              label={activeTenant.connectionStatus === "healthy" ? "Sync Healthy" : "Degraded"}
              size="sm"
            />
            <span className="text-[11px] font-mono text-slate-400 tabular-nums">
              Synced {formatTimestamp(activeTenant.lastSyncTimestamp)}
            </span>
          </div>
        )}
      </div>

      {/* Right: Quick Search, Permissions Check, Refresh, Settings */}
      <div className="flex items-center gap-2">
        {/* Quick Search trigger */}
        <button
          onClick={onOpenSearch}
          className="flex items-center gap-2 px-2.5 py-1 text-xs border border-[#CBD5E1] bg-[#F8FAFC] hover:bg-[#F1F5F9] text-slate-600 hover:text-slate-900 rounded-sm transition-colors"
        >
          <Search size={13} className="text-slate-400" />
          <span className="hidden sm:inline">Quick Jump...</span>
          <kbd className="hidden sm:inline-block text-[10px] font-mono bg-white border border-[#CBD5E1] px-1 rounded-sm text-slate-400">
            Ctrl+K
          </kbd>
        </button>

        {/* Permissions check button */}
        {activeTenant && (
          <button
            onClick={onOpenPermissions}
            title="Confirm Azure App Registration Permissions"
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs border border-[#CBD5E1] bg-white hover:bg-slate-50 text-slate-700 font-medium rounded-sm transition-colors"
          >
            <ShieldCheck size={14} className="text-indigo-600" />
            <span className="hidden md:inline">Permissions</span>
          </button>
        )}

        {/* Refresh / Resync button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Force telemetry sync from Microsoft Graph"
          className="flex items-center gap-1.5 px-2.5 py-1 text-xs border border-[#CBD5E1] bg-white hover:bg-slate-50 text-slate-700 font-medium rounded-sm transition-colors disabled:opacity-50"
        >
          <RefreshCw size={13} className={isRefreshing ? "animate-spin text-emerald-600" : "text-slate-500"} />
          <span className="hidden lg:inline">{isRefreshing ? "Syncing..." : "Sync Tenant"}</span>
        </button>

        {/* Top-Right Settings (Gear Icon) */}
        <button
          onClick={onOpenSettings}
          title="Platform & MCP Settings"
          className="p-1.5 text-slate-600 hover:text-slate-900 border border-[#CBD5E1] bg-white hover:bg-slate-50 rounded-sm transition-colors"
        >
          <Settings size={14} />
        </button>

        {/* Sign out of the operator session */}
        <button
          onClick={onLogout}
          title="Sign out"
          className="p-1.5 text-slate-600 hover:text-red-600 border border-[#CBD5E1] bg-white hover:bg-red-50 rounded-sm transition-colors"
        >
          <LogOut size={14} />
        </button>
      </div>
    </header>
  );
};
