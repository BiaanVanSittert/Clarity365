"use client";

import React, { useState, useEffect, useCallback, useRef, Suspense, lazy } from "react";
import { Tenant, TenantSecuritySnapshot } from "@/lib/types";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { ErrorBoundary } from "../common/ErrorBoundary";
import { SkeletonLoader } from "../common/SkeletonLoader";
import { AddTenantModal } from "../modals/AddTenantModal";
import { DeleteTenantModal } from "../modals/DeleteTenantModal";
import { SettingsModal } from "../modals/SettingsModal";
import { PermissionsModal } from "../modals/PermissionsModal";
import { RemediationDrawer } from "../modals/RemediationDrawer";
import { SearchDialog } from "../common/SearchDialog";
import { generateRemediationPlanForTenant, RemediationPlan } from "@/lib/services/remediation-generator";
import { RefreshCw, CheckCircle, AlertTriangle, X } from "lucide-react";

// Lazy-loaded module components — only fetched when the user navigates to them.
// Cuts initial bundle size significantly since each module is 8-48KB.
const OverviewDashboard = lazy(() => import("../dashboard/OverviewDashboard").then(m => ({ default: m.OverviewDashboard })));
const ConditionalAccessModule = lazy(() => import("../modules/ConditionalAccessModule").then(m => ({ default: m.ConditionalAccessModule })));
const SignInLogsModule = lazy(() => import("../modules/SignInLogsModule").then(m => ({ default: m.SignInLogsModule })));
const SecureScoreModule = lazy(() => import("../modules/SecureScoreModule").then(m => ({ default: m.SecureScoreModule })));
const MfaAuditModule = lazy(() => import("../modules/MfaAuditModule").then(m => ({ default: m.MfaAuditModule })));
const UserClassificationModule = lazy(() => import("../modules/UserClassificationModule").then(m => ({ default: m.UserClassificationModule })));
const MailboxPermissionsModule = lazy(() => import("../modules/MailboxPermissionsModule").then(m => ({ default: m.MailboxPermissionsModule })));
const EmailForwardingModule = lazy(() => import("../modules/EmailForwardingModule").then(m => ({ default: m.EmailForwardingModule })));
const MdoPoliciesModule = lazy(() => import("../modules/MdoPoliciesModule").then(m => ({ default: m.MdoPoliciesModule })));
const AppRegistrationsModule = lazy(() => import("../modules/AppRegistrationsModule").then(m => ({ default: m.AppRegistrationsModule })));
const IntuneSecurityModule = lazy(() => import("../modules/IntuneSecurityModule").then(m => ({ default: m.IntuneSecurityModule })));
const GroupsManagementModule = lazy(() => import("../modules/GroupsManagementModule").then(m => ({ default: m.GroupsManagementModule })));
const SharePointStorageModule = lazy(() => import("../modules/SharePointStorageModule").then(m => ({ default: m.SharePointStorageModule })));
const McpPlaygroundModule = lazy(() => import("../modules/McpPlaygroundModule").then(m => ({ default: m.McpPlaygroundModule })));
const AuditLogModule = lazy(() => import("../modules/AuditLogModule").then(m => ({ default: m.AuditLogModule })));


export const AppShell: React.FC = () => {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [activeTenantId, setActiveTenantId] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<TenantSecuritySnapshot | null>(null);
  const [activeView, setActiveView] = useState<string>("overview");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  // Modals state
  const [isAddTenantOpen, setIsAddTenantOpen] = useState(false);
  const [isDeleteTenantOpen, setIsDeleteTenantOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isPermissionsOpen, setIsPermissionsOpen] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);

  // Sync feedback toast
  const [syncToast, setSyncToast] = useState<{
    show: boolean;
    message: string;
    type: "info" | "success" | "warning" | "error";
  } | null>(null);

  // Remediation Drawer
  const [isRemediationOpen, setIsRemediationOpen] = useState(false);
  const [remediationPlans, setRemediationPlans] = useState<RemediationPlan[]>([]);

  // Tracks the currently-selected tenant for in-flight fetchSnapshot requests,
  // so a slow response for a tenant the user has since switched away from
  // can't clobber the snapshot actually on screen.
  const activeTenantIdRef = useRef<string | null>(null);
  useEffect(() => {
    activeTenantIdRef.current = activeTenantId;
  }, [activeTenantId]);

  // Guards the 60s toast auto-dismiss timer so two syncs within that window
  // can't let the first one's timer erase the second one's still-fresh toast.
  const toastDismissTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Fetch all tenants
  const fetchTenants = useCallback(async () => {
    try {
      const res = await fetch("/api/tenants");
      const data = await res.json();
      if (data.success && data.tenants) {
        setTenants(data.tenants);
        setActiveTenantId((prev) => {
          if (!prev && data.tenants.length > 0) {
            return data.tenants[0].id;
          }
          if (prev && !data.tenants.some((t: Tenant) => t.id === prev)) {
            return data.tenants[0]?.id || null;
          }
          return prev;
        });
      }
    } catch (err) {
      console.error("Failed to load tenants", err);
    }
  }, []);

  // Fetch active snapshot
  const fetchSnapshot = useCallback(async (tenantId: string) => {
    setIsRefreshing(true);
    try {
      const res = await fetch(`/api/tenants/${tenantId}`);
      const data = await res.json();
      // Only apply the result if the user hasn't switched to a different
      // tenant while this request was in flight.
      if (data.success && data.snapshot && activeTenantIdRef.current === tenantId) {
        setSnapshot(data.snapshot);
      }
    } catch (err) {
      console.error("Failed to load snapshot", err);
    } finally {
      if (activeTenantIdRef.current === tenantId) {
        setIsRefreshing(false);
        setIsLoading(false);
      }
    }
  }, []);

  // Force Resync from Microsoft Graph with user notification
  const handleForceSync = async () => {
    if (!activeTenantId) return;
    const currentTenant = tenants.find((t) => t.id === activeTenantId);
    const tenantName = currentTenant?.displayName || "Tenant";

    setIsRefreshing(true);
    setSyncToast({
      show: true,
      message: `Connecting to Microsoft Graph API and synchronizing ${tenantName}...`,
      type: "info",
    });

    try {
      const res = await fetch(`/api/tenants/${activeTenantId}/sync`, { method: "POST" });
      const data = await res.json();
      if (data.success && data.snapshot) {
        setSnapshot(data.snapshot);
        await fetchTenants();
        const syncHealth = data.snapshot.syncHealth;
        if (syncHealth?.isPartial) {
          setSyncToast({
            show: true,
            message: `Sync completed for ${tenantName} with some sections incomplete: ${syncHealth.errors.join(" | ")}`,
            type: "warning",
          });
        } else {
          setSyncToast({
            show: true,
            message: `Synchronization complete for ${tenantName}. Live Conditional Access policies and telemetry updated at ${new Date().toLocaleTimeString()}.`,
            type: "success",
          });
        }
      } else if (data.stale && data.snapshot) {
        // Live sync failed entirely (e.g. bad credentials) but a cached
        // snapshot exists and is being shown — make that failure visible
        // instead of silently rendering the stale data as if sync succeeded.
        setSnapshot(data.snapshot);
        setSyncToast({
          show: true,
          message: `Sync failed for ${tenantName}: ${data.error || "Could not reach Microsoft Graph"}. Showing last known data.`,
          type: "error",
        });
      } else {
        setSyncToast({
          show: true,
          message: `Sync failed for ${tenantName}: ${data.error || "Could not complete live sync and no cached data is available."}`,
          type: "error",
        });
      }
    } catch (err: any) {
      setSyncToast({
        show: true,
        message: `Sync Error: ${err.message || "Failed to reach backend sync service"}`,
        type: "error",
      });
    } finally {
      setIsRefreshing(false);
      if (toastDismissTimerRef.current) {
        clearTimeout(toastDismissTimerRef.current);
      }
      toastDismissTimerRef.current = setTimeout(() => {
        setSyncToast((prev) => (prev?.type === "success" ? null : prev));
        toastDismissTimerRef.current = null;
      }, 60000); // 60 seconds persistence or manual dismissal
    }
  };

  useEffect(() => {
    fetchTenants();
  }, [fetchTenants]);

  useEffect(() => {
    if (activeTenantId) {
      fetchSnapshot(activeTenantId);
    }
  }, [activeTenantId, fetchSnapshot]);

  // Keyboard shortcut for Cmd/Ctrl+K search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setIsSearchOpen(true);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleOpenRemediation = (findingType?: string) => {
    if (!snapshot) return;
    const plans = generateRemediationPlanForTenant(snapshot, findingType === "all" ? undefined : findingType);
    setRemediationPlans(plans);
    setIsRemediationOpen(true);
  };

  const activeTenant = tenants.find((t) => t.id === activeTenantId) || null;

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      window.location.href = "/login";
    }
  };

  return (
    <ErrorBoundary moduleName="Application Shell">
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-white text-slate-900 font-sans">
      {/* Top Header with Tenant Switcher and Settings Gear Icon */}
      <Header
        tenants={tenants}
        activeTenant={activeTenant}
        activeSnapshot={snapshot}
        onSelectTenant={(id) => setActiveTenantId(id)}
        onOpenAddTenant={() => setIsAddTenantOpen(true)}
        onOpenDeleteTenant={() => setIsDeleteTenantOpen(true)}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenSearch={() => setIsSearchOpen(true)}
        onOpenPermissions={() => setIsPermissionsOpen(true)}
        onRefresh={handleForceSync}
        isRefreshing={isRefreshing}
        onLogout={handleLogout}
      />

      {/* Real-time Sync & Notification Toast Banner */}
      {syncToast && syncToast.show && (
        <div
          className={`px-4 py-2 text-xs flex items-center justify-between border-b transition-all select-none ${
            syncToast.type === "info"
              ? "bg-slate-900 text-white border-slate-800"
              : syncToast.type === "success"
              ? "bg-emerald-50 text-emerald-900 border-emerald-300"
              : syncToast.type === "warning"
              ? "bg-amber-50 text-amber-900 border-amber-300"
              : "bg-rose-50 text-rose-900 border-rose-300"
          }`}
        >
          <div className="flex items-center gap-2 font-medium">
            {syncToast.type === "info" && <RefreshCw size={13} className="animate-spin text-emerald-400" />}
            {syncToast.type === "success" && <CheckCircle size={14} className="text-emerald-600" />}
            {syncToast.type === "warning" && <AlertTriangle size={14} className="text-amber-600" />}
            {syncToast.type === "error" && <AlertTriangle size={14} className="text-rose-600" />}
            <span>{syncToast.message}</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSyncToast(null)}
              className="px-2 py-0.5 text-[11px] font-medium border border-current rounded-sm opacity-80 hover:opacity-100 transition-opacity"
            >
              Dismiss
            </button>
            <button
              onClick={() => setSyncToast(null)}
              className="p-1 hover:opacity-75 transition-opacity"
              title="Dismiss notification"
            >
              <X size={13} />
            </button>
          </div>
        </div>
      )}

      {/* Main Layout: Fixed Sidebar + Viewport-Optimized Content Body */}
      <div className="flex flex-1 h-[calc(100vh-3rem)] overflow-hidden">
        {/* Left Sidebar */}
        <Sidebar
          activeView={activeView}
          onSelectView={(view) => setActiveView(view)}
          snapshot={snapshot}
        />

        {/* Dynamic Main Workspace Container */}
        <main className="flex-1 overflow-y-auto bg-white">
          <Suspense fallback={<SkeletonLoader />}>
            <ErrorBoundary moduleName="Overview Dashboard" key={`eb-overview-${activeTenantId}`}>
              {activeView === "overview" && (
                <OverviewDashboard
                  snapshot={snapshot}
                  isLoading={isLoading}
                  onNavigate={(view) => setActiveView(view)}
                  onOpenRemediation={handleOpenRemediation}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Conditional Access" key={`eb-ca-${activeTenantId}`}>
              {activeView === "ca_baseline" && snapshot && (
                <ConditionalAccessModule
                  snapshot={snapshot}
                  onOpenRemediation={handleOpenRemediation}
                  onRefresh={handleForceSync}
                  onNavigate={(view) => setActiveView(view)}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Sign-In Logs" key={`eb-signin-${activeTenantId}`}>
              {activeView === "signin_logs" && snapshot && (
                <SignInLogsModule
                  snapshot={snapshot}
                  onRefresh={handleForceSync}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Secure Score" key={`eb-secscore-${activeTenantId}`}>
              {activeView === "sec_score" && snapshot && (
                <SecureScoreModule
                  snapshot={snapshot}
                  onOpenRemediation={handleOpenRemediation}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="MFA Audit" key={`eb-mfa-${activeTenantId}`}>
              {activeView === "mfa_audit" && snapshot && (
                <MfaAuditModule
                  snapshot={snapshot}
                  onOpenRemediation={handleOpenRemediation}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="User Classification" key={`eb-userclass-${activeTenantId}`}>
              {activeView === "user_class" && snapshot && (
                <UserClassificationModule
                  snapshot={snapshot}
                  onOpenRemediation={handleOpenRemediation}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Mailbox Permissions" key={`eb-mailbox-${activeTenantId}`}>
              {activeView === "mailboxes" && snapshot && (
                <MailboxPermissionsModule snapshot={snapshot} />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Email Forwarding" key={`eb-fwd-${activeTenantId}`}>
              {activeView === "forwarding" && snapshot && (
                <EmailForwardingModule
                  snapshot={snapshot}
                  onOpenRemediation={handleOpenRemediation}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="MDO Policies & TABL" key={`eb-mdo-${activeTenantId}`}>
              {activeView === "mdo_tabl" && snapshot && (
                <MdoPoliciesModule
                  snapshot={snapshot}
                  onRefresh={handleForceSync}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="App Registrations" key={`eb-appreg-${activeTenantId}`}>
              {activeView === "app_regs" && snapshot && (
                <AppRegistrationsModule snapshot={snapshot} />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Intune Security" key={`eb-intune-${activeTenantId}`}>
              {activeView === "intune" && snapshot && (
                <IntuneSecurityModule snapshot={snapshot} />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Groups Management" key={`eb-groups-${activeTenantId}`}>
              {activeView === "groups" && snapshot && (
                <GroupsManagementModule
                  snapshot={snapshot}
                  onRefresh={handleForceSync}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="SharePoint Storage" key={`eb-sp-${activeTenantId}`}>
              {activeView === "sharepoint" && snapshot && (
                <SharePointStorageModule
                  snapshot={snapshot}
                  onRefresh={handleForceSync}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="MCP Playground" key={`eb-mcp-${activeTenantId}`}>
              {activeView === "mcp" && snapshot && (
                <McpPlaygroundModule snapshot={snapshot} />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Audit Log" key={`eb-audit-${activeTenantId}`}>
              {activeView === "audit_log" && <AuditLogModule tenants={tenants} />}
            </ErrorBoundary>
          </Suspense>
        </main>
      </div>

      {/* Modals & Drawers */}
      <AddTenantModal
        isOpen={isAddTenantOpen}
        onClose={() => setIsAddTenantOpen(false)}
        onTenantAdded={() => fetchTenants()}
      />

      <DeleteTenantModal
        isOpen={isDeleteTenantOpen}
        onClose={() => setIsDeleteTenantOpen(false)}
        tenant={activeTenant}
        onTenantDeleted={() => fetchTenants()}
      />

      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
      />

      {activeTenant && (
        <PermissionsModal
          isOpen={isPermissionsOpen}
          onClose={() => setIsPermissionsOpen(false)}
          tenant={activeTenant}
        />
      )}

      <SearchDialog
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        onSelectView={(view) => setActiveView(view)}
        tenants={tenants}
        onSelectTenant={(id) => setActiveTenantId(id)}
      />

      <RemediationDrawer
        isOpen={isRemediationOpen}
        onClose={() => setIsRemediationOpen(false)}
        plans={remediationPlans}
        tenantName={activeTenant?.displayName || "Organization"}
      />
    </div>
    </ErrorBoundary>
  );
};
