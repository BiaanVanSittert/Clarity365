"use client";

import React, { useState, useEffect, useCallback, lazy, Suspense, useRef } from "react";
import {
  Tenant,
  TenantSecuritySnapshot,
  FleetPostureSummary,
  FleetLicenseOptimizationSummary,
} from "@/lib/types";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { SkeletonLoader } from "../common/SkeletonLoader";
import { AddTenantModal } from "../modals/AddTenantModal";
import { DeleteTenantModal } from "../modals/DeleteTenantModal";
import { SettingsModal } from "../modals/SettingsModal";
import { PermissionsModal } from "../modals/PermissionsModal";
import { SearchDialog } from "../common/SearchDialog";
import { GlobalFleetSearchDialog } from "../common/GlobalFleetSearchDialog";
import { RemediationDrawer } from "../modals/RemediationDrawer";
import { RemediationPlan, generateRemediationPlanForTenant } from "@/lib/services/remediation-generator";
import { RefreshCw, CheckCircle, AlertTriangle, X } from "lucide-react";
import { ErrorBoundary } from "../common/ErrorBoundary";

// Lazy-load module components for fast initial load
const OverviewDashboard = lazy(() => import("../dashboard/OverviewDashboard").then(m => ({ default: m.OverviewDashboard })));
const FleetOverviewDashboard = lazy(() => import("../dashboard/FleetOverviewDashboard").then(m => ({ default: m.FleetOverviewDashboard })));
const FleetLicenseOptimizationModule = lazy(() => import("../modules/FleetLicenseOptimizationModule").then(m => ({ default: m.FleetLicenseOptimizationModule })));
const FleetBaselineRolloutModule = lazy(() => import("../modules/FleetBaselineRolloutModule").then(m => ({ default: m.FleetBaselineRolloutModule })));
const FleetBaselineDriftModule = lazy(() => import("../modules/FleetBaselineDriftModule").then(m => ({ default: m.FleetBaselineDriftModule })));
const FleetTablSyncModule = lazy(() => import("../modules/FleetTablSyncModule").then(m => ({ default: m.FleetTablSyncModule })));
const TenantLicenseOptimizationModule = lazy(() => import("../modules/TenantLicenseOptimizationModule").then(m => ({ default: m.TenantLicenseOptimizationModule })));
const EventResponseModule = lazy(() => import("../modules/EventResponseModule").then(m => ({ default: m.EventResponseModule })));
const ConditionalAccessModule = lazy(() => import("../modules/ConditionalAccessModule").then(m => ({ default: m.ConditionalAccessModule })));
const SignInLogsModule = lazy(() => import("../modules/SignInLogsModule").then(m => ({ default: m.SignInLogsModule })));
const SecureScoreModule = lazy(() => import("../modules/SecureScoreModule").then(m => ({ default: m.SecureScoreModule })));
const MfaAuditModule = lazy(() => import("../modules/MfaAuditModule").then(m => ({ default: m.MfaAuditModule })));
const UserClassificationModule = lazy(() => import("../modules/UserClassificationModule").then(m => ({ default: m.UserClassificationModule })));
const MailboxPermissionsModule = lazy(() => import("../modules/MailboxPermissionsModule").then(m => ({ default: m.MailboxPermissionsModule })));
const EmailForwardingModule = lazy(() => import("../modules/EmailForwardingModule").then(m => ({ default: m.EmailForwardingModule })));
const MailflowRulesModule = lazy(() => import("../modules/MailflowRulesModule").then(m => ({ default: m.MailflowRulesModule })));
const DomainAuthModule = lazy(() => import("../modules/DomainAuthModule").then(m => ({ default: m.DomainAuthModule })));
const MdoPoliciesModule = lazy(() => import("../modules/MdoPoliciesModule").then(m => ({ default: m.MdoPoliciesModule })));
const AppRegistrationsModule = lazy(() => import("../modules/AppRegistrationsModule").then(m => ({ default: m.AppRegistrationsModule })));
const IntuneSecurityModule = lazy(() => import("../modules/IntuneSecurityModule").then(m => ({ default: m.IntuneSecurityModule })));
const GroupsManagementModule = lazy(() => import("../modules/GroupsManagementModule").then(m => ({ default: m.GroupsManagementModule })));
const SharePointStorageModule = lazy(() => import("../modules/SharePointStorageModule").then(m => ({ default: m.SharePointStorageModule })));
const McpPlaygroundModule = lazy(() => import("../modules/McpPlaygroundModule").then(m => ({ default: m.McpPlaygroundModule })));
const AuditLogModule = lazy(() => import("../modules/AuditLogModule").then(m => ({ default: m.AuditLogModule })));
const ExecutiveReportingModule = lazy(() => import("../modules/ExecutiveReportingModule").then(m => ({ default: m.ExecutiveReportingModule })));
const ComplianceMatrixModule = lazy(() => import("../modules/ComplianceMatrixModule").then(m => ({ default: m.ComplianceMatrixModule })));

export const AppShell: React.FC = () => {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [activeTenantId, setActiveTenantId] = useState<string | null>("fleet"); // Default to Fleet View on startup
  const [snapshot, setSnapshot] = useState<TenantSecuritySnapshot | null>(null);
  const [activeView, setActiveView] = useState<string>("fleet_overview");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  // Target row / entity highlighting state
  const [highlightEntityId, setHighlightEntityId] = useState<string | null>(null);

  // Fleet data state
  const [fleetSummary, setFleetSummary] = useState<FleetPostureSummary | null>(null);
  const [fleetWasteSummary, setFleetWasteSummary] = useState<FleetLicenseOptimizationSummary | null>(null);
  const [allSnapshots, setAllSnapshots] = useState<TenantSecuritySnapshot[]>([]);
  const isFleetMode = activeTenantId === "fleet" || activeTenantId === null;

  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    try {
      return localStorage.getItem("clarity365_sidebar_collapsed") === "1";
    } catch {
      return false;
    }
  });

  const toggleSidebarCollapsed = () => {
    setIsSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("clarity365_sidebar_collapsed", next ? "1" : "0");
      } catch {
        // Ignore
      }
      return next;
    });
  };

  // Modals state
  const [isAddTenantOpen, setIsAddTenantOpen] = useState(false);
  const [isDeleteTenantOpen, setIsDeleteTenantOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isPermissionsOpen, setIsPermissionsOpen] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isUniversalSearchOpen, setIsUniversalSearchOpen] = useState(false);

  // Sync feedback toast
  const [syncToast, setSyncToast] = useState<{
    show: boolean;
    message: string;
    type: "info" | "success" | "warning" | "error";
  } | null>(null);

  // Remediation Drawer
  const [isRemediationOpen, setIsRemediationOpen] = useState(false);
  const [remediationPlans, setRemediationPlans] = useState<RemediationPlan[]>([]);

  const activeTenantIdRef = useRef<string | null>(null);
  useEffect(() => {
    activeTenantIdRef.current = activeTenantId;
  }, [activeTenantId]);

  const toastDismissTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Fetch all tenants
  const fetchTenants = useCallback(async () => {
    try {
      const res = await fetch("/api/tenants");
      const data = await res.json();
      if (data.success && data.tenants) {
        setTenants(data.tenants);
      }
    } catch (err) {
      console.error("Failed to fetch tenants", err);
    }
  }, []);

  // Fetch Global Fleet Posture & License Optimization Data
  const fetchFleetData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [postureRes, wasteRes] = await Promise.all([
        fetch("/api/fleet/posture"),
        fetch("/api/fleet/license-waste"),
      ]);

      const [postureData, wasteData] = await Promise.all([
        postureRes.json(),
        wasteRes.json(),
      ]);

      if (postureData.success && postureData.summary) {
        setFleetSummary(postureData.summary);
      }
      if (wasteData.success && (wasteData.waste || wasteData.summary)) {
        setFleetWasteSummary(wasteData.waste || wasteData.summary);
      }

      // Fetch all tenant snapshots for fleet governance modules
      const tenantsRes = await fetch("/api/tenants");
      const tenantsData = await tenantsRes.json();
      if (tenantsData.success && tenantsData.tenants) {
        setTenants(tenantsData.tenants);
        const snapshotPromises = tenantsData.tenants.map((t: Tenant) =>
          fetch(`/api/tenants/${t.id}`)
            .then((r) => r.json())
            .then((d) => d.snapshot)
            .catch(() => null)
        );
        const fetchedSnapshots = (await Promise.all(snapshotPromises)).filter(Boolean);
        setAllSnapshots(fetchedSnapshots);
      }
    } catch (err) {
      console.error("Failed to fetch fleet data", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Fetch security snapshot for active tenant
  const fetchSnapshot = useCallback(async (tenantId: string) => {
    try {
      const res = await fetch(`/api/tenants/${tenantId}`);
      const data = await res.json();
      if (data.success && data.snapshot) {
        setSnapshot(data.snapshot);
      }
    } catch (err) {
      console.error(`Failed to fetch snapshot for tenant ${tenantId}`, err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Local refresh (e.g. after rule toggle) - keeps snapshot in sync without full reload
  const handleLocalRefresh = useCallback(async () => {
    if (!activeTenantId || activeTenantId === "fleet") return;
    try {
      const res = await fetch(`/api/tenants/${activeTenantId}`);
      const data = await res.json();
      if (data.success && data.snapshot) {
        setSnapshot(data.snapshot);
      }
    } catch (err) {
      console.error("Failed to locally refresh snapshot", err);
    }
  }, [activeTenantId]);

  // Force sync with Microsoft Graph API
  const handleForceSync = async () => {
    if (!activeTenantId) return;

    if (activeTenantId === "fleet") {
      setIsRefreshing(true);
      await fetchFleetData();
      setIsRefreshing(false);
      setSyncToast({
        show: true,
        message: "Fleet telemetry updated across all customer tenants.",
        type: "success",
      });
      return;
    }

    const tenant = tenants.find((t) => t.id === activeTenantId);
    const tenantName = tenant ? tenant.displayName : "Active Tenant";

    setIsRefreshing(true);
    setSyncToast({
      show: true,
      message: `Connecting to Microsoft Graph API and Exchange Online for ${tenantName}...`,
      type: "info",
    });

    try {
      const res = await fetch(`/api/tenants/${activeTenantId}/sync`, { method: "POST" });
      const data = await res.json();

      if (data.success && data.snapshot) {
        setSnapshot(data.snapshot);
        if (data.warning) {
          setSyncToast({
            show: true,
            message: `Sync partially complete for ${tenantName}: ${data.warning}`,
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
      }, 60000);
    }
  };

  useEffect(() => {
    fetchTenants();
  }, [fetchTenants]);

  useEffect(() => {
    if (activeTenantId === "fleet" || !activeTenantId) {
      setSnapshot(null);
      fetchFleetData();
    } else {
      setSnapshot(null);
      setIsLoading(true);
      fetchSnapshot(activeTenantId);
    }
  }, [activeTenantId, fetchSnapshot, fetchFleetData]);

  // Keyboard shortcut for Cmd/Ctrl+K search and Cmd/Ctrl+Shift+F universal search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === "f") {
        e.preventDefault();
        setIsUniversalSearchOpen(true);
      } else if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        if (isFleetMode) {
          setIsUniversalSearchOpen(true);
        } else {
          setIsSearchOpen(true);
        }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isFleetMode]);

  const handleSelectTenant = (tenantId: string, targetModule?: string, targetEntityId?: string) => {
    if (targetEntityId) {
      setHighlightEntityId(targetEntityId);
    }
    if (tenantId === "fleet") {
      setActiveTenantId("fleet");
      setActiveView(targetModule || "fleet_overview");
    } else {
      setActiveTenantId(tenantId);
      setActiveView(targetModule || "overview");
    }
  };

  const handleOpenRemediation = (findingType?: string) => {
    if (!snapshot) return;
    const plans = generateRemediationPlanForTenant(snapshot, findingType === "all" ? undefined : findingType);
    setRemediationPlans(plans);
    setIsRemediationOpen(true);
  };

  const activeTenant = !isFleetMode ? tenants.find((t) => t.id === activeTenantId) || null : null;

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      window.location.href = "/login";
    }
  };

  return (
    <ErrorBoundary moduleName="Application Shell">
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-sans">
      {/* Top Header with Tenant Switcher and Settings Gear Icon */}
      <Header
        tenants={tenants}
        activeTenant={activeTenant}
        activeSnapshot={snapshot}
        isFleetMode={isFleetMode}
        onSelectTenant={handleSelectTenant}
        onOpenAddTenant={() => setIsAddTenantOpen(true)}
        onOpenDeleteTenant={() => setIsDeleteTenantOpen(true)}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenSearch={() => setIsSearchOpen(true)}
        onOpenUniversalSearch={() => setIsUniversalSearchOpen(true)}
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
              ? "bg-slate-900 dark:bg-slate-800 text-white border-slate-800 dark:border-slate-700"
              : syncToast.type === "success"
              ? "bg-emerald-50 dark:bg-emerald-950 text-emerald-900 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800"
              : syncToast.type === "warning"
              ? "bg-amber-50 dark:bg-amber-950 text-amber-900 dark:text-amber-300 border-amber-300 dark:border-amber-800"
              : "bg-rose-50 dark:bg-rose-950 text-rose-900 dark:text-rose-300 border-rose-300 dark:border-rose-800"
          }`}
        >
          <div className="flex items-center gap-2 font-medium">
            {syncToast.type === "info" && <RefreshCw size={13} className="animate-spin text-emerald-400" />}
            {syncToast.type === "success" && <CheckCircle size={14} className="text-emerald-600 dark:text-emerald-400" />}
            {syncToast.type === "warning" && <AlertTriangle size={14} className="text-amber-600 dark:text-amber-400" />}
            {syncToast.type === "error" && <AlertTriangle size={14} className="text-rose-600 dark:text-red-400" />}
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
          isFleetMode={isFleetMode}
          fleetSummary={fleetSummary}
          onSelectTenant={handleSelectTenant}
          isCollapsed={isSidebarCollapsed}
          onToggleCollapse={toggleSidebarCollapsed}
        />

        {/* Dynamic Main Workspace Container */}
        <main className="flex-1 overflow-y-auto bg-white dark:bg-slate-800">
          <Suspense fallback={<SkeletonLoader />}>
            {/* Phase 2.1: Fleet Command Views */}
            <ErrorBoundary moduleName="Fleet Overview Dashboard" key="eb-fleet-overview">
              {activeView === "fleet_overview" && (
                <FleetOverviewDashboard
                  summary={fleetSummary}
                  isLoading={isLoading}
                  onSelectTenant={handleSelectTenant}
                  onOpenUniversalSearch={() => setIsUniversalSearchOpen(true)}
                />
              )}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Fleet License Optimization" key="eb-fleet-licenses">
              {activeView === "fleet_licenses" && (
                <FleetLicenseOptimizationModule
                  wasteSummary={fleetWasteSummary}
                  isLoading={isLoading}
                  onSelectTenant={handleSelectTenant}
                />
              )}
            </ErrorBoundary>

            {/* Phase 2.2: Fleet Baseline Rollout Engine */}
            <ErrorBoundary moduleName="Fleet Baseline Rollout" key="eb-fleet-rollout">
              {activeView === "fleet_rollout" && (
                <FleetBaselineRolloutModule
                  tenants={tenants}
                  snapshots={allSnapshots}
                  onSelectTenant={handleSelectTenant}
                  onRefresh={fetchFleetData}
                />
              )}
            </ErrorBoundary>

            {/* Phase 2.2: Golden Baseline Drift Monitor */}
            <ErrorBoundary moduleName="Golden Baseline Drift" key="eb-fleet-drift">
              {activeView === "fleet_drift" && (
                <FleetBaselineDriftModule
                  snapshots={allSnapshots}
                  onSelectTenant={handleSelectTenant}
                  onRefresh={fetchFleetData}
                />
              )}
            </ErrorBoundary>

            {/* Phase 2.2: Cross-Tenant Threat Synchronizer (TABL) */}
            <ErrorBoundary moduleName="Fleet TABL Sync" key="eb-fleet-tabl">
              {activeView === "fleet_tabl" && (
                <FleetTablSyncModule
                  tenants={tenants}
                  onSelectTenant={handleSelectTenant}
                />
              )}
            </ErrorBoundary>

            {/* Phase 2.3: Executive & QBR Reports */}
            <ErrorBoundary moduleName="Executive & QBR Reports" key="eb-executive-reports">
              {activeView === "executive_reports" && (
                <ExecutiveReportingModule
                  tenants={tenants}
                  snapshots={allSnapshots}
                  onSelectTenant={handleSelectTenant}
                />
              )}
            </ErrorBoundary>

            {/* Phase 2.3: Compliance Frameworks (CIS/NIST/Essential 8) */}
            <ErrorBoundary moduleName="Compliance Matrix" key="eb-compliance-matrix">
              {activeView === "compliance_matrix" && (
                <ComplianceMatrixModule
                  tenants={tenants}
                  snapshots={allSnapshots}
                  onSelectTenant={handleSelectTenant}
                />
              )}
            </ErrorBoundary>

            {/* Individual Tenant Views */}
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

            {/* Per-Tenant License & Cost Optimizer */}
            <ErrorBoundary moduleName="Tenant License Optimizer" key={`eb-license-optimizer-${activeTenantId}`}>
              {activeView === "license_optimizer" && snapshot && (
                <TenantLicenseOptimizationModule
                  snapshot={snapshot}
                  onNavigate={(view, entityId) => handleSelectTenant(activeTenantId!, view, entityId)}
                  highlightEntityId={highlightEntityId}
                  onClearHighlight={() => setHighlightEntityId(null)}
                />
              )}
              {activeView === "license_optimizer" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            {/* Security Operations & Event Response Center (Single & Multi-Tenant Fleet Feed) */}
            <ErrorBoundary moduleName="Event & Response Center" key={`eb-event-response-${activeTenantId}`}>
              {activeView === "event_response" && (
                <EventResponseModule
                  isFleetMode={isFleetMode}
                  fleetIncidents={fleetSummary?.recentCrossTenantIncidents}
                  tenants={tenants}
                  snapshot={snapshot}
                  onLocalRefresh={isFleetMode ? fetchFleetData : handleLocalRefresh}
                  highlightEntityId={highlightEntityId}
                  onClearHighlight={() => setHighlightEntityId(null)}
                  onSelectTenant={handleSelectTenant}
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
                  highlightEntityId={highlightEntityId}
                  onClearHighlight={() => setHighlightEntityId(null)}
                />
              )}
              {activeView === "ca_baseline" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Sign-In Logs" key={`eb-signin-${activeTenantId}`}>
              {activeView === "signin_logs" && snapshot && (
                <SignInLogsModule
                  snapshot={snapshot}
                  onRefresh={handleForceSync}
                  highlightEntityId={highlightEntityId}
                  onClearHighlight={() => setHighlightEntityId(null)}
                />
              )}
              {activeView === "signin_logs" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Secure Score" key={`eb-secscore-${activeTenantId}`}>
              {activeView === "sec_score" && snapshot && (
                <SecureScoreModule
                  snapshot={snapshot}
                  onOpenRemediation={handleOpenRemediation}
                />
              )}
              {activeView === "sec_score" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="MFA Audit" key={`eb-mfa-${activeTenantId}`}>
              {activeView === "mfa_audit" && snapshot && (
                <MfaAuditModule
                  snapshot={snapshot}
                  onOpenRemediation={handleOpenRemediation}
                />
              )}
              {activeView === "mfa_audit" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="User Classification" key={`eb-userclass-${activeTenantId}`}>
              {activeView === "user_class" && snapshot && (
                <UserClassificationModule
                  snapshot={snapshot}
                  onOpenRemediation={handleOpenRemediation}
                  highlightEntityId={highlightEntityId}
                  onClearHighlight={() => setHighlightEntityId(null)}
                />
              )}
              {activeView === "user_class" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Mailbox Permissions" key={`eb-mailbox-${activeTenantId}`}>
              {activeView === "mailboxes" && snapshot && (
                <MailboxPermissionsModule
                  snapshot={snapshot}
                  onLocalRefresh={handleLocalRefresh}
                  onOpenPermissions={() => setIsPermissionsOpen(true)}
                  highlightEntityId={highlightEntityId}
                  onClearHighlight={() => setHighlightEntityId(null)}
                />
              )}
              {activeView === "mailboxes" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Email Forwarding" key={`eb-fwd-${activeTenantId}`}>
              {activeView === "forwarding" && snapshot && (
                <EmailForwardingModule
                  snapshot={snapshot}
                  onOpenRemediation={handleOpenRemediation}
                  onLocalRefresh={handleLocalRefresh}
                  onOpenPermissions={() => setIsPermissionsOpen(true)}
                  highlightEntityId={highlightEntityId}
                  onClearHighlight={() => setHighlightEntityId(null)}
                />
              )}
              {activeView === "forwarding" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Transport & Mail Flow Rules" key={`eb-mailflow-rules-${activeTenantId}`}>
              {activeView === "mailflow_rules" && snapshot && (
                <MailflowRulesModule
                  snapshot={snapshot}
                  onLocalRefresh={handleLocalRefresh}
                  onOpenPermissions={() => setIsPermissionsOpen(true)}
                />
              )}
              {activeView === "mailflow_rules" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Domain Authentication" key={`eb-domain-auth-${activeTenantId}`}>
              {activeView === "domain_auth" && snapshot && (
                <DomainAuthModule snapshot={snapshot} onOpenPermissions={() => setIsPermissionsOpen(true)} />
              )}
              {activeView === "domain_auth" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="MDO Policies & TABL" key={`eb-mdo-${activeTenantId}`}>
              {activeView === "mdo_tabl" && snapshot && (
                <MdoPoliciesModule
                  snapshot={snapshot}
                  onLocalRefresh={handleLocalRefresh}
                  onOpenPermissions={() => setIsPermissionsOpen(true)}
                />
              )}
              {activeView === "mdo_tabl" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="App Registrations" key={`eb-appreg-${activeTenantId}`}>
              {activeView === "app_regs" && snapshot && (
                <AppRegistrationsModule snapshot={snapshot} />
              )}
              {activeView === "app_regs" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Intune Security" key={`eb-intune-${activeTenantId}`}>
              {activeView === "intune" && snapshot && (
                <IntuneSecurityModule
                  snapshot={snapshot}
                  highlightEntityId={highlightEntityId}
                  onClearHighlight={() => setHighlightEntityId(null)}
                />
              )}
              {activeView === "intune" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="Groups Management" key={`eb-groups-${activeTenantId}`}>
              {activeView === "groups" && snapshot && (
                <GroupsManagementModule
                  snapshot={snapshot}
                  onLocalRefresh={handleLocalRefresh}
                />
              )}
              {activeView === "groups" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            <ErrorBoundary moduleName="SharePoint Storage" key={`eb-sp-${activeTenantId}`}>
              {activeView === "sharepoint" && snapshot && (
                <SharePointStorageModule
                  snapshot={snapshot}
                  onLocalRefresh={handleLocalRefresh}
                />
              )}
              {activeView === "sharepoint" && !snapshot && <SkeletonLoader />}
            </ErrorBoundary>

            {/* MCP In-House Tool Inspector & Playground (Single & Fleet Mode) */}
            <ErrorBoundary moduleName="MCP Playground" key={`eb-mcp-${activeTenantId}`}>
              {activeView === "mcp" && (
                <McpPlaygroundModule
                  snapshot={snapshot}
                  tenants={tenants}
                  isFleetMode={isFleetMode}
                />
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
        onSelectView={(view: string) => setActiveView(view)}
        tenants={tenants}
        onSelectTenant={handleSelectTenant}
      />

      <GlobalFleetSearchDialog
        isOpen={isUniversalSearchOpen}
        onClose={() => setIsUniversalSearchOpen(false)}
        onSelectResult={(tenantId, targetModule, targetEntityId) => {
          handleSelectTenant(tenantId, targetModule, targetEntityId);
        }}
      />

      <RemediationDrawer
        isOpen={isRemediationOpen}
        onClose={() => setIsRemediationOpen(false)}
        plans={remediationPlans}
        tenantName={activeTenant?.displayName || snapshot?.tenant?.displayName || "Organization"}
      />
    </div>
    </ErrorBoundary>
  );
};
