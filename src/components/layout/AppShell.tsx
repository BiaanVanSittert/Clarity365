"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Tenant, TenantSecuritySnapshot } from "@/lib/types";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { OverviewDashboard } from "../dashboard/OverviewDashboard";
import { ConditionalAccessModule } from "../modules/ConditionalAccessModule";
import { SignInLogsModule } from "../modules/SignInLogsModule";
import { SecureScoreModule } from "../modules/SecureScoreModule";
import { MfaAuditModule } from "../modules/MfaAuditModule";
import { UserClassificationModule } from "../modules/UserClassificationModule";
import { MailboxPermissionsModule } from "../modules/MailboxPermissionsModule";
import { EmailForwardingModule } from "../modules/EmailForwardingModule";
import { MdoPoliciesModule } from "../modules/MdoPoliciesModule";
import { AppRegistrationsModule } from "../modules/AppRegistrationsModule";
import { IntuneSecurityModule } from "../modules/IntuneSecurityModule";
import { GroupsManagementModule } from "../modules/GroupsManagementModule";
import { SharePointStorageModule } from "../modules/SharePointStorageModule";
import { McpPlaygroundModule } from "../modules/McpPlaygroundModule";
import { AddTenantModal } from "../modals/AddTenantModal";
import { DeleteTenantModal } from "../modals/DeleteTenantModal";
import { SettingsModal } from "../modals/SettingsModal";
import { RemediationDrawer } from "../modals/RemediationDrawer";
import { SearchDialog } from "../common/SearchDialog";
import { generateRemediationPlanForTenant, RemediationPlan } from "@/lib/services/remediation-generator";

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
  const [isSearchOpen, setIsSearchOpen] = useState(false);

  // Remediation Drawer
  const [isRemediationOpen, setIsRemediationOpen] = useState(false);
  const [remediationPlans, setRemediationPlans] = useState<RemediationPlan[]>([]);

  // Fetch all tenants
  const fetchTenants = useCallback(async () => {
    try {
      const res = await fetch("/api/tenants");
      const data = await res.json();
      if (data.success && data.tenants) {
        setTenants(data.tenants);
        if (!activeTenantId && data.tenants.length > 0) {
          setActiveTenantId(data.tenants[0].id);
        } else if (activeTenantId && !data.tenants.some((t: Tenant) => t.id === activeTenantId)) {
          setActiveTenantId(data.tenants[0]?.id || null);
        }
      }
    } catch (err) {
      console.error("Failed to load tenants", err);
    }
  }, [activeTenantId]);

  // Fetch active snapshot
  const fetchSnapshot = useCallback(async (tenantId: string) => {
    setIsRefreshing(true);
    try {
      const res = await fetch(`/api/tenants/${tenantId}`);
      const data = await res.json();
      if (data.success && data.snapshot) {
        setSnapshot(data.snapshot);
      }
    } catch (err) {
      console.error("Failed to load snapshot", err);
    } finally {
      setIsRefreshing(false);
      setIsLoading(false);
    }
  }, []);

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

  return (
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
        onRefresh={() => activeTenantId && fetchSnapshot(activeTenantId)}
        isRefreshing={isRefreshing}
      />

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
          {activeView === "overview" && (
            <OverviewDashboard
              snapshot={snapshot}
              isLoading={isLoading}
              onNavigate={(view) => setActiveView(view)}
              onOpenRemediation={handleOpenRemediation}
            />
          )}

          {activeView === "ca_baseline" && snapshot && (
            <ConditionalAccessModule
              snapshot={snapshot}
              onOpenRemediation={handleOpenRemediation}
            />
          )}

          {activeView === "signin_logs" && snapshot && (
            <SignInLogsModule snapshot={snapshot} />
          )}

          {activeView === "sec_score" && snapshot && (
            <SecureScoreModule
              snapshot={snapshot}
              onOpenRemediation={handleOpenRemediation}
            />
          )}

          {activeView === "mfa_audit" && snapshot && (
            <MfaAuditModule
              snapshot={snapshot}
              onOpenRemediation={handleOpenRemediation}
            />
          )}

          {activeView === "user_class" && snapshot && (
            <UserClassificationModule
              snapshot={snapshot}
              onOpenRemediation={handleOpenRemediation}
            />
          )}

          {activeView === "mailboxes" && snapshot && (
            <MailboxPermissionsModule snapshot={snapshot} />
          )}

          {activeView === "forwarding" && snapshot && (
            <EmailForwardingModule
              snapshot={snapshot}
              onOpenRemediation={handleOpenRemediation}
            />
          )}

          {activeView === "mdo_tabl" && snapshot && (
            <MdoPoliciesModule
              snapshot={snapshot}
              onRefresh={() => activeTenantId && fetchSnapshot(activeTenantId)}
            />
          )}

          {activeView === "app_regs" && snapshot && (
            <AppRegistrationsModule snapshot={snapshot} />
          )}

          {activeView === "intune" && snapshot && (
            <IntuneSecurityModule snapshot={snapshot} />
          )}

          {activeView === "groups" && snapshot && (
            <GroupsManagementModule
              snapshot={snapshot}
              onRefresh={() => activeTenantId && fetchSnapshot(activeTenantId)}
            />
          )}

          {activeView === "sharepoint" && snapshot && (
            <SharePointStorageModule
              snapshot={snapshot}
              onRefresh={() => activeTenantId && fetchSnapshot(activeTenantId)}
            />
          )}

          {activeView === "mcp" && snapshot && (
            <McpPlaygroundModule snapshot={snapshot} />
          )}
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
  );
};
