import React, { useState, useEffect } from "react";
import { Modal } from "./Modal";
import { Search, Shield, Key, Mail, Lock, Server, Users, HardDrive, FileSpreadsheet, ArrowRight } from "lucide-react";
import { Tenant } from "@/lib/types";

interface SearchDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectView: (view: string) => void;
  tenants: Tenant[];
  onSelectTenant: (tenantId: string) => void;
}

interface SearchItem {
  id: string;
  title: string;
  category: "Navigation" | "Tenant" | "Standard";
  view?: string;
  tenantId?: string;
  icon: React.ElementType;
}

export const SearchDialog: React.FC<SearchDialogProps> = ({
  isOpen,
  onClose,
  onSelectView,
  tenants,
  onSelectTenant,
}) => {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);

  const staticNavItems: SearchItem[] = [
    { id: "nav-overview", title: "Security Overview Dashboard (Top 6 Priority)", category: "Navigation", view: "overview", icon: Shield },
    { id: "nav-ca", title: "Conditional Access Baseline (CA01 - CA10)", category: "Navigation", view: "ca_baseline", icon: Lock },
    { id: "nav-signin", title: "Sign-In Logs & CA Diagnostic Engine", category: "Navigation", view: "signin_logs", icon: Key },
    { id: "nav-secscore", title: "Microsoft Defender Secure Score & Timeline", category: "Navigation", view: "sec_score", icon: Shield },
    { id: "nav-mfa", title: "MFA Enforcement & Auth Methods Audit", category: "Navigation", view: "mfa_audit", icon: Key },
    { id: "nav-users", title: "User & Account Classification (Licensed / Unlicensed Active)", category: "Navigation", view: "user_class", icon: Users },
    { id: "nav-mailboxes", title: "Exchange Mailbox Permissions & Shared Mailbox Waste", category: "Navigation", view: "mailboxes", icon: Mail },
    { id: "nav-forwarding", title: "Email Forwarding Vectors & Exfiltration Rules", category: "Navigation", view: "forwarding", icon: Mail },
    { id: "nav-mailflow-rules", title: "Transport & Mail Flow Rules Baseline", category: "Navigation", view: "mailflow_rules", icon: Mail },
    { id: "nav-domain-auth", title: "Domain Authentication (SPF / DKIM / DMARC)", category: "Navigation", view: "domain_auth", icon: Mail },
    { id: "nav-mdo", title: "Defender for Office 365 (MDO) & TABL Manager", category: "Navigation", view: "mdo_tabl", icon: Shield },
    { id: "nav-apps", title: "Connected Services & High-Privilege App Registrations", category: "Navigation", view: "app_regs", icon: Server },
    { id: "nav-intune", title: "Intune Endpoint Security (Antivirus & EDR Fleet)", category: "Navigation", view: "intune", icon: HardDrive },
    { id: "nav-groups", title: "Microsoft Groups & Distribution Management", category: "Navigation", view: "groups", icon: Users },
    { id: "nav-sharepoint", title: "SharePoint Storage & External Sharing Tiers", category: "Navigation", view: "sharepoint", icon: FileSpreadsheet },
    { id: "nav-mcp", title: "Model Context Protocol (MCP) Tools & Settings", category: "Navigation", view: "mcp", icon: Server },
    { id: "nav-audit", title: "System Audit Log", category: "Navigation", view: "audit_log", icon: Shield },
  ];

  const tenantItems: SearchItem[] = tenants.map((t) => ({
    id: `tenant-${t.id}`,
    title: `Tenant: ${t.displayName} (${t.defaultDomainName})`,
    category: "Tenant",
    tenantId: t.id,
    icon: Server,
  }));

  const allItems = [...staticNavItems, ...tenantItems];

  const filteredItems = query.trim() === ""
    ? allItems
    : allItems.filter((item) =>
        item.title.toLowerCase().includes(query.toLowerCase()) ||
        item.category.toLowerCase().includes(query.toLowerCase())
      );

  const handleSelect = (item: SearchItem) => {
    if (item.view) {
      onSelectView(item.view);
    }
    if (item.tenantId) {
      onSelectTenant(item.tenantId);
    }
    onClose();
  };

  useEffect(() => {
    setSelectedIndex(0);
  }, [query, isOpen]);

  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (filteredItems.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % filteredItems.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredItems.length) % filteredItems.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const item = filteredItems[selectedIndex];
      if (item) handleSelect(item);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Quick Navigation & Global Search"
      subtitle="Search across security modules, customer tenants, and policies"
      maxWidth="lg"
    >
      <div className="space-y-3">
        <div className="relative">
          <Search size={15} className="absolute left-3 top-2.5 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            autoFocus
            placeholder="Type a module name or tenant (e.g., 'Conditional Access', 'Contoso', 'MFA')..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleInputKeyDown}
            className="w-full pl-9 pr-3 py-2 text-xs border border-[#CBD5E1] dark:border-slate-600 rounded-sm focus:outline-none focus:border-slate-800 dark:focus:border-slate-400 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="max-h-64 overflow-y-auto space-y-1 divide-y divide-slate-100 dark:divide-slate-700">
          {filteredItems.length === 0 ? (
            <div className="p-4 text-center text-xs text-slate-500 dark:text-slate-400">No matching views or tenants found.</div>
          ) : (
            filteredItems.map((item, idx) => {
              const Icon = item.icon;
              const isSelected = idx === selectedIndex;
              return (
                <button
                  key={item.id}
                  onClick={() => handleSelect(item)}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`w-full px-3 py-2 text-left flex items-center justify-between rounded-sm text-xs text-slate-800 dark:text-slate-200 group transition-colors ${
                    isSelected ? "bg-slate-100 dark:bg-slate-700" : "hover:bg-slate-50 dark:hover:bg-slate-700/60"
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon size={14} className={isSelected ? "text-slate-900 dark:text-slate-100" : "text-slate-500 dark:text-slate-400 group-hover:text-slate-900 dark:group-hover:text-slate-100"} />
                    <span>{item.title}</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] text-slate-400 dark:text-slate-500 font-mono">
                    <span>{item.category}</span>
                    <ArrowRight size={12} className={`transition-opacity ${isSelected ? "opacity-100" : "opacity-0 group-hover:opacity-100"}`} />
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>
    </Modal>
  );
};
