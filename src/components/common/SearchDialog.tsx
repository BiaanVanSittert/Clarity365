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

  const staticNavItems: SearchItem[] = [
    { id: "nav-overview", title: "Security Overview Dashboard (Top 6 Priority)", category: "Navigation", view: "overview", icon: Shield },
    { id: "nav-ca", title: "Conditional Access Baseline (CA01 - CA10)", category: "Navigation", view: "ca_baseline", icon: Lock },
    { id: "nav-signin", title: "Sign-In Logs & CA Diagnostic Engine", category: "Navigation", view: "signin_logs", icon: Key },
    { id: "nav-secscore", title: "Microsoft Defender Secure Score & Timeline", category: "Navigation", view: "sec_score", icon: Shield },
    { id: "nav-mfa", title: "MFA Enforcement & Auth Methods Audit", category: "Navigation", view: "mfa_audit", icon: Key },
    { id: "nav-users", title: "User & Account Classification (Licensed / Unlicensed Active)", category: "Navigation", view: "user_class", icon: Users },
    { id: "nav-mailboxes", title: "Exchange Mailbox Permissions & Shared Mailbox Waste", category: "Navigation", view: "mailboxes", icon: Mail },
    { id: "nav-forwarding", title: "Email Forwarding Vectors & Exfiltration Rules", category: "Navigation", view: "forwarding", icon: Mail },
    { id: "nav-mdo", title: "Defender for Office 365 (MDO) & TABL Manager", category: "Navigation", view: "mdo_tabl", icon: Shield },
    { id: "nav-apps", title: "Connected Services & High-Privilege App Registrations", category: "Navigation", view: "app_regs", icon: Server },
    { id: "nav-intune", title: "Intune Endpoint Security (Antivirus & EDR Fleet)", category: "Navigation", view: "intune", icon: HardDrive },
    { id: "nav-groups", title: "Microsoft Groups & Distribution Management", category: "Navigation", view: "groups", icon: Users },
    { id: "nav-sharepoint", title: "SharePoint Storage & External Sharing Tiers", category: "Navigation", view: "sharepoint", icon: FileSpreadsheet },
    { id: "nav-mcp", title: "Model Context Protocol (MCP) Tools & Settings", category: "Navigation", view: "mcp", icon: Server },
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
          <Search size={15} className="absolute left-3 top-2.5 text-slate-400" />
          <input
            type="text"
            autoFocus
            placeholder="Type a module name or tenant (e.g., 'Conditional Access', 'Contoso', 'MFA')..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="max-h-64 overflow-y-auto space-y-1 divide-y divide-slate-100">
          {filteredItems.length === 0 ? (
            <div className="p-4 text-center text-xs text-slate-500">No matching views or tenants found.</div>
          ) : (
            filteredItems.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => handleSelect(item)}
                  className="w-full px-3 py-2 text-left flex items-center justify-between hover:bg-slate-50 rounded-sm text-xs text-slate-800 group transition-colors"
                >
                  <div className="flex items-center gap-2.5">
                    <Icon size={14} className="text-slate-500 group-hover:text-slate-900" />
                    <span>{item.title}</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] text-slate-400 font-mono">
                    <span>{item.category}</span>
                    <ArrowRight size={12} className="opacity-0 group-hover:opacity-100 transition-opacity" />
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
