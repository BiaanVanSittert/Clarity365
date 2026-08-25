import React, { useState } from "react";
import { TenantSecuritySnapshot, UserMfaProfile, AuthMethodType } from "@/lib/types";
import { StatusPill } from "../common/StatusPill";
import { ShieldCheck, ShieldAlert, Key, Search, Filter, AlertTriangle, Smartphone, Mail, Hash, Shield, Download } from "lucide-react";
import { exportToCsv, csvFilename } from "@/lib/utils/csv";
import { EmptyStateRow } from "../common/EmptyStateRow";

interface MfaAuditModuleProps {
  snapshot: TenantSecuritySnapshot;
  onOpenRemediation: (findingType?: string) => void;
}

const METHOD_LABELS: Record<AuthMethodType, { name: string; isWeak: boolean; isPhishingResistant: boolean }> = {
  passkey_fido2: { name: "Passkey (FIDO2) / Hardware Token", isWeak: false, isPhishingResistant: true },
  ms_authenticator_push: { name: "Microsoft Authenticator (Push)", isWeak: false, isPhishingResistant: false },
  ms_authenticator_totp: { name: "Microsoft Authenticator (TOTP)", isWeak: false, isPhishingResistant: false },
  sms: { name: "SMS / Text Message", isWeak: true, isPhishingResistant: false },
  voice_call: { name: "Voice Call", isWeak: true, isPhishingResistant: false },
  email_otp: { name: "Email OTP", isWeak: true, isPhishingResistant: false },
  app_password: { name: "App Password", isWeak: true, isPhishingResistant: false },
  none: { name: "None (MFA Not Registered)", isWeak: true, isPhishingResistant: false },
};

export const MfaAuditModule: React.FC<MfaAuditModuleProps> = ({ snapshot, onOpenRemediation }) => {
  const { mfaAudit } = snapshot;
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<string>("all");

  const totalUsers = mfaAudit.length;
  const weakAuthUsers = mfaAudit.filter((u) => u.isWeakAuth && u.mfaRegistered);
  const missingMfaUsers = mfaAudit.filter((u) => !u.mfaRegistered);
  const phishingResistantUsers = mfaAudit.filter((u) => u.defaultMethod === "passkey_fido2");

  const filteredUsers = mfaAudit.filter((u) => {
    const matchesSearch =
      u.displayName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.userPrincipalName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.department.toLowerCase().includes(searchQuery.toLowerCase());

    if (filterType === "all") return matchesSearch;
    if (filterType === "weak") return matchesSearch && (u.isWeakAuth || !u.mfaRegistered);
    if (filterType === "missing") return matchesSearch && !u.mfaRegistered;
    if (filterType === "admins") return matchesSearch && u.isAdmin;
    if (filterType === "phishing_resistant") return matchesSearch && u.defaultMethod === "passkey_fido2";
    return matchesSearch;
  });

  // Export to CSV
  const handleExportCSV = () => {
    const headers = [
      "DisplayName",
      "UserPrincipalName",
      "PrivilegeLevel",
      "DefaultAuthMethod",
      "RegisteredMethods",
      "MfaEnforcedByPolicy",
      "SecurityPosture",
    ];

    const rows = filteredUsers.map((user) => {
      const methodMeta = METHOD_LABELS[user.defaultMethod];
      const isWeak = user.isWeakAuth || !user.mfaRegistered;
      const posture = methodMeta.isPhishingResistant ? "Phishing-Resistant" : isWeak ? "Weak Auth / Fail" : "Strong Push";
      return [
        user.displayName,
        user.userPrincipalName,
        user.isAdmin ? user.adminRoles?.[0] || "Directory Admin" : user.department || "Standard User",
        methodMeta.name,
        user.registeredMethods.map((m) => METHOD_LABELS[m]?.name || m).join("; "),
        user.mfaEnforcedByPolicy ? "Yes" : "No",
        posture,
      ];
    });

    exportToCsv(csvFilename("MfaAudit", snapshot.tenant.defaultDomainName), headers, rows);
  };

  return (
    <div className="p-5 space-y-4 max-w-[1600px] mx-auto">
      {/* Header */}
      <div className="bg-[#F8FAFC] border border-[#CBD5E1] p-4 rounded-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldCheck size={18} className="text-slate-800" />
            <h2 className="text-sm font-bold text-slate-900 tracking-tight">
              Module 4: MFA Enforcement & Authentication Method Audit
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Audit user authentication strengths: Passkeys, Microsoft Authenticator, and weak vectors (SMS, Voice, Email OTP).
          </p>
        </div>

        <button
          onClick={() => onOpenRemediation("mfa_audit")}
          className="px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-sm flex items-center gap-1.5 transition-colors shadow-sm"
        >
          <ShieldAlert size={14} className="text-amber-400" />
          <span>Enforce Strong MFA Policy</span>
        </button>
      </div>

      {/* Summary Matrix Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-white border border-[#CBD5E1] rounded-sm">
          <div className="text-[10px] uppercase font-mono text-slate-500 font-semibold">Total Audited Users</div>
          <div className="text-xl font-bold font-mono text-slate-900 tabular-nums mt-0.5">{totalUsers}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Directory accounts</div>
        </div>

        <div className="p-3 bg-[#ECFDF5] border border-[#10B981] rounded-sm">
          <div className="text-[10px] uppercase font-mono text-[#065F46] font-semibold">Phishing-Resistant (FIDO2)</div>
          <div className="text-xl font-bold font-mono text-[#065F46] tabular-nums mt-0.5">
            {phishingResistantUsers.length}
          </div>
          <div className="text-[11px] text-[#065F46] mt-0.5">FIDO2 / Security Keys</div>
        </div>

        <div className="p-3 bg-[#FEF2F2] border border-[#EF4444] rounded-sm">
          <div className="text-[10px] uppercase font-mono text-[#991B1B] font-semibold flex items-center gap-1">
            <AlertTriangle size={11} />
            <span>Weak Authentication (SMS/OTP)</span>
          </div>
          <div className="text-xl font-bold font-mono text-[#991B1B] tabular-nums mt-0.5">
            {weakAuthUsers.length}
          </div>
          <div className="text-[11px] text-[#991B1B] mt-0.5">Susceptible to SIM Swap</div>
        </div>

        <div className="p-3 bg-[#FEF2F2] border border-[#EF4444] rounded-sm">
          <div className="text-[10px] uppercase font-mono text-[#991B1B] font-semibold flex items-center gap-1">
            <AlertTriangle size={11} />
            <span>Missing MFA Registration</span>
          </div>
          <div className="text-xl font-bold font-mono text-[#991B1B] tabular-nums mt-0.5">
            {missingMfaUsers.length}
          </div>
          <div className="text-[11px] text-[#991B1B] mt-0.5">Zero MFA Enrolled</div>
        </div>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-3 border border-[#CBD5E1] rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search users by name, UPN, or department..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-[#CBD5E1] rounded-sm focus:outline-none focus:border-slate-800 bg-white font-medium"
          >
            <option value="all">All Users ({mfaAudit.length})</option>
            <option value="weak">Weak / Missing MFA Flags</option>
            <option value="admins">Privileged Administrators</option>
            <option value="phishing_resistant">Phishing-Resistant (FIDO2)</option>
          </select>

          <button
            onClick={handleExportCSV}
            title="Export filtered users to CSV"
            className="px-2.5 py-1.5 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-[#CBD5E1] rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} className="text-slate-500" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* User Table */}
      <div className="border border-[#CBD5E1] bg-white rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-[#F8FAFC] border-b border-[#CBD5E1] flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
            User Authentication Method Audit & Policy Compliance
          </h3>
          <span className="text-[11px] font-mono text-slate-500">{filteredUsers.length} Accounts Listed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th>User / Identity</th>
                <th>Privilege Level</th>
                <th>Default Auth Method</th>
                <th>Registered Methods</th>
                <th>MFA Enforced by Policy</th>
                <th className="w-28 text-right">Security Posture</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.length === 0 ? (
                <EmptyStateRow colSpan={6} entityLabel="users" isFiltered={searchQuery.trim().length > 0 || filterType !== "all"} />
              ) : (
                filteredUsers.map((user) => {
                  const methodMeta = METHOD_LABELS[user.defaultMethod];
                  const isWeak = user.isWeakAuth || !user.mfaRegistered;

                  return (
                    <tr key={user.id} className={isWeak ? "bg-red-50/20" : ""}>
                      <td>
                        <div className="font-semibold text-xs text-slate-900">{user.displayName}</div>
                        <div className="text-[11px] font-mono text-slate-500">{user.userPrincipalName}</div>
                      </td>
                      <td>
                        {user.isAdmin ? (
                          <span className="inline-flex items-center gap-1 font-mono text-[10px] font-bold px-1.5 py-0.5 bg-red-100 text-red-900 border border-red-300 rounded-sm">
                            <Shield size={10} />
                            <span>{user.adminRoles?.[0] || "Directory Admin"}</span>
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-600 font-medium">{user.department || "Standard User"}</span>
                        )}
                      </td>
                      <td>
                        <div className="text-xs font-medium text-slate-800 flex items-center gap-1.5">
                          {methodMeta.name}
                        </div>
                      </td>
                      <td className="font-mono text-[11px] text-slate-600">
                        {user.registeredMethods.length === 0 ? (
                          <span className="text-red-700 italic">None</span>
                        ) : (
                          user.registeredMethods.map((m) => METHOD_LABELS[m]?.name || m).join(", ")
                        )}
                      </td>
                      <td>
                        <StatusPill
                          status={user.mfaEnforcedByPolicy ? "pass" : "fail"}
                          label={user.mfaEnforcedByPolicy ? "Policy Enforced" : "Not Enforced"}
                          size="sm"
                        />
                      </td>
                      <td className="text-right">
                        {methodMeta.isPhishingResistant ? (
                          <StatusPill status="pass" label="Phishing-Resistant" size="sm" />
                        ) : isWeak ? (
                          <StatusPill status="fail" label="Weak Auth / Fail" size="sm" />
                        ) : (
                          <StatusPill status="pass" label="Strong Push" size="sm" />
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
