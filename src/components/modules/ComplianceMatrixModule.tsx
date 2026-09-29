import React, { useState, useMemo } from "react";
import {
  Tenant,
  TenantSecuritySnapshot,
  ComplianceFramework,
  ComplianceControlItem,
} from "@/lib/types";
import {
  evaluateTenantCompliance,
  evaluateFleetCompliance,
} from "@/lib/services/compliance-evaluator";
import {
  Award,
  ShieldCheck,
  ShieldAlert,
  ShieldEllipsis,
  AlertTriangle,
  Search,
  Filter,
  Download,
  Building2,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Info,
  ClipboardCheck,
  Loader2,
} from "lucide-react";
import { exportToCsv } from "@/lib/utils/csv";

// One-line "what is this and who enforces it" per framework, shown under the
// tab row so clicking a tab actually explains what you're looking at instead
// of just a control list. Facts checked against real sources during planning
// (2026-09-22) - see ai-context-vault/Optimization/Compliance Readiness
// Checklist Plan.md for citations. Penalty figures for GDPR/POPIA/HIPAA in
// particular are the kind of thing that changes (HIPAA's are inflation-
// adjusted annually by HHS) - worth a periodic re-check, not a one-time fact.
const FRAMEWORK_DESCRIPTIONS: Record<ComplianceFramework, { what: string; enforcement: string; sourceUrl?: string }> = {
  cis_m365_v3: {
    what: "Published by the Center for Internet Security (CIS), a nonprofit - vendor-agnostic, prescriptive technical configuration guidance for Microsoft 365.",
    enforcement: "Not enforced by any regulator directly, but widely referenced by cyber-insurance underwriting and vendor-risk questionnaires.",
    sourceUrl: "https://www.cisecurity.org/benchmark/microsoft_365",
  },
  nist_csf_v2: {
    what: "Published by the US National Institute of Standards and Technology (NIST) - a voluntary, outcome-based framework organized around six functions: Govern, Identify, Protect, Detect, Respond, Recover.",
    enforcement: "Not directly enforced, but commonly required contractually by US federal agencies and their supply chains.",
    sourceUrl: "https://www.nist.gov/cyberframework",
  },
  essential_eight: {
    what: "Published by the Australian Cyber Security Centre (ACSC) - eight prioritized mitigation strategies, each scored across four maturity levels (0-3).",
    enforcement: "Mandatory for non-corporate Commonwealth entities in Australia; adopted voluntarily elsewhere as a compact technical baseline.",
    sourceUrl: "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
  },
  popia: {
    what: "South Africa's Protection of Personal Information Act - applies to any organization processing personal information in South Africa, not just South African companies.",
    enforcement: "Enforced by the Information Regulator, which can issue an administrative fine of up to R10 million directly, without going to court. Ignoring an enforcement notice is a separate criminal offence, carrying a fine and/or up to 10 years' imprisonment.",
    sourceUrl: "https://popia.co.za/",
  },
  gdpr_uk_gdpr: {
    what: "The EU's General Data Protection Regulation and its UK equivalent (UK GDPR, under the Data Protection Act 2018) - applies to any organization processing the personal data of EU/UK residents, regardless of where the organization itself is based.",
    enforcement: "EU fines run up to €20 million or 4% of global annual turnover, whichever is higher, for the most serious infringements (a lower tier caps at €10m/2%). The UK's ICO enforces separately, up to £17.5 million or 4% of global turnover.",
    sourceUrl: "https://gdpr-info.eu/art-83-gdpr/",
  },
  hipaa: {
    what: "The US Health Insurance Portability and Accountability Act - applies to healthcare providers, health plans, and their business associates handling protected health information (PHI).",
    enforcement: "Enforced by the HHS Office for Civil Rights (OCR). Civil penalties are tiered by culpability, roughly $145 to $2.19 million per violation as of the 2026 inflation adjustment (HHS updates these figures annually), with a separate annual cap per violation category.",
    sourceUrl: "https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/index.html",
  },
};

interface ComplianceMatrixModuleProps {
  tenants: Tenant[];
  snapshots: TenantSecuritySnapshot[];
  onSelectTenant: (tenantId: string, targetModule?: string, targetEntityId?: string) => void;
  // Called after a successful attestation save so the parent refetches
  // tenants/snapshots - this module only holds props, it doesn't own the
  // underlying data. See handleToggleAttestation below.
  onRefresh?: () => void;
}

export const ComplianceMatrixModule: React.FC<ComplianceMatrixModuleProps> = ({
  tenants,
  snapshots,
  onSelectTenant,
  onRefresh,
}) => {
  const [selectedFramework, setSelectedFramework] = useState<ComplianceFramework>("cis_m365_v3");
  const [selectedTenantId, setSelectedTenantId] = useState<string>("fleet");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [levelFilter, setLevelFilter] = useState<string>("all");
  const [expandedControlId, setExpandedControlId] = useState<string | null>(null);
  const [attestationNoteDraft, setAttestationNoteDraft] = useState<string>("");
  const [savingAttestationKey, setSavingAttestationKey] = useState<string | null>(null);
  const [attestationError, setAttestationError] = useState<string | null>(null);

  const isReadinessFramework = selectedFramework === "popia" || selectedFramework === "gdpr_uk_gdpr" || selectedFramework === "hipaa";

  // Attestation is inherently single-tenant (a real fact about one client's
  // paperwork) - "fleet" is a representative-sample view (see the existing
  // assessment useMemo below), so there is no one real tenant to write to.
  // No cross-tenant write path exists here, matching the standing
  // no-cross-tenant-actions rule (this isn't even a fleet action to begin
  // with - it's just not meaningful without a specific tenant selected).
  const handleToggleAttestation = async (attestationKey: string, nextAttested: boolean) => {
    if (selectedTenantId === "fleet") return;
    const tenant = tenants.find((t) => t.id === selectedTenantId);
    if (!tenant) return;

    setSavingAttestationKey(attestationKey);
    setAttestationError(null);
    try {
      // Partial merge on the server is SHALLOW - complianceAttestations must
      // be sent as a full map (existing entries + this change), never a
      // single key, or every other attested item on this tenant would be
      // silently wiped. See Tenant.complianceAttestations's own comment.
      const mergedAttestations = {
        ...(tenant.complianceAttestations || {}),
        [attestationKey]: nextAttested
          ? {
              attested: true,
              attestedAt: new Date().toISOString(),
              attestedBy: "Operator",
              note: attestationNoteDraft || undefined,
            }
          : { attested: false },
      };

      const res = await fetch(`/api/tenants/${selectedTenantId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ complianceAttestations: mergedAttestations }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error || "Failed to save attestation.");

      setAttestationNoteDraft("");
      onRefresh?.();
    } catch (err: any) {
      setAttestationError(err.message || "Failed to save attestation.");
    } finally {
      setSavingAttestationKey(null);
    }
  };

  // Snapshot map
  const snapshotMap = useMemo(() => {
    const map = new Map<string, TenantSecuritySnapshot>();
    for (const snap of snapshots) {
      map.set(snap.tenant.id, snap);
    }
    return map;
  }, [snapshots]);

  // Assessment computation
  const assessment = useMemo(() => {
    if (selectedTenantId === "fleet") {
      // Evaluate first tenant or aggregate
      const firstSnap = snapshots[0];
      return firstSnap ? evaluateTenantCompliance(firstSnap, selectedFramework) : null;
    }
    const snap = snapshotMap.get(selectedTenantId);
    return snap ? evaluateTenantCompliance(snap, selectedFramework) : null;
  }, [selectedTenantId, selectedFramework, snapshots, snapshotMap]);

  const fleetSummary = useMemo(() => {
    return evaluateFleetCompliance(snapshots, selectedFramework);
  }, [snapshots, selectedFramework]);

  // Filtered controls
  const filteredControls = useMemo(() => {
    if (!assessment) return [];
    return assessment.controls.filter((ctrl) => {
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        ctrl.controlNumber.toLowerCase().includes(q) ||
        ctrl.title.toLowerCase().includes(q) ||
        ctrl.description.toLowerCase().includes(q) ||
        ctrl.section.toLowerCase().includes(q);

      if (!matchesSearch) return false;

      if (statusFilter !== "all" && ctrl.status !== statusFilter) return false;
      if (levelFilter !== "all" && ctrl.level !== levelFilter) return false;

      return true;
    });
  }, [assessment, searchQuery, statusFilter, levelFilter]);

  const handleExportCsv = () => {
    if (!assessment) return;
    const headers = ["ControlNumber", "Section", "Title", "Level", "Status", "Relevance", "Evidence", "RemediationGuide"];
    const rows = assessment.controls.map((c) => [
      c.controlNumber,
      c.section,
      c.title,
      c.level || "N/A",
      c.status,
      c.relevance,
      c.evidence,
      c.remediationGuide,
    ]);

    exportToCsv(`Compliance_${selectedFramework}_${selectedTenantId}.csv`, headers, rows);
  };

  const statusIcons = {
    compliant: <CheckCircle2 size={15} className="text-emerald-600 dark:text-emerald-400" />,
    non_compliant: <XCircle size={15} className="text-rose-600 dark:text-rose-400" />,
    partially_compliant: <AlertTriangle size={15} className="text-amber-600 dark:text-amber-400" />,
    not_applicable: <HelpCircle size={15} className="text-slate-400" />,
  };

  const statusBadges = {
    compliant: "bg-emerald-50 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800",
    non_compliant: "bg-rose-50 text-rose-800 border-rose-300 dark:bg-rose-950 dark:text-rose-300 dark:border-rose-800",
    partially_compliant: "bg-amber-50 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800",
    not_applicable: "bg-slate-100 text-slate-600 border-slate-300 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
  };

  const statusLabels = {
    compliant: "Compliant (Pass)",
    non_compliant: "Non-Compliant (Fail)",
    partially_compliant: "Partially Compliant",
    // No longer says "(License Gated)" - CIS/NIST/Essential Eight's
    // not_applicable controls usually are licence-gated (e.g. Entra P2), but
    // the readiness frameworks' own not_applicable controls can be
    // not-applicable for other reasons (e.g. Exchange Online not connected)
    // - the expanded row's evidence text always has the real reason.
    not_applicable: "Not Applicable",
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-white dark:bg-slate-800 p-5 border border-slate-200 dark:border-slate-700 rounded-sm shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Award className="text-emerald-600 dark:text-emerald-400" size={18} />
              <span>Compliance Frameworks & Audit Evidence</span>
            </h2>
            <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 rounded-sm">
              PHASE 2.3
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Automated alignment against the CIS Microsoft 365 Foundations Benchmark, NIST CSF 2.0, and Essential Eight - plus
            POPIA, GDPR/UK GDPR and HIPAA readiness, combining live technical evidence with manual attestation for the
            organizational/legal requirements no security tool can verify on its own.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCsv}
            className="px-3.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 border border-slate-300 dark:border-slate-700 rounded-sm flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <Download size={13} />
            <span>Export Audit CSV</span>
          </button>
        </div>
      </div>

      {/* Framework Selector Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-700 pb-2 overflow-x-auto">
        <button
          onClick={() => setSelectedFramework("cis_m365_v3")}
          className={`px-3.5 py-2 text-xs font-semibold rounded-sm border transition-colors flex items-center gap-2 ${
            selectedFramework === "cis_m365_v3"
              ? "bg-slate-900 text-white border-slate-900 dark:bg-emerald-600 dark:border-emerald-600 shadow-xs"
              : "bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:bg-slate-50"
          }`}
        >
          <Award size={14} />
          <span>CIS Microsoft 365 Foundations v3.0</span>
        </button>

        <button
          onClick={() => setSelectedFramework("nist_csf_v2")}
          className={`px-3.5 py-2 text-xs font-semibold rounded-sm border transition-colors flex items-center gap-2 ${
            selectedFramework === "nist_csf_v2"
              ? "bg-slate-900 text-white border-slate-900 dark:bg-emerald-600 dark:border-emerald-600 shadow-xs"
              : "bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:bg-slate-50"
          }`}
        >
          <ShieldCheck size={14} />
          <span>NIST Cybersecurity Framework (CSF 2.0)</span>
        </button>

        <button
          onClick={() => setSelectedFramework("essential_eight")}
          className={`px-3.5 py-2 text-xs font-semibold rounded-sm border transition-colors flex items-center gap-2 ${
            selectedFramework === "essential_eight"
              ? "bg-slate-900 text-white border-slate-900 dark:bg-emerald-600 dark:border-emerald-600 shadow-xs"
              : "bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:bg-slate-50"
          }`}
        >
          <ShieldAlert size={14} />
          <span>Essential Eight (ACSC)</span>
        </button>

        <div className="w-px self-stretch bg-slate-200 dark:bg-slate-700 mx-1" />

        {(
          [
            ["popia", "POPIA Readiness"],
            ["gdpr_uk_gdpr", "GDPR/UK GDPR Readiness"],
            ["hipaa", "HIPAA Readiness"],
          ] as [ComplianceFramework, string][]
        ).map(([fw, label]) => (
          <button
            key={fw}
            onClick={() => setSelectedFramework(fw)}
            className={`px-3.5 py-2 text-xs font-semibold rounded-sm border transition-colors flex items-center gap-2 ${
              selectedFramework === fw
                ? "bg-indigo-700 text-white border-indigo-700 dark:bg-indigo-600 dark:border-indigo-600 shadow-xs"
                : "bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:bg-slate-50"
            }`}
          >
            <ShieldEllipsis size={14} />
            <span>{label}</span>
          </button>
        ))}
      </div>

      {/* Per-framework description - previously the only explanation of any
          framework was the tab label itself, plus one generic banner shown
          identically for all three readiness frameworks. Added 2026-09-22
          after direct user feedback that clicking a tab explained nothing. */}
      <div className="p-3.5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm space-y-1.5">
        <p className="text-xs text-slate-700 dark:text-slate-300">{FRAMEWORK_DESCRIPTIONS[selectedFramework].what}</p>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          <span className="font-semibold text-slate-600 dark:text-slate-300">Enforcement: </span>
          {FRAMEWORK_DESCRIPTIONS[selectedFramework].enforcement}
        </p>
        {FRAMEWORK_DESCRIPTIONS[selectedFramework].sourceUrl && (
          <a
            href={FRAMEWORK_DESCRIPTIONS[selectedFramework].sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-[11px] text-blue-600 dark:text-blue-400 hover:underline"
          >
            <span>Source</span>
            <ExternalLink size={10} />
          </a>
        )}
      </div>

      {isReadinessFramework && (
        <div className="flex items-start gap-2 text-[11px] text-indigo-800 dark:text-indigo-300 bg-indigo-50 dark:bg-indigo-950/30 border border-indigo-200 dark:border-indigo-900 rounded-sm px-3 py-2">
          <Info size={13} className="flex-shrink-0 mt-0.5" />
          <span>
            Readiness, not a compliance certificate. Section 1 is computed from this tenant's live configuration; section 2 is
            organizational/legal and can only be confirmed by a human (see each item's "Attest" control) - Clarity365 cannot
            verify a contract was signed or a registration was filed. Technical-to-legal mapping, not legal advice.
          </span>
        </div>
      )}

      {/* Tenant Filter Selector */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-slate-500 flex items-center gap-1 mr-1">
            <Building2 size={13} />
            <span>Scope:</span>
          </span>
          {tenants.map((t) => (
            <button
              key={t.id}
              onClick={() => setSelectedTenantId(t.id)}
              className={`px-2.5 py-1 text-xs font-medium rounded-sm border transition-colors ${
                selectedTenantId === t.id
                  ? "bg-slate-900 text-white border-slate-900 dark:bg-slate-100 dark:text-slate-900 dark:border-slate-100 font-bold"
                  : "bg-slate-50 dark:bg-slate-900 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700 hover:bg-slate-100"
              }`}
            >
              {t.displayName}
            </button>
          ))}
        </div>

        <div className="text-xs text-slate-500 font-mono">
          Fleet Avg: <strong className="text-slate-800 dark:text-slate-200">{fleetSummary.overallFleetCompliancePercentage}%</strong>
        </div>
      </div>

      {/* Assessment Scorecards */}
      {assessment && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
            <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Compliance Score</div>
            <div className="text-3xl font-black text-slate-900 dark:text-slate-100 mt-1">
              {assessment.scorePercentage}%
            </div>
            <p className="text-[10px] text-slate-500 mt-1">
              {assessment.compliantCount} of {assessment.totalControls} controls passing
            </p>
          </div>

          <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
            <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Level 1 (Foundations)</div>
            <div className="text-3xl font-black text-emerald-700 dark:text-emerald-400 mt-1">
              {assessment.level1ScorePercentage !== undefined ? `${assessment.level1ScorePercentage}%` : "100%"}
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Essential defense baseline</p>
          </div>

          <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
            <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Level 2 (Hardened)</div>
            <div className="text-3xl font-black text-blue-700 dark:text-blue-400 mt-1">
              {assessment.level2ScorePercentage !== undefined ? `${assessment.level2ScorePercentage}%` : "N/A"}
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Defense-in-depth risk policies</p>
          </div>

          <div className="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm shadow-2xs">
            <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Non-Compliant Gaps</div>
            <div className="text-3xl font-black text-rose-600 mt-1">
              {assessment.nonCompliantCount}
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Immediate remediation targets</p>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-2.5 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search controls, sections, or keywords..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-slate-200 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter size={14} className="text-slate-500" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2 py-1 text-xs border border-slate-200 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
          >
            <option value="all">All Statuses</option>
            <option value="non_compliant">Non-Compliant (Failing)</option>
            <option value="compliant">Compliant (Pass)</option>
            <option value="partially_compliant">Partially Compliant</option>
          </select>

          {selectedFramework === "cis_m365_v3" && (
            <select
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value)}
              className="px-2 py-1 text-xs border border-slate-200 dark:border-slate-700 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-medium"
            >
              <option value="all">All Levels (L1 & L2)</option>
              <option value="Level 1">Level 1 Only</option>
              <option value="Level 2">Level 2 Only</option>
            </select>
          )}
        </div>
      </div>

      {/* Controls Evaluation Table */}
      <div className="border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 rounded-sm overflow-hidden shadow-xs">
        <div className="px-4 py-2.5 bg-slate-50 dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200">
            {assessment?.frameworkTitle} Control Specification
          </h3>
          <span className="text-[11px] font-mono text-slate-500">
            {filteredControls.length} Controls Evaluated
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse table-dense">
            <thead>
              <tr>
                <th className="w-10"></th>
                <th className="w-20">Control</th>
                <th className="w-48">Section</th>
                <th>Requirement & Title</th>
                <th className="w-24">Level</th>
                <th className="w-48">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredControls.map((ctrl) => {
                const isExpanded = expandedControlId === ctrl.id;

                return (
                  <React.Fragment key={ctrl.id}>
                    <tr
                      onClick={() => setExpandedControlId(isExpanded ? null : ctrl.id)}
                      className="cursor-pointer hover:bg-slate-50/80 dark:hover:bg-slate-800/60 transition-colors"
                    >
                      <td className="text-center text-slate-400">
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </td>
                      <td className="font-mono font-bold text-xs text-slate-900 dark:text-slate-100">
                        {ctrl.controlNumber}
                      </td>
                      <td className="text-xs text-slate-500 font-medium truncate max-w-[180px]" title={ctrl.section}>
                        {ctrl.section}
                      </td>
                      <td>
                        <div className="font-semibold text-xs text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                          <span>{ctrl.title}</span>
                          {ctrl.relatedBaselineCode && (
                            <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 rounded-sm">
                              {ctrl.relatedBaselineCode}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 line-clamp-1">
                          {ctrl.description}
                        </div>
                      </td>
                      <td>
                        {ctrl.level ? (
                          <span className="px-1.5 py-0.5 text-[10px] font-bold rounded-sm bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                            {ctrl.level}
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-400 font-mono">-</span>
                        )}
                      </td>
                      <td>
                        <div className="flex items-center gap-1.5">
                          {statusIcons[ctrl.status]}
                          <span className={`px-2 py-0.5 text-[11px] font-bold rounded-sm border ${statusBadges[ctrl.status]}`}>
                            {statusLabels[ctrl.status]}
                          </span>
                        </div>
                      </td>
                    </tr>

                    {/* Expandable Technical Evidence & Remediation Drawer */}
                    {isExpanded && (
                      <tr className="bg-slate-50/50 dark:bg-slate-900/40">
                        <td></td>
                        <td colSpan={5} className="py-3 px-4 space-y-2.5">
                          <div className="p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm space-y-2 shadow-2xs">
                            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800 dark:text-slate-200">
                              <Info size={14} className="text-blue-500" />
                              <span>Verifiable Technical Audit Evidence</span>
                            </div>
                            <div className="p-2.5 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-sm font-mono text-[11px] text-slate-800 dark:text-slate-200">
                              {ctrl.evidence}
                            </div>

                            <div className="pt-2 border-t border-slate-100 dark:border-slate-700 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs">
                              <div>
                                <span className="font-bold text-slate-700 dark:text-slate-300">Remediation Guidance: </span>
                                <span className="text-slate-600 dark:text-slate-400">{ctrl.remediationGuide}</span>
                              </div>

                              {ctrl.relatedBaselineCode && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onSelectTenant(selectedTenantId === "fleet" ? tenants[0]?.id : selectedTenantId, "fleet_rollout");
                                  }}
                                  className="px-2.5 py-1 text-[11px] font-semibold text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 rounded-sm flex items-center gap-1 shrink-0"
                                >
                                  <span>Deploy {ctrl.relatedBaselineCode}</span>
                                  <ExternalLink size={12} />
                                </button>
                              )}
                            </div>

                            {ctrl.sourceUrl && (
                              <a
                                href={ctrl.sourceUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                onClick={(e) => e.stopPropagation()}
                                className="inline-flex items-center gap-1 text-[11px] text-blue-600 dark:text-blue-400 hover:underline"
                              >
                                <span>Source</span>
                                <ExternalLink size={10} />
                              </a>
                            )}
                          </div>

                          {/* Manual attestation control - only rendered for
                              organizational/legal items (ctrl.attestationKey
                              set). This is the one write path in this
                              module: single-tenant only, a human explicitly
                              clicks it, never inferred - see
                              handleToggleAttestation above. */}
                          {ctrl.attestationKey && (
                            <div className="p-3 bg-indigo-50/50 dark:bg-indigo-950/20 border border-indigo-200 dark:border-indigo-900 rounded-sm space-y-2">
                              <div className="flex items-center gap-1.5 text-xs font-bold text-indigo-900 dark:text-indigo-300">
                                <ClipboardCheck size={14} />
                                <span>Manual Attestation</span>
                              </div>

                              {selectedTenantId === "fleet" ? (
                                <p className="text-[11px] text-indigo-800 dark:text-indigo-400">
                                  Select a specific tenant above (not the fleet-wide view) to attest this item.
                                </p>
                              ) : (
                                <>
                                  {ctrl.status !== "compliant" && (
                                    <input
                                      type="text"
                                      placeholder="Optional note (e.g. 'Registered 2026-09-22, filed in SharePoint')"
                                      value={attestationNoteDraft}
                                      onChange={(e) => setAttestationNoteDraft(e.target.value)}
                                      onClick={(e) => e.stopPropagation()}
                                      className="w-full px-2.5 py-1.5 text-xs border border-indigo-200 dark:border-indigo-800 rounded-sm bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100"
                                    />
                                  )}
                                  <div className="flex items-center gap-2">
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleToggleAttestation(ctrl.attestationKey!, ctrl.status !== "compliant");
                                      }}
                                      disabled={savingAttestationKey === ctrl.attestationKey}
                                      className={`px-3 py-1.5 text-[11px] font-semibold rounded-sm flex items-center gap-1.5 disabled:opacity-60 ${
                                        ctrl.status === "compliant"
                                          ? "bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-600 hover:bg-slate-50"
                                          : "bg-indigo-700 hover:bg-indigo-800 text-white"
                                      }`}
                                    >
                                      {savingAttestationKey === ctrl.attestationKey ? (
                                        <Loader2 size={12} className="animate-spin" />
                                      ) : (
                                        <ClipboardCheck size={12} />
                                      )}
                                      <span>{ctrl.status === "compliant" ? "Revert to Not Attested" : "Mark as Attested"}</span>
                                    </button>
                                    {attestationError && savingAttestationKey === null && (
                                      <span className="text-[11px] text-rose-600 dark:text-rose-400">{attestationError}</span>
                                    )}
                                  </div>
                                </>
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
