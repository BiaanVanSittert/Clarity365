import { TenantSecuritySnapshot } from "../types";
import { FIX_GUIDES, GuideShell, SHELL_CONNECT } from "../data/scenario-fix-guides";
import { ResolvedFixGuide, buildFixGuide } from "./scenario-fix-guide-builder";
import { ScenarioCheckStatus, evaluateScenarios } from "./security-scenarios";
import { toPowerShell } from "../utils/powershell-literal";

// Prevention plan (one scenario) and Hardening plan (the whole tenant):
// every outstanding "How to fix" guide for ONE tenant, once each, in a
// sensible order, as a printable checklist and one PowerShell script.
// Guides only - Clarity365 makes no change; the script asks before every
// section. Scenario Fix Guides Plan, Stage 4.

export type PlanPhaseId = "investigate" | "visibility" | "checkFirst" | "closeDoors" | "identity" | "privilege" | "data";

// "Investigate now" guides whose checks Clarity365 couldn't assess (usually
// Exchange isn't connected) aren't evidence of a compromise; they go here,
// right after visibility, instead.
const CHECK_FIRST = {
  id: "checkFirst" as const,
  title: "Check what Clarity365 couldn't see",
  why: "Clarity365 couldn't read these (usually because Exchange Online isn't connected for this tenant). Check them; anything found should be handled as an incident.",
};

// Biggest protection for least disruption first. Within a phase, guides run
// in the order listed (curated: for example register MFA before requiring it).
export const PLAN_PHASES: { id: PlanPhaseId; title: string; why: string; guides: string[] }[] = [
  {
    id: "investigate",
    title: "Investigate now",
    why: "These may be signs of a compromise that is already happening: mail leaving the organisation, risky apps holding access, outsiders with admin roles.",
    guides: ["stop-external-mailbox-forwarding", "disable-external-transport-rules", "revoke-risky-app-consent", "remove-guest-admin-roles"],
  },
  {
    id: "visibility",
    title: "Turn on visibility",
    why: "No effect on users, and nothing else can be investigated without it.",
    guides: ["enable-unified-audit-log", "enable-mailbox-auditing", "alert-audit-config-changes", "alert-user-deletion"],
  },
  {
    id: "closeDoors",
    title: "Close the doors attackers use most",
    why: "Legacy protocols, device-code phishing, automatic forwarding and user consent are the commonest ways in; each is one setting or one report-only policy.",
    guides: [
      "block-legacy-auth",
      "disable-smtp-auth-org",
      "restrict-smtp-auth-mailboxes",
      "disable-pop-imap",
      "sharepoint-block-legacy-auth",
      "block-device-code-flow",
      "block-authentication-transfer",
      "block-external-autoforward-outbound",
      "block-autoforward-remote-domain",
      "restrict-user-consent",
      "enable-admin-consent-workflow",
    ],
  },
  {
    id: "identity",
    title: "Strengthen sign-in (report-only first)",
    why: "Conditional Access policies, each created in report-only with break-glass accounts excluded. Register MFA before requiring it.",
    guides: [
      "mfa-registration-drive",
      "protect-security-info-registration",
      "require-mfa-all-users",
      "require-mfa-guests",
      "require-phishing-resistant-admins",
      "admin-session-limits",
      "require-compliant-device-admins",
      "block-foreign-countries",
      "include-unknown-countries",
      "require-mfa-device-registration",
      "require-risk-remediation",
      "keep-cae-on",
      "remove-individual-exclusions",
      "require-compliant-device-desktop",
      "require-token-protection",
      "protect-sensitive-admin-actions",
    ],
  },
  {
    id: "privilege",
    title: "Reduce standing privilege",
    why: "Fewer permanent admins and over-privileged apps means a stolen account or secret does less damage.",
    guides: ["right-size-global-admins", "make-admin-roles-eligible", "remove-role-group-owners", "review-app-permissions"],
  },
  {
    id: "data",
    title: "Tighten guest access and sharing",
    why: "Limits what a guest or an anonymous link can reach. Some of these change how people share files; agree them with the business.",
    guides: [
      "restrict-guest-invites",
      "restrict-guest-directory-access",
      "sharepoint-restrict-anyone-org",
      "sharepoint-restrict-anyone-sites",
      "sharepoint-anyone-link-expiry",
      "sharepoint-default-link-type",
      "sharepoint-prevent-guest-reshare",
      "sharepoint-domain-allowlist",
      "sharepoint-limit-unmanaged-devices",
      "sharepoint-sync-domain-joined",
    ],
  },
];

export interface PlanCheckRef {
  scenarioId: string;
  scenarioTitle: string;
  checkId: string;
  label: string;
  status: ScenarioCheckStatus;
}

export interface PlanEntry {
  guideId: string;
  guide: ResolvedFixGuide;
  // The checks this guide addresses (one guide often fixes several).
  checks: PlanCheckRef[];
}

// A check that isn't green but has no guide (a licence note, for example).
export interface PlanOtherItem extends PlanCheckRef {
  fix?: string;
  docsUrl?: string;
}

export interface HardeningPlan {
  kind: "tenant" | "scenario";
  tenantName: string;
  tenantDomain: string;
  generatedAt: string;
  lastSync?: string;
  scenarioTitle?: string;
  phases: { id: PlanPhaseId; title: string; why: string; entries: PlanEntry[] }[];
  other: PlanOtherItem[];
  counts: { guides: number; checks: number; notAssessed: number };
}

const GUIDE_PHASE = new Map<string, { phase: PlanPhaseId; order: number }>();
PLAN_PHASES.forEach((p) => p.guides.forEach((g, order) => GUIDE_PHASE.set(g, { phase: p.id, order })));

// The outstanding guides for one tenant (or one of its scenarios), ordered.
export function buildHardeningPlan(snapshot: TenantSecuritySnapshot, options: { scenarioId?: string; now?: Date } = {}): HardeningPlan {
  const now = options.now || new Date();
  const results = evaluateScenarios(snapshot, { now }).filter((r) => !options.scenarioId || r.id === options.scenarioId);
  const byGuide = new Map<string, PlanCheckRef[]>();
  const other: PlanOtherItem[] = [];
  for (const r of results) {
    for (const c of r.checks) {
      if (c.status === "prevented") continue;
      const ref: PlanCheckRef = { scenarioId: r.id, scenarioTitle: r.title, checkId: c.id, label: c.label, status: c.status };
      if (c.guideId && GUIDE_PHASE.has(c.guideId)) byGuide.set(c.guideId, [...(byGuide.get(c.guideId) || []), ref]);
      else other.push({ ...ref, fix: c.fix, docsUrl: c.docsUrl });
    }
  }
  const built: { id: PlanPhaseId; title: string; why: string; entries: PlanEntry[] }[] = PLAN_PHASES.map((p) => ({
    id: p.id,
    title: p.title,
    why: p.why,
    entries: p.guides
      .filter((g) => byGuide.has(g))
      .map((g) => ({ guideId: g, guide: buildFixGuide(g, snapshot)!, checks: byGuide.get(g)! }))
      .filter((e) => !!e.guide),
  }));
  const investigate = built.find((p) => p.id === "investigate")!;
  const unassessed = investigate.entries.filter((e) => e.checks.every((c) => c.status === "notAssessed"));
  investigate.entries = investigate.entries.filter((e) => !unassessed.includes(e));
  built.splice(built.findIndex((p) => p.id === "visibility") + 1, 0, { ...CHECK_FIRST, entries: unassessed });
  const phases = built.filter((p) => p.entries.length > 0);
  const entries = phases.flatMap((p) => p.entries);
  const allChecks = [...entries.flatMap((e) => e.checks), ...other];
  return {
    kind: options.scenarioId ? "scenario" : "tenant",
    tenantName: snapshot.tenant.displayName,
    tenantDomain: snapshot.tenant.defaultDomainName,
    generatedAt: now.toISOString(),
    lastSync: snapshot.tenant.lastSyncTimestamp || undefined,
    scenarioTitle: options.scenarioId ? results[0]?.title : undefined,
    phases,
    other,
    counts: { guides: entries.length, checks: allChecks.length, notAssessed: allChecks.filter((c) => c.status === "notAssessed").length },
  };
}

export const STATUS_TEXT: Record<ScenarioCheckStatus, string> = {
  prevented: "Prevented",
  partial: "Partly prevented",
  notPrevented: "Not prevented",
  notAssessed: "Not assessed",
};

export function planTitle(plan: HardeningPlan): string {
  return plan.kind === "scenario" ? `Prevention plan: ${plan.scenarioTitle}` : "Hardening plan";
}

export function planFileStem(plan: HardeningPlan): string {
  const kind = plan.kind === "scenario" ? "PreventionPlan" : "HardeningPlan";
  return `Clarity365_${kind}_${plan.tenantDomain}_${plan.generatedAt.slice(0, 10)}`;
}

// ---------------------------------------------------------------- script

// Values Clarity365 couldn't fill in (for example <break-glass account object ID>).
const PLACEHOLDER = /<(?!#)[A-Za-z][^<>\r\n]*>/;
const indent = (text: string, pad = "    ") => text.split("\n").map((l) => (l.length > 0 ? pad + l : l)).join("\n");
const commentLines = (text: string) => text.split("\n").map((l) => `# ${l}`).join("\n");

// One script for the whole plan: connect once per tool, then every command
// in plan order, each section behind a y/N prompt and its own try/catch.
export function renderHardeningPlanScript(plan: HardeningPlan): string {
  const entries = plan.phases.flatMap((p) => p.entries);
  const commands = entries.flatMap((e) => e.guide.steps.map((s) => s.command).filter(Boolean)) as NonNullable<ResolvedFixGuide["steps"][number]["command"]>[];
  const shells = new Set<GuideShell>(commands.map((c) => c.shell));
  const graphScopes = [...new Set(commands.filter((c) => c.shell === "MicrosoftGraph" || c.shell === "MicrosoftGraphBeta").flatMap((c) => c.graphScopes || []))].sort();
  const tenantId = commands.find((c) => c.shell === "MicrosoftGraph" || c.shell === "MicrosoftGraphBeta")?.connect.match(/-TenantId "([^"]+)"/)?.[1];

  const out: string[] = [];
  out.push(`<#
${planTitle(plan)} for ${plan.tenantName} (${plan.tenantDomain})
Generated by Clarity365 on ${plan.generatedAt.slice(0, 10)} from the sync of ${plan.lastSync ? plan.lastSync.slice(0, 10) : "(never synced)"}.

Read the checklist first. This script makes changes to the tenant above:
every section asks before it runs (type y), and a failure in one section
doesn't stop the others. Conditional Access policies are created in
report-only. Portal-only steps are listed as comments. Sections marked
NEEDS EDITING contain a value Clarity365 couldn't fill in; edit it first.
Re-sync the tenant in Clarity365 afterwards to see the result.
#>

function Confirm-Step([string]$Title) {
    $answer = Read-Host "Run: $Title ? (y/N)"
    return $answer -eq 'y'
}
`);

  out.push("# ---------------------------------------------------------------- connect");
  if (shells.has("MicrosoftGraph") || shells.has("MicrosoftGraphBeta")) {
    out.push(`# First time: ${SHELL_CONNECT.MicrosoftGraph.install}${shells.has("MicrosoftGraphBeta") ? `; ${SHELL_CONNECT.MicrosoftGraphBeta.install}` : ""}`);
    out.push(SHELL_CONNECT.MicrosoftGraph.connect({ tenantId, graphScopes }));
  }
  for (const shell of ["ExchangeOnline", "SecurityCompliance", "SharePointOnline"] as GuideShell[]) {
    const first = commands.find((c) => c.shell === shell);
    if (!first) continue;
    out.push(`# First time: ${first.install}`);
    out.push(first.connect);
  }
  if (shells.size === 0) out.push("# Nothing in this plan has a command; follow the portal steps in the checklist.");

  let n = 0;
  for (const phase of plan.phases) {
    out.push(`\n#region ${phase.title}\n# ${phase.why}`);
    for (const e of phase.entries) {
      n++;
      out.push(`\n# ===== ${n}. ${e.guide.title}\n# Fixes: ${e.checks.map((c) => `${c.scenarioTitle} / ${c.label}`).join("; ")}`);
      e.guide.warnings.forEach((w) => out.push(`# WARNING: ${w}`));
      e.guide.steps.forEach((s, i) => {
        const title = `${n}.${i + 1} ${e.guide.title}: ${s.title}`;
        if (!s.command) {
          const lines = [s.portal ? `${s.portal.url}: ${s.portal.steps.join(" / ")}` : "", s.note || ""].filter(Boolean).join("\n");
          if (lines) out.push(`# Step ${n}.${i + 1} ${s.title} (in the portal, not scripted)\n${commentLines(lines)}`);
          return;
        }
        const needsEditing = PLACEHOLDER.test(s.command.script);
        out.push(
          `${needsEditing ? "# NEEDS EDITING: replace the <...> values in this section before answering y.\n" : ""}if (Confirm-Step ${toPowerShell(title)}) {
    try {
${indent(s.command.script, "        ")}
    } catch {
        Write-Warning "${n}.${i + 1} failed: $_"
    }
}`
        );
      });
    }
    out.push("#endregion");
  }
  return out.join("\n") + "\n";
}

// ---------------------------------------------------------------- checklist

const escapeHtml = (value: unknown) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const day = (iso?: string) => {
  if (!iso) return "never";
  const d = new Date(iso);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
};

const STATUS_CLASS: Record<ScenarioCheckStatus, string> = { prevented: "ok", partial: "partial", notPrevented: "bad", notAssessed: "unknown" };

// Printable checklist: one tick box per guide, with the steps and commands.
export function renderHardeningPlanHtml(plan: HardeningPlan): string {
  let n = 0;
  const phases = plan.phases
    .map((p) => {
      const entries = p.entries
        .map((e) => {
          n++;
          const g = e.guide;
          const steps = g.steps
            .map(
              (s) => `<li><strong>${escapeHtml(s.title)}</strong>${s.portal ? `<div class="muted">${escapeHtml(s.portal.url)}</div><ol>${s.portal.steps.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ol>` : ""}${
                s.command ? `<div class="muted">${escapeHtml(s.command.shellLabel)}: ${escapeHtml(s.command.connect)}</div><pre>${escapeHtml(s.command.script)}</pre>` : ""
              }${s.note ? `<div class="note">${escapeHtml(s.note)}</div>` : ""}</li>`
            )
            .join("");
          return `<div class="entry">
<h3><span class="box"></span>${n}. ${escapeHtml(g.title)}</h3>
<div class="fixes">${e.checks.map((c) => `<span class="pill ${STATUS_CLASS[c.status]}">${escapeHtml(STATUS_TEXT[c.status])}</span> ${escapeHtml(c.scenarioTitle)}: ${escapeHtml(c.label)}`).join("<br>")}</div>
<p>${escapeHtml(g.summary)}</p>
<p><strong>Who is affected:</strong> ${escapeHtml(g.impact)}</p>
${g.rollout ? `<p><strong>Rollout:</strong> ${escapeHtml(g.rollout)}</p>` : ""}
<p class="muted">Before you start: ${[g.prerequisites.licence ? `licence ${g.prerequisites.licence}` : "", `role ${g.prerequisites.adminRole}`, ...(g.prerequisites.other || [])].filter(Boolean).map(escapeHtml).join("; ")}</p>
${g.warnings.map((w) => `<div class="warn">${escapeHtml(w)}</div>`).join("")}
<ol class="steps">${steps}</ol>
<p><strong>Confirm:</strong> ${escapeHtml(g.verify.inClarity)}</p>
<p class="muted"><strong>Undo:</strong> ${escapeHtml(g.undo.text)}</p>
</div>`;
        })
        .join("\n");
      return `<h2>${escapeHtml(p.title)}</h2><p class="muted">${escapeHtml(p.why)}</p>${entries}`;
    })
    .join("\n");

  const other =
    plan.other.length > 0
      ? `<h2>Also outstanding (no guide)</h2><ul>${plan.other
          .map((o) => `<li><span class="pill ${STATUS_CLASS[o.status]}">${escapeHtml(STATUS_TEXT[o.status])}</span> ${escapeHtml(o.scenarioTitle)}: ${escapeHtml(o.label)}${o.fix ? ` <span class="muted">- ${escapeHtml(o.fix)}</span>` : ""}</li>`)
          .join("")}</ul>`
      : "";

  const title = planTitle(plan);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(title)} - ${escapeHtml(plan.tenantName)}</title>
<style>
  body { font-family: "Segoe UI", Arial, sans-serif; color: #0f172a; margin: 24px auto; max-width: 960px; padding: 0 16px; font-size: 12px; }
  h1 { font-size: 20px; margin: 0 0 2px; } h2 { font-size: 15px; margin: 26px 0 4px; border-bottom: 1px solid #cbd5e1; padding-bottom: 3px; }
  h3 { font-size: 13px; margin: 0 0 4px; display: flex; align-items: center; gap: 8px; }
  .box { display: inline-block; width: 13px; height: 13px; border: 1.5px solid #334155; border-radius: 2px; flex-shrink: 0; }
  .entry { border: 1px solid #cbd5e1; border-radius: 3px; padding: 10px 12px; margin: 10px 0; page-break-inside: avoid; }
  .fixes { margin: 0 0 6px; line-height: 1.7; } .muted { color: #64748b; }
  .pill { display: inline-block; font-size: 10px; font-weight: 600; padding: 0 5px; border-radius: 2px; border: 1px solid; }
  .pill.bad { color: #991b1b; border-color: #fca5a5; background: #fef2f2; } .pill.partial { color: #92400e; border-color: #fcd34d; background: #fffbeb; }
  .pill.unknown { color: #9a3412; border-color: #fdba74; border-style: dashed; } .pill.ok { color: #065f46; border-color: #6ee7b7; }
  pre { background: #0f172a; color: #e2e8f0; padding: 6px 8px; border-radius: 2px; white-space: pre-wrap; word-break: break-all; font-size: 10.5px; }
  .note { background: #f1f5f9; border: 1px solid #cbd5e1; padding: 4px 6px; margin: 4px 0; } .warn { background: #fffbeb; border: 1px solid #fcd34d; padding: 4px 6px; margin: 4px 0; }
  .summary { display: flex; gap: 18px; margin: 10px 0; } .summary div { border: 1px solid #cbd5e1; padding: 6px 10px; } .summary b { font-size: 18px; display: block; }
  ol.steps > li { margin: 6px 0; }
  @media print { button { display: none; } body { margin: 0; max-width: none; } pre { background: #f8fafc; color: #0f172a; border: 1px solid #cbd5e1; } }
</style></head><body>
<button onclick="window.print()">Print or save as PDF</button>
<h1>${escapeHtml(title)}</h1>
<div class="muted">${escapeHtml(plan.tenantName)} (${escapeHtml(plan.tenantDomain)}) · generated ${day(plan.generatedAt)} from the sync of ${day(plan.lastSync)}</div>
<div class="summary"><div><b>${plan.counts.guides}</b>fixes to work through</div><div><b>${plan.counts.checks}</b>checks they address</div><div><b>${plan.counts.notAssessed}</b>not assessed (check first)</div></div>
<p class="note">Work through the fixes in order: the first sections stop active threats and turn on logging, later ones change how people sign in and share. Conditional Access policies are created in report-only; switch each on after a week of report-only results. Clarity365 makes none of these changes: you run them, then re-sync the tenant to see the result.</p>
${plan.counts.guides === 0 && plan.other.length === 0 ? "<p>Nothing outstanding: every check is prevented.</p>" : ""}
${phases}
${other}
</body></html>`;
}
