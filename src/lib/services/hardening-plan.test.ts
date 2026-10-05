import { describe, expect, it } from "vitest";
import { PLAN_PHASES, buildHardeningPlan, planFileStem, renderHardeningPlanHtml, renderHardeningPlanScript } from "./hardening-plan";
import { FIX_GUIDES } from "../data/scenario-fix-guides";
import { evaluateScenarios } from "./security-scenarios";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { TenantSecuritySnapshot } from "../types";

const NOW = new Date("2026-10-05T10:00:00Z");
const demos = Object.values(MOCK_TENANT_DATA) as TenantSecuritySnapshot[];

describe("plan order", () => {
  it("places every guide in exactly one phase", () => {
    const placed = PLAN_PHASES.flatMap((p) => p.guides);
    expect(new Set(placed).size).toBe(placed.length);
    expect([...placed].sort()).toEqual(FIX_GUIDES.map((g) => g.id).sort());
  });

  it("registers MFA before requiring it, and stops active threats before anything else", () => {
    const order = PLAN_PHASES.flatMap((p) => p.guides);
    expect(order.indexOf("mfa-registration-drive")).toBeLessThan(order.indexOf("require-mfa-all-users"));
    expect(order.indexOf("protect-security-info-registration")).toBeLessThan(order.indexOf("require-mfa-all-users"));
    expect(PLAN_PHASES[0].id).toBe("investigate");
  });
});

describe("buildHardeningPlan", () => {
  it("lists every outstanding guide once, with every check it addresses (every demo tenant)", () => {
    for (const snap of demos) {
      const plan = buildHardeningPlan(snap, { now: NOW });
      const outstanding = evaluateScenarios(snap, { now: NOW }).flatMap((r) => r.checks.filter((c) => c.status !== "prevented"));
      const entries = plan.phases.flatMap((p) => p.entries);
      expect(new Set(entries.map((e) => e.guideId)).size, snap.tenant.displayName).toBe(entries.length);
      expect(new Set(entries.map((e) => e.guideId)), snap.tenant.displayName).toEqual(new Set(outstanding.filter((c) => c.guideId).map((c) => c.guideId)));
      // Nothing is lost: every non-green check is either under a guide or in "other".
      expect(plan.counts.checks, snap.tenant.displayName).toBe(outstanding.length);
      expect(entries.reduce((n, e) => n + e.checks.length, 0) + plan.other.length).toBe(outstanding.length);
    }
  });

  it("follows the phase order", () => {
    const order = ["investigate", "visibility", "checkFirst", "closeDoors", "identity", "privilege", "data"];
    for (const snap of demos) {
      const phaseIndex = buildHardeningPlan(snap, { now: NOW }).phases.map((p) => order.indexOf(p.id));
      expect(phaseIndex).toEqual([...phaseIndex].sort((a, b) => a - b));
    }
  });

  it("keeps only real findings under Investigate now; unassessed ones go to Check first", () => {
    // Exchange not connected: mailbox and transport rules can't be read.
    const snap = { ...demos[0], tenant: { ...demos[0].tenant, isDemo: false }, emailForwarding: [], mailflowTransportRules: [], mailboxAuditingEnabled: undefined } as TenantSecuritySnapshot;
    const plan = buildHardeningPlan(snap, { now: NOW });
    const investigate = plan.phases.find((p) => p.id === "investigate");
    for (const e of investigate?.entries || []) expect(e.checks.some((c) => c.status !== "notAssessed"), e.guideId).toBe(true);
    const checkFirst = plan.phases.find((p) => p.id === "checkFirst")!;
    expect(checkFirst.entries.map((e) => e.guideId)).toEqual(expect.arrayContaining(["stop-external-mailbox-forwarding", "disable-external-transport-rules"]));
  });

  it("limits a Prevention plan to its scenario", () => {
    const snap = demos[0];
    const scenario = evaluateScenarios(snap, { now: NOW }).find((r) => r.checks.some((c) => c.guideId))!;
    const plan = buildHardeningPlan(snap, { scenarioId: scenario.id, now: NOW });
    expect(plan.kind).toBe("scenario");
    expect(plan.scenarioTitle).toBe(scenario.title);
    for (const e of plan.phases.flatMap((p) => p.entries)) for (const c of e.checks) expect(c.scenarioId).toBe(scenario.id);
    expect(planFileStem(plan)).toMatch(/^Clarity365_PreventionPlan_.+_2026-10-05$/);
  });
});

describe("renderHardeningPlanScript", () => {
  const plan = buildHardeningPlan(demos[0], { now: NOW });
  const script = renderHardeningPlanScript(plan);

  it("connects to Microsoft Graph once with every scope the plan needs", () => {
    const connects = script.split("\n").filter((l) => l.startsWith("Connect-MgGraph"));
    expect(connects).toHaveLength(1);
    const scopes = new Set(plan.phases.flatMap((p) => p.entries).flatMap((e) => e.guide.steps.flatMap((s) => (s.command?.shell.startsWith("MicrosoftGraph") ? s.command.graphScopes || [] : []))));
    for (const scope of scopes) expect(connects[0]).toContain(`"${scope}"`);
  });

  it("asks before every scripted step and catches its errors", () => {
    const steps = plan.phases.flatMap((p) => p.entries).flatMap((e) => e.guide.steps.filter((s) => s.command));
    expect(script.match(/^if \(Confirm-Step /gm)?.length).toBe(steps.length);
    expect(script.match(/^    try \{$/gm)?.length).toBe(steps.length);
  });

  it("flags sections that still contain a value to fill in", () => {
    const withPlaceholder = buildHardeningPlan({ ...demos[0], mfaAudit: [], conditionalAccess: { ...(demos[0].conditionalAccess as any), policies: [] } } as TenantSecuritySnapshot, { now: NOW });
    const s = renderHardeningPlanScript(withPlaceholder);
    expect(s).toContain("<break-glass account object ID>");
    const i = s.indexOf("<break-glass account object ID>");
    expect(s.lastIndexOf("# NEEDS EDITING", i)).toBeGreaterThan(s.lastIndexOf("if (Confirm-Step", s.lastIndexOf("if (Confirm-Step", i) - 1));
  });
});

// PowerShell can't parse a bare <placeholder> (the '<' operator is
// reserved), so one unquoted placeholder stops the whole downloaded script
// from running. Found by running every generated plan through PowerShell's
// parser; this keeps it from coming back.
describe("placeholders in commands", () => {
  const unquoted = (line: string) => {
    const out: string[] = [];
    for (const m of line.matchAll(/<(?!#)[A-Za-z][^<>]*>/g)) {
      const before = line.slice(0, m.index);
      const singles = (before.match(/'/g) || []).length;
      const doubles = (before.match(/"/g) || []).length;
      if (singles % 2 === 0 && doubles % 2 === 0 && !before.trimStart().startsWith("#")) out.push(m[0]);
    }
    return out;
  };

  it("are always inside quotes, in every guide, connect line and plan script (every demo tenant)", () => {
    for (const snap of demos) {
      const plan = buildHardeningPlan(snap, { now: NOW });
      const lines = renderHardeningPlanScript(plan).split("\n");
      const bad = lines.flatMap(unquoted);
      expect(bad, snap.tenant.displayName).toEqual([]);
    }
    // Commands not in any plan (all guides, empty context) too.
    for (const g of FIX_GUIDES) {
      const ctx = { tenantName: "x", breakGlass: [], items: [], observedCountries: [] };
      for (const s of g.steps(ctx)) for (const line of (s.command?.script || "").split("\n")) expect(unquoted(line), g.id).toEqual([]);
      for (const c of [g.verify.command, g.undo.command]) for (const line of (c?.script || "").split("\n")) expect(unquoted(line), g.id).toEqual([]);
    }
  });
});

describe("renderHardeningPlanHtml", () => {
  it("escapes tenant values and lists one tick box per fix", () => {
    const snap = { ...demos[0], tenant: { ...demos[0].tenant, displayName: `<script>alert("x")</script>` } } as TenantSecuritySnapshot;
    const plan = buildHardeningPlan(snap, { now: NOW });
    const html = renderHardeningPlanHtml(plan);
    expect(html).not.toContain("<script>alert");
    expect(html).toContain("&lt;script&gt;");
    expect(html.match(/class="box"/g)?.length).toBe(plan.counts.guides);
    expect(html).toContain("generated 5 Oct 2026");
  });
});
