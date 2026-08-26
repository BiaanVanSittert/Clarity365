import { describe, it, expect } from "vitest";
import { evaluateMailflowBaseline, MailflowBaselineInput } from "./mailflow-baseline-matcher";
import { MAILFLOW_BASELINE_STANDARDS } from "../data/mailflow-baseline-definitions";
import { MailflowTransportRule, MdoThreatPolicy, MailflowConnector } from "../types";

function rule(overrides: Partial<MailflowTransportRule> & Pick<MailflowTransportRule, "id" | "name">): MailflowTransportRule {
  return {
    state: "Enabled",
    redirectsExternally: false,
    overridesSpamConfidence: false,
    hasNoScopingConditions: false,
    hasExpiry: false,
    ...overrides,
  };
}

function connector(overrides: Partial<MailflowConnector> & Pick<MailflowConnector, "id" | "name">): MailflowConnector {
  return {
    direction: "Inbound",
    enabled: true,
    trustsAnonymousSenders: false,
    requiresTls: true,
    ...overrides,
  };
}

function outboundPolicy(autoForwardingBlocked: boolean): MdoThreatPolicy {
  return {
    id: "outbound-1",
    policyType: "AntiSpamOutbound",
    displayName: "Default",
    state: "Enabled",
    assignedScope: "Default (Organization-wide)",
    impersonationProtection: false,
    spoofIntelligence: false,
    zapEnabled: false,
    complianceRating: "compliant",
    realTimeScanning: false,
    blockingAction: false,
    commonAttachmentFilter: false,
    outboundNotify: true,
    autoForwardingBlocked,
  };
}

function baseInput(overrides: Partial<MailflowBaselineInput> = {}): MailflowBaselineInput {
  return {
    transportRules: [],
    policies: [outboundPolicy(true)],
    connectors: [],
    remoteDomainAutoForwardBlocked: true,
    externalSenderTagEnabled: true,
    ...overrides,
  };
}

describe("evaluateMailflowBaseline", () => {
  it("scores 100% when everything is compliant", () => {
    const { results, coveragePercent } = evaluateMailflowBaseline(baseInput());
    expect(coveragePercent).toBe(100);
    expect(results).toHaveLength(MAILFLOW_BASELINE_STANDARDS.length);
    expect(results.every((r) => r.met)).toBe(true);
  });

  it("MF01 flags enabled rules that redirect externally, ignoring disabled ones", () => {
    const rules = [
      rule({ id: "1", name: "Leak Rule", redirectsExternally: true }),
      rule({ id: "2", name: "Old Leak Rule", redirectsExternally: true, state: "Disabled" }),
    ];
    const result = evaluateMailflowBaseline(baseInput({ transportRules: rules })).results.find((r) => r.code === "MF01")!;
    expect(result.met).toBe(false);
    expect(result.offendingRuleNames).toEqual(["Leak Rule"]);
  });

  it("MF03 flags an unscoped rule only when it also has no expiry", () => {
    const permanent = [rule({ id: "2", name: "Permanent Broad Rule", hasNoScopingConditions: true, hasExpiry: false })];
    const result = evaluateMailflowBaseline(baseInput({ transportRules: permanent })).results.find((r) => r.code === "MF03")!;
    expect(result.met).toBe(false);
  });

  it("MF04 reflects the AntiSpamOutbound policy's autoForwardingBlocked field", () => {
    expect(evaluateMailflowBaseline(baseInput({ policies: [outboundPolicy(false)] })).results.find((r) => r.code === "MF04")!.met).toBe(false);
    expect(evaluateMailflowBaseline(baseInput({ policies: [] })).results.find((r) => r.code === "MF04")!.met).toBe(false);
  });

  it("MF05 flags enabled connectors that trust anonymous senders", () => {
    const connectors = [connector({ id: "c1", name: "Legacy Partner", trustsAnonymousSenders: true })];
    const result = evaluateMailflowBaseline(baseInput({ connectors })).results.find((r) => r.code === "MF05")!;
    expect(result.met).toBe(false);
    expect(result.offendingRuleNames).toEqual(["Legacy Partner"]);
  });

  it("MF05 ignores disabled connectors", () => {
    const connectors = [connector({ id: "c1", name: "Old Connector", trustsAnonymousSenders: true, enabled: false })];
    expect(evaluateMailflowBaseline(baseInput({ connectors })).results.find((r) => r.code === "MF05")!.met).toBe(true);
  });

  it("MF06 flags enabled connectors that don't require TLS", () => {
    const connectors = [connector({ id: "c1", name: "Plaintext Partner", requiresTls: false })];
    const result = evaluateMailflowBaseline(baseInput({ connectors })).results.find((r) => r.code === "MF06")!;
    expect(result.met).toBe(false);
    expect(result.offendingRuleNames).toEqual(["Plaintext Partner"]);
  });

  it("MF07 reflects remoteDomainAutoForwardBlocked", () => {
    expect(evaluateMailflowBaseline(baseInput({ remoteDomainAutoForwardBlocked: false })).results.find((r) => r.code === "MF07")!.met).toBe(false);
    expect(evaluateMailflowBaseline(baseInput({ remoteDomainAutoForwardBlocked: undefined })).results.find((r) => r.code === "MF07")!.met).toBe(false);
  });

  it("MF08 reflects externalSenderTagEnabled", () => {
    expect(evaluateMailflowBaseline(baseInput({ externalSenderTagEnabled: false })).results.find((r) => r.code === "MF08")!.met).toBe(false);
  });
});
