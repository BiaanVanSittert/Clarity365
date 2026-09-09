import { describe, it, expect } from "vitest";
import {
  buildAsrSlugMap,
  mapAsrSettingDefinitionIdsToSignals,
  mapNamedPropertyValuesToSignals,
  mergeAsrRuleStates,
  LEGACY_ASR_PROPERTY_TO_RULE_ID,
} from "./asr-configuration-mapper";
import { ASR_RULE_DEFINITIONS } from "../data/asr-rule-definitions";

const RANSOMWARE_ID = "c1db55ab-c21a-4637-bb3f-a12568109d35";
const CRED_THEFT_ID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2";
const ROOT_PREFIX = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_";

describe("buildAsrSlugMap", () => {
  it("matches a catalog entry to its rule id by normalized display name", () => {
    const def = ASR_RULE_DEFINITIONS.find((d) => d.id === RANSOMWARE_ID)!;
    const { slugToRuleId, unmatchedCount } = buildAsrSlugMap([
      { settingDefinitionId: `${ROOT_PREFIX}useadvancedprotectionagainstransomware`, displayName: def.name },
    ]);
    expect(slugToRuleId.get("useadvancedprotectionagainstransomware")).toBe(RANSOMWARE_ID);
    expect(unmatchedCount).toBe(0);
  });

  it("tolerates case and punctuation differences when matching names", () => {
    const def = ASR_RULE_DEFINITIONS.find((d) => d.id === RANSOMWARE_ID)!;
    const { slugToRuleId } = buildAsrSlugMap([
      { settingDefinitionId: `${ROOT_PREFIX}someslug`, displayName: `  ${def.name.toUpperCase()}!!  ` },
    ]);
    expect(slugToRuleId.get("someslug")).toBe(RANSOMWARE_ID);
  });

  it("counts an entry that matches no known rule name as unmatched instead of guessing", () => {
    const { slugToRuleId, unmatchedCount } = buildAsrSlugMap([
      { settingDefinitionId: `${ROOT_PREFIX}somefutureslug`, displayName: "Some brand new rule Microsoft added later" },
    ]);
    expect(slugToRuleId.size).toBe(0);
    expect(unmatchedCount).toBe(1);
  });

  it("ignores metadata rows outside the ASR root definition", () => {
    const { slugToRuleId, unmatchedCount } = buildAsrSlugMap([
      { settingDefinitionId: "device_vendor_msft_policy_config_defender_someunrelatedsetting", displayName: "Unrelated" },
    ]);
    expect(slugToRuleId.size).toBe(0);
    expect(unmatchedCount).toBe(0);
  });
});

describe("mapAsrSettingDefinitionIdsToSignals", () => {
  const slugToRuleId = new Map([["blockexecutionofpotentiallyobfuscatedscripts", RANSOMWARE_ID]]);

  it("resolves a real-shaped settingDefinitionId to a block signal", () => {
    const signals = mapAsrSettingDefinitionIdsToSignals(
      [`${ROOT_PREFIX}blockexecutionofpotentiallyobfuscatedscripts_block`],
      "My ASR Policy",
      slugToRuleId
    );
    expect(signals).toEqual([{ ruleId: RANSOMWARE_ID, mode: "block", sourceName: "My ASR Policy" }]);
  });

  it("resolves audit and warn suffixes correctly", () => {
    const audit = mapAsrSettingDefinitionIdsToSignals(
      [`${ROOT_PREFIX}blockexecutionofpotentiallyobfuscatedscripts_audit`],
      "P",
      slugToRuleId
    );
    expect(audit[0].mode).toBe("audit");

    const warn = mapAsrSettingDefinitionIdsToSignals(
      [`${ROOT_PREFIX}blockexecutionofpotentiallyobfuscatedscripts_warn`],
      "P",
      slugToRuleId
    );
    expect(warn[0].mode).toBe("warn");
  });

  it("skips off/disabled/not-configured actions - they carry no opinion", () => {
    const signals = mapAsrSettingDefinitionIdsToSignals(
      [
        `${ROOT_PREFIX}blockexecutionofpotentiallyobfuscatedscripts_off`,
        `${ROOT_PREFIX}blockexecutionofpotentiallyobfuscatedscripts_disabled`,
        `${ROOT_PREFIX}blockexecutionofpotentiallyobfuscatedscripts_notconfigured`,
      ],
      "P",
      slugToRuleId
    );
    expect(signals).toEqual([]);
  });

  it("skips an unknown slug instead of throwing", () => {
    expect(() =>
      mapAsrSettingDefinitionIdsToSignals([`${ROOT_PREFIX}somebrandnewrule_block`], "P", slugToRuleId)
    ).not.toThrow();
    expect(mapAsrSettingDefinitionIdsToSignals([`${ROOT_PREFIX}somebrandnewrule_block`], "P", slugToRuleId)).toEqual([]);
  });

  it("ignores settingDefinitionIds outside the ASR root prefix", () => {
    expect(mapAsrSettingDefinitionIdsToSignals(["some_other_setting_block"], "P", slugToRuleId)).toEqual([]);
  });
});

describe("mapNamedPropertyValuesToSignals", () => {
  it("maps every known legacy property/value pair to the correct rule and mode", () => {
    const signals = mapNamedPropertyValuesToSignals(
      [
        { propertyName: "defenderPreventCredentialStealingType", rawValue: "enable" },
        { propertyName: "defenderBlockPersistenceThroughWmiType", rawValue: "auditMode" },
      ],
      "Legacy Endpoint Protection Profile"
    );
    expect(signals).toEqual([
      { ruleId: CRED_THEFT_ID, mode: "block", sourceName: "Legacy Endpoint Protection Profile" },
      { ruleId: "e6db77e5-3df2-4cf1-b95a-636979351e5b", mode: "audit", sourceName: "Legacy Endpoint Protection Profile" },
    ]);
  });

  it("treats userDefined/disable/notConfigured as no opinion", () => {
    const signals = mapNamedPropertyValuesToSignals(
      [
        { propertyName: "defenderPreventCredentialStealingType", rawValue: "userDefined" },
        { propertyName: "defenderPreventCredentialStealingType", rawValue: "notConfigured" },
      ],
      "P"
    );
    expect(signals).toEqual([]);
  });

  it("ignores a property that isn't a known ASR rule, even if it looks like one", () => {
    // Network Protection and Controlled Folder Access share the defender*Type
    // naming convention but are NOT attack surface reduction rules.
    const signals = mapNamedPropertyValuesToSignals(
      [
        { propertyName: "defenderNetworkProtectionType", rawValue: "enable" },
        { propertyName: "defenderGuardMyFoldersType", rawValue: "enable" },
      ],
      "P"
    );
    expect(signals).toEqual([]);
  });

  it("covers all 15 verified legacy properties without throwing", () => {
    const properties = Object.keys(LEGACY_ASR_PROPERTY_TO_RULE_ID).map((propertyName) => ({
      propertyName,
      rawValue: "block",
    }));
    expect(Object.keys(LEGACY_ASR_PROPERTY_TO_RULE_ID).length).toBe(15);
    expect(() => mapNamedPropertyValuesToSignals(properties, "P")).not.toThrow();
    expect(mapNamedPropertyValuesToSignals(properties, "P").length).toBe(15);
  });
});

describe("mergeAsrRuleStates", () => {
  it("returns exactly 19 entries, not_configured with no sources for a rule with zero signals", () => {
    const states = mergeAsrRuleStates([]);
    expect(states.length).toBe(ASR_RULE_DEFINITIONS.length);
    expect(states.every((s) => s.mode === "not_configured" && !s.sourcePolicyNames && !s.hasConflict)).toBe(true);
  });

  it("adopts the single signal's mode and source for a rule with one signal", () => {
    const states = mergeAsrRuleStates([{ ruleId: RANSOMWARE_ID, mode: "block", sourceName: "Policy A" }]);
    const rule = states.find((s) => s.ruleId === RANSOMWARE_ID)!;
    expect(rule).toEqual({ ruleId: RANSOMWARE_ID, mode: "block", sourcePolicyNames: ["Policy A"] });
  });

  it("dedupes source names and keeps the mode when multiple sources agree", () => {
    const states = mergeAsrRuleStates([
      { ruleId: RANSOMWARE_ID, mode: "block", sourceName: "Policy A" },
      { ruleId: RANSOMWARE_ID, mode: "block", sourceName: "Policy B" },
      { ruleId: RANSOMWARE_ID, mode: "block", sourceName: "Policy A" },
    ]);
    const rule = states.find((s) => s.ruleId === RANSOMWARE_ID)!;
    expect(rule.mode).toBe("block");
    expect(rule.hasConflict).toBeUndefined();
    expect(rule.sourcePolicyNames).toEqual(["Policy A", "Policy B"]);
  });

  it("flags a conflict and forces not_configured when sources disagree, but keeps every source name", () => {
    const states = mergeAsrRuleStates([
      { ruleId: RANSOMWARE_ID, mode: "block", sourceName: "Policy A" },
      { ruleId: RANSOMWARE_ID, mode: "audit", sourceName: "Policy B" },
    ]);
    const rule = states.find((s) => s.ruleId === RANSOMWARE_ID)!;
    expect(rule.mode).toBe("not_configured");
    expect(rule.hasConflict).toBe(true);
    expect(rule.sourcePolicyNames).toEqual(["Policy A", "Policy B"]);
  });
});
