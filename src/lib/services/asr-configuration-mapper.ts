// Pulled out of graph-client.ts for the same reason asr-detection-mapper.ts
// was: the mapping/merge rules here are unit-testable pure functions that
// don't need a live Graph response to exercise. All raw-JSON walking for the
// three live Intune surfaces (Settings Catalog / Device Configuration
// profile / Endpoint Security Template intents) stays in graph-client.ts;
// these functions only ever see already-flattened, simple shapes.
import { ASR_RULE_DEFINITIONS } from "../data/asr-rule-definitions";
import { AsrRuleMode, AsrRuleState } from "../types";

export interface AsrConfigSignal {
  ruleId: string;
  // Never "not_configured" - the absence of any signal for a rule already
  // means not_configured, so a signal only ever asserts a positive opinion.
  mode: Exclude<AsrRuleMode, "not_configured">;
  sourceName: string;
}

export interface CatalogSettingMetadata {
  settingDefinitionId: string;
  displayName: string;
}

const SETTINGS_CATALOG_ASR_ROOT_PREFIX = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_";

function normalizeForMatch(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

// Cross-matches Microsoft's tenant-agnostic Settings Catalog metadata for the
// ASR root setting (one row per rule, keyed by a human-readable slug rather
// than the rule's GUID) against ASR_RULE_DEFINITIONS' already-verified
// names, so the slug<->GUID map is derived from real Microsoft data instead
// of 19 hand-typed guesses - exactly the kind of guess that silently drifts
// and reintroduces this same bug for a different reason.
export function buildAsrSlugMap(catalogMetadata: CatalogSettingMetadata[]): {
  slugToRuleId: Map<string, string>;
  unmatchedCount: number;
} {
  const nameToRuleId = new Map(ASR_RULE_DEFINITIONS.map((def) => [normalizeForMatch(def.name), def.id]));
  const slugToRuleId = new Map<string, string>();
  let unmatchedCount = 0;

  for (const setting of catalogMetadata) {
    if (!setting.settingDefinitionId.startsWith(SETTINGS_CATALOG_ASR_ROOT_PREFIX)) continue;
    const slug = setting.settingDefinitionId.slice(SETTINGS_CATALOG_ASR_ROOT_PREFIX.length);
    const ruleId = nameToRuleId.get(normalizeForMatch(setting.displayName));
    if (ruleId) slugToRuleId.set(slug, ruleId);
    else unmatchedCount++;
  }

  return { slugToRuleId, unmatchedCount };
}

const SETTINGS_CATALOG_ACTION_SUFFIXES: { suffix: string; mode: AsrConfigSignal["mode"] | null }[] = [
  // Longest/most-specific suffixes first so "auditmode" isn't cut short by "audit".
  { suffix: "auditmode", mode: "audit" },
  { suffix: "audit", mode: "audit" },
  { suffix: "block", mode: "block" },
  { suffix: "warn", mode: "warn" },
  { suffix: "off", mode: null },
  { suffix: "disabled", mode: null },
  { suffix: "disable", mode: null },
  { suffix: "notconfigured", mode: null },
];

// One entry per leaf choice-setting value actually selected in a live
// Settings Catalog policy, e.g.
// "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_block".
// Unknown slugs and "no opinion" actions (off/disabled/not configured) are
// silently skipped, not thrown - a rule this policy doesn't touch should
// fall through to the shared not_configured default, same as every other
// surface.
export function mapAsrSettingDefinitionIdsToSignals(
  settingDefinitionIds: string[],
  sourceName: string,
  slugToRuleId: Map<string, string>
): AsrConfigSignal[] {
  const signals: AsrConfigSignal[] = [];

  for (const id of settingDefinitionIds) {
    if (!id.startsWith(SETTINGS_CATALOG_ASR_ROOT_PREFIX)) continue;
    const remainder = id.slice(SETTINGS_CATALOG_ASR_ROOT_PREFIX.length);

    const matchedSuffix = SETTINGS_CATALOG_ACTION_SUFFIXES.find(
      ({ suffix }) => remainder === suffix || remainder.endsWith(`_${suffix}`)
    );
    if (!matchedSuffix) continue;

    const slug = matchedSuffix.suffix === remainder ? "" : remainder.slice(0, -(matchedSuffix.suffix.length + 1));
    const ruleId = slugToRuleId.get(slug);
    if (!ruleId || !matchedSuffix.mode) continue;

    signals.push({ ruleId, mode: matchedSuffix.mode, sourceName });
  }

  return signals;
}

// The 15 ASR rules expressible via the legacy windows10EndpointProtectionConfiguration
// schema (shared verbatim by both the classic Device Configuration profile
// resource and the older Endpoint Security Template/intents resource, whose
// definitionId is this same property name prefixed with
// "deviceConfiguration--windows10EndpointProtectionConfiguration_"). Verified
// against Microsoft's Graph beta resource reference - deliberately a hand
// -built allowlist, NOT a generic "defender*Type" name match: two properties
// that fit that naming pattern (defenderNetworkProtectionType,
// defenderGuardMyFoldersType) configure Network Protection and Controlled
// Folder Access, unrelated Defender features, not ASR rules. The remaining 4
// catalog rules (e.g. Block Webshell creation for Servers) don't exist in
// this legacy schema at all and can only ever be found via the Settings
// Catalog surface above.
export const LEGACY_ASR_PROPERTY_TO_RULE_ID: Record<string, string> = {
  defenderPreventCredentialStealingType: "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
  defenderBlockPersistenceThroughWmiType: "e6db77e5-3df2-4cf1-b95a-636979351e5b",
  defenderAdobeReaderLaunchChildProcess: "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
  defenderOfficeAppsLaunchChildProcessType: "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
  defenderEmailContentExecutionType: "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
  defenderUntrustedExecutableType: "01443614-cd74-433a-b99e-2ecdc07bfc25",
  defenderScriptObfuscatedMacroCodeType: "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
  defenderScriptDownloadedPayloadExecutionType: "d3e037e1-3eb8-44c8-a917-57927947596d",
  defenderOfficeAppsExecutableContentCreationOrLaunchType: "3b576869-a4ec-4529-8536-b80a7769e899",
  defenderOfficeAppsOtherProcessInjectionType: "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
  defenderOfficeCommunicationAppsLaunchChildProcess: "26190899-1602-49e8-8b27-eb1d0a1ce869",
  defenderProcessCreationType: "d1e49aac-8f56-4280-b9ba-993a6d77406c",
  defenderUntrustedUSBProcessType: "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
  defenderOfficeMacroCodeAllowWin32ImportsType: "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
  defenderAdvancedRansomewareProtectionType: "c1db55ab-c21a-4637-bb3f-a12568109d35",
};

const LEGACY_VALUE_TO_MODE: Record<string, AsrConfigSignal["mode"] | undefined> = {
  block: "block",
  enable: "block",
  auditMode: "audit",
  warn: "warn",
  // userDefined / disable / notConfigured all mean "no opinion" - omitted
  // rather than mapped, so lookups above naturally fall through to skip.
};

// Shared by both the legacy Device Configuration profile surface (already
// flat key/value pairs) and the Endpoint Security Template/intents surface
// (flattened by the caller from settingInstances first) - one table and one
// function, not two, so the two surfaces can never silently drift apart on
// what a given property value means.
export function mapNamedPropertyValuesToSignals(
  properties: { propertyName: string; rawValue: string }[],
  sourceName: string
): AsrConfigSignal[] {
  const signals: AsrConfigSignal[] = [];

  for (const { propertyName, rawValue } of properties) {
    const ruleId = LEGACY_ASR_PROPERTY_TO_RULE_ID[propertyName];
    if (!ruleId) continue;
    const mode = LEGACY_VALUE_TO_MODE[rawValue];
    if (!mode) continue;
    signals.push({ ruleId, mode, sourceName });
  }

  return signals;
}

// The cross-surface merge + conflict detector - the single place all three
// live surfaces (and mock data, indirectly, via the same AsrRuleState shape)
// funnel through, so this project doesn't repeat the "duplicated
// classification logic drifts apart" bug class documented in
// ai-context-vault/Optimization/Optimization Plan.md. Always returns exactly
// 19 entries, one per ASR_RULE_DEFINITIONS, so callers never need a null
// check for a rule nobody has an opinion on.
export function mergeAsrRuleStates(signals: AsrConfigSignal[]): AsrRuleState[] {
  const signalsByRule = new Map<string, AsrConfigSignal[]>();
  for (const signal of signals) {
    const existing = signalsByRule.get(signal.ruleId);
    if (existing) existing.push(signal);
    else signalsByRule.set(signal.ruleId, [signal]);
  }

  return ASR_RULE_DEFINITIONS.map((def) => {
    const ruleSignals = signalsByRule.get(def.id);
    if (!ruleSignals || ruleSignals.length === 0) {
      return { ruleId: def.id, mode: "not_configured" as const };
    }

    const distinctModes = new Set(ruleSignals.map((s) => s.mode));
    const sourcePolicyNames = Array.from(new Set(ruleSignals.map((s) => s.sourceName)));

    if (distinctModes.size > 1) {
      // Per Microsoft's documented ASR policy merge behavior, a genuine
      // conflict between sources is dropped entirely rather than one source
      // winning - so the effective, on-device mode really is not_configured.
      // hasConflict is what keeps that distinguishable from a rule nobody
      // has touched, since a self-canceling policy pair is a real,
      // actionable misconfiguration an engineer needs to find and fix.
      return { ruleId: def.id, mode: "not_configured" as const, sourcePolicyNames, hasConflict: true };
    }

    return { ruleId: def.id, mode: ruleSignals[0].mode, sourcePolicyNames };
  });
}
