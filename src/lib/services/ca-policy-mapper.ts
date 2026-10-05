import { CAPolicyRule } from "../types";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { classifyPolicyBaselineCode } from "./ca-baseline-matcher";
import { mapCaPolicyExtendedFields } from "./ca-environment-mapper";

// Microsoft Graph conditionalAccessPolicy -> the app's CAPolicyRule. Pure, so
// it runs anywhere: the sync (graph-client.ts re-exports it) and, in the
// browser, the fix guides' impact preview, which maps a proposed policy the
// same way a synced one is mapped.

// Maps one raw Graph conditionalAccessPolicy into Clarity365's CAPolicyRule
// shape. Pulled out of fetchLiveTenantSnapshot's inline .map() so this
// mapping/classification step is unit-testable directly (same convention as
// secure-score-mapper.ts) - this exact function is where the CA04
// includeGuestsOrExternalUsers bug lived, and it had zero test coverage of
// its own before this extraction (only the pure ca-baseline-matcher.ts
// functions it calls were tested in isolation).
export function mapConditionalAccessPolicy(p: any): CAPolicyRule {
  const detectedCode = classifyPolicyBaselineCode(p);
  const baselineDef = CA_BASELINE_STANDARDS.find((b) => b.code === detectedCode);

  // Graph's grantControls.authenticationStrength is a sibling object to
  // builtInControls, not an entry inside it - encode its presence as a marker
  // string in the array (matching this app's own convention, e.g. the
  // "authenticationStrength:PhishingResistantMFA" strings used when Clarity365
  // deploys its own CA10 policy) so ca-baseline-matcher.ts's array-based
  // hasAuthStrengthOrSession/controlsInclude checks can see it.
  const builtInControls: string[] = p.grantControls?.builtInControls || [];
  const authStrengthName = p.grantControls?.authenticationStrength?.displayName || p.grantControls?.authenticationStrength?.id;
  const grantControls = authStrengthName ? [...builtInControls, `authenticationStrength:${authStrengthName}`] : builtInControls;

  // Fields the Security Simulations engine needs that this mapper used to
  // drop (see ai-context-vault/Optimization/Security Simulations Plan.md).
  const extended = mapCaPolicyExtendedFields(p);

  return {
    id: p.id,
    name: p.displayName,
    baselineCode: detectedCode,
    baselineTitle: baselineDef?.name,
    state: p.state as any,
    modifiedDateTime: p.modifiedDateTime || new Date().toISOString(),
    createdDateTime: p.createdDateTime || new Date().toISOString(),
    grantControls,
    conditions: {
      // Guest/external-user targeting moved from a plain "GuestsOrExternalUsers"
      // string inside includeUsers/excludeUsers to a structured
      // includeGuestsOrExternalUsers/excludeGuestsOrExternalUsers object - Graph
      // still silently accepts (and auto-upgrades) the deprecated string on
      // create, but a live GET only ever returns the new structured field, never
      // the string. Without this, includeUsers/excludeUsers come back empty for
      // a CA04 (or CA02's guest exclusion) policy that is genuinely correctly
      // configured, and re-validation against this mapped shape falsely reports
      // it as Misconfigured even though the raw sync-time classification (which
      // reads the raw Graph response directly, not this mapped shape) got it
      // right. Re-encoded as the same "GuestsOrExternalUsers" marker string
      // ca-baseline-matcher.ts's targetsGuests() already looks for, so no
      // matcher change is needed - confirmed live against a real dmafrica CA04
      // policy Graph had already silently upgraded this way.
      users: {
        // No "|| includeRoles" fallback here on purpose: Graph always
        // returns includeUsers as an array (empty, never omitted) for a
        // role-scoped policy, and [] is truthy in JS, so that fallback
        // could never actually fire - found during a follow-up review as
        // dead code with the exact same "empty array masks a real value"
        // shape as the CA04 bug above, just not currently symptomatic
        // because targetsAdminRoles() already reads includeRoles from its
        // own preserved field below, not from this array. Merging role
        // GUIDs into include would also be semantically wrong regardless
        // (they aren't user/group identifiers, and other checks scan
        // include specifically for "All"/"GuestsOrExternalUsers" markers).
        include: [
          ...(p.conditions?.users?.includeUsers || []),
          ...(p.conditions?.users?.includeGuestsOrExternalUsers ? ["GuestsOrExternalUsers"] : []),
        ],
        exclude: [
          ...(p.conditions?.users?.excludeUsers || []),
          ...(p.conditions?.users?.excludeGuestsOrExternalUsers ? ["GuestsOrExternalUsers"] : []),
        ],
        excludeGroupIds: p.conditions?.users?.excludeGroups || [],
        includeRoles: p.conditions?.users?.includeRoles || [],
        ...extended.users,
      },
      applications: {
        include: p.conditions?.applications?.includeApplications || [],
        exclude: p.conditions?.applications?.excludeApplications || [],
        ...extended.applications,
      },
      clientAppTypes: p.conditions?.clientAppTypes || [],
      // Previously dropped entirely - CA06 (signInRiskLevels), CA07
      // (userRiskLevels), and CA08 (locations) all validate structurally
      // against these fields, so a live-synced policy that legitimately
      // satisfies them was still failing re-validation against the stored
      // snapshot even though the initial sync-time classification (run
      // against the raw Graph response above) correctly detected the code.
      platforms: {
        include: p.conditions?.platforms?.includePlatforms || [],
        exclude: p.conditions?.platforms?.excludePlatforms || [],
      },
      locations: {
        include: p.conditions?.locations?.includeLocations || [],
        exclude: p.conditions?.locations?.excludeLocations || [],
      },
      userRiskLevels: p.conditions?.userRiskLevels || [],
      signInRiskLevels: p.conditions?.signInRiskLevels || [],
      ...extended.conditions,
    },
    grantOperator: extended.grantOperator,
    sessionControls: extended.sessionControls,
    matchesBaseline: !!detectedCode,
  };
}
