import { SecureScoreControlDeployment } from "../types";

// Maps a live Microsoft Secure Score controlName (Graph's own internal id,
// confirmed against a real tenant - see [[Secure Score & Timeline]] in the
// vault) to a Clarity365 baseline code this app already has a live Graph
// write path for.
//
// Deliberately conservative and short: a controlName only belongs here once
// it's been confirmed live to correspond 1:1 with a policy Clarity365's own
// deploy code creates/checks. Promising "Auto-Deploy" for a control this app
// can't actually satisfy would mislead a security engineer - see the
// disproved CA05 appId guesses and the templateId guess this session for
// what happens when Graph behavior gets assumed instead of verified.
//
// Notably absent: EDR/AV/ASR/BitLocker and CA04/CA05/CA08/CA09/CA10. The
// Device-category Secure Score controls (scid_2000, scid_2010, scid_2090,
// etc.) score actual per-device telemetry, not "does this Settings Catalog
// policy exist" - deploying the matching Clarity365 policy should improve
// those scores over time as devices come into compliance, but it isn't the
// same deterministic existence check CA baselines get, so it stays "guided"
// rather than "auto" until proven otherwise against a live tenant.
export const SECURE_SCORE_AUTO_DEPLOY_MAP: Record<string, string> = {
  BlockLegacyAuthentication: "CA01",
  MFARegistrationV2: "CA02",
  AdminMFAV2: "CA03",
  SigninRiskPolicy: "CA06",
  UserRiskPolicy: "CA07",
};

// Overrides a control's default guided/manual_only deployment to "auto" when
// its controlName has a confirmed baseline mapping above. Leaves every other
// control's deployment untouched.
export function applyAutoDeployMapping(
  controlName: string,
  defaultDeployment: SecureScoreControlDeployment
): SecureScoreControlDeployment {
  const clarity365Action = SECURE_SCORE_AUTO_DEPLOY_MAP[controlName];
  if (!clarity365Action) return defaultDeployment;
  return { type: "auto", clarity365Action };
}
