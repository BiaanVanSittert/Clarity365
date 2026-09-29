import { SecureScoreControl } from "../types";

// Company sign-in page branding is NOT part of Microsoft's own Secure Score
// catalog at all - confirmed live by checking every one of the ~462 real
// secureScoreControlProfiles entries, none exist for it. This is Clarity365's
// own recommendation, added to the same table because it's genuinely useful
// security-adjacent guidance (a branded sign-in page helps end users spot a
// phishing look-alike that doesn't match), not because Microsoft scores it.
// Deliberately live-checked rather than a static decoration: status reflects
// whether this tenant's sign-in experience actually has a logo/background
// configured, via Graph's organization/{id}/branding/localizations - the same
// Organization.Read.All permission already required for tenant capability
// detection, so no new grant is needed.
export const COMPANY_BRANDING_CONTROL_ID = "clarity365_company_branding";

export interface RawOrganizationalBrandingLocalization {
  bannerLogoRelativeUrl?: string | null;
  squareLogoRelativeUrl?: string | null;
  backgroundImageRelativeUrl?: string | null;
  [key: string]: unknown;
}

export function hasCompanyBrandingConfigured(localizations: RawOrganizationalBrandingLocalization[]): boolean {
  return localizations.some(
    (loc) => !!loc.bannerLogoRelativeUrl || !!loc.squareLogoRelativeUrl || !!loc.backgroundImageRelativeUrl
  );
}

// Points fixed at 0/0 - this deliberately never counts toward the real
// Microsoft attainment percentage shown at the top of the Secure Score
// module (that comes straight from Graph's own currentScore/maxScore, not a
// sum of this controls array, but 0/0 keeps the intent explicit either way).
export function buildCompanyBrandingControl(localizations: RawOrganizationalBrandingLocalization[]): SecureScoreControl {
  const configured = hasCompanyBrandingConfigured(localizations);
  return {
    id: COMPANY_BRANDING_CONTROL_ID,
    title: "Add your organization's branding to the sign-in page",
    category: "Identity",
    scoreCurrent: 0,
    scoreMax: 0,
    implementationCost: "Low",
    userImpact: "Low",
    status: configured ? "Completed" : "Unresolved",
    actionType: "Configuration",
    description:
      "Custom sign-in page branding (your logo, background image, and colors) helps end users visually recognize your organization's real Microsoft 365 sign-in page, making a phishing look-alike that doesn't match easier to spot. It also gives staff and clients a more professional, trustworthy first impression.",
    remediationSummary:
      "1. Go to the Microsoft Entra admin center (entra.microsoft.com) and open Customization > Company branding.\n2. Add a logo, background image, and (optionally) sign-in page text for the default sign-in experience - additional per-language variants are optional.\n3. Save. Changes apply within a few minutes.",
    // Deliberately the top-level Entra admin center URL, not a deep-link
    // fragment to the exact blade - that exact path hasn't been verified
    // live, and a wrong fragment silently redirects to the portal root
    // anyway, so it isn't worth the false precision.
    actionUrl: "https://entra.microsoft.com/",
    // Guided, not auto: this needs an actual logo/background image file
    // uploaded, which isn't something a one-click deploy can do without
    // Clarity365 hosting client-supplied brand assets.
    deployment: { type: "guided" },
  };
}
