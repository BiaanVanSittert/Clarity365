// Mirrors mailflow-baseline-definitions.ts's/groups-baseline-definitions.ts's
// pattern for SharePoint, OneDrive & Storage: named checks scored against
// live site/tenant-setting data by sharepoint-baseline-matcher.ts.
//
// No check in this file ships a one-click fix in this pass. SP01-SP03 are
// tenant-wide settings that likely ARE writable via
// PATCH /admin/sharepoint/settings, but that Graph resource's exact write
// contract isn't confirmed against a live tenant yet — shipping a "fix"
// button against an unverified write shape risks a confusing failure on a
// real tenant, so this pass is read/visibility-only, same "no auto-fix until
// confirmed" convention already used elsewhere (MF05/MF06/G01-G04). SP04/SP05
// are per-site judgment calls (is the sharing level actually wrong for this
// site's business purpose; who should own it) that wouldn't be auto-fixable
// even with a confirmed write path.

export interface SharePointBaselineCheck {
  code: string;
  name: string;
  description: string;
  riskMitigated: string;
}

export const SHAREPOINT_BASELINE_STANDARDS: SharePointBaselineCheck[] = [
  {
    code: "SP01",
    name: "Tenant-wide sharing ceiling is not \"Anyone\"",
    description: "The tenant-wide maximum SharePoint/OneDrive sharing level is capped below unauthenticated \"Anyone\" links.",
    riskMitigated:
      "\"Anyone\" as the tenant ceiling means every site can potentially be shared with anyone on the internet, with no sign-in required, regardless of what any individual site owner intends.",
  },
  {
    code: "SP02",
    name: "Anonymous links expire",
    description: "Anonymous \"Anyone\" links are set to expire after a bounded number of days, not left to never expire.",
    riskMitigated: "A non-expiring anonymous link is a permanent, unauthenticated door into whatever it points to — it doesn't self-close even after the business need for it has passed.",
  },
  {
    code: "SP03",
    name: "Default share link isn't more permissive than necessary",
    description: "The default link type users get when they click \"Share\" is not \"Anyone\", regardless of what the tenant ceiling allows.",
    riskMitigated: "Even with a safer ceiling configured, most users never change the default link type — if the default itself is \"Anyone\", the safer ceiling rarely gets used in practice.",
  },
  {
    code: "SP04",
    name: "No sensitive-data site allows open sharing",
    description: "No site flagged as likely containing sensitive data (by name/keyword) also allows \"Anyone\" or guest sharing.",
    riskMitigated: "A site with sensitive data AND open sharing is a materially worse finding than either fact alone — this is exactly the compounding-risk pattern that's easy to miss scanning either signal in isolation.",
  },
  {
    code: "SP05",
    name: "No site is owned by a disabled or departed account",
    description: "Every site (including personal OneDrive sites) has an owner who is still an active, licensed account.",
    riskMitigated: "A site \"owned\" by a disabled or departed employee is effectively ownerless without anyone noticing — nobody is accountable for its sharing settings or content going forward.",
  },
];
