// Approximate estimated monthly USD cost per seat, keyed by Graph's
// subscribedSkus.skuPartNumber - same "estimated public list price, not a
// live pricing API call" framing as fleet-analyzer.ts's own
// LICENSE_TIER_MONTHLY_COST (which this table replaces for per-SKU waste
// costing - that one only ever priced a whole tenant at one flat per-seat
// rate regardless of which specific SKU was actually involved, which is
// exactly what let a handful of $0 self-service SKUs with huge quantities
// - 1,000,000 "free student" seats, 10,000 FLOW_FREE, etc. - get costed as
// if they were the tenant's premium paid tier).
export const LICENSE_SKU_MONTHLY_COST_USD: Record<string, number> = {
  SPE_E5: 57,
  SPE_E3: 38,
  SPE_F1: 8,
  SPB: 22,
  O365_BUSINESS_PREMIUM: 12.5,
  O365_BUSINESS_ESSENTIALS: 6,
  ENTERPRISEPACK: 23,
  ENTERPRISEPREMIUM: 38,
  EXCHANGESTANDARD: 4,
  EXCHANGEENTERPRISE: 8,
  EXCHANGEONLINE: 4,
  POWER_BI_PRO: 10,
  VISIOCLIENT: 15,
  PROJECTPROFESSIONAL: 30,
  PROJECTPREMIUM: 55,
  EMSPREMIUM: 14.8,
  EMS: 8.8,
  AAD_PREMIUM_P2: 9,
  AAD_PREMIUM: 6,
  DEFENDER_FOR_BUSINESS: 3,
  // EDU paid tiers (A3/A5 - not the free A1 tier, see FREE_LICENSE_SKUS)
  ENTERPRISEPACKPLUS_FACULTY: 3.5,
  ENTERPRISEPACKPLUS_STUDENT: 2.5,
  ENTERPRISEPREMIUM_FACULTY: 5.5,
  ENTERPRISEPREMIUM_STUDENT: 3,
  M365EDU_A3_FACULTY: 3.5,
  M365EDU_A3_STUDENT: 2.5,
  M365EDU_A5_FACULTY: 5.5,
  M365EDU_A5_STUDENT: 3,
  AAD_PREMIUM_P2_FACULTY: 3,

  // Mock/demo tenant data (mock-tenants.ts) stores `user.licenses` as
  // friendly display names rather than Graph skuPartNumbers - see
  // license-sku-names.ts's own note that "mock data already uses friendly
  // names." Mirrored here so a demo tenant's estimated cost matches its
  // live-tenant equivalent instead of falling through to the generic
  // DEFAULT_LICENSE_SKU_COST_USD fallback.
  "Microsoft 365 E5": 57,
  "Microsoft 365 E3": 38,
  "Microsoft 365 F3": 8,
  "Microsoft 365 Business Premium": 22,
  "Microsoft 365 Business Standard": 12.5,
  "Microsoft 365 Business Basic": 6,
  "Office 365 E3": 23,
  "Office 365 E5": 38,
  "Microsoft Entra ID P2": 9,
  "Microsoft Entra ID P1": 6,
  "Defender for Endpoint P2": 3,
  "Enterprise Mobility + Security E5": 14.8,
  "Enterprise Mobility + Security E3": 8.8,
  "Power BI Pro": 10,
  "Visio Plan 2": 15,
  "Project Plan 3": 30,
  "Project Plan 5": 55,
  "Microsoft Defender for Business": 3,
};

// Real, documented $0 SKUs - verified against Microsoft's own
// documentation, not assumed. Two distinct reasons a SKU ends up here:
// self-service/viral trial grants a user can activate without an admin
// ever purchasing anything (FLOW_FREE, POWER_BI_STANDARD, POWERAPPS_VIRAL,
// TEAMS_EXPLORATORY), and per-org free entitlements Microsoft provisions
// automatically (PHONESYSTEM_VIRTUALUSER, a retired legacy SKU that still
// lingers in older tenants - WINDOWS_STORE - and Microsoft's donated free
// education tier, Office 365 A1 - STANDARDWOFFPACK_STUDENT/_FACULTY).
// Both kinds commonly show up with an implausibly large quantity (granted
// per-org, not per actual purchased seat) - exactly what was inflating
// waste estimates before this fix existed.
export const FREE_LICENSE_SKUS = new Set<string>([
  "FLOW_FREE",
  "POWER_BI_STANDARD",
  "POWERAPPS_VIRAL",
  "TEAMS_EXPLORATORY",
  "PHONESYSTEM_VIRTUALUSER",
  "WINDOWS_STORE",
  "STANDARDWOFFPACK_STUDENT",
  "STANDARDWOFFPACK_FACULTY",
  // Microsoft Stream (Classic) - a tenant's large STREAM quantity is the
  // Stream trial grant, not a purchase (confirmed: "the unlimited Stream
  // licenses visible in a tenant are for the Stream trial").
  "STREAM",
  // Friendly-name equivalents (see the mock-tenant note above).
  "Power BI (Free)",
  "Power Automate (Free)",
  "Microsoft Teams Exploratory",
]);

// Fallback for a SKU this table doesn't recognize - deliberately modest,
// not a tenant's premium-tier cost, since an unrecognized SKU with a huge
// quantity is far more likely to be one of Microsoft's own auto-granted,
// no-cost per-org service plans than an actual bulk purchase. The License
// & Cost Optimizer's manual per-SKU disable toggle is the intended escape
// hatch for the cases this table genuinely can't know about.
export const DEFAULT_LICENSE_SKU_COST_USD = 12;

// Microsoft's own naming convention consistently marks trial/preview/viral/
// dev-tier SKUs this way (e.g. AX7_USER_TRIAL, CCIBOTS_PRIVPREV_VIRAL,
// POWERAPPS_DEV) - new SKUs like these appear constantly and can't all be
// hand-enumerated above, so a name match is used as a disclosed heuristic,
// never silently treated as equivalent to the confirmed list above (see
// getLicenseSkuCostInfo's costBasis: "likely-free-by-name" vs
// "confirmed-free" - the UI shows these differently on purpose).
const LIKELY_FREE_SKU_NAME_PATTERN = /trial|viral|privpreview|privprev|exploratory|(^|_)dev(_|$)/i;

export type LicenseSkuCostBasis = "confirmed-free" | "known-cost" | "likely-free-by-name" | "unknown-default";

export interface LicenseSkuCostInfo {
  monthlyCostUsd: number;
  costBasis: LicenseSkuCostBasis;
}

export function getLicenseSkuCostInfo(skuPartNumber: string): LicenseSkuCostInfo {
  if (FREE_LICENSE_SKUS.has(skuPartNumber)) {
    return { monthlyCostUsd: 0, costBasis: "confirmed-free" };
  }
  if (skuPartNumber in LICENSE_SKU_MONTHLY_COST_USD) {
    return { monthlyCostUsd: LICENSE_SKU_MONTHLY_COST_USD[skuPartNumber], costBasis: "known-cost" };
  }
  if (LIKELY_FREE_SKU_NAME_PATTERN.test(skuPartNumber)) {
    return { monthlyCostUsd: 0, costBasis: "likely-free-by-name" };
  }
  return { monthlyCostUsd: DEFAULT_LICENSE_SKU_COST_USD, costBasis: "unknown-default" };
}

export function getLicenseSkuMonthlyCost(skuPartNumber: string): number {
  return getLicenseSkuCostInfo(skuPartNumber).monthlyCostUsd;
}
