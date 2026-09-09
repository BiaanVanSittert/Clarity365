// Microsoft Graph's subscribedSkus.skuPartNumber is a short, often cryptic
// product code (e.g. "SPE_E5"), not a display name. This maps the common
// M365/Office 365 SKUs to their marketing name; anything unmapped (a live
// tenant can hold hundreds of possible SKUs) falls back to the raw code.
const LICENSE_SKU_DISPLAY_NAMES: Record<string, string> = {
  SPE_E5: "Microsoft 365 E5",
  SPE_E3: "Microsoft 365 E3",
  SPE_F1: "Microsoft 365 F3",
  SPB: "Microsoft 365 Business Premium",
  O365_BUSINESS_PREMIUM: "Microsoft 365 Business Standard",
  O365_BUSINESS_ESSENTIALS: "Microsoft 365 Business Basic",
  ENTERPRISEPACK: "Office 365 E3",
  ENTERPRISEPREMIUM: "Office 365 E5",
  EXCHANGESTANDARD: "Exchange Online (Plan 1)",
  EXCHANGEENTERPRISE: "Exchange Online (Plan 2)",
  EXCHANGEONLINE: "Exchange Online (Plan 1)",
  POWER_BI_PRO: "Power BI Pro",
  POWER_BI_STANDARD: "Power BI (Free)",
  VISIOCLIENT: "Visio Plan 2",
  PROJECTPROFESSIONAL: "Project Plan 3",
  PROJECTPREMIUM: "Project Plan 5",
  EMSPREMIUM: "Enterprise Mobility + Security E5",
  EMS: "Enterprise Mobility + Security E3",
  AAD_PREMIUM_P2: "Microsoft Entra ID P2",
  AAD_PREMIUM: "Microsoft Entra ID P1",
  FLOW_FREE: "Power Automate (Free)",
  TEAMS_EXPLORATORY: "Microsoft Teams Exploratory",
  DEFENDER_FOR_BUSINESS: "Microsoft Defender for Business",
};

export function getLicenseSkuDisplayName(skuPartNumber: string): string {
  return LICENSE_SKU_DISPLAY_NAMES[skuPartNumber] || skuPartNumber;
}
