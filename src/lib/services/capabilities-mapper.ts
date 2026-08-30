import { TenantCapability } from "../types";

export function mapSubscribedSkusToCapabilities(skus: any[]): TenantCapability[] {
  const activeSkus = Array.isArray(skus)
    ? skus
        .filter((s: any) => s.capabilityStatus === "Enabled" || s.consumedUnits > 0)
        .map((s: any) => (s.skuPartNumber || "").toUpperCase())
    : [];

  const hasSku = (substrings: string[]) =>
    activeSkus.some((sku) => substrings.some((sub) => sku.includes(sub)));

  const hasEntraP2 = hasSku(["AAD_PREMIUM_P2", "SPE_E5", "EMSPREMIUM", "ENTERPRISEPREMIUM"]);
  const hasEntraP1 = hasEntraP2 || hasSku(["AAD_PREMIUM", "SPE_E3", "EMS", "M365_BUSINESS_PREMIUM", "SPB"]);
  const hasIntune = hasSku(["INTUNE", "SPE_E3", "SPE_E5", "M365_BUSINESS_PREMIUM", "EMS", "EMSPREMIUM"]);
  const hasMde = hasSku(["DEFENDER_ENDPOINT", "WINDOWS_DEFENDER_ATP", "SPE_E5", "MDE"]);
  const hasMdo = hasSku(["O365_ADVANCED_THREAT_PROTECTION", "ATP_ENTERPRISE", "SPE_E5", "M365_BUSINESS_PREMIUM", "THREAT_INTELLIGENCE"]);
  const hasPurview = hasSku(["ADVANCED_AUDITING", "COMPLIANCE", "INFORMATION_PROTECTION", "SPE_E5"]);

  return [
    {
      id: "cap-entra",
      name: "Microsoft Entra ID P1/P2",
      category: "Identity",
      licensed: hasEntraP1,
      tier: hasEntraP2 ? "Plan 2 (P2)" : hasEntraP1 ? "Plan 1 (P1)" : "Free / Standard",
      description: "Identity and Access Management with Conditional Access and Identity Protection.",
    },
    {
      id: "cap-intune",
      name: "Microsoft Intune",
      category: "Endpoint",
      licensed: hasIntune,
      tier: hasIntune ? "Active" : "Unlicensed",
      description: "Cloud-based Unified Endpoint Management (UEM) and Device Compliance.",
    },
    {
      id: "cap-mde",
      name: "Defender for Endpoint",
      category: "Endpoint",
      licensed: hasMde,
      tier: hasMde ? "Active (P2)" : "Unlicensed",
      description: "Enterprise endpoint detection, response (EDR), and threat vulnerability management.",
    },
    {
      id: "cap-mdo",
      name: "Defender for Office 365",
      category: "Threat",
      licensed: hasMdo,
      tier: hasMdo ? "Active (Plan 1/2)" : "Unlicensed",
      description: "Email & Collaboration Threat Protection, Safe Links, Safe Attachments, and TABL.",
    },
    {
      id: "cap-purview",
      name: "Microsoft Purview Compliance",
      category: "Compliance",
      licensed: hasPurview,
      tier: hasPurview ? "Active" : "Standard",
      description: "Unified data governance, insider risk management, and audit logging retention.",
    },
  ];
}
