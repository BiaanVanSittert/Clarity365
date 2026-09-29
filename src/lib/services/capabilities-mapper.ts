import { TenantCapability } from "../types";

// "BUSINESS_PREMIUM" alone is a trap: Microsoft's own legacy SKU name for what
// is now Microsoft 365 Business STANDARD is literally "O365_BUSINESS_PREMIUM"
// (a branding leftover from before the Business Standard/Premium split) - it
// does NOT include Intune/MDE, so it's excluded explicitly. The real Business
// Premium SKUs are bare "SPB" and the newer bundled
// "BUSINESS_PREMIUM_AND_MICROSOFT_365_COPILOT_FOR_BUSINESS" (confirmed live
// against Coetzee Architects' tenant, which has 8 consumed seats of that exact
// skuPartNumber and 0 on the legacy one) - both genuinely include Intune,
// Defender for Business, and MDO P1. Exported so both the tenant-wide
// capability check below and any per-user SKU check (e.g.
// intune-coverage-analyzer.ts) apply the identical rule instead of each
// re-deriving their own copy that can silently drift apart.
export function isBusinessPremiumSku(skuPartNumbers: string[]): boolean {
  const upper = skuPartNumbers.map((s) => (s || "").toUpperCase());
  return upper.some((sku) => sku === "SPB" || (sku.includes("BUSINESS_PREMIUM") && sku !== "O365_BUSINESS_PREMIUM"));
}

// Whether a set of assigned skuPartNumber strings includes at least one
// Intune-capable license - the same rule `mapSubscribedSkusToCapabilities`
// uses tenant-wide (`cap-intune`), extracted so a per-user check (does *this*
// specific user's own license support Intune, not just the tenant overall)
// applies the identical, already-live-verified SKU list rather than a second
// copy that could drift from this one.
export function isIntuneCapableSkuPartNumber(skuPartNumbers: string[]): boolean {
  const upper = skuPartNumbers.map((s) => (s || "").toUpperCase());
  const hasSku = (substrings: string[]) => upper.some((sku) => substrings.some((sub) => sku.includes(sub)));
  return isBusinessPremiumSku(skuPartNumbers) || hasSku(["INTUNE", "SPE_E3", "SPE_E5", "EMS", "EMSPREMIUM", "M365EDU_A3", "M365EDU_A5"]);
}

export function mapSubscribedSkusToCapabilities(skus: any[]): TenantCapability[] {
  const activeSkus = Array.isArray(skus)
    ? skus
        .filter((s: any) => s.capabilityStatus === "Enabled" || s.consumedUnits > 0)
        .map((s: any) => (s.skuPartNumber || "").toUpperCase())
    : [];

  const hasSku = (substrings: string[]) =>
    activeSkus.some((sku) => substrings.some((sub) => sku.includes(sub)));

  // "ENTERPRISEPREMIUM" alone (or with a _NOPSTNCONF suffix) is the commercial
  // Office 365 E5 SKU, which genuinely bundles Entra ID P2 - but the same
  // substring also appears in "ENTERPRISEPREMIUM_FACULTY"/"_STUDENT" (Office
  // 365 A5 for Faculty/Students), which per Microsoft's own EDU licensing
  // comparison does NOT include Entra P2 (only the separate "Microsoft 365
  // A5" EDU tier does, handled by the M365EDU_A5 check below) - excluded
  // explicitly so an EDU tenant on Office 365 A5 doesn't get a false positive.
  const hasCommercialEnterprisePremium = activeSkus.some(
    (sku) => sku.includes("ENTERPRISEPREMIUM") && !sku.endsWith("_FACULTY") && !sku.endsWith("_STUDENT") && !sku.endsWith("_STUUSEBNFT")
  );
  // M365EDU_A5_* (Microsoft 365 A5 for Faculty/Students, and their
  // _STUUSEBNFT/_NOPSTNCONF_ variants - all share this one substring,
  // verified against Microsoft's own Education SKU reference) genuinely
  // bundles Entra ID P2, Defender for Endpoint P2, and Defender for Office
  // 365 P2 - confirmed via Microsoft's A5 feature comparison table. M365EDU_A3
  // only goes as far as Entra ID P1 - it does not include P2, MDE, or MDO P2.
  const hasBusinessPremium = isBusinessPremiumSku(activeSkus);
  const hasEntraP2 = hasSku(["AAD_PREMIUM_P2", "SPE_E5", "EMSPREMIUM", "M365EDU_A5"]) || hasCommercialEnterprisePremium;
  const hasEntraP1 = hasEntraP2 || hasBusinessPremium || hasSku(["AAD_PREMIUM", "SPE_E3", "EMS", "M365EDU_A3"]);
  const hasIntune = isIntuneCapableSkuPartNumber(activeSkus);
  // Defender for Business - the SMB-scoped equivalent of Defender for
  // Endpoint - so a Business Premium tenant genuinely has this capability even
  // though its SKU name never contains "DEFENDER_ENDPOINT" or "MDE".
  const hasMde = hasBusinessPremium || hasSku(["DEFENDER_ENDPOINT", "WINDOWS_DEFENDER_ATP", "SPE_E5", "MDE", "M365EDU_A5"]);
  // Business Premium also bundles Defender for Office 365 Plan 1.
  const hasMdo = hasBusinessPremium || hasSku(["O365_ADVANCED_THREAT_PROTECTION", "ATP_ENTERPRISE", "SPE_E5", "THREAT_INTELLIGENCE", "M365EDU_A5"]);
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
