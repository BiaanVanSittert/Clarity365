// Regulation- and data-type-driven DLP/sensitivity-label recommendation catalog.
// See ai-context-vault/Optimization/DLP & Sensitivity Labels Plan.md for the
// full multi-stage plan this belongs to.
//
// Deliberately independent of any live tenant connection (per the 2026-09-22
// decision: guided instructions only, no automated write path, no dependency
// on Purview sync). Each entry is a standalone recommendation pack an admin
// applies by hand in the Purview compliance portal, or via the optional
// PowerShell script - never deployed by this app directly.
//
// Convention mirrors baseline-definitions.ts's CA_BASELINE_STANDARDS (a typed
// array of definitions, one PowerShell template per entry) so this reads like
// the rest of src/lib/data/ rather than inventing a new shape.
//
// IMPORTANT - unverified content, flagged per entry:
// - Sensitive Information Type names are Microsoft's own built-in SIT display
//   names (stable, documented), referenced by name here since the admin picks
//   them from the Purview portal's own search UI - not matched by GUID. GUID
//   matching only matters once a live automated read/match exists (deferred,
//   see the plan). Names below are believed correct but not independently
//   re-verified against a live tenant's SIT list in this session.
// - PowerShell templates use documented Security & Compliance PowerShell
///  cmdlet names and parameters. Stage 0's live connectivity check was
//   inconclusive (see the plan), so these templates are NOT verified against
//   a real deploy the way CA_BASELINE_STANDARDS' templates are. Each carries
//   its own caveat comment; treat as a strong starting point, not a confirmed
//   working script.
// - Regulation citations are a technical-to-legal mapping for engineering
//   purposes, not legal advice. Whoever owns compliance for a given client
//   should confirm citations before they go in front of that client.

export type Regulation = "popia" | "gdpr_uk_gdpr" | "hipaa";

export const REGULATION_LABELS: Record<Regulation, string> = {
  popia: "POPIA (South Africa)",
  gdpr_uk_gdpr: "GDPR / UK GDPR",
  hipaa: "HIPAA (US)",
};

export type DataCategory =
  | "government_id"
  | "health"
  | "financial_banking"
  | "payment_card"
  | "credentials_secrets"
  | "bulk_pii"
  | "ip_contracts"
  // Not a content-type category like the others above - a transfer-mechanism
  // one (where is this going, not what is it). Added 2026-09-22 for the
  // POPIA cross-border-transfer entry; see that entry's own summary.
  | "cross_border_transfer";

export const DATA_CATEGORY_LABELS: Record<DataCategory, string> = {
  government_id: "Government-issued IDs",
  health: "Health records",
  financial_banking: "Banking & financial data",
  payment_card: "Payment card data",
  credentials_secrets: "Credentials & secrets",
  bulk_pii: "Bulk customer/HR records",
  ip_contracts: "IP, contracts & source code",
  cross_border_transfer: "Cross-border transfer",
};

export type LicenseTier = "business_premium_e3" | "e5";

export interface RegulationReference {
  citation: string; // e.g. "POPIA s.19" - technical mapping, confirm with compliance owner before client-facing use
  note: string;
}

export interface GuidedPortalStep {
  step: number;
  instruction: string;
}

export interface SensitiveInfoTypeRef {
  /** Microsoft's own built-in SIT display name, as shown in the Purview portal's condition picker. */
  displayName: string;
  /** Minimum recommended confidence level/instance count for this SIT in the rule, where applicable. */
  matchGuidance: string;
}

export interface DlpRecommendation {
  id: string;
  title: string;
  regulations: Regulation[];
  dataCategories: DataCategory[];
  /** Lowest tier this recommendation works on. E5-only capabilities are called out separately in e5Enhancements. */
  minimumLicenseTier: LicenseTier;
  summary: string;
  sensitiveInfoTypes: SensitiveInfoTypeRef[];
  recommendedLocations: string[];
  /** Starting mode - always a test mode, matching the CA report-only convention. Never recommend enforce as the first state. */
  recommendedStartingMode: "Test with notifications" | "Test without notifications";
  ruleLogicSummary: string;
  actions: string[];
  portalSteps: GuidedPortalStep[];
  /**
   * Best-effort Security & Compliance PowerShell script. NOT verified against a
   * live deploy (Stage 0's connectivity check was inconclusive) - the admin
   * should review every parameter before running it, same spirit as CA's
   * "review sign-in logs before enabling" note but with less confidence behind it.
   */
  powershellTemplate: (policyNamePrefix: string) => string;
  e5Enhancements?: string[];
  regulationRefs: RegulationReference[];
  /** Anything that should give an admin pause before applying this as-is. */
  caveats: string[];
  /**
   * ids of other entries in this catalog that overlap in topic or Sensitive
   * Information Type but answer a genuinely different question - e.g.
   * popia-sa-id-and-health (who this is shared with) and
   * popia-cross-border-transfer (where it ends up). Surfaced as clickable
   * links in the UI so the relationship reads as intentional, not
   * accidental/duplicate content - added 2026-09-22 after a user review
   * question about exactly that risk. Keep this reciprocal (if A lists B, B
   * should list A) when adding new entries.
   */
  relatedRecommendationIds?: string[];
}

// ---------------------------------------------------------------------------
// Sensitivity label recommendations - added 2026-09-22, the label half of
// "Data Protection (DLP & Sensitivity Labels)" that hadn't been built despite
// the module's own name. A label recommendation is structurally different
// from a DlpRecommendation (a taxonomy + a label policy + optionally an
// auto-labeling policy, not a single SIT-based rule) - see the Sensitivity
// Labels Catalog Plan in the vault for why this is a separate type rather
// than force-fit into DlpRecommendation's fields. Deliberately kept in the
// SAME catalog array as the DLP entries, discriminated by `kind: "label"` -
// per explicit user direction ("make it a category under the DLP"), not a
// separate module or a separate list.
// ---------------------------------------------------------------------------

export interface SensitivityLabelDef {
  name: string;
  /** Lower number = lower sensitivity. Matters for RequireDowngradeJustification - see the PowerShell caveat on each entry. */
  priority: number;
  encrypted: boolean;
  contentMarking: boolean;
  /** What the end user sees when picking this label - New-Label's -ToolTip. */
  tooltip: string;
}

export interface LabelRecommendation {
  id: string;
  kind: "label";
  title: string;
  regulations: Regulation[];
  dataCategories: DataCategory[];
  minimumLicenseTier: LicenseTier;
  summary: string;
  /**
   * Concrete guidance on which clients/scenarios this entry actually fits -
   * added 2026-09-22 after direct user feedback that the four label entries
   * looked like interchangeable alternatives rather than a foundation plus
   * three optional layers on top of it. Not present on DlpRecommendation,
   * since each DLP entry is already self-contained and doesn't need this.
   */
  recommendedFor: string;
  /**
   * ids of OTHER LABEL entries that must be deployed before this one makes
   * sense - a genuinely different relationship from
   * relatedRecommendationIds ("different question, worth knowing about,
   * doesn't imply an order") which this catalog already used for the two
   * POPIA entries. Rendered as its own "Deploy first" section, distinct from
   * "Related recommendations," so the two kinds of link never blur together
   * again the way they did before this field existed.
   */
  buildsOn?: string[];
  labels: SensitivityLabelDef[];
  labelPolicySettings: {
    defaultLabelName?: string;
    mandatoryLabeling: boolean;
    requireDowngradeJustification: boolean;
    locations: string[];
  };
  /** Only present on the auto-labeling entry - E5-only, see that entry's own caveats for why no Business Premium/E3 fallback is offered. */
  autoLabeling?: {
    targetLabelName: string;
    sitReferences: string[];
    mode: "Test with notifications" | "Test without notifications";
  };
  portalSteps: GuidedPortalStep[];
  powershellTemplate: (policyNamePrefix: string) => string;
  e5Enhancements?: string[];
  regulationRefs: RegulationReference[];
  caveats: string[];
  relatedRecommendationIds?: string[];
}

export type DataProtectionCatalogEntry = DlpRecommendation | LabelRecommendation;

// ---------------------------------------------------------------------------
// One fully worked example (POPIA x Government ID / Health) - reviewed before
// the rest of the catalog (GDPR, HIPAA, and the remaining data categories) is
// built out in the same shape.
// ---------------------------------------------------------------------------

export const DATA_PROTECTION_RECOMMENDATIONS: DataProtectionCatalogEntry[] = [
  {
    id: "popia-sa-id-and-health",
    title: "Protect South African ID numbers and health records (POPIA)",
    regulations: ["popia"],
    dataCategories: ["government_id", "health"],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "POPIA classifies both a South African ID number and health information as special categories of personal information requiring extra safeguards (s.26, s.32). This pack blocks unencrypted external sharing of documents/emails containing an SA ID number, optionally combined with health terminology, across Exchange, SharePoint and OneDrive - the three locations DLP for Exchange/SharePoint/OneDrive licenses cover on Business Premium and E3.",
    sensitiveInfoTypes: [
      {
        displayName: "South Africa Identification Number",
        matchGuidance: "High confidence, 1+ instance - this SIT already validates the check-digit, so false positives are low even at 1 instance.",
      },
      {
        displayName: "International Classification of Diseases (ICD-9-CM)",
        matchGuidance: "Used only in the combined health-context variant below, not the baseline ID-number rule.",
      },
      {
        displayName: "International Classification of Diseases (ICD-10-CM)",
        matchGuidance: "Same as ICD-9-CM above - Microsoft ships both; include both so older and newer coded records are caught.",
      },
    ],
    recommendedLocations: ["Exchange email", "SharePoint sites", "OneDrive accounts"],
    recommendedStartingMode: "Test with notifications",
    ruleLogicSummary:
      "Rule 1 (baseline): South Africa Identification Number found, sent or shared with a recipient outside the organization -> notify sender, generate incident report, do not block yet (test mode). Rule 2 (elevated): South Africa Identification Number AND (ICD-9-CM OR ICD-10-CM) found together, shared externally -> same test-mode actions, flagged high priority - this combination is the actual POPIA special-category health-data case, not just an ID number alone.",
    actions: [
      "Notify the user with a policy tip explaining why the content was flagged",
      "Generate an incident report to the compliance/security team",
      "Do not block in the initial test period - move to block after reviewing 2-4 weeks of test-mode matches for false positives",
      "Once promoted to enforce: block external sharing, allow override with business justification (required field) so legitimate cases - e.g. authorized third-party payroll processors - aren't hard-blocked",
    ],
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Data loss prevention -> Policies -> Create policy." },
      { step: 2, instruction: "Choose \"Custom\" (not one of the built-in regional templates, which don't cover South Africa) -> \"Custom policy\"." },
      { step: 3, instruction: "Name it e.g. \"POPIA - SA ID & Health Data\". Add a description referencing POPIA s.26/s.32 for audit trail purposes." },
      { step: 4, instruction: "Choose locations: turn on Exchange email, SharePoint sites, OneDrive accounts. Leave Teams/Endpoint off (not covered on Business Premium/E3 - see caveats)." },
      { step: 5, instruction: "Create Rule 1: add condition \"Content contains\" -> Sensitive info types -> search \"South Africa Identification Number\" -> add, instance count 1 to any, confidence level High." },
      { step: 6, instruction: "Under that same rule, add condition group \"the recipient is\" -> \"outside my organization\"." },
      { step: 7, instruction: "Actions: enable \"Restrict access or encrypt the content in Microsoft 365 locations\" but leave it unticked for now (test mode); enable \"Generate an incident report\" and \"Notify users\" with a custom policy tip." },
      { step: 8, instruction: "Set this rule's mode toggle (bottom of rule editor) to \"Test it out first\" -> \"Turn it on right away, but keep it in test mode\"." },
      { step: 9, instruction: "Create Rule 2 (optional, elevated case): duplicate rule 1, add a second sensitive-info-type condition group for ICD-9-CM OR ICD-10-CM with the group operator set to \"AND\" against the SA ID number group. Mark this rule higher priority (lower number) than Rule 1." },
      { step: 10, instruction: "Save, review, and turn the policy on. It starts collecting matches in test mode - nothing is blocked yet." },
      { step: 11, instruction: "After 2-4 weeks, review Activity Explorer (Data loss prevention -> Activity explorer, filter to this policy) for false positives before promoting either rule out of test mode." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - Stage 0's live connectivity check for the Security & Compliance
# PowerShell REST endpoint was inconclusive (see the plan). Review every
# parameter below against the Purview portal before running this - do not
# trust it the way CA_BASELINE_STANDARDS' templates (which are live-verified)
# can be trusted. Requires Compliance Administrator or equivalent, and
# Connect-IPPSSession (Exchange Online Management module).

Connect-IPPSSession

# 1. Create the policy shell (locations only, no rules yet)
New-DlpCompliancePolicy -Name "${prefix} - POPIA SA ID & Health Data" \`
    -ExchangeLocation All \`
    -SharePointLocation All \`
    -OneDriveLocation All \`
    -Mode TestWithNotifications \`
    -Comment "POPIA s.26/s.32 - SA ID number and health-data protection, generated by Clarity365 (unverified template, review before enabling)"

# 2. Baseline rule: SA ID number shared externally
New-DlpComplianceRule -Name "${prefix} - SA ID external share" \`
    -Policy "${prefix} - POPIA SA ID & Health Data" \`
    -ContentContainsSensitiveInformation @{Name="South Africa Identification Number"; minCount="1"} \`
    -AccessScope NotInOrganization \`
    -GenerateIncidentReport SiteAdmin \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly

# 3. Elevated rule: SA ID number combined with ICD-coded health data
New-DlpComplianceRule -Name "${prefix} - SA ID + health data external share" \`
    -Policy "${prefix} - POPIA SA ID & Health Data" \`
    -ContentContainsSensitiveInformation @(
        @{Name="South Africa Identification Number"; minCount="1"},
        @{Name="International Classification of Diseases (ICD-9-CM)"; minCount="1"}
    ) \`
    -AccessScope NotInOrganization \`
    -GenerateIncidentReport SiteAdmin \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly \`
    -Priority 0

Write-Host "Created in test mode - review Activity Explorer for 2-4 weeks before promoting to enforce (Set-DlpCompliancePolicy -Mode Enable)." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Add Teams chat/channel messages as a location (requires E5 or the Teams DLP add-on - not available on Business Premium/E3).",
      "Add Endpoint DLP to also catch the same SA-ID-plus-health-data pattern being copied to USB or printed (requires E5 or the Endpoint DLP add-on).",
      "Auto-apply a \"Highly Confidential - POPIA\" sensitivity label wherever this content is detected, instead of relying on the DLP rule alone (auto-labeling requires E5).",
    ],
    regulationRefs: [
      { citation: "POPIA s.19", note: "Security safeguards - appropriate technical measures against loss, unlawful access." },
      { citation: "POPIA s.26", note: "Special personal information includes health data." },
      { citation: "POPIA s.22", note: "Notification of a compromise - having an incident-report trail supports this obligation." },
    ],
    caveats: [
      "PowerShell template is unverified against a live tenant - see the note in the script itself.",
      "\"South Africa Identification Number\" is Microsoft's own built-in SIT name as documented; not independently re-confirmed against a live tenant's SIT list in this session.",
      "Teams and Endpoint locations are deliberately left off this recommendation on Business Premium/E3 - they are not licensed there, not just unconfigured. Adding them without E5/the add-on will fail in the portal.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice - have whoever owns POPIA compliance for the client confirm the citations and the block-vs-warn decision before promoting out of test mode.",
    ],
    relatedRecommendationIds: ["popia-cross-border-transfer", "label-auto-labeling-sensitive-categories"],
  },
  {
    id: "hipaa-phi",
    title: "Protect Protected Health Information / PHI (HIPAA)",
    regulations: ["hipaa"],
    dataCategories: ["health"],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "HIPAA's Security Rule requires technical safeguards for electronic PHI, including encryption of data in transit where reasonable and appropriate (45 CFR 164.312(e)). Unlike the POPIA/GDPR packs, this one deliberately favors encrypt-on-send over block-on-send as the default enforce action - blocking a referral or care-coordination email can cause real patient-care harm, where HIPAA's own requirement is to safeguard the transmission, not stop it. A stricter block variant is offered separately for organizations that want it.",
    sensitiveInfoTypes: [
      {
        displayName: "U.S. Social Security Number (SSN)",
        matchGuidance: "High confidence, 1+ instance.",
      },
      {
        displayName: "International Classification of Diseases (ICD-9-CM)",
        matchGuidance: "Combined with SSN below to identify the actual PHI case, not a bare SSN (which alone isn't health data).",
      },
      {
        displayName: "International Classification of Diseases (ICD-10-CM)",
        matchGuidance: "Same as ICD-9-CM - include both so older and newer coded records are caught.",
      },
    ],
    recommendedLocations: ["Exchange email", "SharePoint sites", "OneDrive accounts"],
    recommendedStartingMode: "Test with notifications",
    ruleLogicSummary:
      "Rule 1: SSN AND (ICD-9-CM OR ICD-10-CM) found together, shared externally -> notify sender, generate incident report to the privacy officer, test mode only. This combination requirement (not SSN alone) is what actually indicates PHI rather than an unrelated SSN reference.",
    actions: [
      "Notify the user with a policy tip explaining why the content was flagged",
      "Generate an incident report to the privacy/compliance officer",
      "Do not block or encrypt in the initial test period - review 2-4 weeks of matches first",
      "Once promoted: apply Office 365 Message Encryption automatically on external matches rather than blocking, so clinical/administrative communication still reaches its recipient, just protected",
      "Optional stricter variant: maintain an allow-list of established Business Associate domains that bypass the encryption requirement (already covered by a signed BAA), and block (not just encrypt) any external match to a domain not on that list",
    ],
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Data loss prevention -> Policies -> Create policy." },
      { step: 2, instruction: "Choose \"Custom\" -> \"Custom policy\". Name it e.g. \"HIPAA - PHI Protection\", description referencing 45 CFR 164.312 for the audit trail." },
      { step: 3, instruction: "Choose locations: Exchange email, SharePoint sites, OneDrive accounts." },
      { step: 4, instruction: "Create the rule: condition group \"Content contains\" -> Sensitive info types -> add \"U.S. Social Security Number (SSN)\", group operator AND, add \"International Classification of Diseases (ICD-9-CM)\" OR \"International Classification of Diseases (ICD-10-CM)\", instance count 1+, confidence High." },
      { step: 5, instruction: "Add condition group \"the recipient is\" -> \"outside my organization\"." },
      { step: 6, instruction: "Actions (test period): enable \"Generate an incident report\" and \"Notify users\" with a custom policy tip referencing HIPAA. Leave encryption/blocking off for now." },
      { step: 7, instruction: "Set the rule to \"Test it out first\" -> \"Turn it on right away, but keep it in test mode\"." },
      { step: 8, instruction: "After 2-4 weeks reviewing Activity Explorer: edit the rule, add action \"Restrict access or encrypt the content in Microsoft 365 locations\" -> \"Apply Office 365 Message Encryption and rights protection\", and move the rule out of test mode." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - same caveat as every template in this catalog: Stage 0's live
# connectivity check was inconclusive. The encryption action parameters below
# in particular need live confirmation - review against the Purview portal's
# own rule editor before running this.

Connect-IPPSSession

New-DlpCompliancePolicy -Name "${prefix} - HIPAA PHI Protection" \`
    -ExchangeLocation All \`
    -SharePointLocation All \`
    -OneDriveLocation All \`
    -Mode TestWithNotifications \`
    -Comment "HIPAA 45 CFR 164.312 - PHI protection, generated by Clarity365 (unverified template, review before enabling)"

New-DlpComplianceRule -Name "${prefix} - PHI external share" \`
    -Policy "${prefix} - HIPAA PHI Protection" \`
    -ContentContainsSensitiveInformation @(
        @{Name="U.S. Social Security Number (SSN)"; minCount="1"},
        @{Name="International Classification of Diseases (ICD-9-CM)"; minCount="1"}
    ) \`
    -AccessScope NotInOrganization \`
    -GenerateIncidentReport SiteAdmin \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly

Write-Host "Created in test mode. After 2-4 weeks, promote with:" -ForegroundColor Yellow
Write-Host '  Set-DlpComplianceRule -Identity "${prefix} - PHI external share" -ApplyOffice365MessageEncryption $true -Mode Enable' -ForegroundColor Yellow`,
    e5Enhancements: [
      "Add Teams chat/channel messages as a location (requires E5 or the Teams DLP add-on).",
      "Add Endpoint DLP to also catch PHI being copied to USB or printed (requires E5 or the Endpoint DLP add-on).",
      "Auto-apply a \"Highly Confidential - PHI\" sensitivity label wherever this content is detected (auto-labeling requires E5).",
    ],
    regulationRefs: [
      { citation: "HIPAA 45 CFR 164.312(a)(2)(iv)", note: "Encryption and decryption - a technical safeguard, not an absolute requirement, but 'addressable' meaning it must be implemented or an equivalent alternative documented." },
      { citation: "HIPAA 45 CFR 164.312(e)(1) & (e)(2)(ii)", note: "Transmission security - guard against unauthorized access to ePHI in transit." },
      { citation: "HIPAA 45 CFR 164.502", note: "Minimum necessary standard - not itself DLP-enforceable, but worth pairing this policy with an access-review process." },
    ],
    caveats: [
      "PowerShell template is unverified, and the encryption-action cmdlet parameter shown (-ApplyOffice365MessageEncryption) is a best-effort guess at the real Set-DlpComplianceRule parameter name - confirm the exact parameter in the Purview portal's rule editor before relying on the script.",
      "This pack deliberately encrypts rather than blocks by default - confirm that design choice with the client's privacy officer before deploying; a client that wants a harder stance can use the block variant described in Actions.",
      "Clarity365 itself is not a HIPAA covered entity or business associate and does not sign BAAs - this pack only helps configure a technical control inside the client's own tenant.",
      "\"U.S. Social Security Number (SSN)\" and the ICD SIT names are Microsoft's own documented built-in names; not independently re-confirmed against a live tenant's SIT list in this session.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice - have whoever owns HIPAA compliance for the client confirm the citations before promoting out of test mode.",
    ],
    relatedRecommendationIds: ["label-auto-labeling-sensitive-categories"],
  },
  {
    id: "gdpr-uk-government-id-and-special-category",
    title: "Protect UK/EU national identifiers and special category data (GDPR/UK GDPR)",
    regulations: ["gdpr_uk_gdpr"],
    dataCategories: ["government_id", "health"],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "GDPR/UK GDPR treats health data as 'special category' data needing extra safeguards under Article 9, and requires appropriate technical measures for any personal data under Article 32. This pack starts with UK-specific identifiers (most directly relevant under UK GDPR) plus the generic EU passport type, combined with the same ICD-coded health-context logic used in the POPIA and HIPAA packs above.",
    sensitiveInfoTypes: [
      {
        displayName: "UK National Insurance Number (NINO)",
        matchGuidance: "High confidence, 1+ instance.",
      },
      {
        displayName: "UK Passport Number",
        matchGuidance: "High confidence, 1+ instance.",
      },
      {
        displayName: "EU Passport Number",
        matchGuidance: "Generic EU-wide pattern - broader net for non-UK EU passports; lower confidence than the UK-specific types above.",
      },
      {
        displayName: "International Classification of Diseases (ICD-9-CM)",
        matchGuidance: "Used only in the elevated special-category rule, combined with an identifier above.",
      },
      {
        displayName: "International Classification of Diseases (ICD-10-CM)",
        matchGuidance: "Same as ICD-9-CM.",
      },
    ],
    recommendedLocations: ["Exchange email", "SharePoint sites", "OneDrive accounts"],
    recommendedStartingMode: "Test with notifications",
    ruleLogicSummary:
      "Rule 1 (baseline): UK NINO, UK Passport Number, or EU Passport Number found, shared externally -> notify, incident report, test mode. Rule 2 (elevated): any identifier above found together with ICD-9-CM or ICD-10-CM, shared externally -> same test-mode actions, flagged high priority as the Article 9 special-category case.",
    actions: [
      "Notify the user with a policy tip explaining why the content was flagged",
      "Generate an incident report to the compliance/DPO team",
      "Do not block in the initial test period - review 2-4 weeks of matches for false positives",
      "Once promoted: block external sharing, allow override with justification. The incident-report trail this policy generates also supports GDPR's 72-hour breach notification clock (Art. 33) by surfacing a possible exposure as soon as it happens, not after the fact",
    ],
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Data loss prevention -> Policies -> Create policy." },
      { step: 2, instruction: "Choose \"Custom\" -> \"Custom policy\". Name it e.g. \"GDPR/UK GDPR - National ID & Special Category\", description referencing Art. 9/32 for the audit trail." },
      { step: 3, instruction: "Choose locations: Exchange email, SharePoint sites, OneDrive accounts." },
      { step: 4, instruction: "Create Rule 1: condition \"Content contains\" -> Sensitive info types -> add UK National Insurance Number (NINO), UK Passport Number, EU Passport Number (group operator OR), instance count 1+." },
      { step: 5, instruction: "Add condition group \"the recipient is\" -> \"outside my organization\"." },
      { step: 6, instruction: "Actions: enable \"Generate an incident report\" and \"Notify users\"; leave \"Restrict access or encrypt\" unticked for now (test mode)." },
      { step: 7, instruction: "Set the rule to \"Test it out first\" -> \"Turn it on right away, but keep it in test mode\"." },
      { step: 8, instruction: "Create Rule 2 (elevated): duplicate Rule 1, add a second condition group for ICD-9-CM OR ICD-10-CM with group operator AND against the identifier group. Set higher priority (lower number) than Rule 1." },
      { step: 9, instruction: "After 2-4 weeks reviewing Activity Explorer, promote both rules out of test mode with block + override-with-justification." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - see the catalog-wide caveat. Review every parameter against
# the Purview portal before running this.

Connect-IPPSSession

New-DlpCompliancePolicy -Name "${prefix} - GDPR National ID & Special Category" \`
    -ExchangeLocation All \`
    -SharePointLocation All \`
    -OneDriveLocation All \`
    -Mode TestWithNotifications \`
    -Comment "GDPR/UK GDPR Art. 9/32 - national ID and special category data, generated by Clarity365 (unverified template, review before enabling)"

New-DlpComplianceRule -Name "${prefix} - National ID external share" \`
    -Policy "${prefix} - GDPR National ID & Special Category" \`
    -ContentContainsSensitiveInformation @(
        @{Name="UK National Insurance Number (NINO)"; minCount="1"},
        @{Name="UK Passport Number"; minCount="1"},
        @{Name="EU Passport Number"; minCount="1"}
    ) \`
    -AccessScope NotInOrganization \`
    -GenerateIncidentReport SiteAdmin \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly

New-DlpComplianceRule -Name "${prefix} - National ID + special category external share" \`
    -Policy "${prefix} - GDPR National ID & Special Category" \`
    -ContentContainsSensitiveInformation @(
        @{Name="UK National Insurance Number (NINO)"; minCount="1"},
        @{Name="International Classification of Diseases (ICD-9-CM)"; minCount="1"}
    ) \`
    -AccessScope NotInOrganization \`
    -GenerateIncidentReport SiteAdmin \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly \`
    -Priority 0

Write-Host "Created in test mode - review Activity Explorer for 2-4 weeks before promoting to enforce." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Add Teams chat/channel messages as a location (requires E5 or the Teams DLP add-on).",
      "Add Endpoint DLP for the same pattern being copied to USB or printed (requires E5 or the Endpoint DLP add-on).",
      "Auto-apply a \"Highly Confidential - GDPR\" sensitivity label wherever this content is detected (auto-labeling requires E5).",
    ],
    regulationRefs: [
      { citation: "GDPR/UK GDPR Art. 5(1)(f)", note: "Integrity and confidentiality principle." },
      { citation: "GDPR/UK GDPR Art. 9", note: "Special categories of personal data - health data is one of the listed categories." },
      { citation: "GDPR/UK GDPR Art. 32", note: "Security of processing - appropriate technical and organizational measures." },
      { citation: "GDPR/UK GDPR Art. 33", note: "Notification of a personal data breach within 72 hours - this policy's incident-report trail supports meeting that window." },
    ],
    caveats: [
      "PowerShell template is unverified against a live tenant - see the catalog-wide note.",
      "GDPR/UK GDPR covers 27 EU member states plus the UK, each with its own national ID formats. This pack deliberately starts narrow (UK-specific types plus the generic EU passport type) rather than guessing at every country's SIT name - expand with country-specific identifiers (searchable in the portal's SIT picker) once the client's actual EU footprint is known.",
      "This pack covers only the health special category, not GDPR Art. 9's other listed categories (racial/ethnic origin, religious belief, biometric/genetic data, sexual orientation, trade union membership) - several of those aren't reliably text-pattern-detectable by DLP the way an ID number or ICD code is, and would need a different approach.",
      "Teams and Endpoint locations are deliberately left off this recommendation on Business Premium/E3 - not licensed there, not just unconfigured.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice - have whoever owns GDPR/UK GDPR compliance for the client confirm the citations before promoting out of test mode.",
    ],
    relatedRecommendationIds: ["label-auto-labeling-sensitive-categories"],
  },
  {
    id: "credentials-and-secrets-leak-prevention",
    title: "Prevent credential and secret leakage",
    regulations: ["popia", "gdpr_uk_gdpr", "hipaa"],
    dataCategories: ["credentials_secrets"],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "Leaked passwords, API keys, and connection strings are a root cause of breaches, and every regulation in this catalog cites a version of 'appropriate technical safeguards' that this addresses (POPIA s.19, GDPR Art. 32, HIPAA's Security Rule). Unlike the identity/health packs above, this one isn't regulation-specific - it's a generic, low-false-positive control worth deploying regardless of which regulations apply to a given client. Microsoft's built-in credential-detection sensitive info type needs no custom regex.",
    sensitiveInfoTypes: [
      {
        displayName: "All Credential Types",
        matchGuidance: "Microsoft's built-in bundled sensitive info type covering common credential/key formats (passwords, connection strings, generic API keys, private keys). Exact composition of this bundle should be confirmed live - see caveats.",
      },
    ],
    recommendedLocations: ["Exchange email", "SharePoint sites", "OneDrive accounts"],
    recommendedStartingMode: "Test with notifications",
    ruleLogicSummary:
      "Rule 1: content matches \"All Credential Types\", shared with anyone (internal or external) -> notify sender with remediation guidance (rotate the credential if real), generate incident report, test mode only. Unlike the identity-focused packs above, this rule deliberately does not require external sharing as a condition - an internally-shared credential is still a real exposure (e.g. in an internal Teams channel with broad membership).",
    actions: [
      "Notify the user with a policy tip that also tells them to rotate the credential immediately if it's real",
      "Generate an incident report to the security team",
      "Do not block in the initial test period - review 1-2 weeks of matches (this category has fewer expected false positives than the identity-focused packs, so a shorter review window is reasonable)",
      "Once promoted: block sharing entirely for external recipients; keep internal sharing at notify-only unless the client wants a harder internal stance too",
    ],
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Data loss prevention -> Policies -> Create policy." },
      { step: 2, instruction: "Choose \"Custom\" -> \"Custom policy\". Name it e.g. \"Credential & Secret Leak Prevention\"." },
      { step: 3, instruction: "Choose locations: Exchange email, SharePoint sites, OneDrive accounts." },
      { step: 4, instruction: "Create the rule: condition \"Content contains\" -> Sensitive info types -> search \"All Credential Types\" (or the closest-named bundle/group the portal offers - naming has shifted in Microsoft's own UI before, confirm what's actually available)." },
      { step: 5, instruction: "Do not add a recipient-location condition - leave this rule applying to both internal and external sharing." },
      { step: 6, instruction: "Actions: enable \"Generate an incident report\" and \"Notify users\", with a custom policy tip telling the user to rotate the credential if it's real." },
      { step: 7, instruction: "Set the rule to \"Test it out first\" -> \"Turn it on right away, but keep it in test mode\"." },
      { step: 8, instruction: "After 1-2 weeks, add an \"the recipient is outside my organization\" condition to a second, stricter rule that blocks instead of just notifying, and promote that one out of test mode." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - see the catalog-wide caveat. The exact sensitive info type
# name/bundle for credentials has shifted in Microsoft's own tooling before -
# confirm what's actually offered in the portal's SIT picker before running this.

Connect-IPPSSession

New-DlpCompliancePolicy -Name "${prefix} - Credential & Secret Leak Prevention" \`
    -ExchangeLocation All \`
    -SharePointLocation All \`
    -OneDriveLocation All \`
    -Mode TestWithNotifications \`
    -Comment "Generic security safeguard (POPIA s.19 / GDPR Art. 32 / HIPAA Security Rule) - generated by Clarity365 (unverified template, review before enabling)"

New-DlpComplianceRule -Name "${prefix} - Credential or secret detected" \`
    -Policy "${prefix} - Credential & Secret Leak Prevention" \`
    -ContentContainsSensitiveInformation @{Name="All Credential Types"; minCount="1"} \`
    -GenerateIncidentReport SiteAdmin \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly

Write-Host "Created in test mode - after 1-2 weeks, add an external-recipient rule with -BlockAccess to enforce." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Add Teams chat/channel messages as a location - this is a particularly high-value addition here specifically, since developers pasting secrets into chat is a common real-world leak path (requires E5 or the Teams DLP add-on).",
      "Add Endpoint DLP to also block copying credentials/secrets to USB or clipboard-risky destinations (requires E5 or the Endpoint DLP add-on).",
    ],
    regulationRefs: [
      { citation: "POPIA s.19", note: "Security safeguards against unlawful access." },
      { citation: "GDPR/UK GDPR Art. 32(1)(a)/(b)", note: "Pseudonymisation/encryption and ongoing confidentiality of processing systems." },
      { citation: "HIPAA 45 CFR 164.312(a)(2)(iv)", note: "Encryption/access-control technical safeguard." },
    ],
    caveats: [
      "PowerShell template is unverified against a live tenant - see the catalog-wide note.",
      "\"All Credential Types\" is referenced from memory as Microsoft's built-in credential-detection bundle - its exact name and composition should be confirmed live in the portal's sensitive info type picker before relying on it; this is a lower-confidence SIT reference than the well-documented per-country identity types used in the other packs.",
      "This pack isn't tied to one regulation the way the others are - it's a general security control every regulation here implicitly requires. Worth deploying on every client regardless of which specific regulations apply to them.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice.",
    ],
  },
  {
    id: "financial-banking-data",
    title: "Protect banking and financial account data",
    regulations: ["popia", "gdpr_uk_gdpr"],
    dataCategories: ["financial_banking"],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "Bank account and routing details aren't a POPIA 'special category' (those are health, religious/political belief, biometric, criminal-behaviour data) or a GDPR Art. 9 special category either - so this pack cites the general security-safeguards provisions (POPIA s.19, GDPR Art. 32), the same ones the credentials pack above uses, not the special-category articles the identity packs cite. It detects international banking identifiers shared externally across Exchange, SharePoint and OneDrive.",
    sensitiveInfoTypes: [
      {
        displayName: "International Banking Account Number (IBAN)",
        matchGuidance: "High confidence, 1+ instance. IBAN is a European standard - see caveats for a real gap this creates for South African clients.",
      },
      {
        displayName: "SWIFT Code",
        matchGuidance: "High confidence, 1+ instance. Often appears alongside an IBAN in wire-transfer instructions.",
      },
      {
        displayName: "ABA Routing Number (also known as ABA Number or Routing Transit Number)",
        matchGuidance: "Moderate confidence, 1+ instance. US-specific (ACH/wire routing); relevant for clients with US banking relationships.",
      },
    ],
    recommendedLocations: ["Exchange email", "SharePoint sites", "OneDrive accounts"],
    recommendedStartingMode: "Test with notifications",
    ruleLogicSummary:
      "Rule 1: IBAN, SWIFT Code, or ABA Routing Number found, shared externally -> notify sender, generate incident report, test mode only. No elevated/combined variant - unlike the health packs, there's no natural second identifier to pair these with for a 'worse case.'",
    actions: [
      "Notify the user with a policy tip explaining why the content was flagged",
      "Generate an incident report to the compliance/security team",
      "Do not block in the initial test period - review 2-4 weeks of matches for false positives",
      "Once promoted: block external sharing, allow override with business justification (required field) so legitimate cases - e.g. the finance team's own outgoing wire instructions - aren't hard-blocked",
    ],
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Data loss prevention -> Policies -> Create policy." },
      { step: 2, instruction: "Choose \"Custom\" -> \"Custom policy\". Name it e.g. \"Financial & Banking Data Protection\", description referencing POPIA s.19 / GDPR Art. 32 for the audit trail." },
      { step: 3, instruction: "Choose locations: Exchange email, SharePoint sites, OneDrive accounts." },
      { step: 4, instruction: "Create the rule: condition \"Content contains\" -> Sensitive info types -> add International Banking Account Number (IBAN), SWIFT Code, and ABA Routing Number (group operator OR), instance count 1+, confidence High." },
      { step: 5, instruction: "Add condition group \"the recipient is\" -> \"outside my organization\"." },
      { step: 6, instruction: "Actions: enable \"Generate an incident report\" and \"Notify users\" with a custom policy tip. Leave \"Restrict access or encrypt\" unticked for now (test mode)." },
      { step: 7, instruction: "Set the rule to \"Test it out first\" -> \"Turn it on right away, but keep it in test mode\"." },
      { step: 8, instruction: "After 2-4 weeks reviewing Activity Explorer, promote to block + override-with-justification." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - see the catalog-wide caveat. Review every parameter against
# the Purview portal before running this.

Connect-IPPSSession

New-DlpCompliancePolicy -Name "${prefix} - Financial & Banking Data" \`
    -ExchangeLocation All \`
    -SharePointLocation All \`
    -OneDriveLocation All \`
    -Mode TestWithNotifications \`
    -Comment "POPIA s.19 / GDPR Art. 32 - banking data protection, generated by Clarity365 (unverified template, review before enabling)"

New-DlpComplianceRule -Name "${prefix} - Banking data external share" \`
    -Policy "${prefix} - Financial & Banking Data" \`
    -ContentContainsSensitiveInformation @(
        @{Name="International Banking Account Number (IBAN)"; minCount="1"},
        @{Name="SWIFT Code"; minCount="1"},
        @{Name="ABA Routing Number (also known as ABA Number or Routing Transit Number)"; minCount="1"}
    ) \`
    -AccessScope NotInOrganization \`
    -GenerateIncidentReport SiteAdmin \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly

Write-Host "Created in test mode - review Activity Explorer for 2-4 weeks before promoting to enforce." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Exact Data Match (EDM) is unusually well-suited here - matching the client's own actual list of known account numbers exactly, instead of a generic international pattern, cuts false positives sharply (requires E5).",
      "Add Teams chat/channel messages as a location (requires E5 or the Teams DLP add-on).",
      "Add Endpoint DLP for the same pattern being copied to USB or printed (requires E5 or the Endpoint DLP add-on).",
    ],
    regulationRefs: [
      { citation: "POPIA s.19", note: "Security safeguards against unlawful access - the general provision, not a special-category one." },
      { citation: "GDPR/UK GDPR Art. 32(1)(a)/(b)", note: "Security of processing - appropriate technical and organizational measures." },
    ],
    caveats: [
      "PowerShell template is unverified against a live tenant - see the catalog-wide note.",
      "IBAN is a European standard - South African bank accounts don't use IBAN, and there is no known South-Africa-specific bank-account-number built-in Sensitive Information Type. For a POPIA-driven South African client, this pack is meaningfully weaker at catching domestic SA banking data than international wire details. Ships anyway since SWIFT codes and international transfers are still a real, common leak path - just don't present this as full coverage.",
      "SIT names are Microsoft's own documented built-in names, not independently re-confirmed against a live tenant's SIT list in this session.",
      "Teams and Endpoint locations are deliberately left off this recommendation on Business Premium/E3 - not licensed there, not just unconfigured.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice.",
    ],
  },
  {
    id: "payment-card-data",
    title: "Protect payment card data",
    regulations: ["popia", "gdpr_uk_gdpr"],
    dataCategories: ["payment_card"],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "This pack protects card numbers as personal information/personal data under POPIA and GDPR - it is deliberately NOT presented as a PCI DSS compliance measure. PCI DSS itself requires far more than a DLP rule (network segmentation, a formal QSA assessment, quarterly scans); a DLP policy alone must never be treated as making a tenant 'PCI compliant.' If the client already has a policy named for PCI DSS, layer this personal-data-focused pack alongside it - they answer different questions (is this personal information safe, versus is this tenant PCI compliant) and one doesn't substitute for the other.",
    sensitiveInfoTypes: [
      {
        displayName: "Credit Card Number",
        matchGuidance: "High confidence - one of Microsoft's oldest, checksum-validated built-in SITs.",
      },
      {
        displayName: "EU Debit Card Number",
        matchGuidance: "Moderate confidence, 1+ instance.",
      },
    ],
    recommendedLocations: ["Exchange email", "SharePoint sites", "OneDrive accounts"],
    recommendedStartingMode: "Test with notifications",
    ruleLogicSummary:
      "Volume-tiered, not a single trigger: Rule 1 (baseline, 1-9 instances) -> notify only, low severity, test mode. Rule 2 (elevated, 10+ instances) -> block external sharing and alert compliance directly, higher priority - a much stronger signal of an actual card-data dump (e.g. a batch export) rather than one customer's card number mentioned once.",
    actions: [
      "1-9 instances: notify the user with a policy tip, log for review - do not block",
      "10+ instances: generate an incident report to compliance directly and treat as high priority",
      "Both rules start in test mode; the 10+ rule can reasonably be promoted to block sooner than the 1-9 rule, since a 10+ match has a much lower false-positive rate",
      "Once promoted: block external sharing on the 10+ rule; keep the 1-9 rule at notify-only unless the client wants a harder stance on single card-number mentions too",
    ],
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Data loss prevention -> Policies -> Create policy." },
      { step: 2, instruction: "Choose \"Custom\" -> \"Custom policy\". Name it e.g. \"Payment Card Data Protection\" - not \"PCI DSS\", to avoid implying this alone satisfies PCI DSS." },
      { step: 3, instruction: "Choose locations: Exchange email, SharePoint sites, OneDrive accounts." },
      { step: 4, instruction: "Create Rule 1 (baseline): condition \"Content contains\" -> Sensitive info types -> add Credit Card Number and EU Debit Card Number (group operator OR), instance count 1 to 9." },
      { step: 5, instruction: "Rule 1 actions: enable \"Notify users\" with a policy tip; do not enable blocking or incident report yet." },
      { step: 6, instruction: "Create Rule 2 (elevated): same sensitive info types, instance count 10 to any. Set higher priority (lower number) than Rule 1." },
      { step: 7, instruction: "Rule 2 actions: enable \"Generate an incident report\" (send directly to the compliance team) and \"Notify users\"." },
      { step: 8, instruction: "Set both rules to \"Test it out first\" -> \"Turn it on right away, but keep it in test mode\"." },
      { step: 9, instruction: "After reviewing Activity Explorer, promote Rule 2 to block external sharing first (lower false-positive risk at that volume), then Rule 1 once its own false-positive rate is confirmed acceptable." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - see the catalog-wide caveat. Review every parameter against
# the Purview portal before running this.

Connect-IPPSSession

New-DlpCompliancePolicy -Name "${prefix} - Payment Card Data" \`
    -ExchangeLocation All \`
    -SharePointLocation All \`
    -OneDriveLocation All \`
    -Mode TestWithNotifications \`
    -Comment "POPIA s.19 / GDPR Art. 32 - payment card data as personal information. NOT a PCI DSS compliance measure on its own - generated by Clarity365 (unverified template, review before enabling)"

# Rule 1: baseline, 1-9 instances - notify only
New-DlpComplianceRule -Name "${prefix} - Card data (low volume)" \`
    -Policy "${prefix} - Payment Card Data" \`
    -ContentContainsSensitiveInformation @(
        @{Name="Credit Card Number"; minCount="1"; maxCount="9"},
        @{Name="EU Debit Card Number"; minCount="1"; maxCount="9"}
    ) \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly

# Rule 2: elevated, 10+ instances - incident report, higher priority
New-DlpComplianceRule -Name "${prefix} - Card data (bulk)" \`
    -Policy "${prefix} - Payment Card Data" \`
    -ContentContainsSensitiveInformation @(
        @{Name="Credit Card Number"; minCount="10"},
        @{Name="EU Debit Card Number"; minCount="10"}
    ) \`
    -GenerateIncidentReport SiteAdmin \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly \`
    -Priority 0

Write-Host "Created in test mode. Consider promoting the bulk rule to -BlockAccess -AccessScope NotInOrganization sooner than the low-volume rule." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Add Teams chat/channel messages as a location (requires E5 or the Teams DLP add-on).",
      "Add Endpoint DLP for the same pattern being copied to USB or printed (requires E5 or the Endpoint DLP add-on).",
      "Auto-apply a \"Confidential - Payment Data\" sensitivity label wherever this content is detected (auto-labeling requires E5).",
    ],
    regulationRefs: [
      { citation: "POPIA s.19", note: "Security safeguards - the basis for protecting card numbers as personal information, independent of any PCI DSS obligation." },
      { citation: "GDPR/UK GDPR Art. 32", note: "Security of processing." },
      { citation: "PCI DSS v4 (context only, not satisfied by this pack)", note: "Req. 3/4.2.2 address stored and transmitted cardholder data - a full PCI DSS program needs far more than this DLP policy; see summary." },
    ],
    caveats: [
      "This pack does NOT make a tenant PCI DSS compliant - it protects card numbers as personal data under POPIA/GDPR only. PCI DSS compliance requires a formal assessment, network segmentation, and controls well beyond DLP.",
      "If the client already runs a policy named for PCI DSS (already the case on at least one demo tenant), treat the two as complementary, not redundant - don't delete or replace either based on this recommendation.",
      "PowerShell template is unverified against a live tenant, and the maxCount parameter shown for the low-volume rule should be confirmed against the portal's own rule editor - see the catalog-wide note.",
      "\"Credit Card Number\" and \"EU Debit Card Number\" are Microsoft's own documented built-in SIT names; not independently re-confirmed against a live tenant's SIT list in this session.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice.",
    ],
  },
  {
    id: "bulk-pii-exfiltration",
    title: "Detect bulk personal-data exfiltration",
    regulations: ["popia", "gdpr_uk_gdpr"],
    dataCategories: ["bulk_pii"],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "Unlike every other pack in this catalog, this one introduces no new Sensitive Information Type - it reuses the identifiers already shipped in the POPIA, GDPR and financial-banking packs above, at a much higher instance count. The signal here isn't which identifier is present, it's an unusually large number of any of them in one item - the shape of a mass export or data dump rather than a single reference. Depends on the financial-banking pack's SITs already existing, so build this one after that.",
    sensitiveInfoTypes: [
      { displayName: "South Africa Identification Number", matchGuidance: "50+ combined instances - a bulk-export signal, not a single-reference match." },
      { displayName: "UK National Insurance Number (NINO)", matchGuidance: "Same 50+ threshold." },
      { displayName: "UK Passport Number", matchGuidance: "Same 50+ threshold." },
      { displayName: "EU Passport Number", matchGuidance: "Same 50+ threshold." },
      { displayName: "International Banking Account Number (IBAN)", matchGuidance: "Same 50+ threshold." },
      { displayName: "SWIFT Code", matchGuidance: "Same 50+ threshold." },
    ],
    recommendedLocations: ["Exchange email", "SharePoint sites", "OneDrive accounts"],
    recommendedStartingMode: "Test with notifications",
    ruleLogicSummary:
      "Any of the identifiers above reaching 50 or more combined instances in a single email or file, shared internally OR externally (not restricted to external, unlike most packs above - a 50-instance internal share to an over-permissioned group is still worth flagging) -> notify, generate incident report, test mode. This is a per-item volume check (each file/email is scored on its own); it does not catch a slow drip of many small exports spread across days or weeks - that time-windowed pattern needs a different, E5-only capability (see e5Enhancements).",
    actions: [
      "Notify the user with a policy tip explaining why the content was flagged",
      "Generate an incident report to the compliance/security team",
      "Given the much lower false-positive risk of a 50-instance match compared to a 1-instance one, a shorter test-mode review window (1-2 weeks, not the usual 2-4) is reasonable before promoting",
      "Once promoted: block both internal and external sharing above the threshold, since a bulk match this size is rarely a legitimate everyday action",
    ],
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Data loss prevention -> Policies -> Create policy." },
      { step: 2, instruction: "Choose \"Custom\" -> \"Custom policy\". Name it e.g. \"Bulk Personal Data Exfiltration Detection\"." },
      { step: 3, instruction: "Choose locations: Exchange email, SharePoint sites, OneDrive accounts." },
      { step: 4, instruction: "Create the rule: condition \"Content contains\" -> Sensitive info types -> add all six identifiers listed above (group operator OR), and set the instance count to 50 or more on each." },
      { step: 5, instruction: "Do not add a recipient-location condition - leave this rule applying to both internal and external sharing." },
      { step: 6, instruction: "Actions: enable \"Generate an incident report\" and \"Notify users\"." },
      { step: 7, instruction: "Set the rule to \"Test it out first\" -> \"Turn it on right away, but keep it in test mode\"." },
      { step: 8, instruction: "After 1-2 weeks, review Activity Explorer and promote to block if the match rate looks accurate." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - see the catalog-wide caveat. In particular, whether the
# portal/cmdlet aggregates instance counts ACROSS different sensitive info
# types into one combined number, or requires each type to independently
# reach 50, was not confirmed live - review this specifically in the portal's
# rule editor before trusting the shape below.

Connect-IPPSSession

New-DlpCompliancePolicy -Name "${prefix} - Bulk PII Exfiltration Detection" \`
    -ExchangeLocation All \`
    -SharePointLocation All \`
    -OneDriveLocation All \`
    -Mode TestWithNotifications \`
    -Comment "POPIA s.22 / GDPR Art. 33 - bulk exfiltration detection, generated by Clarity365 (unverified template, review before enabling)"

New-DlpComplianceRule -Name "${prefix} - Bulk identifier match" \`
    -Policy "${prefix} - Bulk PII Exfiltration Detection" \`
    -ContentContainsSensitiveInformation @(
        @{Name="South Africa Identification Number"; minCount="50"},
        @{Name="UK National Insurance Number (NINO)"; minCount="50"},
        @{Name="UK Passport Number"; minCount="50"},
        @{Name="EU Passport Number"; minCount="50"},
        @{Name="International Banking Account Number (IBAN)"; minCount="50"},
        @{Name="SWIFT Code"; minCount="50"}
    ) \`
    -GenerateIncidentReport SiteAdmin \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly

Write-Host "Created in test mode - after 1-2 weeks, promote with -BlockAccess (no -AccessScope, applies to both internal and external)." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Insider Risk Management / Adaptive Protection can detect the same pattern spread over time (many small exports across days or weeks) - a genuinely different, E5-only capability this per-item DLP rule can only approximate, not replace.",
      "Add Endpoint DLP to also catch bulk copies to USB (requires E5 or the Endpoint DLP add-on).",
      "Add Teams chat/channel messages as a location (requires E5 or the Teams DLP add-on).",
    ],
    regulationRefs: [
      { citation: "POPIA s.22", note: "Notification of a compromise - this is the exfiltration-detection use case that provision anticipates." },
      { citation: "GDPR/UK GDPR Art. 33", note: "72-hour breach notification - an early incident-report trail on a bulk match directly supports meeting that window." },
    ],
    caveats: [
      "PowerShell template is unverified against a live tenant, and specifically whether instance counts aggregate across different sensitive info types the way the script assumes - confirm in the portal's rule editor before trusting it.",
      "This pack depends on the financial-banking pack's two SITs (IBAN, SWIFT Code) already existing in the catalog - built after that pack, not independently.",
      "This is a per-item (one email or file) volume check, not a time-windowed one - it will not catch a slow, deliberate trickle of exports below the 50-instance threshold. See the Insider Risk Management note above for the capability that actually addresses that pattern.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice.",
    ],
  },
  {
    id: "ip-contracts-source-code",
    title: "Protect intellectual property, contracts, and source code",
    regulations: [],
    dataCategories: ["ip_contracts"],
    minimumLicenseTier: "e5",
    summary:
      "Intellectual property, contracts, and source code aren't personal data, so POPIA, GDPR/UK GDPR and HIPAA simply don't apply here - there is no privacy-law citation behind this pack, unlike every other entry in this catalog. There is also no reliable built-in Sensitive Information Type for 'this is a contract' or 'this is source code' the way there is for a checksum-validated ID or card number - real detection needs Microsoft Purview's Trainable Classifiers, which is an E5 (or Purview add-on) capability. Per the 2026-09-22 decision, this entry deliberately has no Business Premium/E3 fallback: a keyword/file-extension approximation would be materially weaker than every other pack in this catalog and risks giving a client false confidence in a control that doesn't actually work well.",
    sensitiveInfoTypes: [
      {
        displayName: "Source Code (trainable classifier)",
        matchGuidance: "Referenced from memory as one of Microsoft's pre-trained, ready-to-use classifiers - confirm it's still present in the tenant's classifier list (Data classification -> Trainable classifiers) before relying on it; Microsoft's pre-trained list has changed over time.",
      },
      {
        displayName: "Contracts / IP documents (custom trainable classifier)",
        matchGuidance: "No pre-trained classifier for this is assumed to exist - this must be a custom classifier, trained on the client's own sample contracts/IP documents (Microsoft recommends 50+ seed items). Training takes time and must reach \"ready to use\" before it can be referenced in a DLP rule.",
      },
    ],
    recommendedLocations: ["Exchange email", "SharePoint sites", "OneDrive accounts", "Teams chat and channel messages"],
    recommendedStartingMode: "Test with notifications",
    ruleLogicSummary:
      "Content matching the \"Source Code\" pre-trained classifier and/or the custom-trained \"Contracts/IP\" classifier, shared externally -> notify, generate incident report, test mode. Because classifier matches are probabilistic (a confidence score, not a deterministic pattern match like a SIT), expect a materially higher false-positive rate than every SIT-based pack above - plan for a longer review window before any enforcement.",
    actions: [
      "Notify the user with a policy tip explaining why the content was flagged",
      "Generate an incident report to the compliance/security team",
      "Review at least 4 weeks of test-mode matches - longer than the SIT-based packs above - before considering any enforcement, given classifiers' inherently higher false-positive rate",
      "Once promoted: block external sharing with override-and-justification, never a hard block with no override - a classifier will misfire on real business content more often than a SIT does",
    ],
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Data classification -> Trainable classifiers. Confirm \"Source code\" appears in the pre-built/ready-to-use list." },
      { step: 2, instruction: "If a contracts/IP classifier isn't already present, select \"Create trainable classifier\" -> \"Custom\". Provide 50+ sample documents that are genuinely contracts/IP material as positive seed examples, and a comparable set of negative examples (ordinary business documents that should NOT match)." },
      { step: 3, instruction: "Wait for the custom classifier's status to reach \"Ready to use\" - this can take from hours to a few days and is not instant, unlike everything else in this catalog." },
      { step: 4, instruction: "Go to Data loss prevention -> Policies -> Create policy -> \"Custom\" -> \"Custom policy\". Name it e.g. \"IP, Contracts & Source Code Protection\"." },
      { step: 5, instruction: "Choose locations: Exchange email, SharePoint sites, OneDrive accounts, Teams chat and channel messages." },
      { step: 6, instruction: "Create the rule: condition \"Content contains\" -> switch the picker to Trainable classifiers (not Sensitive info types) -> select \"Source code\" and the custom contracts/IP classifier." },
      { step: 7, instruction: "Add condition group \"the recipient is\" -> \"outside my organization\"." },
      { step: 8, instruction: "Actions: enable \"Generate an incident report\" and \"Notify users\". Leave blocking off for now." },
      { step: 9, instruction: "Set the rule to \"Test it out first\" -> \"Turn it on right away, but keep it in test mode\"." },
      { step: 10, instruction: "Review Activity Explorer for at least 4 weeks - classifier false-positive rates need more evidence than a SIT match does - before promoting to block with override." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED, AND LESS CONFIDENT THAN EVERY OTHER TEMPLATE IN THIS CATALOG.
# Trainable-classifier-based DLP rule conditions use a different mechanism
# than the Sensitive-Information-Type conditions every other template in this
# catalog relies on, and the exact PowerShell parameter for referencing a
# classifier in New-DlpComplianceRule was NOT reliably recalled in this
# session - rather than guess at a plausible-looking but possibly wrong
# parameter name, this script only creates the policy shell. Build the actual
# rule (the classifier condition itself) through the portal UI - see the
# portal steps above.

Connect-IPPSSession

New-DlpCompliancePolicy -Name "${prefix} - IP, Contracts & Source Code" \`
    -ExchangeLocation All \`
    -SharePointLocation All \`
    -OneDriveLocation All \`
    -TeamsLocation All \`
    -Mode TestWithNotifications \`
    -Comment "IP/contract/source-code protection (E5 trainable classifiers) - policy shell only, generated by Clarity365. Add the classifier-based rule condition through the Purview portal, not PowerShell - see caveats."

Write-Host "Policy shell created. Add the trainable-classifier rule condition via the Purview portal - see this recommendation's portal steps." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Exact Data Match (EDM) for known deal names or project code names - a further step up from classifiers for the client's own specifically named confidential projects.",
      "Extend Endpoint DLP to block copying classifier-matched files to USB.",
      "Defender for Cloud Apps session policies can block or watermark IP being uploaded through a browser to unsanctioned personal cloud storage - a common exfiltration path a mail/file-focused DLP policy alone won't see. Beyond this catalog's core scope, but worth flagging as the natural next layer.",
    ],
    regulationRefs: [
      { citation: "Contract law (general)", note: "Most commercial and employment contracts carry their own confidentiality/IP-assignment clauses - this pack helps enforce those obligations technically. Not a privacy statute; confirm the specific contractual basis with the client's legal counsel, not this catalog." },
      { citation: "ISO 27001:2022 A.8.12", note: "Data leakage prevention - the closest formal framework reference for this control, though ISO 27001 isn't itself one of this catalog's three chosen regulations." },
    ],
    caveats: [
      "No privacy-law regulation applies to this category - POPIA/GDPR/HIPAA don't govern IP or contracts. The references above are contractual/framework references, not statutes.",
      "No Business Premium/E3 version is offered for this entry - see the 2026-09-22 decision recorded in the DLP Stage 3 plan. A keyword/file-extension approximation was deliberately not shipped rather than presented with the same confidence as the SIT-based packs.",
      "\"Source Code\" is referenced from memory as one of Microsoft's pre-trained classifiers - confirm it's still present and named that way in the tenant's own classifier list before relying on it.",
      "The contracts/IP classifier is assumed to require custom training - there's no evidence a ready-made one exists. Training needs real sample documents and takes real time; this isn't a same-day setup like the SIT-based packs above.",
      "PowerShell for the classifier-based rule condition itself is deliberately not provided - the exact cmdlet parameter wasn't reliably known in this session. Build that part through the portal UI only.",
      "Classifier matches are probabilistic and will have a materially higher false-positive rate than a checksum-validated SIT - budget a longer review period and a softer enforcement posture (override-with-justification, never a hard block) than the rest of the catalog.",
    ],
  },
  {
    id: "popia-cross-border-transfer",
    title: "Restrict cross-border transfer of South African personal information",
    regulations: ["popia"],
    dataCategories: ["cross_border_transfer"],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "POPIA s.72 restricts transferring personal information outside South Africa unless the receiving party is subject to adequate protection (a law, binding corporate rules, or a qualifying agreement), the data subject consented, or another listed exception applies. Every other entry in this catalog checks whether a recipient is 'outside my organization' - a different, more generic condition. This one checks the thing POPIA actually regulates: is the data leaving South Africa, not just leaving the tenant. It's a destination-based control - personal information matched against a client-maintained allowlist of approved (South African or already-vetted foreign-partner) domains, flagged whenever it's headed anywhere else.",
    sensitiveInfoTypes: [
      {
        displayName: "South Africa Identification Number",
        matchGuidance: "The primary trigger - the single most universal South African personal identifier. Extend with any other identifier SIT already in this catalog (International Banking Account Number (IBAN), SWIFT Code, Credit Card Number, etc.) to broaden coverage - the destination-based condition below works identically regardless of which SIT triggers it.",
      },
    ],
    recommendedLocations: ["Exchange email"],
    recommendedStartingMode: "Test with notifications",
    ruleLogicSummary:
      "South Africa Identification Number found, recipient domain NOT in an admin-maintained approved-domains list (built as an exception - the rule fires for every domain except the ones explicitly listed as approved) -> notify sender, generate incident report, test mode only.",
    actions: [
      "Notify the user with a policy tip explaining POPIA's cross-border transfer restriction",
      "Generate an incident report to the compliance/DPO team",
      "Do not block in the initial test period - use the 2-4 week review specifically to build out the real approved-domains list, since a freshly-started list will under-cover legitimate business destinations at first",
      "Once promoted: block, with an override-and-justification path for legitimate ad hoc cases (a new partner not yet added to the list) rather than a hard block, since the list will always lag slightly behind real business relationships",
    ],
    portalSteps: [
      { step: 1, instruction: "Before creating the policy: build the approved-domains list. List every domain your organization already regularly and legitimately sends South African personal information to - your own domain(s), established partners, vetted SA or adequately-protected cloud/SaaS vendors. Start conservative; adding more later has no downside." },
      { step: 2, instruction: "Go to https://compliance.microsoft.com -> Data loss prevention -> Policies -> Create policy -> \"Custom\" -> \"Custom policy\". Name it e.g. \"POPIA - Cross-Border Transfer Restriction\"." },
      { step: 3, instruction: "Choose locations: Exchange email only - see caveats for why SharePoint/OneDrive need a separate, non-DLP control." },
      { step: 4, instruction: "Create the rule: condition \"Content contains\" -> Sensitive info types -> South Africa Identification Number (add other identifier SITs from this catalog to broaden coverage if wanted)." },
      { step: 5, instruction: "Add an exception: \"Except if\" -> \"The recipient domain is\" -> add every domain from your approved-domains list." },
      { step: 6, instruction: "Actions: enable \"Generate an incident report\" and \"Notify users\" with a policy tip explaining the POPIA cross-border restriction. Leave blocking off for now." },
      { step: 7, instruction: "Set the rule to \"Test it out first\" -> \"Turn it on right away, but keep it in test mode\"." },
      { step: 8, instruction: "Separately, and not a DLP rule: in the SharePoint admin center's Sharing settings, review the allowed/blocked domains list for external sharing to apply the equivalent restriction to SharePoint and OneDrive." },
      { step: 9, instruction: "Review Activity Explorer for 2-4 weeks. Expect to add domains to the approved list repeatedly during this period, more than any other entry in this catalog, before the false-positive rate reflects real business flows." },
      { step: 10, instruction: "Once the false-positive rate looks right, promote to block with override-and-justification." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - see the catalog-wide caveat. The exception parameter shown
# (-ExceptIfRecipientDomainIs) is a best-effort guess based on the standard
# ExceptIf* naming convention used elsewhere in Exchange/DLP rule cmdlets -
# confirm the exact parameter in the Purview portal's rule editor before
# running this. Replace the placeholder domains below with your own real
# approved-domains list before running.

Connect-IPPSSession

$approvedDomains = @("yourdomain.co.za", "trusted-partner.co.za")

New-DlpCompliancePolicy -Name "${prefix} - POPIA Cross-Border Transfer" \`
    -ExchangeLocation All \`
    -Mode TestWithNotifications \`
    -Comment "POPIA s.72 - cross-border transfer restriction, generated by Clarity365 (unverified template, review before enabling)"

New-DlpComplianceRule -Name "${prefix} - Personal info to non-approved domain" \`
    -Policy "${prefix} - POPIA Cross-Border Transfer" \`
    -ContentContainsSensitiveInformation @{Name="South Africa Identification Number"; minCount="1"} \`
    -ExceptIfRecipientDomainIs $approvedDomains \`
    -GenerateIncidentReport SiteAdmin \`
    -NotifyUser Owner \`
    -NotifyUserType NotifyOnly

Write-Host "Created in test mode. Expect to iterate on \`\$approvedDomains\` more than any other rule in this catalog before promoting." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Defender for Cloud Apps session policies can enforce the same domain-based restriction for browser-based uploads to SharePoint/OneDrive/Teams, not just Exchange mail - a more complete technical approximation of s.72 than DLP alone can reach (requires E5).",
      "Add Teams chat/channel messages as a covered location using the same domain-exception logic (requires E5 or the Teams DLP add-on).",
    ],
    regulationRefs: [
      { citation: "POPIA s.72", note: "Transfer of personal information outside the Republic - prohibited unless the receiving party is subject to a law, binding corporate rules, or an agreement providing adequate protection, or another listed exception (consent, contractual necessity, etc.) applies." },
      { citation: "POPIA s.19", note: "Security safeguards - the general basis for controlling how personal information leaves the organization at all." },
    ],
    caveats: [
      "PowerShell template is unverified, and the exception parameter shown (-ExceptIfRecipientDomainIs) is a best-effort guess based on a standard naming convention, not confirmed against a live tenant - check the Purview portal's own rule editor before running this.",
      "This rule's domain-exception mechanism is Exchange-specific (it checks a mail recipient's domain). SharePoint and OneDrive external sharing don't have a 'recipient domain' the same way - the equivalent restriction there is the SharePoint admin center's own tenant-level allowed/blocked domains list, a separate native setting, not a DLP rule. Apply both for real coverage.",
      "This rule needs more iteration than any other entry in this catalog: a freshly-built approved-domains list will flag ordinary, legitimate business email until it's populated with every real destination. Budget real review time before promoting to block.",
      "POPIA s.72's actual exceptions (adequate protection, binding corporate rules, contractual necessity, consent) are a legal judgment call, not something a domain allowlist alone can determine - the allowlist is a practical technical approximation of 'destinations already assessed as acceptable,' and that assessment is the client's (or their legal counsel's) responsibility, not this catalog's.",
      "\"South Africa Identification Number\" is Microsoft's own documented built-in SIT name, not independently re-confirmed against a live tenant's SIT list in this session.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice.",
    ],
    relatedRecommendationIds: ["popia-sa-id-and-health"],
  },
  {
    id: "label-baseline-taxonomy",
    kind: "label",
    title: "Publish a baseline label taxonomy (Public / General / Confidential / Highly Confidential)",
    regulations: ["popia", "gdpr_uk_gdpr", "hipaa"],
    dataCategories: [],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "A documented information-classification scheme is the foundation every other label recommendation in this catalog builds on, and is itself referenced as a safeguard by all three regulations' general security provisions (POPIA s.19, GDPR Art. 32, HIPAA's Security Rule) - not because any of them mandates this exact four-tier structure, but because 'appropriate technical measures' is easier to demonstrate with a real, applied taxonomy than without one. This is the smallest possible first step: four labels, published, with a safe default and mandatory labeling - no encryption yet (see the Highly Confidential Encryption entry) and no automation yet (see the Auto-Labeling entry).",
    recommendedFor:
      "Every client, without exception. This is the ROOT of the label category - the other three entries all reference labels this one creates, and none of them can be deployed before this one. There's no client this doesn't apply to; if you're doing any sensitivity-labeling work at all, this is always where you start.",
    labels: [
      { name: "Public", priority: 0, encrypted: false, contentMarking: false, tooltip: "Cleared for public release - marketing material, published content." },
      { name: "General", priority: 1, encrypted: false, contentMarking: false, tooltip: "Everyday internal business content with no special sensitivity. Default label." },
      { name: "Confidential", priority: 2, encrypted: false, contentMarking: true, tooltip: "Client data, contracts, financial reports - internal use, not for external sharing without authorization." },
      { name: "Highly Confidential", priority: 3, encrypted: false, contentMarking: true, tooltip: "The most sensitive content this organization handles. See the Highly Confidential Encryption recommendation to add real protection, not just a marking." },
    ],
    labelPolicySettings: {
      defaultLabelName: "General",
      mandatoryLabeling: true,
      requireDowngradeJustification: true,
      locations: ["Exchange email", "SharePoint sites", "OneDrive accounts", "Word/Excel/PowerPoint (Office apps)"],
    },
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Information protection -> Labels -> Create a label." },
      { step: 2, instruction: "Create all four labels in order (Public, General, Confidential, Highly Confidential) - creation order sets default priority, and priority matters for downgrade-justification logic later, so create them lowest-to-highest." },
      { step: 3, instruction: "For each label: set the name and the tooltip text users will see when picking it. Leave encryption off for all four at this stage - that's the next recommendation, not this one." },
      { step: 4, instruction: "For Confidential and Highly Confidential: under \"Define protection settings for files and emails\" -> enable content marking (a header/footer or watermark) so the label is visible on the document itself, not just in metadata." },
      { step: 5, instruction: "Go to Label policies -> Publish labels. Select all four, choose locations (Exchange, SharePoint, OneDrive, Office apps)." },
      { step: 6, instruction: "Set the default label to \"General\"." },
      { step: 7, instruction: "Enable \"Require users to apply a label\" (mandatory labeling) and \"Require users to provide justification to remove a label or lower its classification\" (downgrade justification)." },
      { step: 8, instruction: "Publish. Labels can take up to 24 hours to appear in Office apps for all users - this isn't a test-mode/enforce distinction the way DLP has; there's no equivalent \"safe\" trial period, so review the label names and tooltips carefully before publishing." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - see the catalog-wide caveat (this file's DLP entries carry the
# same one). New-Label/New-LabelPolicy themselves are well-documented public
# cmdlets, more confidently correct than this catalog's earlier trainable-
# classifier gap - but the exact -AdvancedSettings key names for mandatory
# labeling and downgrade justification below are less commonly documented
# and worth confirming in the portal's own policy editor before trusting.
# Neither PowerShell nor the compliance service validates AdvancedSettings
# key names - a typo is silently accepted and does nothing.

Connect-IPPSSession

New-Label -Name "Public" -DisplayName "Public" -ToolTip "Cleared for public release." -Comment "${prefix} - baseline taxonomy, generated by Clarity365"
New-Label -Name "General" -DisplayName "General" -ToolTip "Everyday internal business content. Default label." -Comment "${prefix} - baseline taxonomy, generated by Clarity365"
New-Label -Name "Confidential" -DisplayName "Confidential" -ToolTip "Client data, contracts, financial reports - internal use only." -Comment "${prefix} - baseline taxonomy, generated by Clarity365"
New-Label -Name "HighlyConfidential" -DisplayName "Highly Confidential" -ToolTip "This organization's most sensitive content." -Comment "${prefix} - baseline taxonomy, generated by Clarity365"

New-LabelPolicy -Name "${prefix} - Baseline Label Policy" \`
    -Labels "Public","General","Confidential","HighlyConfidential" \`
    -ExchangeLocation All \`
    -SharePointLocation All \`
    -OneDriveLocation All

Set-LabelPolicy -Identity "${prefix} - Baseline Label Policy" \`
    -AdvancedSettings @{mandatory="true"; requiredowngradejustification="true"}

Write-Host "Published with mandatory labeling and downgrade justification. Confirm both settings in the portal's policy editor before relying on this script alone." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Container labels for Teams/sites/groups extend this same taxonomy to collaboration surfaces, not just documents and email - see the Container Labels recommendation.",
      "Auto-labeling removes the dependence on users correctly picking a label by hand - see the Auto-Labeling recommendation.",
    ],
    regulationRefs: [
      { citation: "POPIA s.19", note: "Security safeguards - a documented classification scheme is standard evidence of 'appropriate technical measures.'" },
      { citation: "GDPR/UK GDPR Art. 32", note: "Security of processing." },
      { citation: "HIPAA Security Rule (general)", note: "Data classification supports the risk-analysis and access-control requirements throughout the Security Rule." },
    ],
    caveats: [
      "PowerShell template is unverified against a live tenant - see the catalog-wide note. The AdvancedSettings key names shown (mandatory, requiredowngradejustification) are documented but worth confirming in the portal before trusting the script.",
      "Unlike DLP policies, there is no test-mode equivalent for labels - a published label policy is live immediately. Review names, tooltips, and the default label carefully before publishing, not after.",
      "Four tiers is a starting proposal, not a fixed requirement - a client with genuinely different classification needs may need a fifth tier or different names; this is a reasonable default, not the only correct taxonomy.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice.",
    ],
  },
  {
    id: "label-highly-confidential-encryption",
    kind: "label",
    title: "Add encryption to the Highly Confidential label",
    regulations: ["popia", "gdpr_uk_gdpr", "hipaa"],
    dataCategories: [],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "Extends the baseline taxonomy's top label from a visible marking to real protection: encrypting Highly Confidential content restricts who can open it regardless of where the file ends up, which is a meaningfully stronger control than a DLP rule alone (DLP controls where content can go; label encryption controls who can open it even after it gets there). Available on Business Premium/E3 - encryption itself doesn't need E5, only auto-applying the label without a human does.",
    recommendedFor:
      "Clients who genuinely handle sensitive data - health records, financial data, legal/contract material, government IDs - and need real protection, not just a marking someone can ignore. Optional, not universal: a client whose Highly Confidential content is mostly low-stakes internal material may not need this yet. Requires the baseline taxonomy already deployed - this entry only edits the label that entry already created.",
    buildsOn: ["label-baseline-taxonomy"],
    labels: [
      { name: "Highly Confidential", priority: 3, encrypted: true, contentMarking: true, tooltip: "The most sensitive content this organization handles - encrypted, restricted to authorized users only." },
    ],
    labelPolicySettings: {
      mandatoryLabeling: true,
      requireDowngradeJustification: true,
      locations: ["Exchange email", "SharePoint sites", "OneDrive accounts", "Word/Excel/PowerPoint (Office apps)"],
    },
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Information protection -> Labels -> select the existing \"Highly Confidential\" label -> Edit label." },
      { step: 2, instruction: "Under \"Define protection settings for files and emails\", turn on \"Apply or remove encryption\"." },
      { step: 3, instruction: "Choose \"Assign permissions now\" (not \"Let users assign permissions\") for a consistent, predictable rights set." },
      { step: 4, instruction: "Grant access to a defined group (e.g. an \"Executives\" or \"Confidential-Access\" security group) rather than \"All employees,\" and choose whether external recipients can ever be granted access (usually no, for this tier)." },
      { step: 5, instruction: "Set permissions: Co-Author or Reviewer rather than Full Control for most members, so encrypted content can be worked with but not have its protection stripped by everyone who can open it." },
      { step: 6, instruction: "Save. Existing content already labeled Highly Confidential is not retroactively re-encrypted - only content labeled (or re-saved) after this change picks up encryption." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - see the catalog-wide caveat. Encryption/permission assignment
# for a label is configured through a nested EncryptionRms* set of
# parameters on Set-Label - the exact shape of the permission list below
# should be confirmed against the portal's own label editor, since this is
# one of the more complex parts of Purview's PowerShell surface.

Connect-IPPSSession

Set-Label -Identity "HighlyConfidential" \`
    -EncryptionEnabled $true \`
    -EncryptionProtectionType "Template" \`
    -EncryptionRightsDefinitions "REPLACE-WITH-YOUR-ACCESS-GROUP-EMAIL:VIEW,DOCEDIT,EDIT,EXTRACT,OBJMODEL,COMMENT,FORWARD"

Write-Host "Review the granted rights and the recipient group above before applying - this does not retroactively re-encrypt already-labeled content." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Auto-labeling can apply this encrypted label automatically wherever matching sensitive content is found, instead of relying on a user to select it - see the Auto-Labeling recommendation.",
    ],
    regulationRefs: [
      { citation: "POPIA s.19", note: "Encryption is one of the most direct 'appropriate technical measures' for the highest-sensitivity tier." },
      { citation: "GDPR/UK GDPR Art. 32(1)(a)", note: "Pseudonymisation and encryption of personal data, named explicitly." },
      { citation: "HIPAA 45 CFR 164.312(a)(2)(iv)", note: "Encryption - an addressable specification, meaning it must be implemented, an equivalent alternative implemented, or the decision not to documented in writing." },
    ],
    caveats: [
      "PowerShell template is unverified, and the encryption/rights-definition parameters specifically are among the least confidently verified in this catalog - use the portal's label editor as the primary path, treat this script as a starting point only.",
      "Not retroactive - only newly labeled or re-saved content is encrypted. A separate content-scan/relabeling exercise is needed for anything already labeled Highly Confidential before this change.",
      "Choosing the wrong access group (too broad) defeats the point of this control - review who's actually in the granted group before publishing, not after.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice.",
    ],
  },
  {
    id: "label-auto-labeling-sensitive-categories",
    kind: "label",
    title: "Auto-apply Highly Confidential to PHI, SA ID and government ID content",
    regulations: ["popia", "gdpr_uk_gdpr", "hipaa"],
    dataCategories: ["health", "government_id"],
    minimumLicenseTier: "e5",
    summary:
      "Removes the dependence on a user correctly and consistently picking Highly Confidential by hand: this policy scans content and applies the label automatically wherever it finds the same Sensitive Information Types this catalog's identity/health DLP recommendations already key on. E5-only, no Business Premium/E3 fallback - manual labeling (the baseline taxonomy entry) is the correct fallback there, not a weaker imitation of automation.",
    recommendedFor:
      "E5 clients handling PHI, government IDs, or health data at real volume - a healthcare practice, a professional services firm processing ID documents day-to-day - where relying on every staff member to correctly hand-pick Highly Confidential every time isn't realistic. Not for smaller clients or anyone below E5: entries 1+2 (manual taxonomy plus encryption) are the right fit there, not a weaker version of this entry. Requires the encrypted Highly Confidential label from entry 2 to already exist.",
    buildsOn: ["label-highly-confidential-encryption"],
    labels: [
      { name: "Highly Confidential", priority: 3, encrypted: true, contentMarking: true, tooltip: "Auto-applied - detected sensitive identity or health information." },
    ],
    labelPolicySettings: {
      mandatoryLabeling: true,
      requireDowngradeJustification: true,
      locations: ["SharePoint sites", "OneDrive accounts", "Exchange email"],
    },
    autoLabeling: {
      targetLabelName: "Highly Confidential",
      sitReferences: [
        "South Africa Identification Number",
        "U.S. Social Security Number (SSN)",
        "UK National Insurance Number (NINO)",
        "International Classification of Diseases (ICD-9-CM)",
        "International Classification of Diseases (ICD-10-CM)",
      ],
      mode: "Test with notifications",
    },
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Information protection -> Auto-labeling policies -> Create auto-labeling policy." },
      { step: 2, instruction: "Choose \"Custom\" -> select the \"Highly Confidential\" label (already encrypted, per the Highly Confidential Encryption recommendation)." },
      { step: 3, instruction: "Choose locations: SharePoint sites, OneDrive accounts, Exchange email." },
      { step: 4, instruction: "Create a rule: condition \"Content contains\" -> add South Africa Identification Number, U.S. Social Security Number (SSN), UK National Insurance Number (NINO) (group operator OR) - the same identifiers this catalog's identity DLP recommendations already use." },
      { step: 5, instruction: "Create a second rule (or an AND group within the same rule) for ICD-9-CM/ICD-10-CM combined with any of the identifiers above, for the health-context case." },
      { step: 6, instruction: "Set the policy to \"Test it out first\" -> \"Turn it on right away, but keep it in test mode\" - the same three-state convention DLP recommendations in this catalog already use." },
      { step: 7, instruction: "Review Activity Explorer for 2-4 weeks before promoting to Enable." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - see the catalog-wide caveat.

Connect-IPPSSession

New-AutoSensitivityLabelPolicy -Name "${prefix} - Auto-Label Identity & Health Data" \`
    -SharePointLocation All \`
    -OneDriveLocation All \`
    -ExchangeLocation All \`
    -ApplySensitivityLabel "HighlyConfidential" \`
    -Mode TestWithNotifications \`
    -Comment "Auto-apply Highly Confidential to detected identity/health data - generated by Clarity365 (unverified, review before enabling)"

New-AutoSensitivityLabelRule -Name "${prefix} - Identity data detected" \`
    -Policy "${prefix} - Auto-Label Identity & Health Data" \`
    -ContentContainsSensitiveInformation @(
        @{Name="South Africa Identification Number"; minCount="1"},
        @{Name="U.S. Social Security Number (SSN)"; minCount="1"},
        @{Name="UK National Insurance Number (NINO)"; minCount="1"}
    )

Write-Host "Created in test mode - review Activity Explorer for 2-4 weeks before promoting with Set-AutoSensitivityLabelPolicy -Mode Enable." -ForegroundColor Yellow`,
    regulationRefs: [
      { citation: "POPIA s.19/s.26", note: "Security safeguards and special personal information (health)." },
      { citation: "GDPR/UK GDPR Art. 9/32", note: "Special category data and security of processing." },
      { citation: "HIPAA 45 CFR 164.312(a)(2)(iv)", note: "Encryption, applied automatically rather than depending on a user's judgment." },
    ],
    caveats: [
      "PowerShell template is unverified against a live tenant - see the catalog-wide note.",
      "No Business Premium/E3 version is offered - see the 2026-09-22 decision recorded in the Sensitivity Labels Catalog Plan, the same call already made for the ip_contracts DLP entry. The correct fallback below E5 is the manual baseline taxonomy entry, not an imitation of automation.",
      "Auto-labeling policies can take longer to reflect on already-existing content than newly created content - a full tenant content scan is not instantaneous.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice.",
    ],
    relatedRecommendationIds: ["hipaa-phi", "popia-sa-id-and-health", "gdpr-uk-government-id-and-special-category"],
  },
  {
    id: "label-container-labels",
    kind: "label",
    title: "Extend labels to Teams, groups and SharePoint sites (container labels)",
    regulations: [],
    dataCategories: [],
    minimumLicenseTier: "business_premium_e3",
    summary:
      "Everything else in this catalog labels documents and email. Container labels apply the same taxonomy to the container itself - a Team, a Microsoft 365 group, or a SharePoint site - governing settings like whether the team is public or private and whether guests can be added, not just what's inside it.",
    recommendedFor:
      "Clients who collaborate heavily through Teams and SharePoint sites and need to control the container's own settings by sensitivity - not just what's inside individual documents. Particularly relevant for a client running a sensitive external-facing project (an M&A deal team, a project site shared with an outside contractor) where the whole site needs locking down, not just the files in it. Less relevant for a client that barely uses Teams/SharePoint sites for collaboration. Requires the baseline taxonomy already deployed.",
    buildsOn: ["label-baseline-taxonomy"],
    labels: [
      { name: "Confidential (container)", priority: 2, encrypted: false, contentMarking: false, tooltip: "Applied to a Team, group, or site - not a document." },
      { name: "Highly Confidential (container)", priority: 3, encrypted: false, contentMarking: false, tooltip: "Applied to a Team, group, or site - not a document." },
    ],
    labelPolicySettings: {
      mandatoryLabeling: false,
      requireDowngradeJustification: false,
      locations: ["Microsoft 365 groups & Teams"],
    },
    portalSteps: [
      { step: 1, instruction: "Go to https://compliance.microsoft.com -> Information protection -> Labels -> select the Confidential label (or create dedicated container-scoped labels, as listed here) -> Edit label." },
      { step: 2, instruction: "Under \"Define protection settings for groups and sites\", turn this on and configure privacy (Private/Public), whether unmanaged devices can access, and whether external users/guests are allowed." },
      { step: 3, instruction: "Repeat for the Highly Confidential container label with stricter settings (Private, no guests)." },
      { step: 4, instruction: "Go to Label policies -> edit the existing policy (or create one) -> add \"Groups & sites\" as a location for these container labels." },
      { step: 5, instruction: "Publish. New Teams/groups/sites will prompt for a label at creation; existing ones need to be labeled manually or via a script." },
    ],
    powershellTemplate: (prefix) => `# UNVERIFIED - see the catalog-wide caveat. Container-label group/site
# protection settings are configured with a distinct set of parameters from
# document labels - confirm the exact shape in the portal's label editor
# before relying on this script; this is one of the less-verified corners of
# this catalog, similar in spirit to the encryption entry above.

Connect-IPPSSession

Set-Label -Identity "Confidential" \`
    -SiteAndGroupProtectionEnabled $true \`
    -SiteAndGroupProtectionPrivacy "Private" \`
    -SiteAndGroupProtectionAllowAccessFromUnmanagedDevice "BlockAccess" \`
    -SiteAndGroupProtectionAllowEmailFromGuestUsers $false

Write-Host "Review privacy, unmanaged-device, and guest-access settings above before applying to real teams/sites." -ForegroundColor Yellow`,
    e5Enhancements: [
      "Defender for Cloud Apps session policies can enforce container-label-aware restrictions in real time (e.g. blocking downloads from a Highly Confidential site on an unmanaged device), beyond what the label's own settings do alone.",
    ],
    regulationRefs: [
      { citation: "POPIA s.19 / GDPR Art. 32 / HIPAA Security Rule (general)", note: "Access control extended to collaboration surfaces, not just documents." },
    ],
    caveats: [
      "PowerShell template is unverified, and container-label settings are among the least confidently verified parts of this catalog - use the portal as the primary path.",
      "Requires Entra ID P1 for the label's group/site settings to actually take effect - this was not independently re-verified live or against current Microsoft documentation in this session; confirm before presenting it to a client as a firm prerequisite.",
      "Only new Teams/groups/sites are prompted for a label at creation - existing ones need a separate manual or scripted labeling pass.",
      "This is a technical-to-legal mapping for engineering purposes, not legal advice.",
    ],
  },
];
