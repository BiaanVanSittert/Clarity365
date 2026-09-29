// Fills a real, live-verified gap in Microsoft's own Secure Score remediation
// text: for many controls (confirmed live against Coetzee Architects - 22 of
// 41 open controls, ~54%) `secureScoreControlProfiles.remediation` names the
// exact setting/toggle to change but never says which admin portal or blade
// it lives on. e.g. "mdo_phishthresholdlevel" says to set the "Phishing email
// threshold" option to 2 or 3 "by either updating your existing policies or
// creating new ones" - never once mentioning the Microsoft Defender Portal.
//
// This is authored content Microsoft's catalog doesn't provide, layered on
// top of (not replacing) Graph's own remediation text - the drawer renders
// this "where to go" block first, then Graph's "what to set" text below it.
// Keyed by the real Graph controlName, confirmed live, not the Excel export's
// display names. Scoped deliberately to controls found weak on a live audit,
// not Microsoft's entire ~460-control catalog - extend this map as new gaps
// are spotted on other tenants, the same way baseline-definitions.ts's CA
// PowerShell templates grew one baseline at a time.
export interface SecureScoreRemediationGuide {
  portalName: string;
  url: string;
  navPath: string[];
}

const MDO_ANTI_PHISHING: SecureScoreRemediationGuide = {
  portalName: "Microsoft Defender Portal",
  url: "https://security.microsoft.com/antiphishing",
  navPath: ["Email & collaboration", "Policies & rules", "Threat policies", "Anti-phishing", "edit the default policy (or create one), then open its Actions section"],
};

const MDO_ANTI_SPAM_INBOUND: SecureScoreRemediationGuide = {
  portalName: "Microsoft Defender Portal",
  url: "https://security.microsoft.com/antispam",
  navPath: ["Email & collaboration", "Policies & rules", "Threat policies", "Anti-spam", "Anti-spam inbound policy (Default)"],
};

const MDO_ANTI_MALWARE: SecureScoreRemediationGuide = {
  portalName: "Microsoft Defender Portal",
  url: "https://security.microsoft.com/antimalwarev2",
  navPath: ["Email & collaboration", "Policies & rules", "Threat policies", "Anti-malware"],
};

const MDO_SAFE_ATTACHMENTS: SecureScoreRemediationGuide = {
  portalName: "Microsoft Defender Portal",
  url: "https://security.microsoft.com/safeattachmentv2",
  navPath: ["Email & collaboration", "Policies & rules", "Threat policies", "Safe Attachments"],
};

const MDO_SAFE_ATTACHMENTS_GLOBAL: SecureScoreRemediationGuide = {
  portalName: "Microsoft Defender Portal",
  url: "https://security.microsoft.com/safeattachmentv2",
  navPath: ["Email & collaboration", "Policies & rules", "Threat policies", "Safe Attachments", "Global settings (scroll to Safe Documents)"],
};

const PURVIEW_LABEL_POLICIES: SecureScoreRemediationGuide = {
  portalName: "Microsoft Purview Compliance Portal",
  url: "https://compliance.microsoft.com/informationprotection",
  navPath: ["Solutions", "Information protection", "Label policies"],
};

const PURVIEW_AUTO_LABELING: SecureScoreRemediationGuide = {
  portalName: "Microsoft Purview Compliance Portal",
  url: "https://compliance.microsoft.com/informationprotection",
  navPath: ["Solutions", "Information protection", "Auto-labeling"],
};

const PURVIEW_DATA_MAP: SecureScoreRemediationGuide = {
  portalName: "Microsoft Purview Compliance Portal",
  url: "https://compliance.microsoft.com/informationprotection",
  navPath: ["Information protection", "Data map settings", "Extend labeling to assets"],
};

const EXO_POWERSHELL_ONLY: SecureScoreRemediationGuide = {
  portalName: "Exchange admin center",
  url: "https://admin.exchange.microsoft.com/",
  navPath: ["No GUI toggle for this setting", "connect via Connect-ExchangeOnline", "run the PowerShell command below"],
};

export const SECURE_SCORE_REMEDIATION_GUIDES: Record<string, SecureScoreRemediationGuide> = {
  mdo_phisspamacation: MDO_ANTI_SPAM_INBOUND,
  mdo_allowedsenderscombined: MDO_ANTI_SPAM_INBOUND,
  mdo_bulkthreshold: MDO_ANTI_SPAM_INBOUND,
  mdo_commonattachmentsfilter: MDO_ANTI_MALWARE,
  mdo_safeattachments: MDO_SAFE_ATTACHMENTS,
  mdo_safedocuments: MDO_SAFE_ATTACHMENTS_GLOBAL,
  mdo_mailboxintelligenceprotection: MDO_ANTI_PHISHING,
  mdo_mailboxintelligenceprotectionaction: MDO_ANTI_PHISHING,
  mdo_enabledomainstoprotect: MDO_ANTI_PHISHING,
  mdo_phishthresholdlevel: MDO_ANTI_PHISHING,
  mdo_similardomainssafetytips: MDO_ANTI_PHISHING,
  mdo_similaruserssafetytips: MDO_ANTI_PHISHING,
  mdo_targeteddomainprotectionaction: MDO_ANTI_PHISHING,
  mdo_targeteduserprotectionaction: MDO_ANTI_PHISHING,
  mdo_targetedusersprotection: MDO_ANTI_PHISHING,
  mdo_unusualcharacterssafetytips: MDO_ANTI_PHISHING,
  mip_sensitivitylabelspolicies: PURVIEW_LABEL_POLICIES,
  mip_autosensitivitylabelspolicies: PURVIEW_AUTO_LABELING,
  mip_purviewlabelconsent: PURVIEW_DATA_MAP,
  exo_mailtipsenabled: EXO_POWERSHELL_ONLY,
  exo_mailboxaudit: EXO_POWERSHELL_ONLY,
  exo_storageproviderrestricted: EXO_POWERSHELL_ONLY,
};

export function getSecureScoreRemediationGuide(controlId: string): SecureScoreRemediationGuide | undefined {
  return SECURE_SCORE_REMEDIATION_GUIDES[controlId];
}
