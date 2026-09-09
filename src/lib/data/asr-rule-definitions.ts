// Microsoft Defender Attack Surface Reduction (ASR) rules reference data.
// Verified against Microsoft Learn's "Attack surface reduction rules
// reference" (https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference):
// GUIDs, Advanced Hunting DeviceEvents ActionType names, and per-rule
// Warn-mode/telemetry support are all real, not placeholders.
export interface AsrRuleDefinition {
  id: string; // GUID Intune/Graph identifies the rule by
  name: string;
  description: string;
  riskMitigated: string;
  category: "standard" | "other";
  // Both false only for "Block Webshell creation for Servers" and both true
  // is the common case; the two LSASS/Office-injection rules support Block
  // and Audit but not Warn.
  supportsWarnMode: boolean;
  hasAdvancedHuntingTelemetry: boolean;
  advancedHuntingActionTypes: string[];
  // Plain-text guidance shown in the rule drawer before any auto-deploy
  // write path exists (and alongside it once one does) - PowerShell for
  // local/single-device testing plus the Intune portal click-path, since
  // unlike a Conditional Access policy an ASR rule has no single
  // domain-parameterized script that fully deploys it tenant-wide.
  manualSetupGuidance: string;
}

const INTUNE_STEPS =
  "Intune admin center > Endpoint security > Attack surface reduction > Create Policy > Windows 10 and later > Attack Surface Reduction Rules > set this rule to Audit > assign to a pilot group first.";

export const ASR_RULE_DEFINITIONS: AsrRuleDefinition[] = [
  // Standard protection rules - Microsoft's own curated "enable these first" set.
  {
    id: "56a863a9-875e-4185-98a7-b882c64b5ce5",
    name: "Block abuse of exploited vulnerable signed drivers",
    description:
      "Prevents apps from saving a vulnerable signed driver to disk, where it could later be loaded to gain kernel-level access and disable security tooling.",
    riskMitigated: "BYOVD (bring your own vulnerable driver) attacks used to blind or disable EDR/AV.",
    category: "standard",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrVulnerableSignedDriverAudited", "AsrVulnerableSignedDriverBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    name: "Block credential stealing from the Windows local security authority subsystem",
    description:
      "Locks down LSASS so tools like Mimikatz can't scrape cleartext passwords and NTLM hashes from process memory.",
    riskMitigated: "Credential theft and lateral movement following an initial foothold.",
    category: "standard",
    supportsWarnMode: false,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrLsassCredentialTheftAudited", "AsrLsassCredentialTheftBlocked"],
    manualSetupGuidance: `Not applicable if LSA Protection and Credential Guard are already enabled (they provide equivalent protection). Otherwise:\n\nPowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}\n\nNote: this rule is noisy in Audit mode (many benign processes touch LSASS). Microsoft's own guidance is that it's often safe to skip straight to Block after a short pilot.`,
  },
  {
    id: "e6db77e5-3df2-4cf1-b95a-636979351e5b",
    name: "Block persistence through WMI event subscription",
    description: "Stops fileless malware from using WMI event subscriptions to survive a reboot undetected.",
    riskMitigated: "Fileless persistence techniques that evade file-based detection.",
    category: "standard",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrPersistenceThroughWmiAudited", "AsrPersistenceThroughWmiBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}\n\nNote: if you use Configuration Manager, test extensively in Audit first - the CM client itself relies heavily on WMI.`,
  },

  // Other ASR rules.
  {
    id: "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    name: "Block Adobe Reader from creating child processes",
    description: "Prevents Adobe Reader from spawning child processes, a common PDF-exploit payload delivery step.",
    riskMitigated: "Malicious PDF attachments breaking out of the reader to run a downloaded payload.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrAdobeReaderChildProcessAudited", "AsrAdobeReaderChildProcessBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    name: "Block all Office applications from creating child processes",
    description: "Blocks Word, Excel, PowerPoint, OneNote, and Access from spawning child processes.",
    riskMitigated: "Malicious macros launching PowerShell, cmd, or a downloaded payload.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrOfficeChildProcessAudited", "AsrOfficeChildProcessBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}\n\nNote: some line-of-business add-ins legitimately spawn child processes (e.g. PowerShell for registry configuration) - review Audit hits before enforcing.`,
  },
  {
    id: "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    name: "Block executable content from email client and webmail",
    description:
      "Blocks executables, scripts, and archives opened directly from Outlook, Outlook.com, and other webmail providers.",
    riskMitigated: "Malicious attachments run directly from the mail client.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrExecutableEmailContentAudited", "AsrExecutableEmailContentBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "01443614-cd74-433a-b99e-2ecdc07bfc25",
    name: "Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
    description: "Blocks executables that aren't yet well-known, aged, or on a trusted list from launching.",
    riskMitigated: "Brand-new or rare executables, a common signal for freshly-compiled malware.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrUntrustedExecutableAudited", "AsrUntrustedExecutableBlocked"],
    manualSetupGuidance: `Requires cloud-delivered protection to be enabled first.\n\nPowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    name: "Block execution of potentially obfuscated scripts",
    description: "Detects suspicious obfuscation patterns in scripts, a technique used to hide malicious code from review.",
    riskMitigated: "Obfuscated PowerShell/script-based malware evading signature detection.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrObfuscatedScriptAudited", "AsrObfuscatedScriptBlocked"],
    manualSetupGuidance: `Requires cloud-delivered protection to be enabled first.\n\nPowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "d3e037e1-3eb8-44c8-a917-57927947596d",
    name: "Block JavaScript or VBScript from launching downloaded executable content",
    description: "Stops JavaScript/VBScript acting as a downloader that fetches and launches other malware.",
    riskMitigated: "Script-based downloader malware, a common initial-access stage.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrScriptExecutableDownloadAudited", "AsrScriptExecutableDownloadBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "3b576869-a4ec-4529-8536-b80a7769e899",
    name: "Block Office applications from creating executable content",
    description: "Blocks Office apps from saving executable content to disk, a common macro-persistence technique.",
    riskMitigated: "Malicious macros persisting a payload to disk to survive a reboot.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrExecutableOfficeContentAudited", "AsrExecutableOfficeContentBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    name: "Block Office applications from injecting code into other processes",
    description: "Blocks Word, Excel, OneNote, and PowerPoint from injecting code into other running processes.",
    riskMitigated: "Process injection used to masquerade malicious code as a trusted, clean process.",
    category: "other",
    supportsWarnMode: false,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrOfficeProcessInjectionAudited", "AsrOfficeProcessInjectionBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}\n\nNote: Office apps need a restart after this rule's configuration changes take effect.`,
  },
  {
    id: "26190899-1602-49e8-8b27-eb1d0a1ce869",
    name: "Block Office communication application from creating child processes",
    description: "Prevents Outlook from spawning child processes while leaving normal Outlook functionality intact.",
    riskMitigated: "Outlook rules/forms exploits and social-engineering attacks that spawn a payload from Outlook.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrOfficeCommAppChildProcessAudited", "AsrOfficeCommAppChildProcessBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "d1e49aac-8f56-4280-b9ba-993a6d77406c",
    name: "Block process creations originating from PSExec and WMI commands",
    description: "Blocks processes launched via PsExec or WMI, both common remote code execution tools.",
    riskMitigated: "Lateral movement and command-and-control via remote execution tooling.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrPsexecWmiChildProcessAudited", "AsrPsexecWmiChildProcessBlocked"],
    manualSetupGuidance: `Do not enable via Configuration Manager if you rely on it - the CM client relies heavily on WMI.\n\nPowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "33ddedf1-c6e0-47cb-833e-de6133960387",
    name: "Block rebooting machine in Safe Mode",
    description: "Prevents commands like bcdedit and bootcfg from forcing a reboot into Safe Mode, where many security tools run with reduced functionality.",
    riskMitigated: "Ransomware and tampering that relies on disabling security tooling via Safe Mode.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrSafeModeRebootedAudited", "AsrSafeModeRebootBlocked", "AsrSafeModeRebootWarnBypassed"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids 33ddedf1-c6e0-47cb-833e-de6133960387 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    name: "Block untrusted and unsigned processes that run from USB",
    description: "Blocks unsigned or untrusted executables from running directly off a USB drive or SD card.",
    riskMitigated: "Malware spread via infected removable media.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrUntrustedUsbProcessAudited", "AsrUntrustedUsbProcessBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
    name: "Block use of copied or impersonated system tools",
    description: "Blocks executables identified as copies or impersonations of built-in Windows system tools.",
    riskMitigated: "Malware disguising itself as a trusted system tool to evade detection or gain privileges.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrAbusedSystemToolAudited", "AsrAbusedSystemToolBlocked", "AsrAbusedSystemToolWarnBypassed"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "a8f5898e-1dc8-49a9-9878-85004b8a61e6",
    name: "Block Webshell creation for Servers",
    description: "Blocks web shell script creation on Windows Server running Microsoft Exchange.",
    riskMitigated: "Attacker-controlled web shells planted on a compromised Exchange server.",
    category: "other",
    supportsWarnMode: false,
    hasAdvancedHuntingTelemetry: false,
    advancedHuntingActionTypes: [],
    manualSetupGuidance: `Exchange servers only - not applicable to standard Windows client devices. If you don't manage on-premises/hybrid Exchange servers, Microsoft's guidance is to leave this Not Configured rather than set it either way.\n\nPowerShell (single device test, on the Exchange server):\nSet-MpPreference -AttackSurfaceReductionRules_Ids a8f5898e-1dc8-49a9-9878-85004b8a61e6 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}\n\nNote: this rule produces no Advanced Hunting telemetry at all - detection activity can't be reported for it.`,
  },
  {
    id: "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
    name: "Block Win32 API calls from Office macros",
    description: "Prevents VBA macros from calling Win32 APIs directly.",
    riskMitigated: "Macro malware calling Win32 APIs to launch shellcode without writing anything to disk.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrOfficeMacroWin32ApiCallsAudited", "AsrOfficeMacroWin32ApiCallsBlocked"],
    manualSetupGuidance: `PowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}`,
  },
  {
    id: "c1db55ab-c21a-4637-bb3f-a12568109d35",
    name: "Use advanced protection against ransomware",
    description: "Uses client and cloud heuristics to block files that resemble ransomware, including unknown files without an established reputation yet.",
    riskMitigated: "Ransomware, including novel variants without a known signature.",
    category: "other",
    supportsWarnMode: true,
    hasAdvancedHuntingTelemetry: true,
    advancedHuntingActionTypes: ["AsrRansomwareAudited", "AsrRansomwareBlocked"],
    manualSetupGuidance: `Requires cloud-delivered protection to be enabled first.\n\nPowerShell (single device test):\nSet-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions AuditMode\n\n${INTUNE_STEPS}\n\nNote: blocks on benign, unknown files usually resolve on their own as the file's reputation builds. Use a per-rule exclusion if a specific in-house tool doesn't resolve in a timely manner.`,
  },
];
