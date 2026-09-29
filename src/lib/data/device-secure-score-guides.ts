// Authored gap-fill for Device-category Microsoft Secure Score controls -
// all four sub-domains, 113 controls total (the 19 Attack Surface Reduction
// rules are deliberately NOT duplicated here - they already have full
// per-rule guidance in the Attack Surface Reduction Rules module), per an
// explicit user request to build a guide per Device recommendation covering
// what it protects, user impact, and the guide/PowerShell to implement it.
//
// Confirmed live against three tenants with Device-category Secure Score
// data (Axiomatic Consultants, dmafrica, Zubat Nine - 2026-09-22): for every
// one of these controls, Microsoft Graph's own secureScoreControlProfiles
// returns userImpact="Unknown", remediationImpact="Unknown",
// implementationCost="Unknown", zero powershellCommand, zero threats, and a
// remediationSummary that is the SAME generic "go check Vulnerability
// Management > Recommendations, choose remediation or exception options"
// boilerplate for all of them - unlike the MDO controls (see
// secure-score-remediation-guides.ts), Graph gives no per-control
// deployment mechanism or real impact assessment anywhere in this category.
// `description` is the one field that's genuinely good (real, specific, not
// boilerplate) for almost all of them, so it's left alone and shown as-is
// by the drawer; this file fills the three gaps Graph leaves: real user
// impact, the actual admin mechanism (which portal/CSP/PowerShell, not just
// "go to Recommendations"), and a verified command where one safely exists.
//
// Shipped in two passes, per the user's own sequencing choice:
//  1. Defender AV / EDR / Firewall / SmartScreen / WSL (31 controls)
//  2. BitLocker / TPM / Secure Boot / Credential Guard / VBS / LAPS (13 controls)
//  3. Windows local security policy hardening - password/lockout policy,
//     UAC, SMB/NTLM/LDAP hardening, RDP/WinRM/Remote Assistance, Netlogon
//     secure channel, network/ICS hardening, local/built-in accounts,
//     service account hardening, AutoPlay/AutoRun, browser (Chrome/Adobe)
//     policy, and misc Windows hardening (69 controls) - the largest group,
//     and the one with zero pre-existing Clarity365 module to lean on, so
//     every mechanism here is a genuinely new admin path for this app, not
//     a pointer to something already built.
//
// Every mechanism claim here was verified against Microsoft Learn during
// authoring (not asserted from memory), same discipline as the DLP and
// sensitivity label catalogs - see sourceUrls on each entry. Where Microsoft
// Learn itself flags a setting as newer/less-documented (WSL hardening,
// scid_102's Windows 11 22H2+ LSA variant), that's called out as a caveat
// rather than presented with false confidence.
//
// A PowerShell command is included ONLY where Microsoft documents a real,
// safe cmdlet for it. Several controls are deliberately left without one:
// Tamper Protection cannot be turned on via local PowerShell on a managed
// device (that's the point of it), TPM/Secure Boot state is firmware, not
// policy, and several are diagnostic/health signals with no single "run
// this" fix. Overclaiming a PowerShell fix that doesn't really work would be
// worse than leaving the field empty - same principle already applied to
// ip_contracts in the DLP catalog.

export type DeviceControlMechanism =
  | "clarity365_defender_av" // Clarity365 already deploys this exact toggle via its Defender Antivirus Policy (DefenderConfigurationModule.tsx)
  | "clarity365_edr" // Clarity365 already deploys this via its EDR Policy / onboarding status view
  | "clarity365_bitlocker" // Clarity365 already deploys this via its BitLocker Policy
  | "mde_diagnostic" // A health/connectivity signal about the MDE sensor itself, not a single policy toggle
  | "intune_settings_catalog" // A real Intune Settings Catalog / Endpoint Security setting Clarity365 doesn't deploy yet
  | "intune_firewall" // Intune Endpoint Security Firewall profile (Firewall CSP)
  | "intune_account_protection" // Intune Endpoint Security Account Protection profile (Device Guard / LSA / LAPS CSPs)
  | "hardware_firmware" // Device hardware/firmware state - not remotely settable by any Graph/Intune policy
  | "defender_portal_tenant_wide"; // A Microsoft 365 Defender portal tenant-wide toggle, not an Intune device policy

export interface DeviceControlGuide {
  controlId: string;
  /** What actually happens to users/devices if this is enabled - authored because Graph's own userImpact is literally "Unknown" for all 44 of these. */
  userImpact: string;
  mechanism: DeviceControlMechanism;
  /** Where to go when there's a real admin portal path (Intune, Defender portal, etc.). Omitted for hardware_firmware and some mde_diagnostic entries where there's no single blade to point at. */
  portal?: { name: string; url: string; navPath: string[] };
  /** When mechanism is a clarity365_* type, the exact toggle already in that module. */
  clarity365Action?: string;
  powershellCommand?: string;
  /** Shown under the PowerShell block - when set, makes clear the command is for a single/test/unmanaged machine, not a fleet rollout. */
  powershellCaveat?: string;
  caveats: string[];
  sourceUrls: string[];
}

const DEFENDER_AV_POLICY_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Endpoint security", "Antivirus", "Create Policy", "Windows 10, Windows 11, and Windows Server", "Windows Security experience or Microsoft Defender Antivirus profile"],
};

const INTUNE_ASR_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Endpoint security", "Attack surface reduction", "Create Policy", "Windows 10, Windows 11, and Windows Server", "Attack Surface Reduction Rules or Microsoft Defender Antivirus profile"],
};

const INTUNE_FIREWALL_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Endpoint security", "Firewall", "Create Policy", "Windows 10, Windows 11, and Windows Server", "Windows Firewall profile"],
};

const INTUNE_ACCOUNT_PROTECTION_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Endpoint security", "Account protection", "Create Policy", "Windows 10 and later", "Account protection profile"],
};

const INTUNE_DISK_ENCRYPTION_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Endpoint security", "Disk encryption", "Create Policy", "Windows 10 and later", "BitLocker profile"],
};

const DEFENDER_PORTAL_ADVANCED_FEATURES = {
  name: "Microsoft Defender Portal",
  url: "https://security.microsoft.com/preferences2/integration",
  navPath: ["Settings", "Endpoints", "Advanced features"],
};

const MDE_LEARN_SOURCES = ["https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference"];

// ---------------------------------------------------------------------------
// Portal constants for the Windows local security policy hardening group.
// All of these are exposed via Intune's Settings Catalog (which now ingests
// the classic ADMX/GPO-backed "Local Policies Security Options" and
// "Administrative Templates" categories, confirmed live against Microsoft
// Learn during authoring - not the older, separate "Device Restrictions"/
// "Endpoint Protection" template profiles, which are legacy and don't cover
// most of these). Deploying any of these to an Entra-only (non-domain-
// joined) fleet is the normal MSP case this app targets; a few (Netlogon
// secure channel) are flagged where they only matter for domain-joined
// devices specifically.
// ---------------------------------------------------------------------------

const INTUNE_DEVICE_LOCK_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Device Lock\" category"],
};

const INTUNE_LOCAL_SECURITY_UAC_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Local Policies Security Options\" category", "\"User Account Control\" section"],
};

const INTUNE_LOCAL_SECURITY_NETWORK_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Local Policies Security Options\" category", "\"Network access and security\" / \"MSS (Legacy)\" section"],
};

const INTUNE_LOCAL_SECURITY_DOMAIN_MEMBER_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Local Policies Security Options\" category", "\"Domain member\" section"],
};

const INTUNE_RDS_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Remote Desktop Services\" category"],
};

const INTUNE_WINRM_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Windows Remote Management (WinRM)\" category"],
};

const INTUNE_REMOTE_ASSISTANCE_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Remote Assistance\" category"],
};

const INTUNE_AUTOPLAY_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"AutoPlay\" category"],
};

const INTUNE_FIREWALL_RULES_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Endpoint security", "Firewall", "Create Policy", "Windows 10, Windows 11, and Windows Server", "Windows Firewall Rules profile", "add a rule targeting the specific .exe"],
};

const INTUNE_ADMX_IMPORT_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Devices", "Configuration", "Import ADMX", "import the vendor's .admx/.adml first", "then create a Settings Catalog / Imported Administrative Templates profile"],
};

const INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL = {
  name: "Microsoft Intune admin center",
  url: "https://intune.microsoft.com/",
  navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "search for the setting by its exact name below"],
};

export const DEVICE_CONTROL_GUIDES: Record<string, DeviceControlGuide> = {
  // ---------------------------------------------------------------------
  // Group 1: Defender Antivirus core toggles (all 6 map 1:1 to a checkbox
  // already in DefenderConfigurationModule.tsx's Defender Antivirus Policy
  // section - deploying that policy with these boxes checked is the real
  // fix, not a one-off PowerShell run against a fleet).
  // ---------------------------------------------------------------------
  scid_2010: {
    controlId: "scid_2010",
    userImpact: "None for end users when Defender AV is the sole AV engine (Microsoft's default on Windows 10/11 with no other AV installed) - it runs silently. If a third-party AV was ever installed and later removed without a clean uninstall, Defender AV can be left in a disabled/passive state that this control flags; re-enabling it has no user-facing prompt.",
    mechanism: "clarity365_defender_av",
    portal: DEFENDER_AV_POLICY_PORTAL,
    clarity365Action: "Deploy the Defender Antivirus Policy in the Defender Configuration module - Defender AV activates automatically once no conflicting third-party AV is registered with Windows Security Center.",
    powershellCommand: "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled",
    powershellCaveat: "Diagnostic only, for one machine - confirms whether Defender AV is registered as active. If it reports disabled and no other AV is present, uninstall/repair leftover third-party AV remnants (WMI SecurityCenter2 AntiVirusProduct registrations) rather than trying to force Defender on via PowerShell alone.",
    caveats: ["If a third-party AV is intentionally in use, leave this as-is - Clarity365 should never be used to disable a client's chosen AV to chase this score."],
    sourceUrls: ["https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility"],
  },
  scid_2012: {
    controlId: "scid_2012",
    userImpact: "None visible day-to-day - real-time protection scans files as they're accessed, transparently. The only user-facing moment is a brief scan delay on first-run of a new/unrecognized executable, typically under a second.",
    mechanism: "clarity365_defender_av",
    portal: DEFENDER_AV_POLICY_PORTAL,
    clarity365Action: "Deploy the Defender Antivirus Policy in the Defender Configuration module with \"Allow Realtime Monitoring\" checked.",
    powershellCommand: "Set-MpPreference -DisableRealtimeMonitoring $false",
    powershellCaveat: "For one unmanaged/test machine only - on an Intune-managed device this will be re-overwritten by whatever policy is assigned, so the Intune policy above is the real fix for a fleet.",
    caveats: [],
    sourceUrls: MDE_LEARN_SOURCES,
  },
  scid_91: {
    controlId: "scid_91",
    userImpact: "None visible - behavior monitoring watches running processes for suspicious activity patterns (not just file signatures) in the background. No user prompts unless something is actually flagged.",
    mechanism: "clarity365_defender_av",
    portal: DEFENDER_AV_POLICY_PORTAL,
    clarity365Action: "Deploy the Defender Antivirus Policy in the Defender Configuration module with \"Allow Behavior Monitoring\" checked.",
    powershellCommand: "Set-MpPreference -DisableBehaviorMonitoring $false",
    powershellCaveat: "For one unmanaged/test machine only - use the Intune policy above for a fleet.",
    caveats: [],
    sourceUrls: MDE_LEARN_SOURCES,
  },
  scid_2016: {
    controlId: "scid_2016",
    userImpact: "None visible. Cloud-delivered protection sends file metadata (not file content, unless sample submission is separately consented) to Microsoft's cloud for a near-real-time verdict on brand-new threats, ahead of a signature update. Requires outbound internet access to Microsoft's cloud protection endpoints - fully offline devices won't benefit from it.",
    mechanism: "clarity365_defender_av",
    portal: DEFENDER_AV_POLICY_PORTAL,
    clarity365Action: "Deploy the Defender Antivirus Policy in the Defender Configuration module with \"Allow Cloud Protection\" checked.",
    powershellCommand: "Set-MpPreference -MAPSReporting Advanced",
    powershellCaveat: "For one unmanaged/test machine only - use the Intune policy above for a fleet. \"Advanced\" also shares more detection telemetry than \"Basic\"; use Basic if that's a client concern.",
    caveats: [],
    sourceUrls: MDE_LEARN_SOURCES,
  },
  scid_92: {
    controlId: "scid_92",
    userImpact: "A brief scan delay (usually under a second) the first time a newly downloaded file or email attachment is opened. No user prompt unless the file is flagged.",
    mechanism: "clarity365_defender_av",
    portal: DEFENDER_AV_POLICY_PORTAL,
    clarity365Action: "Deploy the Defender Antivirus Policy in the Defender Configuration module with \"Allow scanning of all downloaded files and attachments\" checked.",
    powershellCommand: "Set-MpPreference -DisableIOAVProtection $false",
    powershellCaveat: "For one unmanaged/test machine only - use the Intune policy above for a fleet.",
    caveats: [],
    sourceUrls: MDE_LEARN_SOURCES,
  },
  scid_90: {
    controlId: "scid_90",
    userImpact: "None visible for standard mail clients. Only scans locally-stored mail files (e.g. Outlook .pst/.ost) - it's not a substitute for Exchange Online Protection/Defender for Office 365's mail-flow scanning, which already covers messages in transit.",
    mechanism: "clarity365_defender_av",
    portal: DEFENDER_AV_POLICY_PORTAL,
    clarity365Action: "Deploy the Defender Antivirus Policy in the Defender Configuration module with \"Allow Email Scanning\" checked.",
    powershellCommand: "Set-MpPreference -DisableEmailScanning $false",
    powershellCaveat: "For one unmanaged/test machine only - use the Intune policy above for a fleet.",
    caveats: [],
    sourceUrls: MDE_LEARN_SOURCES,
  },
  scid_89: {
    controlId: "scid_89",
    userImpact: "A full scan takes longer when a USB drive or external disk is attached at scan time. No impact on normal day-to-day USB use (real-time protection, not this setting, covers files as they're opened).",
    mechanism: "clarity365_defender_av",
    portal: DEFENDER_AV_POLICY_PORTAL,
    clarity365Action: "Deploy the Defender Antivirus Policy in the Defender Configuration module with \"Allow Full Scan Removable Drive Scanning\" checked.",
    powershellCommand: "Set-MpPreference -DisableRemovableDriveScanning $false",
    powershellCaveat: "For one unmanaged/test machine only - use the Intune policy above for a fleet.",
    caveats: [],
    sourceUrls: MDE_LEARN_SOURCES,
  },

  // ---------------------------------------------------------------------
  // Group 2: PUA / Network Protection / Controlled Folder Access - real
  // Defender AV settings, confirmed via Set-MpPreference and Intune's
  // Attack Surface Reduction / Antivirus profiles, but NOT currently
  // exposed as a checkbox in Clarity365's Defender Antivirus Policy form -
  // a genuine product gap worth adding there later.
  // ---------------------------------------------------------------------
  scid_2013: {
    controlId: "scid_2013",
    userImpact: "Block mode can stop installation of legitimate-but-borderline software bundled with adware/toolbars (browser extensions, driver-update utilities, etc.) - users occasionally need an admin exception if a client genuinely wants such a tool. Start in Audit mode on a pilot group if you're unsure how much PUA activity exists in this fleet before moving to Block.",
    mechanism: "intune_settings_catalog",
    // PUA protection lives in the same Antivirus profile as the 6 native
    // toggles above, unlike Network Protection/Controlled Folder Access
    // below (which are Attack Surface Reduction profile settings).
    portal: DEFENDER_AV_POLICY_PORTAL,
    powershellCommand: "Set-MpPreference -PUAProtection Enabled",
    powershellCaveat: "Use AuditMode first on a pilot group to see what would be blocked before rolling out Enabled fleet-wide via Intune.",
    caveats: ["Not yet a checkbox in Clarity365's Defender Antivirus Policy form - deploy via the Intune admin center directly, or flag for the next Defender Configuration module update."],
    sourceUrls: [
      "https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference",
      "https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus",
    ],
  },
  scid_96: {
    controlId: "scid_96",
    userImpact: "Blocks outbound connections to low-reputation domains/IPs system-wide, for any application - not just the browser. A small number of legitimate but obscure or newly-registered business sites can occasionally be caught; audit mode first shows what would be blocked without actually blocking it.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_ASR_PORTAL,
    powershellCommand: "Set-MpPreference -EnableNetworkProtection Enabled",
    powershellCaveat: "Use AuditMode first on a pilot group to see what would be blocked before rolling out Enabled fleet-wide via Intune. Only applies to Windows 10 version 1709+.",
    caveats: [],
    sourceUrls: [
      "https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection",
      "https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference",
    ],
  },
  scid_2021: {
    controlId: "scid_2021",
    userImpact: "Can block legitimate apps (older LOB software, some backup/sync tools) from writing to protected folders (Documents, Pictures, Desktop, etc. by default) until explicitly allowed - this is the single most likely Defender AV setting in this whole group to generate a helpdesk ticket if enabled without a pilot. Start in Audit mode and review the Microsoft Defender Portal's Controlled Folder Access events before switching to Enabled.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_ASR_PORTAL,
    powershellCommand: "Set-MpPreference -EnableControlledFolderAccess AuditMode",
    powershellCaveat: "Start with AuditMode, review blocked-app events in the Microsoft Defender Portal for at least a week, add legitimate apps to the allow list, then switch to Enabled via Intune for the fleet.",
    caveats: ["Requires Defender AV real-time protection to be on (see scid_2012) - it has no effect if real-time protection is disabled."],
    sourceUrls: [
      "https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference",
      "https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure",
    ],
  },

  // ---------------------------------------------------------------------
  // Group 3: Tamper Protection - deliberately no PowerShell command; once
  // on, Tamper Protection specifically blocks local PowerShell/registry
  // changes to Defender settings, so offering a "run this" fix would be
  // both wrong and self-defeating.
  // ---------------------------------------------------------------------
  scid_2003: {
    controlId: "scid_2003",
    userImpact: "None for normal use. The one real effect: local admins (including your own remote-support sessions) can no longer disable Defender AV/real-time protection/cloud protection from the Windows Security app, PowerShell, or the registry - only Intune or the tenant-wide Defender portal toggle can change those settings once this is on. Plan around that before enabling on a device you troubleshoot AV issues on locally.",
    mechanism: "defender_portal_tenant_wide",
    portal: DEFENDER_PORTAL_ADVANCED_FEATURES,
    powershellCommand: undefined,
    caveats: [
      "No supported PowerShell/registry method turns this on for a managed device - that's the point of the control. Enable it via an Intune Antivirus policy's \"Windows security experience\" profile (Tamper protection = On), or tenant-wide from the Defender portal above (requires MDE P1/P2).",
      "Devices must be onboarded to Microsoft Defender for Endpoint (see scid_20000) before this applies.",
    ],
    sourceUrls: ["https://learn.microsoft.com/en-us/defender-endpoint/manage-tamper-protection-intune"],
  },

  // ---------------------------------------------------------------------
  // Group 4: MDE sensor / EDR health & onboarding - diagnostic signals
  // about the sensor itself, layered on Clarity365's existing EDR Policy +
  // onboarding status view rather than a single new toggle.
  // ---------------------------------------------------------------------
  scid_20000: {
    controlId: "scid_20000",
    userImpact: "None for normal use once onboarded - the sensor runs as a background service. Initial onboarding briefly increases CPU/disk activity as the device baselines.",
    mechanism: "clarity365_edr",
    clarity365Action: "The Defender Configuration module's onboarding status table (per-device) and EDR Policy \"Auto from connector\" toggle are exactly this - a device shows here as not onboarded until it picks up the EDR policy or is manually onboarded.",
    caveats: ["A device stuck \"Not Assigned\"/\"Not Onboarded\" for a long time usually means it isn't in the assigned Intune group for the EDR policy, not a sensor problem - check group assignment before troubleshooting the sensor itself."],
    sourceUrls: ["https://learn.microsoft.com/en-us/defender-endpoint/onboard-configure"],
  },
  scid_2000: {
    controlId: "scid_2000",
    userImpact: "None for normal use - same background sensor as scid_20000; this control specifically checks the sensor is running and reporting, not just that onboarding was attempted.",
    mechanism: "clarity365_edr",
    clarity365Action: "Same EDR Policy / onboarding status view as scid_20000 - resolve onboarding gaps there first.",
    powershellCommand: "Get-Service -Name Sense | Select-Object Status, StartType",
    powershellCaveat: "Diagnostic only, run locally on the device in question - confirms the Windows Defender Advanced Threat Protection Service (\"Sense\") is running.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/defender-endpoint/onboard-configure"],
  },
  scid_2001: {
    controlId: "scid_2001",
    userImpact: "None - purely a sensor health/telemetry issue, not a user-facing setting.",
    mechanism: "mde_diagnostic",
    portal: { name: "Microsoft Defender Portal", url: "https://security.microsoft.com/machines", navPath: ["Assets", "Devices", "open the affected device", "check Sensor health state"] },
    caveats: ["Usually resolved by the MDE Client Analyzer tool (run locally) rather than a single PowerShell one-liner - it diagnoses proxy/firewall/service issues preventing data from reaching the MDE cloud service."],
    sourceUrls: ["https://learn.microsoft.com/en-us/defender-endpoint/data-collection-analysis"],
  },
  scid_2002: {
    controlId: "scid_2002",
    userImpact: "None directly - devices with impaired communications still run local protection, they just can't report to or receive updates from the MDE cloud service, which weakens detection/response over time.",
    mechanism: "mde_diagnostic",
    portal: { name: "Microsoft Defender Portal", url: "https://security.microsoft.com/machines", navPath: ["Assets", "Devices", "open the affected device", "check Sensor health state"] },
    powershellCommand: "Test-MDATPConnectivity -Server WinAtpConfigTest",
    powershellCaveat: "Run locally on the affected device - checks reachability of MDE's cloud endpoints and flags proxy/firewall blocks. Requires devices to allow the URLs listed in Microsoft's MDE network requirements doc.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/defender-endpoint/configure-proxy-internet"],
  },
  scid_2004: {
    controlId: "scid_2004",
    userImpact: "No change if Defender AV is already the primary/active AV. If a third-party AV is the primary engine, EDR block mode lets Defender for Endpoint's EDR component still quarantine files/behaviors the third-party AV missed - it does not replace or conflict with the third-party AV's own real-time scanning.",
    mechanism: "defender_portal_tenant_wide",
    portal: DEFENDER_PORTAL_ADVANCED_FEATURES,
    caveats: ["Turned on in the Defender portal (Advanced features), not via Intune device policy or PowerShell - it's a per-device MDE setting surfaced tenant-wide from that page, not a Settings Catalog CSP."],
    sourceUrls: ["https://learn.microsoft.com/en-us/defender-endpoint/edr-in-block-mode"],
  },
  scid_2011: {
    controlId: "scid_2011",
    userImpact: "None - definition updates happen silently in the background, typically multiple times a day.",
    mechanism: "mde_diagnostic",
    powershellCommand: "Update-MpSignature",
    powershellCaveat: "Forces an immediate signature update on one machine - a device stuck on old definitions usually points to a connectivity problem (see scid_2014) rather than needing this run repeatedly.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/powershell/module/defender/update-mpsignature"],
  },
  scid_2014: {
    controlId: "scid_2014",
    userImpact: "None directly - a device with broken cloud connectivity still has local signature-based protection, it just can't reach cloud-delivered protection (scid_2016) or get the fastest signature updates.",
    mechanism: "mde_diagnostic",
    powershellCommand: "Get-MpCloudStatus 2>$null; Set-MpPreference -MAPSReporting Advanced # then re-test connectivity",
    powershellCaveat: "Diagnostic first, run locally. If cloud connectivity still fails after confirming MAPSReporting is enabled, the cause is almost always a proxy/firewall blocking Defender's cloud endpoints, not a Defender AV setting - see the network requirements doc.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/defender-endpoint/configure-network-connections-microsoft-defender-antivirus"],
  },

  // ---------------------------------------------------------------------
  // Group 5: Firewall - on/off, the three "secure this profile" bundled
  // recommendations, notification settings, and local-rule-merge settings.
  // All Intune Firewall profile / Firewall CSP, none currently deployed by
  // Clarity365.
  // ---------------------------------------------------------------------
  scid_2070: {
    controlId: "scid_2070",
    userImpact: "None for normal outbound-initiated traffic (web browsing, email, etc. - the firewall allows all outbound by default and only restricts unsolicited inbound). Custom LOB apps that need unsolicited inbound connections (e.g. a peer-to-peer app, a locally-hosted service another device connects to) need an explicit allow rule or they'll be blocked.",
    mechanism: "intune_firewall",
    portal: INTUNE_FIREWALL_PORTAL,
    powershellCommand: "Set-NetFirewallProfile -All -Enabled True",
    powershellCaveat: "For one unmanaged/test machine only - deploy the Intune Firewall profile above for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/firewall"],
  },
  scid_2071: {
    controlId: "scid_2071",
    userImpact: "Same as scid_2070, scoped to the Domain network profile (devices joined to and connected on the corporate AD/Entra network). Custom inbound LOB traffic on the domain network needs an explicit rule.",
    mechanism: "intune_firewall",
    portal: INTUNE_FIREWALL_PORTAL,
    powershellCommand: "Set-NetFirewallProfile -Profile Domain -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow",
    powershellCaveat: "For one unmanaged/test machine only - deploy the Intune Firewall profile above (Domain profile) for a fleet. This bundles the specific settings Microsoft's own \"secure this profile\" check looks for: firewall on, inbound blocked by default.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-firewall-settings"],
  },
  scid_2072: {
    controlId: "scid_2072",
    userImpact: "Same as scid_2071, scoped to the Private network profile (home/trusted networks a laptop connects to off-site).",
    mechanism: "intune_firewall",
    portal: INTUNE_FIREWALL_PORTAL,
    powershellCommand: "Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow",
    powershellCaveat: "For one unmanaged/test machine only - deploy the Intune Firewall profile above (Private profile) for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-firewall-settings"],
  },
  scid_2073: {
    controlId: "scid_2073",
    userImpact: "Same as scid_2071/2072, scoped to the Public network profile (coffee shops, airports, hotel wifi) - the profile where blocking unsolicited inbound matters most, since the network itself isn't trusted.",
    mechanism: "intune_firewall",
    portal: INTUNE_FIREWALL_PORTAL,
    powershellCommand: "Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow",
    powershellCaveat: "For one unmanaged/test machine only - deploy the Intune Firewall profile above (Public profile) for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-firewall-settings"],
  },
  scid_43: {
    controlId: "scid_43",
    userImpact: "Removes the Windows notification balloon a user sees when the firewall blocks a program from listening for inbound connections, on the Domain profile. Mildly reduces user awareness of what's being blocked, but stops help-desk calls asking \"what is this popup\" for routine, expected blocks.",
    mechanism: "intune_firewall",
    portal: INTUNE_FIREWALL_PORTAL,
    powershellCommand: "Set-NetFirewallProfile -Profile Domain -NotifyOnListen False",
    powershellCaveat: "For one unmanaged/test machine only - deploy the Intune Firewall profile above (Domain profile, Disable Notifications = True) for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-firewall-settings"],
  },
  scid_46: {
    controlId: "scid_46",
    userImpact: "Same as scid_43, scoped to the Private profile.",
    mechanism: "intune_firewall",
    portal: INTUNE_FIREWALL_PORTAL,
    powershellCommand: "Set-NetFirewallProfile -Profile Private -NotifyOnListen False",
    powershellCaveat: "For one unmanaged/test machine only - deploy the Intune Firewall profile above (Private profile, Disable Notifications = True) for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-firewall-settings"],
  },
  scid_49: {
    controlId: "scid_49",
    userImpact: "Same as scid_43, scoped to the Public profile.",
    mechanism: "intune_firewall",
    portal: INTUNE_FIREWALL_PORTAL,
    powershellCommand: "Set-NetFirewallProfile -Profile Public -NotifyOnListen False",
    powershellCaveat: "For one unmanaged/test machine only - deploy the Intune Firewall profile above (Public profile, Disable Notifications = True) for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-firewall-settings"],
  },
  scid_50: {
    controlId: "scid_50",
    userImpact: "Prevents a locally-created firewall rule (by a user, an installer, or malware with local admin rights) from being merged with the rules your Intune Firewall policy assigns on the Public profile - the device only enforces the centrally-managed rule set. A legitimate local app that adds its own firewall rule on an untrusted/public network will need that rule added centrally instead of relying on its own installer-created one.",
    mechanism: "intune_firewall",
    portal: INTUNE_FIREWALL_PORTAL,
    powershellCommand: "Set-NetFirewallProfile -Profile Public -AllowLocalFirewallRules False",
    powershellCaveat: "For one unmanaged/test machine only - deploy the Intune Firewall profile above (Public profile, Allow Local Policy Merge = No) for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-firewall-settings"],
  },
  scid_51: {
    controlId: "scid_51",
    userImpact: "Same principle as scid_50, but for connection security (IPsec) rules specifically, on the Public profile - a narrower rule type, so the practical impact is smaller and mostly affects environments using IPsec-based connection rules.",
    mechanism: "intune_firewall",
    portal: INTUNE_FIREWALL_PORTAL,
    powershellCommand: "Set-NetFirewallProfile -Profile Public -AllowLocalIPsecRules False",
    powershellCaveat: "For one unmanaged/test machine only - deploy the Intune Firewall profile above (Public profile, Allow Local Ipsec Policy Merge = No) for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-firewall-settings"],
  },

  // ---------------------------------------------------------------------
  // Group 6: SmartScreen
  // ---------------------------------------------------------------------
  scid_2060: {
    controlId: "scid_2060",
    userImpact: "Users see a full-screen warning before running an unrecognized/unsigned downloaded executable, with a \"more info\" click-through unless bypass is separately blocked. Occasionally flags legitimate but rarely-downloaded internal tools until they build up enough reputation - expect a handful of early questions from users the first week.",
    mechanism: "intune_settings_catalog",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Endpoint security", "Attack surface reduction", "Create Policy", "Windows 10, Windows 11, and Windows Server", "Settings Catalog", "\"Smart Screen\" category", "Configure Windows Defender SmartScreen"] },
    caveats: ["This is the Windows Explorer/App SmartScreen setting, distinct from the Edge browser SmartScreen setting in scid_2061 - both need configuring separately."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/available-settings"],
  },
  scid_2061: {
    controlId: "scid_2061",
    userImpact: "Edge shows a warning page before loading a known-malicious/phishing site or before running an unrecognized download, with a click-through unless bypass is separately blocked. No impact on normal browsing to established sites.",
    mechanism: "intune_settings_catalog",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Endpoint security", "Attack surface reduction", "Create Policy", "Windows 10, Windows 11, and Windows Server", "Settings Catalog", "\"Microsoft Edge\" category", "Configure Microsoft Defender SmartScreen"] },
    caveats: ["Distinct from scid_2060 (the OS-level Explorer/App SmartScreen setting) - both need configuring for full coverage."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/available-settings"],
  },

  // ---------------------------------------------------------------------
  // Group 7: WSL (Windows Subsystem for Linux) - newer, more niche
  // Secure Score controls; flagged with lower confidence per this
  // project's own "verify before claiming" discipline.
  // ---------------------------------------------------------------------
  scid_6100: {
    controlId: "scid_6100",
    userImpact: "Extends Defender for Endpoint's visibility into Linux processes/files running inside WSL2 distros - no impact on Windows-side behavior. Only relevant to devices where developers/admins actually use WSL2; irrelevant on devices that don't have it installed (Windows should still report it as not applicable there, not as an open gap - verify that's actually the case if this appears on a device you don't expect to have WSL).",
    mechanism: "hardware_firmware",
    caveats: [
      "Newer/more niche control than the rest of this group - verify the current install/enable steps against Microsoft's own MDE-for-Linux/WSL documentation before rolling out, rather than relying on this note alone.",
      "Requires the device to have WSL2 installed and a supported Linux distro; the plugin itself is installed inside the distro, not via a Windows-side Intune policy.",
    ],
    sourceUrls: ["https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl"],
  },
  scid_6101: {
    controlId: "scid_6101",
    userImpact: "Blocks WSL from being pointed at a custom/non-Microsoft kernel or launched with custom kernel command-line arguments - relevant only to advanced WSL users doing kernel-level customization, which is uncommon in a typical business fleet. No impact on standard WSL/dev-container usage.",
    mechanism: "intune_settings_catalog",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Windows Subsystem for Linux\" category"] },
    caveats: [
      "Newer/more niche control - the exact Settings Catalog setting names for WSL hardening should be re-verified live against the current catalog (they've evolved across WSL releases) before writing this into a standard baseline.",
    ],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/wsl/enterprise"],
  },

  // ---------------------------------------------------------------------
  // Group 8: BitLocker - the one setting Clarity365 already deploys, plus
  // two operational/readiness checks that aren't really "policy toggles".
  // ---------------------------------------------------------------------
  scid_2090: {
    controlId: "scid_2090",
    userImpact: "First encryption pass runs in the background and can take from under an hour to overnight depending on drive size, with a small, usually unnoticeable performance dip during that window. After that, encryption is fully transparent. Users must record/have access to a recovery key (stored in Entra ID/AD by default) in case of a forgotten password or hardware change - without it, a locked-out device's data is unrecoverable by design.",
    mechanism: "clarity365_bitlocker",
    clarity365Action: "Deploy the BitLocker Policy in the Defender Configuration module with \"Require Device Encryption\" checked (use \"Use Recommended Settings\" for Clarity365's baseline).",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/encrypt-bitlocker-windows"],
  },
  scid_2091: {
    controlId: "scid_2091",
    userImpact: "None for the user - this is a monitoring/operational check, not a new setting. BitLocker protection is automatically suspended by Windows during some firmware/driver updates and BIOS changes and is supposed to auto-resume after; a device stuck \"suspended\" is effectively unencrypted at the volume level until resumed.",
    mechanism: "mde_diagnostic",
    powershellCommand: "Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq \"Off\" } | Resume-BitLocker -MountPoint { $_.MountPoint }",
    powershellCaveat: "Run locally (or via remote PowerShell/RMM script) per device - this is an operational cleanup task, not a one-time Intune policy; the requireDeviceEncryption policy in scid_2090 re-enforces encryption over time but doesn't proactively resume a suspended volume.",
    caveats: ["Worth a recurring scheduled check (RMM script or Intune remediation script) rather than a one-off fix, since suspensions recur after firmware/driver updates."],
    sourceUrls: ["https://learn.microsoft.com/en-us/powershell/module/bitlocker/resume-bitlocker"],
  },
  scid_2093: {
    controlId: "scid_2093",
    userImpact: "None directly - this is a pre-flight compatibility check (TPM presence, partition layout, UEFI vs legacy BIOS), not a setting a user or admin toggles. A device that fails it needs the underlying hardware/firmware issue fixed (see scid_116/scid_112) before BitLocker can be enabled at all.",
    mechanism: "hardware_firmware",
    powershellCommand: "manage-bde -status",
    powershellCaveat: "Diagnostic only, run locally - shows current BitLocker/TPM/partition state so you know which specific prerequisite (TPM, partition, firmware mode) is blocking encryption on that device.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/manage-bde-status"],
  },

  // ---------------------------------------------------------------------
  // Group 9: BitLocker CSP extras - real Intune BitLocker profile settings,
  // not currently exposed in Clarity365's BitLocker Policy form.
  // ---------------------------------------------------------------------
  scid_61: {
    controlId: "scid_61",
    userImpact: "Users must enter a PIN (minimum 6 digits, per this control) at every boot, in addition to Windows sign-in - a real, daily-visible change and the most user-facing setting in this whole group. Forgotten PINs require the BitLocker recovery key to get back in. Only takes effect on devices not yet BitLocker-enabled - it has no effect on an already-encrypted drive.",
    mechanism: "intune_account_protection",
    portal: INTUNE_DISK_ENCRYPTION_PORTAL,
    caveats: [
      "Also requires \"Startup authentication required\" (scid_62) = Yes and \"Compatible TPM startup PIN\" = Required or Allowed in the same profile - the PIN-length setting alone does nothing without it.",
      "Incompatible with fully silent/Autopilot BitLocker enablement, which requires PIN to be Blocked - decide this trade-off (security vs. zero-touch provisioning) per client before deploying.",
    ],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp#systemdrivesminimumpinlength"],
  },
  scid_62: {
    controlId: "scid_62",
    userImpact: "Depends on which sub-option is chosen: TPM-only (Allowed) is invisible to the user; requiring a startup PIN (see scid_61) is a real daily prompt; requiring a startup key means a USB drive must be inserted at every boot, which is disruptive for laptops and rarely used outside high-security scenarios.",
    mechanism: "intune_account_protection",
    portal: INTUNE_DISK_ENCRYPTION_PORTAL,
    caveats: ["Only takes effect the first time BitLocker is enabled on a device - has no effect if the drive is already encrypted; must decrypt and re-enable to apply a new setting."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp#systemdrivesrequirestartupauthentication"],
  },

  // ---------------------------------------------------------------------
  // Group 10: TPM / Secure Boot - hardware and firmware state, not
  // something a Graph/Intune policy can flip remotely.
  // ---------------------------------------------------------------------
  scid_112: {
    controlId: "scid_112",
    userImpact: "None for the user - this is a background firmware update delivered via Windows Update, part of Microsoft's multi-year Secure Boot certificate rollout (the original 2011 certificates expire progressively through 2026-2027). No action needed beyond keeping devices patched and rebooted; there's no Intune/Graph policy that pushes this directly.",
    mechanism: "hardware_firmware",
    portal: { name: "Microsoft Learn", url: "https://support.microsoft.com/en-us/topic/windows-secure-boot-certificate-expiration-and-ca-updates-90b6eee0-9d29-48dd-9ffb-b6f76a213f6f", navPath: ["Secure Boot certificate rollout - read the current guidance before assuming a fix exists"] },
    caveats: ["Devices well behind on Windows updates, or with third-party UEFI/dual-boot configurations, may need manual firmware intervention - confirm against Microsoft's current rollout guidance, since the rollout schedule itself has shifted since it was first announced."],
    sourceUrls: ["https://support.microsoft.com/en-us/topic/windows-secure-boot-certificate-expiration-and-ca-updates-90b6eee0-9d29-48dd-9ffb-b6f76a213f6f"],
  },
  scid_116: {
    controlId: "scid_116",
    userImpact: "None if TPM is already present and enabled (true for virtually all Windows 11-certified hardware from the factory). On older devices where TPM is disabled in UEFI firmware, enabling it requires a firmware settings change - on most business laptops this is a one-time, non-disruptive change, but it does require either physical access or an OEM-specific remote firmware management tool (Dell, HP, and Lenovo all offer Intune-integrated options for their fleets).",
    mechanism: "hardware_firmware",
    powershellCommand: "Get-Tpm",
    powershellCaveat: "Diagnostic only, run locally - reports TPM present/enabled/activated/owned status. There's no remote PowerShell/Intune command that enables TPM in firmware on a device where it's off; that's a firmware-level change.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm"],
  },

  // ---------------------------------------------------------------------
  // Group 11: VBS / HVCI / Credential Guard / LSA Protection - Intune
  // Account Protection profile (Device Guard CSP family), confirmed via
  // Microsoft Learn's own Account protection settings reference.
  // ---------------------------------------------------------------------
  scid_117: {
    controlId: "scid_117",
    userImpact: "None visible for most modern hardware and software - VBS runs transparently using the hypervisor. On older or less common hardware, or with legacy kernel-mode drivers (some VPN clients, some older printer/scanner drivers, some anti-cheat software), VBS can cause driver load failures or compatibility issues - pilot on a representative sample before a fleet-wide rollout.",
    mechanism: "intune_account_protection",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Endpoint security", "Account protection", "Create Policy", "Windows 10 and later", "Settings Catalog", "\"Device Guard\" category", "Turn On Virtualization Based Security"] },
    caveats: ["Prerequisite for both Credential Guard (scid_2080) and Memory Integrity/HVCI (scid_118) - enable this first."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"],
  },
  scid_118: {
    controlId: "scid_118",
    userImpact: "Real risk of driver-related boot failures if rolled out without checking compatibility first - Microsoft's own guidance (confirmed in the live control description) is to run the HVCI Readiness Scanner before enabling broadly. On hardware without MBEC/GMET support, HVCI runs in software emulation with roughly 5-15% CPU overhead on kernel-intensive workloads. Pilot, don't push tenant-wide on day one.",
    mechanism: "intune_account_protection",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Endpoint security", "Account protection", "Create Policy", "Windows 10 and later", "Settings Catalog", "\"Virtualization Based Technology\" category", "Hypervisor Enforced Code Integrity"] },
    caveats: ["Requires Virtualization Based Security (scid_117) to be enabled first.", "Run Microsoft's HVCI Readiness Scanner on a representative device sample before a fleet rollout - this is the one Device control in this group where skipping a pilot has a real chance of breaking a device's boot."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"],
  },
  scid_2080: {
    controlId: "scid_2080",
    userImpact: "None visible for normal sign-in - Credential Guard isolates credential material in a separate protected process transparently. Requires Secure Boot and DMA protection support in hardware; devices that don't meet those requirements simply won't have Credential Guard turn on, without breaking anything.",
    mechanism: "intune_account_protection",
    portal: INTUNE_ACCOUNT_PROTECTION_PORTAL,
    caveats: ["Choose \"Enable with UEFI lock\" for the strongest setting (requires physical presence to turn off) unless there's a specific operational reason a technician needs to disable it remotely - most MSP fleets should use UEFI lock."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure"],
  },
  scid_25: {
    controlId: "scid_25",
    userImpact: "None visible for normal use - forces the Local Security Authority process to run as a Protected Process Light (PPL), which blocks unsigned/untrusted code from reading credential material out of LSASS memory. The one real compatibility risk: some older/unsigned third-party security or credential-provider software (some legacy antivirus, some VPN clients) may fail to load once this is on - check compatibility before a fleet rollout.",
    mechanism: "intune_account_protection",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Endpoint security", "Account protection", "Create Policy", "Windows 10 and later", "Settings Catalog", "\"Local Security Authority\" category", "Configure LSA Protected Process"] },
    caveats: ["This is the general/legacy LSA protection mechanism (RunAsPPL) - see scid_102 for Microsoft's newer Windows 11 22H2+-specific variant of the same underlying protection."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"],
  },
  scid_102: {
    controlId: "scid_102",
    userImpact: "Same protection and same compatibility caveat as scid_25 (unsigned third-party credential-provider software may fail to load) - this control specifically tracks Microsoft's newer, Windows 11 22H2+ enforcement surface for LSA protection, introduced as its own Secure Score check because Microsoft phased the feature in by OS build.",
    mechanism: "intune_account_protection",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Endpoint security", "Account protection", "Create Policy", "Windows 10 and later", "Settings Catalog", "\"Local Security Authority\" category", "Configure LSA Protected Process"] },
    caveats: [
      "On a device running Windows 11 22H2 or later, the same Settings Catalog \"Configure LSA Protected Process\" setting used for scid_25 should satisfy this control too - the split into two separate Secure Score controls reflects Microsoft's OS-version-gated rollout, not two different settings to configure.",
      "Verify both scid_25 and scid_102 clear together on a test device after deploying, rather than assuming - this control's exact scoring boundary wasn't independently confirmed live in this pass.",
    ],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"],
  },

  // ---------------------------------------------------------------------
  // Group 12: Windows LAPS
  // ---------------------------------------------------------------------
  scid_113: {
    controlId: "scid_113",
    userImpact: "None visible to end users - local admin passwords rotate automatically and silently in the background. IT/helpdesk workflow does change: technicians must retrieve the current local admin password from Entra ID (or AD) per device instead of using a shared/known password - budget time to update runbooks and RMM scripts that assume a static local admin credential.",
    mechanism: "intune_account_protection",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Endpoint security", "Account protection", "Create Policy", "Windows 10 and later", "Local admin password solution (Windows LAPS)"] },
    caveats: [
      "Prerequisite: Entra ID → Devices → Device settings → \"Local administrator password solution (Windows LAPS)\" must be set to Yes before any Intune LAPS policy takes effect.",
      "Assign one LAPS policy per device via device groups, not user groups - devices that receive multiple conflicting LAPS policies can fail to process policy at all.",
      "Doesn't create a new admin account or password on its own - it manages rotation/backup for an account that already exists on the device.",
    ],
    sourceUrls: ["https://learn.microsoft.com/en-us/intune/intune-service/protect/laps-deploy-policy"],
  },

  // =======================================================================
  // GROUP 3: Windows local security policy hardening (69 controls) -
  // password/lockout policy, UAC, SMB/NTLM/LDAP hardening, RDP/WinRM/Remote
  // Assistance, Netlogon secure channel, network/ICS hardening, local
  // accounts, service account hardening, AutoPlay/AutoRun, browser policy,
  // and misc Windows hardening. All confirmed against Microsoft Learn/
  // Intune's Settings Catalog reference during authoring - see sourceUrls.
  // =======================================================================

  // -----------------------------------------------------------------------
  // Group A: Password & account lockout policy (Device Lock CSP / Settings
  // Catalog "Device Lock" category). Local accounts only - Entra ID user
  // accounts are governed by Entra password/lockout policy or a Conditional
  // Access + Identity Protection risk policy instead, not this category.
  // -----------------------------------------------------------------------
  scid_32: {
    controlId: "scid_32",
    userImpact: "Local account passwords (the built-in Administrator, LAPS-managed account, and any other local accounts) must be 14+ characters. Does not affect Entra ID sign-in passwords - those follow Entra's own password policy or, better, phishing-resistant MFA instead of relying on password length at all.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_DEVICE_LOCK_PORTAL,
    powershellCommand: "net accounts /minpwlen:14",
    powershellCaveat: "Local machine only, for a quick test - deploy via the Intune Device Lock profile for a fleet; local `net accounts` changes don't survive a fresh Autopilot/re-image and aren't centrally auditable.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock"],
  },
  scid_33: {
    controlId: "scid_33",
    userImpact: "None visible day-to-day - this only stops a local account from cycling back to a recently-used password. Only matters on devices where a local account's password is changed repeatedly (uncommon once Windows LAPS, see scid_113, is managing rotation automatically).",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_DEVICE_LOCK_PORTAL,
    powershellCommand: "net accounts /uniquepw:24",
    powershellCaveat: "Local machine only, for a quick test - deploy via the Intune Device Lock profile for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock"],
  },
  scid_34: {
    controlId: "scid_34",
    userImpact: "Forces a local account password change at least every 60 days. If Windows LAPS (scid_113) already manages that account's rotation automatically, this setting is largely redundant for it - most relevant on any local account LAPS doesn't cover.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_DEVICE_LOCK_PORTAL,
    powershellCommand: "net accounts /maxpwage:60",
    powershellCaveat: "Local machine only, for a quick test - deploy via the Intune Device Lock profile for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock"],
  },
  scid_35: {
    controlId: "scid_35",
    userImpact: "None visible - prevents a user from immediately cycling a local password back to its previous value to defeat password history (scid_33). Rarely noticed unless someone is actively trying to bypass history.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_DEVICE_LOCK_PORTAL,
    powershellCommand: "net accounts /minpwage:1",
    powershellCaveat: "Local machine only, for a quick test - deploy via the Intune Device Lock profile for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock"],
  },
  scid_41: {
    controlId: "scid_41",
    userImpact: "A locked-out local account stays locked for at least 15 minutes before auto-unlocking - a real, if infrequent, user-facing wait for anyone who mistypes a local password enough times to trigger scid_44's threshold.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_DEVICE_LOCK_PORTAL,
    powershellCommand: "net accounts /lockoutduration:15",
    powershellCaveat: "Local machine only, for a quick test - deploy via the Intune Device Lock profile for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock"],
  },
  scid_42: {
    controlId: "scid_42",
    userImpact: "None visible - controls how long the failed-attempt counter is remembered before resetting, not whether a lockout happens at all. Works together with scid_41/scid_44.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_DEVICE_LOCK_PORTAL,
    powershellCommand: "net accounts /lockoutwindow:15",
    powershellCaveat: "Local machine only, for a quick test - deploy via the Intune Device Lock profile for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock"],
  },
  scid_44: {
    controlId: "scid_44",
    userImpact: "A user who mistypes a local account password too many times (1-10, per this control) gets locked out for the duration set in scid_41. The real-world tradeoff: too low a threshold increases accidental self-lockouts; Microsoft's own guidance favors a value in the middle of that range (around 5) rather than the minimum.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_DEVICE_LOCK_PORTAL,
    powershellCommand: "net accounts /lockoutthreshold:5",
    powershellCaveat: "Local machine only, for a quick test - deploy via the Intune Device Lock profile for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock"],
  },
  scid_71: {
    controlId: "scid_71",
    userImpact: "None for normal use - a local account with a genuinely blank password can only sign in at the physical console, not over the network/RDP, once this is on. Only relevant if any local account is deliberately left without a password (uncommon, and worth fixing directly rather than relying on this control alone).",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-limit-local-account-use-of-blank-passwords"],
  },

  // -----------------------------------------------------------------------
  // Group B: UAC and elevation
  // -----------------------------------------------------------------------
  scid_27: {
    controlId: "scid_27",
    userImpact: "A standard (non-admin) user who triggers a UAC elevation prompt sees it fail outright instead of getting an admin-credential prompt - they must ask an admin to perform the action instead. Meaningful day-to-day friction on any fleet where standard users occasionally need to install software themselves; confirm the actual admin/standard-user split in this fleet before deploying broadly.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_UAC_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-behavior-of-the-elevation-prompt-for-standard-users"],
  },
  scid_52: {
    controlId: "scid_52",
    userImpact: "None for interactive/console use - only affects local accounts connecting over the network (e.g. remote admin shares), forcing them to authenticate as a standard user's token rather than full admin, even if the account is a local admin. Can break legacy remote-admin tooling that assumes full-admin tokens over the network for local accounts - test against any RMM/remote-support tooling that logs in with a local admin account before a fleet rollout.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_UAC_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-apply-uac-restrictions-to-local-accounts-on-network-logons"],
  },
  scid_59: {
    controlId: "scid_59",
    userImpact: "A domain user setting a network's location (Public/Private) for the first time is prompted to elevate rather than it happening silently - a small, rare, one-time-per-network prompt for laptop users moving between networks.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_UAC_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations"],
  },
  scid_66: {
    controlId: "scid_66",
    userImpact: "Blocks Windows Installer (.msi) packages from silently requesting elevated (SYSTEM-level) install rights regardless of the current user's own privileges - a genuine privilege-escalation path when left on. Some older enterprise software deployment tooling relied on this being enabled for silent installs by standard users; verify against this fleet's actual software deployment method (Intune Win32 apps don't need it) before rollout.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_UAC_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-detect-application-installations-and-prompt-for-elevation"],
  },
  scid_29: {
    controlId: "scid_29",
    userImpact: "Hides the list of local administrator account names from the elevation prompt's account picker (which otherwise lets a standard user see every local admin's username, a minor recon aid) - a standard user must know an admin's credentials outright rather than pick a name from a list.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_UAC_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode"],
  },

  // -----------------------------------------------------------------------
  // Group C: SMB / NTLM / LDAP / network authentication hardening (Local
  // Policies Security Options - "Network access and security" / "MSS
  // (Legacy)" categories, all confirmed present natively in Intune's
  // Settings Catalog).
  // -----------------------------------------------------------------------
  scid_30: {
    controlId: "scid_30",
    userImpact: "Blocks SMB guest/anonymous fallback logons - genuinely breaks connecting to very old/consumer NAS devices or unpatched legacy file shares that only support guest access. Uncommon in a modern business fleet, but worth a quick check of any older on-prem NAS/print-server hardware before rollout.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/guest-access-in-smb2-and-smb3-is-disabled-by-default"],
  },
  scid_53: {
    controlId: "scid_53",
    userImpact: "Breaks any connection to a device that only speaks SMBv1 (very old NAS boxes, some scanners/printers, legacy line-of-business file servers). Check for SMBv1-only devices on this fleet's network before disabling - SMBv1 itself has been off by default in Windows 10/11 for years, so this mostly matters on older or manually-restored images.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    powershellCommand: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
    powershellCaveat: "Local machine only, for a quick test/remediation - deploy centrally via the Intune Settings Catalog policy for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"],
  },
  scid_54: {
    controlId: "scid_54",
    userImpact: "Same practical effect as scid_53 but on the server side - this device stops accepting incoming SMBv1 connections from other machines. Matters most if this device shares files/printers to older SMBv1-only clients on the same network.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    powershellCommand: "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
    powershellCaveat: "Local machine only, for a quick test/remediation - deploy centrally via the Intune Settings Catalog policy for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"],
  },
  scid_55: {
    controlId: "scid_55",
    userImpact: "None for normal domain/Entra-joined use. Prevents the \"Everyone\" permission group from silently including anonymous (unauthenticated) network users - closes a decades-old Windows default that's rarely intentional in a modern fleet.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-let-everyone-permissions-apply-to-anonymous-users"],
  },
  scid_57: {
    controlId: "scid_57",
    userImpact: "None for modern authentication - WDigest is a legacy protocol that, when enabled, keeps a reversible copy of a signed-in user's password in LSASS memory (a favorite credential-theft target). Disabling it (Windows default since Windows 8.1/Server 2012 R2) has no effect on anyone using Kerberos/NTLM/modern auth normally.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/security/kerberos/preventing-wdigest-authentication"],
  },
  scid_65: {
    controlId: "scid_65",
    userImpact: "None visible - stops Windows from keeping the weaker LM hash of a password alongside the stronger NTLM hash on the next password change. LM hashes are trivially crackable; this closes that without changing sign-in behavior at all.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change"],
  },
  scid_68: {
    controlId: "scid_68",
    userImpact: "Blocks an unauthenticated network user from enumerating local SAM account names (a common recon step before a password-guessing/brute-force attempt). No effect on legitimate authenticated access.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts"],
  },
  scid_64: {
    controlId: "scid_64",
    userImpact: "Restricts anonymous (unauthenticated) network access to named pipes and shares to only those explicitly listed as allowed, closing a classic remote-enumeration/recon path. Can break an older or misconfigured third-party tool that specifically relies on anonymous named-pipe access - uncommon in a modern fleet, worth a quick check for any legacy line-of-business integration first.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares"],
  },
  scid_72: {
    controlId: "scid_72",
    userImpact: "Forces NTLMv2-only network authentication, refusing the weaker LM/NTLMv1 protocols. Breaks authentication to genuinely ancient devices/software that only speak LM/NTLMv1 (very rare in a modern fleet) - worth a quick check of any legacy line-of-business or embedded-device authentication before a fleet rollout.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"],
  },
  scid_88: {
    controlId: "scid_88",
    userImpact: "Blocks an unauthenticated network user from enumerating the names of shared folders on this device (a recon step, same idea as scid_68 but for shares rather than accounts). No effect on legitimate authenticated file-share access.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts-and-shares"],
  },
  scid_94: {
    controlId: "scid_94",
    userImpact: "Blocks this device from sending an unencrypted password when authenticating to a non-Microsoft SMB server. Breaks compatibility with older third-party SMB implementations (some NAS firmware, some Linux Samba configurations) that only accept plaintext auth - check any such devices before rollout.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-client-send-unencrypted-password-to-third-party-smb-servers"],
  },
  scid_95: {
    controlId: "scid_95",
    userImpact: "None for modern devices - SMB signing adds a small, generally unnoticeable overhead to file-share traffic in exchange for tamper/relay-attack protection. Very old or low-powered devices on a saturated network could see a minor throughput dip on large file transfers.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-6-%e2%80%93-enforcing-smb-signing/4272168"],
  },
  scid_103: {
    controlId: "scid_103",
    userImpact: "Requires this device to sign LDAP requests when it acts as an LDAP client (queries Active Directory). Only relevant on domain-joined/hybrid devices with an on-prem AD to query - no effect on Entra-only, cloud-native devices.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: ["Only applicable to devices that query an on-premises Active Directory (domain-joined or hybrid-joined) - not relevant to Entra-only cloud-native devices."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-ldap-client-signing-requirements"],
  },
  scid_104: {
    controlId: "scid_104",
    userImpact: "Same applicability as scid_103 - encrypts LDAP client traffic to on-prem AD rather than sending it in the clear. No effect on Entra-only devices with no on-prem AD to query.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: ["Only applicable to devices that query an on-premises Active Directory (domain-joined or hybrid-joined) - not relevant to Entra-only cloud-native devices."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-ldap-client-signing-requirements"],
  },
  scid_109: {
    controlId: "scid_109",
    userImpact: "The most disruptive control in this group if deployed carelessly - fully disables the NTLM protocol on this device, which many legacy apps, printers, and some VPN/RADIUS setups still depend on even in Kerberos-capable environments. Microsoft's own guidance is to audit NTLM usage first (Network Security: Restrict NTLM audit settings) before ever fully disabling it fleet-wide.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: ["Audit NTLM usage on this fleet first (a separate \"Restrict NTLM: Audit\" setting in the same category) before enforcing full disablement - this is the single highest-risk-of-breakage control in the whole Windows local security policy group."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview"],
  },
  scid_111: {
    controlId: "scid_111",
    userImpact: "None for normal use - hardens the SMB server against relay attacks that abuse SMB's own authentication flow. Transparent to legitimate SMB clients.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security"],
  },

  // -----------------------------------------------------------------------
  // Group D: RDP / Remote Assistance / WinRM / Remote Registry
  // -----------------------------------------------------------------------
  scid_24: {
    controlId: "scid_24",
    userImpact: "None for a modern RDP client (mstsc.exe on Windows 8+, or any current third-party RDP client) - they already negotiate TLS by default. Only breaks compatibility with very old RDP clients that predate TLS support.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_RDS_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-rdp-security"],
  },
  scid_45: {
    controlId: "scid_45",
    userImpact: "RDP users must authenticate before a full remote desktop session is established (Network Level Authentication), rather than being shown the full login screen first - a real, if minor, change to the RDP connect flow. Most current RDP clients support NLA by default; very old clients may fail to connect.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_RDS_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"],
  },
  scid_110: {
    controlId: "scid_110",
    userImpact: "Users can no longer copy/paste files between their local machine and a device they've RDP'd into (clipboard file transfer and mapped local drives inside the session) - a genuinely noticeable change for anyone who uses RDP as their main remote-work tool and regularly moves files that way. Confirm this workflow doesn't exist before enabling broadly, or provide an alternative file-transfer path (OneDrive, a file share) first.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_RDS_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-rdp-security"],
  },
  scid_63: {
    controlId: "scid_63",
    userImpact: "Removes the option for an IT admin to proactively offer Remote Assistance to a user's session unprompted. Doesn't affect a user-initiated help request (Solicited Remote Assistance, scid_87, is the separate control for that) - only the reverse, admin-initiated \"offer help\" flow, which is rarely used by modern remote-support tooling anyway.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_REMOTE_ASSISTANCE_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/troubleshoot/turn-off-remote-assistance"],
  },
  scid_87: {
    controlId: "scid_87",
    userImpact: "Removes the classic Windows \"Remote Assistance\" invite-a-helper feature entirely. If this MSP's own remote-support tooling is a dedicated RMM/remote-access product (the common case) rather than built-in Windows Remote Assistance, there's no real loss - confirm which tool support staff actually use before disabling.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_REMOTE_ASSISTANCE_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/troubleshoot/turn-off-remote-assistance"],
  },
  scid_73: {
    controlId: "scid_73",
    userImpact: "None for normal WinRM/remote PowerShell use over Kerberos or NTLM (the common cases in a domain/Entra-joined fleet). Only breaks a WinRM client explicitly configured to use Basic auth to a remote host - an uncommon, weaker configuration to begin with.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_WINRM_PORTAL,
    caveats: [],
    sourceUrls: ["https://www.anoopcnair.com/disable-winrm-basic-authentication-using-intune/"],
  },
  scid_74: {
    controlId: "scid_74",
    userImpact: "Same idea as scid_73, server-side - this device stops accepting incoming WinRM connections authenticated with Basic auth. No effect on Kerberos/NTLM-authenticated WinRM/remote PowerShell sessions, which is the default and recommended configuration.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_WINRM_PORTAL,
    caveats: [],
    sourceUrls: ["https://www.anoopcnair.com/disable-winrm-basic-authentication-using-intune/"],
  },
  scid_108: {
    controlId: "scid_108",
    userImpact: "Stops the Remote Registry service from running, which blocks remote registry-editing tools from connecting to this device. Some older RMM/inventory tools use remote registry access for certain checks - verify this fleet's RMM doesn't depend on it before a broad rollout (most modern tools use WinRM/CIM instead).",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    powershellCommand: "Set-Service -Name RemoteRegistry -StartupType Disabled; Stop-Service -Name RemoteRegistry -Force",
    powershellCaveat: "Local machine only, for a quick test - deploy centrally via an Intune Settings Catalog / PowerShell script policy for a fleet, and confirm no RMM tooling depends on this service first.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings"],
  },

  // -----------------------------------------------------------------------
  // Group E: Netlogon secure channel (domain member) - only meaningful for
  // devices actually joined to an on-premises Active Directory domain
  // (including hybrid-joined). Cloud-native Entra-only devices have no
  // Netlogon secure channel to harden at all.
  // -----------------------------------------------------------------------
  scid_36: {
    controlId: "scid_36",
    userImpact: "No effect on Entra-only (cloud-native) devices - there's no domain secure channel to harden. On domain/hybrid-joined devices: none visible, strengthens the cryptographic session key used for the machine account's channel to a domain controller.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_DOMAIN_MEMBER_PORTAL,
    caveats: ["Only applicable to on-premises Active Directory domain-joined (or hybrid-joined) devices - no effect on Entra-only cloud-native devices."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-require-strong-windows-2000-or-later-session-key"],
  },
  scid_37: {
    controlId: "scid_37",
    userImpact: "Same domain/hybrid-only applicability as scid_36. Can break the secure channel to a domain controller that itself doesn't support encrypted/signed secure channel traffic - vanishingly rare with any DC running a supported Windows Server version.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_DOMAIN_MEMBER_PORTAL,
    caveats: ["Only applicable to on-premises Active Directory domain-joined (or hybrid-joined) devices - no effect on Entra-only cloud-native devices."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-digitally-encrypt-or-sign-secure-channel-data-always"],
  },
  scid_38: {
    controlId: "scid_38",
    userImpact: "The softer, \"when possible\" counterpart to scid_37 - same domain/hybrid-only applicability, negotiates encryption when the DC supports it rather than requiring it outright, so it's compatible with a wider (if less secure) range of DC configurations.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_DOMAIN_MEMBER_PORTAL,
    caveats: ["Only applicable to on-premises Active Directory domain-joined (or hybrid-joined) devices - no effect on Entra-only cloud-native devices."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-digitally-encrypt-secure-channel-data-when-possible"],
  },
  scid_39: {
    controlId: "scid_39",
    userImpact: "The signing counterpart to scid_38 - same domain/hybrid-only applicability, negotiates signing (tamper protection) of secure channel traffic when the DC supports it.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_DOMAIN_MEMBER_PORTAL,
    caveats: ["Only applicable to on-premises Active Directory domain-joined (or hybrid-joined) devices - no effect on Entra-only cloud-native devices."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-digitally-sign-secure-channel-data-when-possible"],
  },
  scid_40: {
    controlId: "scid_40",
    userImpact: "This control checks that automatic machine-account password rotation is NOT disabled (i.e. it's flagging a misconfiguration, not asking you to disable something) - domain/hybrid-joined devices should let Windows rotate their own machine account password on its normal schedule. No user-facing impact either way; a device with this disabled just carries a stale machine account password indefinitely, a real lateral-movement risk if that password is ever compromised.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_DOMAIN_MEMBER_PORTAL,
    caveats: ["Only applicable to on-premises Active Directory domain-joined (or hybrid-joined) devices - no effect on Entra-only cloud-native devices."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-disable-machine-account-password-changes"],
  },

  // -----------------------------------------------------------------------
  // Group F: Network / ICS / IP routing hardening
  // -----------------------------------------------------------------------
  scid_58: {
    controlId: "scid_58",
    userImpact: "Blocks a user from creating a Network Bridge (which would let a Wi-Fi and a wired network segment talk to each other through the device, bypassing network segmentation). Only matters if someone has legitimate need to bridge networks on a domain-joined machine, which is rare in a business fleet.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    caveats: ["Setting name to search for: \"Prohibit installation and configuration of Network Bridge on your DNS domain network\"."],
    sourceUrls: ["https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc785293(v=ws.10)"],
  },
  scid_60: {
    controlId: "scid_60",
    userImpact: "Blocks a user from enabling Internet Connection Sharing (turning their device into an ad-hoc router/hotspot for other devices), which could otherwise let an unmanaged device reach the corporate network through a managed one. Rarely used legitimately in a business fleet.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    caveats: ["Setting name to search for: \"Prohibit use of Internet Connection Sharing on your DNS domain network\"."],
    sourceUrls: ["https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc770755(v=ws.10)"],
  },
  scid_81: {
    controlId: "scid_81",
    userImpact: "None visible - hardens how this device handles IPv6 source-routed packets (a technique that can be abused to bypass network security controls). No effect on normal IPv6 connectivity.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    caveats: ["Setting name to search for: \"MSS: (DisableIPSourceRouting IPv6) IP source routing protection level\"."],
    sourceUrls: ["https://learn.microsoft.com/en-us/previous-versions/tn-archive/ms15-001(v=technet.10)"],
  },
  scid_82: {
    controlId: "scid_82",
    userImpact: "Same idea as scid_81, for IPv4 source-routed packets. None visible under normal use.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    caveats: ["Setting name to search for: \"MSS: (DisableIPSourceRouting) IP source routing protection level\"."],
    sourceUrls: ["https://learn.microsoft.com/en-us/previous-versions/tn-archive/ms15-001(v=technet.10)"],
  },
  scid_114: {
    controlId: "scid_114",
    userImpact: "None directly - this is a broader exposure-reduction recommendation (close unnecessary listening ports/services on devices reachable from the public internet) rather than a single toggle. Only relevant to devices genuinely internet-facing (rare for standard end-user endpoints in a well-configured fleet); most relevant to servers.",
    mechanism: "mde_diagnostic",
    portal: { name: "Microsoft Defender Portal", url: "https://security.microsoft.com/exposure-recommendations", navPath: ["Vulnerability management", "Recommendations", "review the specific exposed services/ports flagged for this device"] },
    caveats: ["No single fix - review Defender's own exposure report per device to see exactly which listening service/port is flagged, then close or firewall it individually."],
    sourceUrls: ["https://learn.microsoft.com/en-us/defender-vulnerability-management/tvm-security-recommendation"],
  },

  // -----------------------------------------------------------------------
  // Group G: Local / built-in accounts and credential storage
  // -----------------------------------------------------------------------
  scid_3010: {
    controlId: "scid_3010",
    userImpact: "The built-in \"Administrator\" account can no longer sign in at all (it's renamed/disabled, not deleted) - if any legacy process, script, or break-glass recovery procedure specifically depends on signing in as that exact account, it will stop working. Confirm what this fleet's break-glass/recovery procedure actually uses before disabling broadly; Windows LAPS (scid_113) is the safer modern replacement for \"a known local admin account.\"",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    powershellCommand: "Disable-LocalUser -Name Administrator",
    powershellCaveat: "Local machine only, for a quick test - deploy centrally via Intune Settings Catalog (\"Accounts: Administrator account status\") for a fleet, and make sure another admin path (Windows LAPS, an Entra-managed admin group) exists first.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-administrator-account-status"],
  },
  scid_3011: {
    controlId: "scid_3011",
    userImpact: "The built-in \"Guest\" account can no longer sign in. Already disabled by default on modern Windows 10/11 - this control mostly flags older or manually-reconfigured images.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    powershellCommand: "Disable-LocalUser -Name Guest",
    powershellCaveat: "Local machine only, for a quick test - deploy centrally via Intune Settings Catalog (\"Accounts: Guest account status\") for a fleet.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status"],
  },
  scid_93: {
    controlId: "scid_93",
    userImpact: "Blocks Windows Credential Manager from locally caching passwords/credentials for later automatic reuse (e.g. saved network share or RDP credentials). Users who rely on \"remember my password\" for a network resource will be re-prompted each time - a real, noticeable change worth communicating before a rollout, not just a background hardening step.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    caveats: ["Setting name to search for: \"Network access: Do not allow storage of passwords and credentials for network authentication\"."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication"],
  },
  scid_22: {
    controlId: "scid_22",
    userImpact: "Disables the browser's own built-in password manager (Chrome/Edge), pushing users toward a real enterprise password manager instead. A genuinely disruptive change for anyone used to browser-saved passwords - they'll need an alternative (a proper password manager, ideally) rolled out first, or this generates real helpdesk friction.",
    mechanism: "intune_settings_catalog",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Google Chrome - Default Settings\" or \"Microsoft Edge\" category", "\"Password Manager Enabled\" = Disabled"] },
    caveats: ["Confirm which browser(s) this fleet actually standardizes on before deploying - Chrome and Edge have separate policy settings for this, both natively in Settings Catalog (no ADMX import needed for either)."],
    sourceUrls: ["https://chromeenterprise.google/policies/#PasswordManagerEnabled"],
  },

  // -----------------------------------------------------------------------
  // Group H: Service account hardening - per-instance detection/fix, not a
  // single fleet-wide policy toggle. Best run as a recurring Intune
  // Proactive Remediation (detect + remediate script pair) rather than a
  // one-time fix, since new services can reintroduce the same issue.
  // -----------------------------------------------------------------------
  scid_3001: {
    controlId: "scid_3001",
    userImpact: "None for users - purely a local-privilege-escalation hardening fix for services whose executable path contains spaces and isn't quoted (Windows can be tricked into launching a different, attacker-planted executable from an earlier segment of the unquoted path). Zero risk to fix correctly (just adds quotes around the existing path); a badly-written fix script could break the service if not tested.",
    mechanism: "mde_diagnostic",
    powershellCommand: "Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName.TrimStart() -notlike '\"*' -and $_.PathName -match '\\s' -and $_.PathName -notmatch '(?i)^%SystemRoot%|^C:\\\\Windows\\\\' } | Select-Object Name, PathName",
    powershellCaveat: "Detection only, run per-device - lists services with an unquoted, space-containing path. Fixing each one means quoting its ImagePath registry value; best deployed as an Intune Proactive Remediation detect+remediate script pair run on a schedule (new third-party software can reintroduce this), not a one-time fix.",
    caveats: ["Third-party software installers are the most common source of this - a fix here can be reintroduced by the next installer/update from that vendor, hence the recommendation to run this as a recurring remediation, not a one-off."],
    sourceUrls: ["https://powershellisfun.com/2023/05/03/intune-proactive-remediation-for-microsoft-windows-unquoted-service-path-cve-2013-1609cve-2014-0759cve-2014-5455/"],
  },
  scid_3002: {
    controlId: "scid_3002",
    userImpact: "None for users - flags a service whose executable lives somewhere a standard user could potentially write to/replace (rather than a protected location like Program Files or System32), which is a local-privilege-escalation risk if that folder's permissions are ever weak. Fixing it means moving the executable to a protected folder and updating the service's ImagePath, which needs case-by-case judgment per service (not a blanket script) - some third-party software hardcodes its own install path.",
    mechanism: "mde_diagnostic",
    powershellCommand: "Get-CimInstance Win32_Service | Select-Object Name, PathName, StartMode | Where-Object { $_.PathName -notmatch '^\"?C:\\\\(Program Files|Windows|Program Files \\(x86\\))' }",
    powershellCaveat: "Detection only, run per-device - lists services running from outside the standard protected locations. Review each result individually before moving anything; some are legitimate (a vendor-specific install folder with correctly-locked-down permissions).",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/answers/questions/2182240/fix-unquoted-service-path-for-windows-services"],
  },
  scid_3003: {
    controlId: "scid_3003",
    userImpact: "None for users - flags a service configured to log on as a specific account whose password is cached in a way that's retrievable from the registry by a local admin/attacker, rather than using a Managed Service Account, gMSA, or a built-in identity (LocalSystem/NetworkService/LocalService). Fixing it (reconfiguring the service's logon account) needs per-service judgment - some legitimately need a dedicated service account, in which case a gMSA is the safer replacement, not just removing the account.",
    mechanism: "mde_diagnostic",
    powershellCommand: "Get-CimInstance Win32_Service | Where-Object { $_.StartName -notin @('LocalSystem','NT AUTHORITY\\NetworkService','NT AUTHORITY\\LocalService') } | Select-Object Name, StartName",
    powershellCaveat: "Detection only, run per-device - lists services running as a specific named account rather than a built-in identity. Review each individually before changing anything.",
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts-overview"],
  },

  // -----------------------------------------------------------------------
  // Group I: AutoPlay / AutoRun
  // -----------------------------------------------------------------------
  scid_67: {
    controlId: "scid_67",
    userImpact: "None for normal USB drive use - only stops AutoPlay from triggering on non-volume devices (cameras, phones connected via MTP, etc.), a much less common AutoPlay trigger than inserting a USB drive (covered separately by scid_69).",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_AUTOPLAY_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-autoplay"],
  },
  scid_69: {
    controlId: "scid_69",
    userImpact: "Inserting a USB drive/CD no longer shows the AutoPlay picker or auto-launches anything - a real, small, universally-familiar change (most users barely notice since they dismiss the AutoPlay prompt anyway, but a few who rely on it to quickly open a drive will need to open File Explorer manually instead).",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_AUTOPLAY_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-autoplay"],
  },
  scid_70: {
    controlId: "scid_70",
    userImpact: "Even if AutoPlay itself is triggered (or scid_69 isn't deployed), this stops any autorun.inf-specified command from actually executing - the specific historical malware-delivery mechanism (USB worms) this whole group of settings targets. Complements scid_69 rather than duplicating it.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_AUTOPLAY_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-autoplay"],
  },

  // -----------------------------------------------------------------------
  // Group J: Browser (Chrome) and Adobe Reader/Acrobat hardening - Settings
  // Catalog natively covers a basic set of Chrome policies; anything beyond
  // that (and all Adobe policies) needs the vendor's ADMX/ADML imported
  // into Intune first (Devices > Configuration > Import ADMX).
  // -----------------------------------------------------------------------
  scid_19: {
    controlId: "scid_19",
    userImpact: "Chrome fully closes (no background processes/notifications) when the user closes the last window, instead of continuing to run in the background. Breaks Chrome's own background push-notification and background-sync features for any web app a user relies on for that (e.g. a web-based chat tool's desktop notifications) - confirm that's not a real workflow dependency before a fleet rollout.",
    mechanism: "intune_settings_catalog",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Google Chrome - Default Settings\" category", "\"Background Mode Enabled\" = Disabled"] },
    caveats: ["Natively available in Settings Catalog - no ADMX import needed for this specific Chrome setting."],
    sourceUrls: ["https://chromeenterprise.google/policies/#BackgroundModeEnabled"],
  },
  scid_23: {
    controlId: "scid_23",
    userImpact: "Blocks third-party cookies in Chrome, breaking any legitimate cross-site embedded content that depends on them (some SSO flows, some embedded widgets/payment providers, some analytics-dependent internal tools). Test against this fleet's actual line-of-business web apps before a broad rollout - this is one of the more likely-to-cause-a-support-ticket settings in this whole group.",
    mechanism: "intune_settings_catalog",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Devices", "Configuration", "Create", "New Policy", "Windows 10 and later", "Settings Catalog", "\"Google Chrome - Content Settings\" category", "\"Default Cookies Setting\" / \"Block Third Party Cookies\""] },
    caveats: ["Natively available in Settings Catalog - no ADMX import needed. Pilot before a fleet rollout given the real risk of breaking a legitimate embedded/SSO workflow."],
    sourceUrls: ["https://chromeenterprise.google/policies/#BlockThirdPartyCookies"],
  },
  scid_75: {
    controlId: "scid_75",
    userImpact: "Flash is long past end-of-life (Adobe stopped supporting it in 2020, and Adobe Reader/Acrobat removed Flash support entirely in modern versions) - this control is only relevant on an older Adobe Reader DC install that predates Flash's removal. Confirm the fleet's actual Adobe Reader version first; on a current version this may already be moot.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_ADMX_IMPORT_PORTAL,
    caveats: ["Requires importing Adobe's own ADMX/ADML template into Intune first (Devices > Configuration > Import ADMX) - not natively in Settings Catalog. Check the actual installed Adobe Reader/Acrobat version before treating this as an open gap; current versions have Flash support removed entirely."],
    sourceUrls: ["https://github.com/systmworks/Adobe-DC-ADMX"],
  },
  scid_76: {
    controlId: "scid_76",
    userImpact: "Disables JavaScript execution inside PDFs opened in Adobe Reader DC - a real security hardening step (malicious PDFs commonly use embedded JavaScript), but breaks any legitimate interactive/fillable PDF form that relies on JavaScript for validation or calculated fields. Check for any business-critical interactive PDF forms before a fleet rollout.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_ADMX_IMPORT_PORTAL,
    caveats: ["Requires importing Adobe's own ADMX/ADML template into Intune first (Devices > Configuration > Import ADMX) - not natively in Settings Catalog."],
    sourceUrls: ["https://github.com/systmworks/Adobe-DC-ADMX"],
  },
  scid_97: {
    controlId: "scid_97",
    userImpact: "Same setting and same tradeoff as scid_76 - Microsoft's Secure Score catalog appears to carry both an \"Adobe Reader DC\" and an \"Adobe DC\" variant of the identical JavaScript-disable recommendation (likely reflecting Adobe's Reader vs. Acrobat product split, both covered by the same combined ADMX template). Deploying the one ADMX-based policy should satisfy both controls together - verify that live on a test device rather than assuming.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_ADMX_IMPORT_PORTAL,
    caveats: [
      "Requires importing Adobe's own ADMX/ADML template into Intune first (Devices > Configuration > Import ADMX) - not natively in Settings Catalog.",
      "Likely the same underlying setting as scid_76 under Microsoft's Reader-vs-Acrobat product naming split - confirm both controls clear together on a test device after deploying once, rather than authoring/deploying it twice.",
    ],
    sourceUrls: ["https://github.com/systmworks/Adobe-DC-ADMX"],
  },
  scid_80: {
    controlId: "scid_80",
    userImpact: "Blocks Flash content from auto-activating when embedded inside an Office document (Word/Excel/PowerPoint) - a historical malware-delivery vector. Flash is long past end-of-life and Office itself has blocked/removed Flash support in current versions; relevant mainly on older Office installs.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    caveats: ["Confirm the fleet's actual Office version/build first - current Office builds already block Flash activation by default, so this may already be moot rather than an open gap."],
    sourceUrls: ["https://learn.microsoft.com/en-us/deployoffice/security/change-history-for-security-in-office"],
  },

  // -----------------------------------------------------------------------
  // Group K: Misc Windows hardening
  // -----------------------------------------------------------------------
  scid_15: {
    controlId: "scid_15",
    userImpact: "Ensures Windows Update itself is actually enabled and checking for updates automatically - most fleets already have this via Windows Update for Business/update rings; this control mainly flags a device where automatic updates were manually turned off. No impact if update rings are already deployed and working.",
    mechanism: "intune_settings_catalog",
    portal: { name: "Microsoft Intune admin center", url: "https://intune.microsoft.com/", navPath: ["Devices", "Windows updates", "or Devices → Configuration → Windows 10 and later → Update rings"] },
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/deployment/update/waas-manage-updates-wufb"],
  },
  scid_16: {
    controlId: "scid_16",
    userImpact: "Removes the ability for a local (non-admin-protected) user to disable Windows Update from Settings themselves. A minor loss of user autonomy, no real workflow impact for the vast majority of end users.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    caveats: ["Setting name to search for: \"Remove access to use all Windows Update features\"."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings"],
  },
  scid_26: {
    controlId: "scid_26",
    userImpact: "None visible - forces Windows to search the more restrictive, safer set of folders first when an application loads a DLL by name (rather than a full path), closing a classic DLL-hijacking technique. Transparent to normal application behavior.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: [],
    sourceUrls: ["https://learn.microsoft.com/en-us/previous-versions/tn-archive/ms13-004(v=technet.10)"],
  },
  scid_28: {
    controlId: "scid_28",
    userImpact: "A real, daily-visible change - after 1-900 seconds (whatever value is set) of inactivity, the device auto-locks and requires re-authentication. Pick a value that balances security against user annoyance for this specific client (too short generates real friction/helpdesk pushback); Microsoft's own guidance is 15 minutes (900 seconds) as a common baseline, not the aggressive end of the range.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_LOCAL_SECURITY_NETWORK_PORTAL,
    caveats: ["Pick the actual timeout value deliberately per client, not just \"any nonzero value\" - this is one of the more user-visible settings in this whole group."],
    sourceUrls: ["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit"],
  },
  scid_83: {
    controlId: "scid_83",
    userImpact: "None visible - enables Data Execution Prevention specifically for File Explorer (explorer.exe), hardening it against a class of memory-corruption exploits. Transparent to normal file browsing.",
    mechanism: "intune_settings_catalog",
    portal: INTUNE_SETTINGS_CATALOG_GENERIC_PORTAL,
    caveats: ["Setting name to search for: \"Turn off Data Execution Prevention for Explorer\" = Disabled (double-negative naming - disabling the \"turn off DEP\" setting is what enables DEP)."],
    sourceUrls: ["https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/data-execution-prevention-in-windows"],
  },

  // -----------------------------------------------------------------------
  // Group L: mshta.exe outbound network block - a genuinely new (early
  // 2026) Secure Score recommendation, confirmed via a live search rather
  // than assumed to be part of the existing 19 ASR rules (it isn't).
  // -----------------------------------------------------------------------
  scid_107: {
    controlId: "scid_107",
    userImpact: "Blocks mshta.exe (Microsoft's own HTML Application Host) from making outbound network connections - a legitimate Windows binary that's a well-known living-off-the-land technique for malicious script execution and C2 communication. Breaks any legitimate line-of-business tooling built on .hta files that specifically needs network access (uncommon, but worth a quick check before enforcing) - local-only .hta execution is unaffected.",
    mechanism: "intune_firewall",
    portal: INTUNE_FIREWALL_RULES_PORTAL,
    caveats: [
      "A newer (early 2026) Secure Score recommendation, not part of the app's existing 19 ASR rules - implemented as a per-application outbound Windows Firewall rule (Intune Firewall Rules profile targeting mshta.exe specifically), not a Defender AV/ASR setting.",
      "Evaluate for line-of-business/scripting dependencies on mshta.exe reaching the network before enforcing broadly, per Microsoft's own rollout guidance for this control.",
    ],
    sourceUrls: ["https://github.com/seb1k/block-mshta-with-intune"],
  },
};

export function getDeviceControlGuide(controlId: string): DeviceControlGuide | undefined {
  return DEVICE_CONTROL_GUIDES[controlId];
}
