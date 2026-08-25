import { TenantSecuritySnapshot } from "../types";

export interface RemediationPlan {
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  summary: string;
  steps: string[];
  powershellScript: string;
  graphApiPayload?: object;
  rollbackPlan: string;
}

export function generateRemediationPlanForTenant(snapshot: TenantSecuritySnapshot, findingType?: string): RemediationPlan[] {
  const plans: RemediationPlan[] = [];

  // Check 1: Missing CA Baseline Policies
  const deployedCodes = new Set(snapshot.conditionalAccess.policies.map((p) => p.baselineCode).filter(Boolean));
  const missingCodes = snapshot.conditionalAccess.baselineDefinitions.filter((def) => !deployedCodes.has(def.code));

  if (missingCodes.length > 0 && (!findingType || findingType === "conditional_access")) {
    const missingList = missingCodes.map((m) => `${m.code}: ${m.name}`).join(", ");
    plans.push({
      title: `Deploy Missing Conditional Access Baseline Policies (${missingCodes.length} missing)`,
      category: "Identity & Access",
      severity: missingCodes.some((c) => c.code === "CA01" || c.code === "CA02") ? "critical" : "high",
      summary: `The tenant is missing ${missingCodes.length} recommended baseline policies: ${missingList}. This exposes administrative accounts to credential stuffing and unmanaged device token theft.`,
      steps: [
        "Connect to Microsoft Graph PowerShell using an account with 'Policy.ReadWrite.ConditionalAccess' scope.",
        "Deploy the baseline policies in 'Report-Only' mode first to observe authentication logs for 7 days without blocking valid business traffic.",
        "Review Entra ID Sign-In logs with filter `appliedConditionalAccessPolicies/result eq 'reportOnlyFailure'` to identify legitimate legacy apps requiring exemptions.",
        "Transition policies to 'Enabled' enforcement state.",
      ],
      powershellScript: `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Deploy CA01: Block Legacy Authentication Protocols
$ca01Params = @{
    displayName = "CA01: Block Legacy Authentication Protocols"
    state = "enabledForReportingButNotEnforced" # Switch to 'enabled' after verification
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = @("upn:breakglass-admin@${snapshot.tenant.defaultDomainName}")
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("exchangeActiveSync", "otherClients")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $ca01Params

Write-Host "Conditional Access Baseline deployed in Report-Only mode successfully." -ForegroundColor Green`,
      rollbackPlan: "Set policy state to 'disabled' via `Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId <ID> -State 'disabled'`.",
    });
  }

  // Check 2: External Email Forwarding Vectors
  const criticalForwarding = snapshot.emailForwarding.filter((f) => f.alertLevel === "critical" && f.state === "Enabled");
  if (criticalForwarding.length > 0 && (!findingType || findingType === "email_forwarding")) {
    plans.push({
      title: `Block External Email Forwarding & Remove Suspicious Inbox Rules (${criticalForwarding.length} rules detected)`,
      category: "Exchange & Mailflow",
      severity: "critical",
      summary: `Detected active server-side or inbox forwarding rules targeting external addresses (${criticalForwarding.map((f) => f.forwardingAddress).join(", ")}). This is a primary exfiltration vector in Business Email Compromise (BEC).`,
      steps: [
        "Connect to Exchange Online PowerShell.",
        "Enforce outbound anti-spam policy to globally disable external auto-forwarding across the tenant.",
        "Disable or remove the identified inbox and transport forwarding rules.",
        "Notify the impacted users and initiate an identity security audit for possible session token compromise.",
      ],
      powershellScript: `# Connect to Exchange Online
Connect-ExchangeOnline

# 1. Enforce global outbound forwarding disablement
Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off

# 2. Disable identified malicious inbox forwarding rules
${criticalForwarding
  .filter((f) => f.mailboxOwner)
  .map(
    (f) =>
      `Disable-InboxRule -Mailbox "${f.mailboxOwner}" -Identity "${f.name}" -Confirm:$false`
  )
  .join("\n")}

Write-Host "External email auto-forwarding vectors remediated." -ForegroundColor Green`,
      rollbackPlan: "Re-enable individual mailbox rules if legitimate business exception is formally approved by CISO.",
    });
  }

  // Check 3: Weak Authentication & Missing MFA
  const weakMfaUsers = snapshot.mfaAudit.filter((u) => u.isWeakAuth || !u.mfaRegistered);
  if (weakMfaUsers.length > 0 && (!findingType || findingType === "mfa_audit")) {
    plans.push({
      title: `Enforce Strong MFA Registration & Phishing-Resistant Methods (${weakMfaUsers.length} vulnerable users)`,
      category: "Identity & Authentication",
      severity: "high",
      summary: `${weakMfaUsers.length} user account(s) are either completely missing MFA registration or utilizing weak authentication vectors (SMS / Voice / Email OTP) susceptible to SIM-swapping and AiTM phishing.`,
      steps: [
        "Enforce Microsoft Authenticator with Number Matching via Entra ID Authentication Methods policy.",
        "Enable System-preferred MFA in the Entra ID admin center.",
        "Issue FIDO2 hardware security keys (YubiKey) or passkeys for privileged administrative roles.",
        "Configure registration campaign in Entra ID to prompt users to register Microsoft Authenticator push notifications.",
      ],
      powershellScript: `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.AuthenticationMethod"

# Enable System-Preferred MFA for All Users
$sysPrefParams = @{
    state = "enabled"
}
Update-MgPolicyAuthenticationMethodPolicySystemCredentialPreference -BodyParameter $sysPrefParams

Write-Host "System-Preferred MFA enforced across tenant." -ForegroundColor Green`,
      rollbackPlan: "Set system-preferred MFA state back to 'default'.",
    });
  }

  // Check 4: Unlicensed Active (Orphaned) Accounts
  const orphanedAccounts = snapshot.accountClassification.users.filter((u) => u.classification === "unlicensed_active");
  if (orphanedAccounts.length > 0 && (!findingType || findingType === "user_classification")) {
    plans.push({
      title: `Disable or Secure Unlicensed Active Accounts (${orphanedAccounts.length} orphaned accounts)`,
      category: "User & Identity Lifecycle",
      severity: "high",
      summary: `Found active user accounts with 'accountEnabled: true' but zero assigned licenses. These represent orphaned accounts from previous offboarding failures or unmanaged test accounts.`,
      steps: [
        "Verify if these accounts are required for service/kiosk roles or should be offboarded.",
        "If offboarding: Block interactive sign-in (`accountEnabled = false`) and revoke active refresh tokens.",
        "If service account: Convert to Entra ID Workload Identity or assign proper security policies.",
      ],
      powershellScript: `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.ReadWrite.All"

${orphanedAccounts
  .map(
    (u) => `# Block sign-in and revoke tokens for ${u.userPrincipalName}
Update-MgUser -UserId "${u.userPrincipalName}" -AccountEnabled:$false
Revoke-MgUserSignInSession -UserId "${u.userPrincipalName}"`
  )
  .join("\n\n")}

Write-Host "Orphaned accounts blocked and sessions revoked." -ForegroundColor Green`,
      rollbackPlan: "Re-enable specific account with `Update-MgUser -UserId <UPN> -AccountEnabled:$true`.",
    });
  }

  // Check 5: Open SharePoint/OneDrive Sharing Links ("Anyone" links)
  const openSharingSites = snapshot.sharePoint.sites.filter((s) => s.sharingCapability === "Anyone");
  if (
    (openSharingSites.length > 0 || snapshot.highRiskThreatIndicators.openSharePointSitesCount > 0) &&
    (!findingType || findingType === "sharepoint_sharing")
  ) {
    const siteList = openSharingSites.map((s) => s.siteName).join(", ") || "one or more sites";
    plans.push({
      title: `Restrict "Anyone" External Sharing Links (${openSharingSites.length || snapshot.highRiskThreatIndicators.openSharePointSitesCount} site(s) affected)`,
      category: "Collaboration & Governance",
      severity: "high",
      summary: `${siteList} allow anonymous "Anyone" sharing links, which require no sign-in and can be forwarded indefinitely — a common data exfiltration and unauthorized-access vector.`,
      steps: [
        "Review each flagged site's active sharing links and revoke any that are no longer needed.",
        "Lower the site-level sharing capability from 'Anyone' to 'New and existing guests' or 'Only people in your organization'.",
        "Set a tenant-wide anonymous link expiration policy so any future 'Anyone' links auto-expire.",
        "Re-audit sharing links quarterly via the SharePoint admin center or Microsoft Purview.",
      ],
      powershellScript: `# Connect to SharePoint Online
Connect-SPOService -Url "https://${snapshot.tenant.defaultDomainName.split(".")[0]}-admin.sharepoint.com"

${openSharingSites
  .map(
    (s) => `# Restrict sharing on ${s.siteName}
Set-SPOSite -Identity "${s.siteUrl}" -SharingCapability ExistingExternalUserSharingOnly`
  )
  .join("\n\n") || "# Restrict sharing on the affected site(s) identified in the SharePoint admin center\nSet-SPOSite -Identity \"<SiteUrl>\" -SharingCapability ExistingExternalUserSharingOnly"}

Write-Host "External 'Anyone' sharing links restricted." -ForegroundColor Green`,
      rollbackPlan: "Restore the site's prior sharing capability with `Set-SPOSite -Identity <SiteUrl> -SharingCapability Anyone` if a legitimate business need is approved.",
    });
  }

  // Check 6: Unprotected Global/Privileged Admin Accounts (no MFA or weak MFA)
  const unprotectedAdmins = snapshot.mfaAudit.filter((u) => u.isAdmin && (!u.mfaRegistered || u.isWeakAuth));
  if (
    (unprotectedAdmins.length > 0 || snapshot.highRiskThreatIndicators.unprotectedAdminsCount > 0) &&
    (!findingType || findingType === "unprotected_admins")
  ) {
    const adminList = unprotectedAdmins.map((u) => u.userPrincipalName).join(", ") || "one or more privileged accounts";
    plans.push({
      title: `Secure Unprotected Administrative Accounts (${unprotectedAdmins.length || snapshot.highRiskThreatIndicators.unprotectedAdminsCount} admin(s) affected)`,
      category: "Identity & Authentication",
      severity: "critical",
      summary: `${adminList} hold administrative directory roles but have no MFA registered or rely on a weak authentication method (SMS/Voice/Email OTP). A compromised admin credential without strong MFA is a direct path to full tenant takeover.`,
      steps: [
        "Require immediate MFA registration for every flagged admin account before their next sign-in.",
        "Enforce CA03 (Require MFA for admins) and, where licensed, CA10 (phishing-resistant MFA) for all privileged directory roles.",
        "Issue FIDO2 hardware keys or configure Windows Hello for Business for Global/Privileged Role Administrators.",
        "Audit recent sign-in activity for these accounts for signs of prior compromise.",
      ],
      powershellScript: `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","UserAuthenticationMethod.ReadWrite.All"

${unprotectedAdmins
  .map(
    (u) => `# Flag ${u.userPrincipalName} for mandatory MFA registration
Write-Host "ACTION REQUIRED: Register MFA for admin account ${u.userPrincipalName}" -ForegroundColor Red`
  )
  .join("\n") || "# Identify unprotected admin accounts via the Entra ID admin center and register MFA for each"}

# Deploy/confirm CA03: Require MFA for admins is enabled and enforced (not report-only)
Write-Host "Review CA03 baseline policy state and transition to 'enabled' once verified." -ForegroundColor Yellow`,
      rollbackPlan: "No rollback needed — this hardens an existing gap rather than changing current tenant behavior. If a CA policy is deployed as part of remediation, it can be set back to 'disabled' if it causes unexpected lockouts.",
    });
  }

  return plans;
}
