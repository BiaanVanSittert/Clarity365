import { CABaselineItem } from "../types";

export interface CABaselinePolicyDefinition extends CABaselineItem {
  requiresEntraP2?: boolean;
  powershellTemplate: (domainName: string) => string;
}

export const CA_BASELINE_STANDARDS: CABaselinePolicyDefinition[] = [
  {
    code: "CA01",
    name: "Block legacy authentication",
    description: "Blocks outdated protocols (IMAP4, POP3, SMTP AUTH, MAPI over HTTP, ActiveSync) that cannot evaluate MFA challenges.",
    recommendedState: "enabled",
    targetScope: "All users, all cloud apps, Other clients (legacy basic authentication)",
    riskMitigated: "Over 95% of automated credential stuffing attempts exploiting basic authentication.",
    powershellTemplate: (domain: string) => `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Optional: Safely lookup emergency account GUID if present
$excludeUserIds = @()
$emergencyUser = Get-MgUser -Filter "userPrincipalName eq 'breakglass-emergency@${domain}'" -ErrorAction SilentlyContinue
if ($emergencyUser) {
    $excludeUserIds += $emergencyUser.Id
    Write-Host "Excluded break-glass account: $($emergencyUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Deploy CA01: Block legacy authentication in Report-Only Mode
$ca01Params = @{
    displayName = "CA01: Block legacy authentication"
    state = "enabledForReportingButNotEnforced" # REPORT-ONLY MODE
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = $excludeUserIds
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

try {
    $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca01Params
    Write-Host "CA01 created successfully (ID: $($createdPolicy.Id)) in Report-Only mode." -ForegroundColor Green
    Write-Host "Review sign-in logs before manually enabling the policy in Microsoft Entra Admin Center." -ForegroundColor Yellow
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
}`,
  },
  {
    code: "CA02",
    name: "Require multifactor authentication for all users",
    description: "Mandates multi-factor authentication for all standard and corporate users when accessing any Microsoft 365 cloud application.",
    recommendedState: "enabled",
    targetScope: "All users, All Cloud Apps (Excludes break-glass emergency accounts)",
    riskMitigated: "Account compromise from leaked corporate passwords or phishing.",
    powershellTemplate: (domain: string) => `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Optional: Safely lookup emergency account GUID if present
$excludeUserIds = @()
$emergencyUser = Get-MgUser -Filter "userPrincipalName eq 'breakglass-emergency@${domain}'" -ErrorAction SilentlyContinue
if ($emergencyUser) {
    $excludeUserIds += $emergencyUser.Id
    Write-Host "Excluded break-glass account: $($emergencyUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Deploy CA02: Require multifactor authentication for all users in Report-Only Mode
$ca02Params = @{
    displayName = "CA02: Require multifactor authentication for all users"
    state = "enabledForReportingButNotEnforced" # REPORT-ONLY MODE
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = $excludeUserIds
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}

try {
    $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca02Params
    Write-Host "CA02 created successfully (ID: $($createdPolicy.Id)) in Report-Only mode." -ForegroundColor Green
    Write-Host "Review sign-in logs before manually enabling the policy in Microsoft Entra Admin Center." -ForegroundColor Yellow
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
}`,
  },
  {
    code: "CA03",
    name: "Require multifactor authentication for admins",
    description: "Enforces strong multi-factor authentication for all privileged administrative directory roles on every sign-in.",
    recommendedState: "enabled",
    targetScope: "All privileged directory roles (Global Admin, Security Admin, Exchange Admin, Privileged Role Admin, etc.)",
    riskMitigated: "Privileged account credential stuffing, password spraying, and unauthorized tenant takeover.",
    powershellTemplate: (domain: string) => `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Optional: Safely lookup emergency account GUID if present
$excludeUserIds = @()
$emergencyUser = Get-MgUser -Filter "userPrincipalName eq 'breakglass-emergency@${domain}'" -ErrorAction SilentlyContinue
if ($emergencyUser) {
    $excludeUserIds += $emergencyUser.Id
    Write-Host "Excluded break-glass account: $($emergencyUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Deploy CA03: Require multifactor authentication for admins in Report-Only Mode
$ca03Params = @{
    displayName = "CA03: Require multifactor authentication for admins"
    state = "enabledForReportingButNotEnforced" # REPORT-ONLY MODE
    conditions = @{
        users = @{
            includeRoles = @(
                "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
                "f28a1f50-f6e7-4571-817b-6a15e2e66ad5", # Security Administrator
                "2923200f-7827-46a4-baa5-010e67f0a12f", # Exchange Administrator
                "b1b438e4-250e-4507-a901-57041e44d673", # SharePoint Administrator
                "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
                "7be44c8a-a50e-44d4-aa94-712854cd42c2"  # Conditional Access Administrator
            )
            excludeUsers = $excludeUserIds
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}

try {
    $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca03Params
    Write-Host "CA03 created successfully (ID: $($createdPolicy.Id)) in Report-Only mode." -ForegroundColor Green
    Write-Host "Review sign-in logs before manually enabling the policy in Microsoft Entra Admin Center." -ForegroundColor Yellow
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
}`,
  },
  {
    code: "CA04",
    name: "Require multifactor authentication for guest access",
    description: "Mandates MFA for all external guests, contractors, and B2B collaboration identities accessing tenant resources.",
    recommendedState: "enabled",
    targetScope: "All Guest and External users (B2B collaboration accounts)",
    riskMitigated: "Unauthorized access via unmanaged or compromised external partner credentials.",
    powershellTemplate: (domain: string) => `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Optional: Safely lookup emergency account GUID if present
$excludeUserIds = @()
$emergencyUser = Get-MgUser -Filter "userPrincipalName eq 'breakglass-emergency@${domain}'" -ErrorAction SilentlyContinue
if ($emergencyUser) {
    $excludeUserIds += $emergencyUser.Id
    Write-Host "Excluded break-glass account: $($emergencyUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Deploy CA04: Require multifactor authentication for guest access in Report-Only Mode
$ca04Params = @{
    displayName = "CA04: Require multifactor authentication for guest access"
    state = "enabledForReportingButNotEnforced" # REPORT-ONLY MODE
    conditions = @{
        users = @{
            includeUsers = @("GuestsOrExternalUsers")
            excludeUsers = $excludeUserIds
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}

try {
    $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca04Params
    Write-Host "CA04 created successfully (ID: $($createdPolicy.Id)) in Report-Only mode." -ForegroundColor Green
    Write-Host "Review sign-in logs before manually enabling the policy in Microsoft Entra Admin Center." -ForegroundColor Yellow
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
}`,
  },
  {
    code: "CA05",
    name: "Require multifactor authentication for Azure management",
    description: "Enforces MFA specifically for administrative access to the Azure Portal, Microsoft Azure CLI, PowerShell, and REST APIs.",
    recommendedState: "enabled",
    targetScope: "All users, Target app: Microsoft Azure Management (797f3427-79cd-4827-8132-47d473d450e4)",
    riskMitigated: "Unauthorized administrative modifications to Azure infrastructure and cloud tenant subscriptions.",
    powershellTemplate: (domain: string) => `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Optional: Safely lookup emergency account GUID if present
$excludeUserIds = @()
$emergencyUser = Get-MgUser -Filter "userPrincipalName eq 'breakglass-emergency@${domain}'" -ErrorAction SilentlyContinue
if ($emergencyUser) {
    $excludeUserIds += $emergencyUser.Id
    Write-Host "Excluded break-glass account: $($emergencyUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Deploy CA05: Require multifactor authentication for Azure management in Report-Only Mode
$ca05Params = @{
    displayName = "CA05: Require multifactor authentication for Azure management"
    state = "enabledForReportingButNotEnforced" # REPORT-ONLY MODE
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = $excludeUserIds
        }
        applications = @{
            includeApplications = @("797f3427-79cd-4827-8132-47d473d450e4") # Microsoft Azure Management
        }
        clientAppTypes = @("all")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}

try {
    $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca05Params
    Write-Host "CA05 created successfully (ID: $($createdPolicy.Id)) in Report-Only mode." -ForegroundColor Green
    Write-Host "Review sign-in logs before manually enabling the policy in Microsoft Entra Admin Center." -ForegroundColor Yellow
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
}`,
  },
  {
    code: "CA06",
    name: "Require multifactor authentication for risky sign-ins",
    description: "Dynamically challenges users for MFA or blocks access when Entra Identity Protection detects real-time sign-in risk (e.g. impossible travel, anonymous IP).",
    recommendedState: "enabled",
    targetScope: "All users, Sign-in Risk: Medium and High (Requires Entra ID Plan 2)",
    riskMitigated: "Automated credential replay, proxy networks, and impossible travel session attacks.",
    requiresEntraP2: true,
    powershellTemplate: (domain: string) => `# Connect to Microsoft Graph (NOTE: Requires Microsoft Entra ID Plan 2 license)
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Optional: Safely lookup emergency account GUID if present
$excludeUserIds = @()
$emergencyUser = Get-MgUser -Filter "userPrincipalName eq 'breakglass-emergency@${domain}'" -ErrorAction SilentlyContinue
if ($emergencyUser) {
    $excludeUserIds += $emergencyUser.Id
    Write-Host "Excluded break-glass account: $($emergencyUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Deploy CA06: Require multifactor authentication for risky sign-ins in Report-Only Mode
$ca06Params = @{
    displayName = "CA06: Require multifactor authentication for risky sign-ins"
    state = "enabledForReportingButNotEnforced" # REPORT-ONLY MODE
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = $excludeUserIds
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
        signInRiskLevels = @("medium", "high")
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("mfa")
    }
}

try {
    $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca06Params
    Write-Host "CA06 created successfully (ID: $($createdPolicy.Id)) in Report-Only mode (Requires Entra ID P2)." -ForegroundColor Green
    Write-Host "Review sign-in logs before manually enabling the policy in Microsoft Entra Admin Center." -ForegroundColor Yellow
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
}`,
  },
  {
    code: "CA07",
    name: "Require risk remediation for high-risk users",
    description: "Forces secure password change with multi-factor authentication when a user identity is detected in compromised credential leaks.",
    recommendedState: "enabled",
    targetScope: "All users, User Risk: High (Requires Entra ID Plan 2)",
    riskMitigated: "Dark-web credential dumps and persistent account takeover.",
    requiresEntraP2: true,
    powershellTemplate: (domain: string) => `# Connect to Microsoft Graph (NOTE: Requires Microsoft Entra ID Plan 2 license)
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Optional: Safely lookup emergency account GUID if present
$excludeUserIds = @()
$emergencyUser = Get-MgUser -Filter "userPrincipalName eq 'breakglass-emergency@${domain}'" -ErrorAction SilentlyContinue
if ($emergencyUser) {
    $excludeUserIds += $emergencyUser.Id
    Write-Host "Excluded break-glass account: $($emergencyUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Deploy CA07: Require risk remediation for high-risk users in Report-Only Mode
$ca07Params = @{
    displayName = "CA07: Require risk remediation for high-risk users"
    state = "enabledForReportingButNotEnforced" # REPORT-ONLY MODE
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = $excludeUserIds
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
        userRiskLevels = @("high")
    }
    grantControls = @{
        operator = "AND"
        builtInControls = @("mfa", "passwordChange")
    }
}

try {
    $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca07Params
    Write-Host "CA07 created successfully (ID: $($createdPolicy.Id)) in Report-Only mode (Requires Entra ID P2)." -ForegroundColor Green
    Write-Host "Review sign-in logs before manually enabling the policy in Microsoft Entra Admin Center." -ForegroundColor Yellow
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
}`,
  },
  {
    code: "CA08",
    name: "Block Access from Untrusted Countries",
    description: "Restricts authentication requests originating from geographic locations where the organization has no legitimate operations or presence.",
    recommendedState: "enabled",
    targetScope: "All users, Named Locations (Blocked Geographies list)",
    riskMitigated: "Offshore cybercrime syndicates, hostile state-sponsored reconnaissance, and foreign proxy attacks.",
    powershellTemplate: (domain: string) => `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Optional: Safely lookup emergency account GUID if present
$excludeUserIds = @()
$emergencyUser = Get-MgUser -Filter "userPrincipalName eq 'breakglass-emergency@${domain}'" -ErrorAction SilentlyContinue
if ($emergencyUser) {
    $excludeUserIds += $emergencyUser.Id
    Write-Host "Excluded break-glass account: $($emergencyUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Deploy CA08: Block Access from Untrusted Countries in Report-Only Mode
$ca08Params = @{
    displayName = "CA08: Block Access from Untrusted Countries"
    state = "enabledForReportingButNotEnforced" # REPORT-ONLY MODE
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = $excludeUserIds
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
        locations = @{
            includeLocations = @("All")
            excludeLocations = @("AllTrusted") # Excludes corporate trusted IP ranges and countries
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("block")
    }
}

try {
    $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca08Params
    Write-Host "CA08 created successfully (ID: $($createdPolicy.Id)) in Report-Only mode." -ForegroundColor Green
    Write-Host "Review sign-in logs before manually enabling the policy in Microsoft Entra Admin Center." -ForegroundColor Yellow
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
}`,
  },
  {
    code: "CA09",
    name: "Require MDM-enrolled and compliant device to access cloud apps for all users",
    description: "Restricts access to corporate resources strictly to Microsoft Intune MDM-enrolled and compliant endpoints.",
    recommendedState: "enabled",
    targetScope: "All users, Windows & macOS platforms, All Cloud Apps",
    riskMitigated: "Data leakage, malware exfiltration, and unmanaged BYOD endpoints.",
    powershellTemplate: (domain: string) => `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Optional: Safely lookup emergency account GUID if present
$excludeUserIds = @()
$emergencyUser = Get-MgUser -Filter "userPrincipalName eq 'breakglass-emergency@${domain}'" -ErrorAction SilentlyContinue
if ($emergencyUser) {
    $excludeUserIds += $emergencyUser.Id
    Write-Host "Excluded break-glass account: $($emergencyUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Deploy CA09: Require MDM-enrolled and compliant device in Report-Only Mode
$ca09Params = @{
    displayName = "CA09: Require MDM-enrolled and compliant device to access cloud apps for all users"
    state = "enabledForReportingButNotEnforced" # REPORT-ONLY MODE
    conditions = @{
        users = @{
            includeUsers = @("All")
            excludeUsers = $excludeUserIds
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
        platforms = @{
            includePlatforms = @("windows", "macOS", "iOS", "android")
        }
    }
    grantControls = @{
        operator = "OR"
        builtInControls = @("compliantDevice", "domainJoinedDevice")
    }
}

try {
    $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca09Params
    Write-Host "CA09 created successfully (ID: $($createdPolicy.Id)) in Report-Only mode." -ForegroundColor Green
    Write-Host "Review sign-in logs before manually enabling the policy in Microsoft Entra Admin Center." -ForegroundColor Yellow
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
}`,
  },
  {
    code: "CA10",
    name: "Require phishing-resistant multifactor authentication for admins",
    description: "Requires FIDO2 / Passkeys / Windows Hello for Business or Certificate-Based Authentication for all directory administrators.",
    recommendedState: "enabled",
    targetScope: "All privileged directory roles (Global Admin, Security Admin, etc.)",
    riskMitigated: "Adversary-in-the-Middle (AiTM) proxy phishing attacks bypassing push notifications and OTP codes.",
    powershellTemplate: (domain: string) => `# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Optional: Safely lookup emergency account GUID if present
$excludeUserIds = @()
$emergencyUser = Get-MgUser -Filter "userPrincipalName eq 'breakglass-emergency@${domain}'" -ErrorAction SilentlyContinue
if ($emergencyUser) {
    $excludeUserIds += $emergencyUser.Id
    Write-Host "Excluded break-glass account: $($emergencyUser.UserPrincipalName)" -ForegroundColor Cyan
}

# Deploy CA10: Require phishing-resistant MFA for admins in Report-Only Mode
$ca10Params = @{
    displayName = "CA10: Require phishing-resistant multifactor authentication for admins"
    state = "enabledForReportingButNotEnforced" # REPORT-ONLY MODE
    conditions = @{
        users = @{
            includeRoles = @(
                "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
                "f28a1f50-f6e7-4571-817b-6a15e2e66ad5", # Security Administrator
                "2923200f-7827-46a4-baa5-010e67f0a12f", # Exchange Administrator
                "e8611ab8-c189-46e8-94e1-60213ab1f814"  # Privileged Role Administrator
            )
            excludeUsers = $excludeUserIds
        }
        applications = @{
            includeApplications = @("All")
        }
        clientAppTypes = @("all")
    }
    grantControls = @{
        operator = "OR"
        authenticationStrength = @{
            id = "00000000-0000-0000-0000-000000000004" # Phishing-resistant MFA built-in strength
        }
    }
}

try {
    $createdPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $ca10Params
    Write-Host "CA10 created successfully (ID: $($createdPolicy.Id)) in Report-Only mode." -ForegroundColor Green
    Write-Host "Review sign-in logs before manually enabling the policy in Microsoft Entra Admin Center." -ForegroundColor Yellow
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
}`,
  },
];
