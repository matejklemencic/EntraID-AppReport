<#
.SYNOPSIS
    Generates an interactive HTML security report for Microsoft Entra ID Enterprise Applications.
.DESCRIPTION
    This script connects to Microsoft Graph, retrieves Enterprise Applications (Service Principals),
    analyzes permissions, credentials and ownership, calculates risk scores and produces a filterable
    interactive HTML report with badge-based visualizations and deep links to the Entra portal.
    Includes ownership checking for both Service Principals and App Registrations.
.AUTHOR
    Matej Klemencic (www.matej.guru)
.NOTES
    Version:        1.4
    Last Modified:  2026-06-21
.PARAMETER OutputPath
    Path to save the generated HTML report. Defaults to "EntraIDReport_{TenantName}_{Date}.html".
.PARAMETER TenantId
    Optional. The Entra ID tenant ID to connect to. Required when using Service Principal authentication.
.PARAMETER AccessToken
    Optional. A pre-acquired Microsoft Graph access token (SecureString). Use this when the pipeline
    already has an authenticated Az context (e.g. AzurePowerShell@5 with azureSubscription).
    Obtain with: ConvertTo-SecureString (Get-AzAccessToken -ResourceTypeName MSGraph).Token -AsPlainText -Force
.PARAMETER ClientId
    Optional. The Application (client) ID of a Service Principal for unattended/pipeline authentication.
    Must be combined with either -ClientSecret or -CertificateThumbprint and -TenantId.
.PARAMETER ClientSecret
    Optional. The client secret for Service Principal authentication. Use with -ClientId and -TenantId.
    For production pipelines, prefer certificate authentication or Managed Identity.
.PARAMETER CertificateThumbprint
    Optional. Certificate thumbprint for Service Principal authentication. Use with -ClientId and -TenantId.
.PARAMETER UseManagedIdentity
    Optional. Use the Azure Managed Identity of the hosting environment (e.g. Azure DevOps hosted agent,
    Azure VM, Azure Function). No credentials required.
.PARAMETER NonInteractive
    Optional. Suppress all interactive prompts. Required for unattended/pipeline runs.
    Also suppresses automatic browser launch after report generation.
.PARAMETER OnlyWithPermissions
    Include only applications that have at least one permission (delegated, application or directory role).
.PARAMETER MinimumPermissions
    Include only applications with total permission count >= this number. Default is 0 (no minimum).
.PARAMETER RiskConfigPath
    Path to a JSON file with custom risk scoring configuration. If provided and valid, overrides default risk rules.
.PARAMETER OnlyWithAppRegistrations
    Include only applications that have a corresponding App Registration in the tenant.
.PARAMETER OnlyServicePrincipals
    Include only service principals without an App Registration (e.g. gallery or legacy apps).
.PARAMETER Verbose
    Enable verbose logging for troubleshooting.
.EXAMPLE
    # Interactive: generate a report for the default tenant
    .\Get-EntraIDAppReport.ps1
.EXAMPLE
    # Interactive: generate a report for a specific tenant
    .\Get-EntraIDAppReport.ps1 -TenantId "your-tenant-id"
.EXAMPLE
    # Azure DevOps with azureSubscription service connection (recommended for ADO)
    $token = ConvertTo-SecureString (Get-AzAccessToken -ResourceTypeName MSGraph).Token -AsPlainText -Force
    .\Get-EntraIDAppReport.ps1 -AccessToken $token -NonInteractive -OutputPath "report.html"
.EXAMPLE
    # Service Principal with certificate (recommended for pipelines)
    .\Get-EntraIDAppReport.ps1 -TenantId "tenant-id" -ClientId "app-id" -CertificateThumbprint "thumbprint" -NonInteractive
.EXAMPLE
    # Service Principal with client secret
    .\Get-EntraIDAppReport.ps1 -TenantId "tenant-id" -ClientId "app-id" -ClientSecret "secret" -NonInteractive
.EXAMPLE
    # Managed Identity (Azure DevOps / Azure-hosted agent)
    .\Get-EntraIDAppReport.ps1 -UseManagedIdentity -NonInteractive -OutputPath "$(Build.ArtifactStagingDirectory)\report.html"
.EXAMPLE
    # Save report to a custom path
    .\Get-EntraIDAppReport.ps1 -OutputPath "C:\Reports\MyReport.html"
.EXAMPLE
    # Include only apps with registrations and verbose logging
    .\Get-EntraIDAppReport.ps1 -OnlyWithAppRegistrations -Verbose
.EXAMPLE
    # List only apps with at least 5 permissions
    .\Get-EntraIDAppReport.ps1 -MinimumPermissions 5
.INSTALLATION
    Install the required Microsoft Graph modules:

    # Install only necessary modules
    Install-Module -Name Microsoft.Graph.Authentication,Microsoft.Graph.Applications,Microsoft.Graph.Identity.SignIns,Microsoft.Graph.Identity.DirectoryManagement,Microsoft.Graph.Reports -Scope CurrentUser -AllowClobber

    # Or install the full umbrella module
    Install-Module -Name Microsoft.Graph -Scope CurrentUser -AllowClobber

    #>

param(
    [string]$OutputPath = "",
    [string]$TenantId = "",
    # Pre-acquired token (e.g. from Get-AzAccessToken in AzurePowerShell@5 task)
    [System.Security.SecureString]$AccessToken,
    # Service Principal / pipeline authentication
    [string]$ClientId = "",
    [string]$ClientSecret = "",
    [string]$CertificateThumbprint = "",
    [switch]$UseManagedIdentity,
    [switch]$NonInteractive,
    # Filtering
    [switch]$OnlyWithPermissions,
    [int]$MinimumPermissions = 0,
    [string]$RiskConfigPath = $null,
    [switch]$OnlyWithAppRegistrations,
    [switch]$OnlyServicePrincipals,
    [switch]$Verbose
)

# Validate mutually exclusive parameters
if ($OnlyWithAppRegistrations -and $OnlyServicePrincipals) {
    Write-Error "-OnlyWithAppRegistrations and -OnlyServicePrincipals are mutually exclusive. Use one or the other."
    exit 1
}
if (($ClientId -or $ClientSecret -or $CertificateThumbprint) -and -not $TenantId) {
    Write-Error "-TenantId is required when using Service Principal authentication (-ClientId/-ClientSecret/-CertificateThumbprint)."
    exit 1
}

# Risk scoring configuration
$riskConfig = @{
    HighRiskPermissions = @(
        'Directory.ReadWrite.All', 'Directory.AccessAsUser.All', 'User.ReadWrite.All',
        'Group.ReadWrite.All', 'Application.ReadWrite.All', 'RoleManagement.ReadWrite.Directory',
        'Policy.ReadWrite.All', 'Sites.FullControl.All', 'Files.ReadWrite.All',
        'Mail.ReadWrite', 'Calendars.ReadWrite', 'Contacts.ReadWrite',
        'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementApps.ReadWrite.All',
        'Policy.ReadWrite.ConditionalAccess', 'User.DeleteRestore.All', 'User.EnableDisableAccount.All',
        'PrivilegedAccess.ReadWrite.AzureADGroup', 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup',
        'RoleAssignmentSchedule.ReadWrite.Directory', 'UserAuthenticationMethod.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All',
        'Domain.ReadWrite.All', 'RoleManagementPolicy.ReadWrite.AzureADGroup', 'RoleManagementPolicy.ReadWrite.Directory',
        'GroupMember.ReadWrite.All', 'DeviceManagementRBAC.ReadWrite.All', 'EntitlementManagement.ReadWrite.All',
        'Organization.ReadWrite.All', 'Policy.ReadWrite.AuthenticationMethod', 'Policy.ReadWrite.PermissionGrant'
    )
    MediumRiskPermissions = @(
        'Directory.Read.All', 'User.Read.All', 'Group.Read.All',
        'Application.Read.All', 'Sites.Read.All', 'Files.Read.All',
        'Mail.Read', 'Mail.Send', 'User.ReadBasic.All'
    )
    HighRiskDirectoryRoles = @(
        'Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
        'Application Administrator', 'Cloud Application Administrator', 'User Administrator',
        'Exchange Administrator', 'SharePoint Administrator', 'Intune Administrator', 'Conditional Access Administrator',
        'Privileged Authentication Administrator', 'Hybrid Identity Administrator', 'Authentication Administrator'
    )
    SuspiciousKeywords = @(
        'test', 'demo', 'temp', 'old', 'backup', 'legacy', 'dev', 'staging', 'admin', 'service', 'support', 'update', 'security', 'patch',
        'token', 'authentication', 'auth', 'credential', 'sync', 'connector', 'monitor', 'gateway', 'agent', 'portal', 'framework'
    )
}

# Load external risk configuration if provided
if ($RiskConfigPath -and (Test-Path $RiskConfigPath)) {
    try {
        $externalConfig = Get-Content $RiskConfigPath | ConvertFrom-Json
        $riskConfig = $externalConfig
        Write-Host "Loaded external risk configuration from $RiskConfigPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to load external risk configuration. Using default settings."
    }
}

# Function to safely import modules
function Import-GraphModuleSafely {
    param([string]$ModuleName)
    
    try {
        Import-Module $ModuleName -Force -ErrorAction Stop
        Write-Host "Successfully imported $ModuleName" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not import $ModuleName. Attempting to use Microsoft.Graph umbrella module..."
        try {
            Import-Module Microsoft.Graph -Force -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to import required Graph modules. Please ensure Microsoft Graph PowerShell is properly installed."
            Write-Host "Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
            exit 1
        }
    }
}

# Escape special HTML characters to prevent injection / markup breakage
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}

# Enhanced function to get both Service Principal and App Registration owners
function Get-ServicePrincipalOwners {
    param(
        [string]$ServicePrincipalId,
        [string]$AppId
    )
    
    $allOwners = @{
        ServicePrincipalOwners = @()
        AppRegistrationOwners = @()
        CombinedOwners = @()
        HasServicePrincipalOwners = $false
        HasAppRegistrationOwners = $false
        HasAnyOwners = $false
    }
    
    # Get Service Principal owners
    try {
        $spOwners = Get-MgServicePrincipalOwner -ServicePrincipalId $ServicePrincipalId -All -ErrorAction SilentlyContinue
        $spOwnerDetails = @()
        
        foreach ($owner in $spOwners) {
            try {
                # Try to get user details first
                $user = Get-MgUser -UserId $owner.Id -ErrorAction SilentlyContinue
                if ($user) {
                    $spOwnerDetails += @{
                        Id = $owner.Id
                        DisplayName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        Type = "User"
                        Source = "ServicePrincipal"
                    }
                } else {
                    # Try service principal if not a user
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $owner.Id -ErrorAction SilentlyContinue
                    if ($sp) {
                        $spOwnerDetails += @{
                            Id = $owner.Id
                            DisplayName = $sp.DisplayName
                            UserPrincipalName = $sp.AppId
                            Type = "ServicePrincipal"
                            Source = "ServicePrincipal"
                        }
                    } else {
                        # Fallback for unknown owner type
                        $spOwnerDetails += @{
                            Id = $owner.Id
                            DisplayName = "Unknown"
                            UserPrincipalName = ""
                            Type = "Unknown"
                            Source = "ServicePrincipal"
                        }
                    }
                }
            }
            catch {
                $spOwnerDetails += @{
                    Id = $owner.Id
                    DisplayName = "Unknown"
                    UserPrincipalName = ""
                    Type = "Unknown"
                    Source = "ServicePrincipal"
                }
            }
        }
        
        $allOwners.ServicePrincipalOwners = $spOwnerDetails
        $allOwners.HasServicePrincipalOwners = $spOwnerDetails.Count -gt 0
    }
    catch {
        # Service Principal owners retrieval failed
    }
    
    # Get App Registration owners (if app registration exists)
    try {
        $app = Get-MgApplication -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue
        if ($app) {
            $appOwners = Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction SilentlyContinue
            $appOwnerDetails = @()
            
            foreach ($owner in $appOwners) {
                try {
                    # Try to get user details first
                    $user = Get-MgUser -UserId $owner.Id -ErrorAction SilentlyContinue
                    if ($user) {
                        $appOwnerDetails += @{
                            Id = $owner.Id
                            DisplayName = $user.DisplayName
                            UserPrincipalName = $user.UserPrincipalName
                            Type = "User"
                            Source = "AppRegistration"
                        }
                    } else {
                        # Try service principal if not a user
                        $sp = Get-MgServicePrincipal -ServicePrincipalId $owner.Id -ErrorAction SilentlyContinue
                        if ($sp) {
                            $appOwnerDetails += @{
                                Id = $owner.Id
                                DisplayName = $sp.DisplayName
                                UserPrincipalName = $sp.AppId
                                Type = "ServicePrincipal"
                                Source = "AppRegistration"
                            }
                        } else {
                            # Fallback for unknown owner type
                            $appOwnerDetails += @{
                                Id = $owner.Id
                                DisplayName = "Unknown"
                                UserPrincipalName = ""
                                Type = "Unknown"
                                Source = "AppRegistration"
                            }
                        }
                    }
                }
                catch {
                    $appOwnerDetails += @{
                        Id = $owner.Id
                        DisplayName = "Unknown"
                        UserPrincipalName = ""
                        Type = "Unknown"
                        Source = "AppRegistration"
                    }
                }
            }
            
            $allOwners.AppRegistrationOwners = $appOwnerDetails
            $allOwners.HasAppRegistrationOwners = $appOwnerDetails.Count -gt 0
        }
    }
    catch {
        # App Registration owners retrieval failed
    }
    
    # Combine unique owners from both sources
    $uniqueOwnerIds = @{}
    $combinedOwners = @()
    
    # Add Service Principal owners
    foreach ($owner in $allOwners.ServicePrincipalOwners) {
        if (-not $uniqueOwnerIds.ContainsKey($owner.Id)) {
            $uniqueOwnerIds[$owner.Id] = $true
            $combinedOwners += $owner
        }
    }
    
    # Add App Registration owners (if not already in the list)
    foreach ($owner in $allOwners.AppRegistrationOwners) {
        if (-not $uniqueOwnerIds.ContainsKey($owner.Id)) {
            $uniqueOwnerIds[$owner.Id] = $true
            $combinedOwners += $owner
        } else {
            # Update source to indicate owner is in both places
            $existingOwner = $combinedOwners | Where-Object { $_.Id -eq $owner.Id }
            if ($existingOwner -and $existingOwner.Source -eq "ServicePrincipal") {
                $existingOwner.Source = "Both"
            }
        }
    }
    
    $allOwners.CombinedOwners = $combinedOwners
    $allOwners.HasAnyOwners = $combinedOwners.Count -gt 0
    
    return $allOwners
}

function Get-RiskScore {
    param(
        [array]$Permissions,
        [array]$DirectoryRoles,
        [string]$DisplayName,
        [bool]$HasCredentials,
        [bool]$HasAppRegistration,
        [bool]$HasServicePrincipalOwners,
        [bool]$HasAppRegistrationOwners,
        [bool]$HasAnyOwners,
        [bool]$AssignmentRequired,
        $TotalUsers,
        [bool]$IsInternalApp,
        [bool]$IsMicrosoftApp,
        [bool]$UsesPasswordSecrets,
        [int]$SecretCount,
        [bool]$HasLongLivedCredentials
    )
    
    $score = 0
    $riskFactors = @()
    
    # Permission-based scoring - track unique permissions to avoid double counting
    $uniqueHighRiskPerms = @()
    $uniqueMediumRiskPerms = @()
    $hasApplicationPerms = $false
    
    foreach ($perm in $Permissions) {
        # Track application permissions separately
        if ($perm.Type -eq "Application") {
            $hasApplicationPerms = $true
        }
        
        # Only count each unique permission once
        if ($perm.Permission -in $riskConfig.HighRiskPermissions -and $perm.Permission -notin $uniqueHighRiskPerms) {
            $score += 10
            $uniqueHighRiskPerms += $perm.Permission
            $riskFactors += "High-risk permission: $($perm.Permission)"
        }
        elseif ($perm.Permission -in $riskConfig.MediumRiskPermissions -and $perm.Permission -notin $uniqueMediumRiskPerms) {
            $score += 5
            $uniqueMediumRiskPerms += $perm.Permission
            $riskFactors += "Medium-risk permission: $($perm.Permission)"
        }
    }
    
    # Application permissions bonus (only once, not per permission)
    if ($hasApplicationPerms) {
        $score += 5
        $riskFactors += "Has application permissions"
    }
    
    # Directory role scoring - only count unique roles
    $uniqueRoles = @()
    foreach ($role in $DirectoryRoles) {
        if ($role.Permission -notin $uniqueRoles) {
            $uniqueRoles += $role.Permission
            if ($role.Permission -in $riskConfig.HighRiskDirectoryRoles) {
                $score += 15
                $riskFactors += "High-risk directory role: $($role.Permission)"
            }
            else {
                $score += 8
                $riskFactors += "Directory role: $($role.Permission)"
            }
        }
    }
    
    # Suspicious naming (only check once)
    $suspiciousKeywords = @()
    foreach ($keyword in $riskConfig.SuspiciousKeywords) {
        if ($DisplayName -ilike "*$keyword*" -and $keyword -notin $suspiciousKeywords) {
            $suspiciousKeywords += $keyword
        }
    }
    if ($suspiciousKeywords.Count -gt 0) {
        $score += 5
        $riskFactors += "Suspicious name contains: $($suspiciousKeywords -join ', ')"
    }
    
    # High user count with sensitive permissions (only check once)
    if ($TotalUsers -eq "All Users" -and ($uniqueHighRiskPerms.Count -gt 0 -or $uniqueMediumRiskPerms.Count -gt 0)) {
        $score += 5
        $riskFactors += "Sensitive permissions with all users access"
    }
    elseif ($TotalUsers -is [int] -and $TotalUsers -gt 50 -and ($uniqueHighRiskPerms.Count -gt 0 -or $uniqueMediumRiskPerms.Count -gt 0)) {
        $score += 3
        $riskFactors += "Sensitive permissions affecting many users ($TotalUsers users)"
    }
    
    # No active credentials (only for apps with registrations, check once)
    if (-not $HasCredentials -and $HasAppRegistration) {
        $score += 4
        $riskFactors += "No active credentials/certificates"
    }
        
    # Enhanced ownership checks
    if (-not $HasAnyOwners) {
        $score += 5
        $riskFactors += "No owners assigned (neither Service Principal nor App Registration)"
    }
    elseif (-not $HasServicePrincipalOwners -and $HasAppRegistration) {
        $score += 3
        $riskFactors += "No Service Principal owners (only App Registration owners)"
    }
    elseif (-not $HasAppRegistrationOwners -and $HasAppRegistration) {
        $score += 2
        $riskFactors += "No App Registration owners (only Service Principal owners)"
    }
    
    # Ownership gap detection (only for internal applications)
    if ($HasAppRegistration -and $isInternalApp -and ($HasServicePrincipalOwners -ne $HasAppRegistrationOwners)) {
        $score += 2
        $riskFactors += "Ownership gap - owners differ between Service Principal and App Registration"
    }
    
    # Assignment not required (open access risk)
    if (-not $AssignmentRequired) {
        $score += 4
        $riskFactors += "Assignment not required"
    }

    # Credential type: secrets are less secure than certificates
    if ($UsesPasswordSecrets) {
        $score += 5
        $riskFactors += "Uses password secrets (certificates preferred)"
    }

    # Multiple secrets increase attack surface
    if ($SecretCount -gt 1) {
        $score += 2
        $riskFactors += "Multiple secrets configured ($SecretCount) - reduces auditability"
    }

    # Long-lived credentials (> 1 year) are harder to rotate and track
    if ($HasLongLivedCredentials) {
        $score += 3
        $riskFactors += "Long-lived credentials (expiry > 1 year)"
    }

    # External apps are registered in another tenant. No control over registration or credential rotation
    # Microsoft owned apps are excluded as they are trusted first-party services
    if (-not $IsInternalApp -and -not $IsMicrosoftApp) {
        $score += 5
        $riskFactors += "External application registered in another tenant"
    }

    return @{
        Score = $score
        Level = if ($score -ge 30) { "Critical" } elseif ($score -ge 20) { "High" } elseif ($score -ge 10) { "Medium" } else { "Low" }
        Factors = $riskFactors
    }
}

# Function to get application credentials and registration info
function Get-ApplicationCredentials {
    param(
        [string]$AppId,
        $ServicePrincipal
    )

    $now = Get-Date
    $expiryThreshold = $now.AddDays(30)

    # Service Principal's own credentials (can be assigned directly, e.g. via PowerShell, even without an App Registration)
    $spActiveSecrets = @($ServicePrincipal.PasswordCredentials | Where-Object { $_.EndDateTime -gt $now })
    $spActiveCerts   = @($ServicePrincipal.KeyCredentials | Where-Object { $_.EndDateTime -gt $now })
    $spExpiring      = @(@($ServicePrincipal.PasswordCredentials) + @($ServicePrincipal.KeyCredentials) | Where-Object {
        $_.EndDateTime -gt $now -and $_.EndDateTime -lt $expiryThreshold
    })

    $hasAppReg = $false
    $appRegId = $null
    $appActiveSecrets = @()
    $appActiveCerts = @()
    $appExpiring = @()

    try {
        $app = Get-MgApplication -Filter "appId eq '$AppId'" -Property "Id,PasswordCredentials,KeyCredentials" -ErrorAction SilentlyContinue
        if ($app) {
            $hasAppReg = $true
            $appRegId = $app.Id
            $appActiveSecrets = @($app.PasswordCredentials | Where-Object { $_.EndDateTime -gt $now })
            $appActiveCerts   = @($app.KeyCredentials | Where-Object { $_.EndDateTime -gt $now })
            $appExpiring      = @(@($app.PasswordCredentials) + @($app.KeyCredentials) | Where-Object {
                $_.EndDateTime -gt $now -and $_.EndDateTime -lt $expiryThreshold
            })
        }
    }
    catch { }

    $totalActiveSecrets = $spActiveSecrets.Count + $appActiveSecrets.Count
    $totalActiveCerts   = $spActiveCerts.Count + $appActiveCerts.Count
    $totalExpiring      = $spExpiring.Count + $appExpiring.Count

    # Long-lived: any active credential with expiry > 1 year from now
    $longLivedThreshold = $now.AddDays(365)
    $allActiveCreds = @($spActiveSecrets) + @($appActiveSecrets) + @($spActiveCerts) + @($appActiveCerts)
    $hasLongLived = ($allActiveCreds | Where-Object { $_.EndDateTime -gt $longLivedThreshold }).Count -gt 0

    return @{
        HasAppRegistration   = $hasAppReg
        AppRegistrationId    = $appRegId
        HasActiveCredentials = ($totalActiveSecrets -gt 0 -or $totalActiveCerts -gt 0)
        ActiveSecrets        = $totalActiveSecrets
        ActiveCertificates   = $totalActiveCerts
        ExpiringCredentials  = $totalExpiring
        UsesPasswordSecrets  = ($totalActiveSecrets -gt 0)
        SecretCount          = $totalActiveSecrets
        HasLongLivedCredentials = $hasLongLived
    }
}

# Function to get and process permissions for filtering
function Get-ServicePrincipalPermissions {
    param($ServicePrincipal)
    
    # Get delegated permissions
    $delegatedGrants = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($ServicePrincipal.Id)'" -All
    
    # Get application permissions
    $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -All
    
    # Get directory role assignments
    $roleAssignments = @()
    try {
        $allRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($ServicePrincipal.Id)'" -All -ErrorAction SilentlyContinue
        foreach ($assignment in $allRoleAssignments) {
            $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $assignment.RoleDefinitionId -ErrorAction SilentlyContinue
            if ($roleDefinition) {
                $roleAssignments += $roleDefinition
            }
        }
    }
    catch {
        # Fallback method
        try {
            $allDirectoryRoles = Get-MgDirectoryRole -All -ErrorAction SilentlyContinue
            foreach ($role in $allDirectoryRoles) {
                try {
                    $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
                    if ($roleMembers | Where-Object { $_.Id -eq $ServicePrincipal.Id }) {
                        $roleAssignments += $role
                    }
                }
                catch { continue }
            }
        }
        catch { Write-Warning "Could not retrieve directory role assignments for $($ServicePrincipal.DisplayName)" }
    }
    
    # Calculate total permission count for filtering
    $delegatedPermissionCount = 0
    foreach ($grant in $delegatedGrants) {
        if ($grant.Scope) {
            $scopes = $grant.Scope.Split(' ') | Where-Object { $_ -ne '' }
            $delegatedPermissionCount += $scopes.Count
        }
    }
    
    $applicationPermissionCount = $appRoleAssignments.Count
    $directoryRoleCount = $roleAssignments.Count
    $totalPermissions = $delegatedPermissionCount + $applicationPermissionCount + $directoryRoleCount
    
    return @{
        TotalPermissions = $totalPermissions
        DelegatedGrants = $delegatedGrants
        AppRoleAssignments = $appRoleAssignments
        RoleAssignments = $roleAssignments
        ApplicationPermissionCount = $applicationPermissionCount
        DelegatedPermissionCount = $delegatedPermissionCount
        DirectoryRoleCount = $directoryRoleCount
    }
}

# Import required modules
Write-Host "Importing Microsoft Graph modules..." -ForegroundColor Green
Import-GraphModuleSafely "Microsoft.Graph.Applications"
Import-GraphModuleSafely "Microsoft.Graph.Identity.DirectoryManagement"
Import-GraphModuleSafely "Microsoft.Graph.Users"

# Connect to Microsoft Graph
$scopes = @(
    "Application.Read.All",
    "Directory.Read.All", 
    "DelegatedPermissionGrant.Read.All",
    "RoleManagement.Read.Directory"
)

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Green
if ($AccessToken) {
    # Token passed in — e.g. from AzurePowerShell@5 azureSubscription task
    Write-Host "  Auth method: Pre-acquired access token" -ForegroundColor Cyan
    Connect-MgGraph -AccessToken $AccessToken -NoWelcome
} elseif ($ClientId -and $CertificateThumbprint) {
    # Service Principal with certificate — recommended for pipelines
    Write-Host "  Auth method: Service Principal (certificate)" -ForegroundColor Cyan
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
} elseif ($ClientId -and $ClientSecret) {
    # Service Principal with client secret
    Write-Host "  Auth method: Service Principal (client secret)" -ForegroundColor Cyan
    $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $spCredential = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $spCredential -NoWelcome
} elseif ($UseManagedIdentity) {
    # Managed Identity — for Azure DevOps / Azure-hosted agents
    Write-Host "  Auth method: Managed Identity" -ForegroundColor Cyan
    Connect-MgGraph -Identity -NoWelcome
} elseif ($TenantId) {
    Connect-MgGraph -Scopes $scopes -TenantId $TenantId -NoWelcome
} else {
    Connect-MgGraph -Scopes $scopes -NoWelcome
}

Write-Host "Gathering Enterprise Applications..." -ForegroundColor Green

# Get service principals that match the Entra ID portal "Enterprise Applications" filter
$servicePrincipals = Get-MgServicePrincipal -All -Property @(
    "Id", "AppId", "DisplayName", "AppOwnerOrganizationId", 
    "ServicePrincipalType", "AppRoles", "Oauth2PermissionScopes", "SignInAudience", 
    "Tags", "AppDisplayName", "CreatedDateTime", "Owners", "AppRoleAssignmentRequired", "AccountEnabled",
    "PasswordCredentials", "KeyCredentials"
) | Where-Object { 
    $_.ServicePrincipalType -eq "Application" -and
    #$_.AppOwnerOrganizationId -ne "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -and
    $_.AppId -notin @(
        "00000003-0000-0000-c000-000000000000", # Microsoft Graph
        "00000002-0000-0ff1-ce00-000000000000", # Office 365 Exchange Online
        "00000003-0000-0ff1-ce00-000000000000", # Office 365 SharePoint Online
        "c5393580-f805-4401-95e8-94b7a6ef2fc2", # Office 365 Management APIs
        "d3590ed6-52b3-4102-aeff-aad2292ab01c", # Microsoft Office
        "09abbdfd-ed23-44ee-a2d9-a627aa1c90f3", # Microsoft Graph PowerShell
        "1b730954-1685-4b74-9bfd-dac224a7b894", # Azure Active Directory PowerShell
        "1950a258-227b-4e31-a9cf-717495945fc2", # Microsoft Azure PowerShell
        "797f4846-ba00-4fd7-ba43-dac1f8f63013" # Windows Azure Service Management API
    ) -and
    ($_.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp" -or
     $_.AppOwnerOrganizationId -eq (Get-MgContext).TenantId -or
     $_.SignInAudience -in @("AzureADMyOrg", "AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"))
}

Write-Host "Found $($servicePrincipals.Count) Enterprise Applications" -ForegroundColor Green

# PRE-FILTERING PHASE: Apply quick filters first for performance optimization
if ($OnlyWithPermissions -or $MinimumPermissions -gt 0 -or $OnlyWithAppRegistrations -or $OnlyServicePrincipals) {
    Write-Host "`nPre-filtering applications for performance optimization..." -ForegroundColor Cyan
    
    $filteredServicePrincipals = @()
    $filteringProgress = 0
    
    foreach ($sp in $servicePrincipals) {
        $filteringProgress++
        if ($filteringProgress % 10 -eq 0) {
            Write-Progress -Activity "Pre-filtering applications" -Status "Processing $($sp.DisplayName)" -PercentComplete (($filteringProgress / $servicePrincipals.Count) * 100)
        }
        
        $shouldInclude = $true
        
        # Check App Registration filter first (fastest check)
        if ($OnlyWithAppRegistrations -or $OnlyServicePrincipals) {
            $credentials = Get-ApplicationCredentials -AppId $sp.AppId
            
            if ($OnlyWithAppRegistrations -and -not $credentials.HasAppRegistration) {
                $shouldInclude = $false
            }
            elseif ($OnlyServicePrincipals -and $credentials.HasAppRegistration) {
                $shouldInclude = $false
            }
        }
        
        # Check permissions filter (more expensive check)
        if ($shouldInclude -and ($OnlyWithPermissions -or $MinimumPermissions -gt 0)) {
            $permissionInfo = Get-ServicePrincipalPermissions -ServicePrincipal $sp
            
            if ($OnlyWithPermissions -and $permissionInfo.TotalPermissions -eq 0) {
                $shouldInclude = $false
            }
            elseif ($MinimumPermissions -gt 0 -and $permissionInfo.TotalPermissions -lt $MinimumPermissions) {
                $shouldInclude = $false
            }
        }
        
        if ($shouldInclude) {
            $filteredServicePrincipals += $sp
        }
    }
    
    Write-Progress -Activity "Pre-filtering applications" -Completed
    Write-Host "Pre-filtering complete: $($filteredServicePrincipals.Count) applications match criteria" -ForegroundColor Green
    Write-Host "Performance gain: Skipping detailed analysis for $($servicePrincipals.Count - $filteredServicePrincipals.Count) applications" -ForegroundColor Yellow
    
    $servicePrincipals = $filteredServicePrincipals
}

# Confirmation prompt (skipped in non-interactive / pipeline mode)
if (-not $NonInteractive) {
    Write-Host "`n" -NoNewline
    $confirmation = Read-Host "Continue with detailed analysis of $($servicePrincipals.Count) applications? (Y/N)"
    if ($confirmation -notmatch '^[Yy]') {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        exit 0
    }
} else {
    Write-Host "Processing $($servicePrincipals.Count) applications (non-interactive mode)..." -ForegroundColor Cyan
}

Write-Host "`nProceeding with analysis..." -ForegroundColor Green

$report = @()
$processedCount = 0

foreach ($sp in $servicePrincipals) {
    $processedCount++
    Write-Progress -Activity "Processing applications" -Status "Processing $($sp.DisplayName)" -PercentComplete (($processedCount / $servicePrincipals.Count) * 100)
    Write-Host "Processing: $($sp.DisplayName) ($processedCount/$($servicePrincipals.Count))" -ForegroundColor Yellow
    
    # Get permissions (reuse from pre-filtering if available, otherwise get fresh)
    $permissionInfo = Get-ServicePrincipalPermissions -ServicePrincipal $sp
    
    # Process permissions into detailed format
    $permissions = @()
    $adminConsentCount = 0
    $userConsentCount = 0
    $totalUsers = 0
    
    # Process delegated permissions
    foreach ($grant in $permissionInfo.DelegatedGrants) {
        $consentType = if ($grant.ConsentType -eq "AllPrincipals") { "Admin Consent" } else { "User Consent" }
        
        if ($grant.ConsentType -eq "AllPrincipals") {
            $adminConsentCount++
            $userCount = "All Users"
        } else {
            $userConsentCount++
            $userCount = if ($grant.PrincipalId) { 1 } else { 0 }
            $totalUsers += $userCount
        }
        
        $resourceSP = Get-MgServicePrincipal -ServicePrincipalId $grant.ResourceId -ErrorAction SilentlyContinue
        $resourceName = if ($resourceSP) { $resourceSP.DisplayName } else { "Unknown" }
        
        if ($grant.Scope) {
            $scopes = $grant.Scope.Split(' ') | Where-Object { $_ -ne '' }
            foreach ($scope in $scopes) {
                $permissions += [PSCustomObject]@{
                    Type = "Delegated"
                    Permission = $scope
                    Resource = $resourceName
                    ConsentType = $consentType
                    UserCount = $userCount
                }
            }
        }
    }
    
    # Process application permissions
    foreach ($assignment in $permissionInfo.AppRoleAssignments) {
        $resourceSP = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -ErrorAction SilentlyContinue
        $resourceName = if ($resourceSP) { $resourceSP.DisplayName } else { "Unknown" }
        
        $appRole = $resourceSP.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
        $permissionName = if ($appRole) { $appRole.Value } else { "Unknown Permission" }
        
        $permissions += [PSCustomObject]@{
            Type = "Application"
            Permission = $permissionName
            Resource = $resourceName
            ConsentType = "Admin Consent"
            UserCount = "N/A"
        }
        $adminConsentCount++
    }
    
    # Process directory role assignments
    foreach ($role in $permissionInfo.RoleAssignments) {
        $permissions += [PSCustomObject]@{
            Type = "Directory Role"
            Permission = $role.DisplayName
            Resource = "Entra ID Directory"
            ConsentType = "Admin Assignment"
            UserCount = "N/A"
        }
    }
    
    # Get application credentials (App Registration + Service Principal own credentials)
    $credentials = Get-ApplicationCredentials -AppId $sp.AppId -ServicePrincipal $sp
    
    # Calculate total users affected
    $totalUsersAffected = if ($permissionInfo.DelegatedGrants | Where-Object { $_.ConsentType -eq "AllPrincipals" }) { 
        "All Users" 
    } else { 
        $totalUsers
    }
    
    # Get Service Principal and App Registration owners
    $ownerInfo = Get-ServicePrincipalOwners -ServicePrincipalId $sp.Id -AppId $sp.AppId
    $hasOwners = $ownerInfo.HasAnyOwners
    $assignmentRequired = $sp.AppRoleAssignmentRequired
    $isEnabled = $sp.AccountEnabled
    
    # Calculate if it's an internal app
    $isInternalApp = $sp.AppOwnerOrganizationId -eq (Get-MgContext).TenantId
    $isMicrosoftApp = $sp.AppOwnerOrganizationId -in @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

    # Calculate risk score with enhanced ownership parameters
    $riskAssessment = Get-RiskScore `
        -Permissions $permissions `
        -DirectoryRoles ($permissionInfo.RoleAssignments | ForEach-Object { @{Permission = $_.DisplayName} }) `
        -DisplayName $sp.DisplayName `
        -HasCredentials $credentials.HasActiveCredentials `
        -HasAppRegistration $credentials.HasAppRegistration `
        -HasServicePrincipalOwners $ownerInfo.HasServicePrincipalOwners `
        -HasAppRegistrationOwners $ownerInfo.HasAppRegistrationOwners `
        -HasAnyOwners $ownerInfo.HasAnyOwners `
        -AssignmentRequired $assignmentRequired `
        -TotalUsers $totalUsersAffected `
        -IsInternalApp $isInternalApp `
        -IsMicrosoftApp $isMicrosoftApp `
        -UsesPasswordSecrets $credentials.UsesPasswordSecrets `
        -SecretCount $credentials.SecretCount `
        -HasLongLivedCredentials $credentials.HasLongLivedCredentials
    $report += [PSCustomObject]@{
        DisplayName = $sp.DisplayName
        AppId = $sp.AppId
        ServicePrincipalId = $sp.Id
        AppOwnerOrganizationId = $sp.AppOwnerOrganizationId
        CreatedDate = $sp.CreatedDateTime
        
        # App Registration info
        HasAppRegistration = $credentials.HasAppRegistration
        AppRegistrationId = $credentials.AppRegistrationId
        
        # Enhanced Ownership info
        Owners = $ownerInfo.CombinedOwners
        ServicePrincipalOwners = $ownerInfo.ServicePrincipalOwners
        AppRegistrationOwners = $ownerInfo.AppRegistrationOwners
        HasOwners = $hasOwners
        HasServicePrincipalOwners = $ownerInfo.HasServicePrincipalOwners
        HasAppRegistrationOwners = $ownerInfo.HasAppRegistrationOwners
        OwnershipGap = ($ownerInfo.HasServicePrincipalOwners -ne $ownerInfo.HasAppRegistrationOwners)
        AssignmentRequired = $assignmentRequired
        IsEnabled = $isEnabled
        
        # Permissions
        TotalPermissions = $permissions.Count
        ApplicationPermissions = $permissionInfo.ApplicationPermissionCount
        DelegatedPermissions = $permissionInfo.DelegatedPermissionCount
        DirectoryRoles = $permissionInfo.DirectoryRoleCount
        AdminConsentPermissions = $adminConsentCount
        UserConsentPermissions = $userConsentCount
        Permissions = $permissions
        
        # Credentials
        HasActiveCredentials    = $credentials.HasActiveCredentials
        ActiveSecrets           = $credentials.ActiveSecrets
        ActiveCertificates      = $credentials.ActiveCertificates
        ExpiringCredentials     = $credentials.ExpiringCredentials
        UsesPasswordSecrets     = $credentials.UsesPasswordSecrets
        SecretCount             = $credentials.SecretCount
        HasLongLivedCredentials = $credentials.HasLongLivedCredentials
        
        # Risk assessment
        RiskScore = $riskAssessment.Score
        RiskLevel = $riskAssessment.Level
        RiskFactors = $riskAssessment.Factors
        
        # Other fields
        TotalUsers = $totalUsersAffected
        ServicePrincipalType = $sp.ServicePrincipalType
        SignInAudience = $sp.SignInAudience
    }
}

Write-Progress -Activity "Processing applications" -Completed

# Apply remaining filters (if not already applied during pre-filtering)
Write-Host "Applying final filters..." -ForegroundColor Green

if ($OnlyWithPermissions) {
    $report = $report | Where-Object { $_.TotalPermissions -gt 0 }
}

if ($OnlyWithAppRegistrations) {
    $report = $report | Where-Object { $_.HasAppRegistration -eq $true }
}

if ($OnlyServicePrincipals) {
    $report = $report | Where-Object { $_.HasAppRegistration -eq $false }
}

if ($MinimumPermissions -gt 0) {
    $report = $report | Where-Object { $_.TotalPermissions -ge $MinimumPermissions }
}

Write-Host "Final report contains $($report.Count) applications" -ForegroundColor Green

# Calculate summary statistics
# Note: wrap pipelines in @(...) so .Count is reliable in Windows PowerShell 5.1
# (a single matched object otherwise yields $null for .Count).
$totalApps = @($report).Count
$appsWithRegistrations = @($report | Where-Object { $_.HasAppRegistration -eq $true }).Count
$servicePrincipalsOnly = @($report | Where-Object { $_.HasAppRegistration -eq $false }).Count
$criticalRiskApps = @($report | Where-Object { $_.RiskLevel -eq "Critical" }).Count
$highRiskApps     = @($report | Where-Object { $_.RiskLevel -eq "High" }).Count
$mediumRiskApps   = @($report | Where-Object { $_.RiskLevel -eq "Medium" }).Count
$lowRiskApps      = @($report | Where-Object { $_.RiskLevel -eq "Low" }).Count
$appsWithApplicationPerms = @($report | Where-Object { $_.ApplicationPermissions -gt 0 }).Count
$appsWithDelegatedPerms = @($report | Where-Object { $_.DelegatedPermissions -gt 0 }).Count
$totalApplicationPerms = [int]($report | Measure-Object -Property ApplicationPermissions -Sum).Sum
$totalDelegatedPerms = [int]($report | Measure-Object -Property DelegatedPermissions -Sum).Sum
$appsWithoutCredentials = @($report | Where-Object { $_.HasActiveCredentials -eq $false -and $_.HasAppRegistration -eq $true }).Count

# Get tenant information
$tenantInfo = Get-MgOrganization | Select-Object -First 1
$tenantName = $tenantInfo.DisplayName
$tenantId = $tenantInfo.Id

if (-not $OutputPath) {
    $safeName = $tenantName -replace '[^\w]', '_'
    $OutputPath = "EntraIDReport_${safeName}_$(Get-Date -Format 'yyyy-MM-dd').html"
}

# Ensure output directory exists
$outputDir = Split-Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    Write-Host "Created output directory: $outputDir" -ForegroundColor Cyan
}

# Calculate additional statistics for internal vs external apps and ownership
$internalApps   = @($report | Where-Object { $_.AppOwnerOrganizationId -eq $tenantId }).Count
$microsoftApps  = @($report | Where-Object { $_.AppOwnerOrganizationId -in @('f8cdef31-a31e-4b4a-93e4-5f571e91255a','72f988bf-86f1-41af-91ab-2d7cd011db47') }).Count
$externalApps   = @($report | Where-Object { $_.AppOwnerOrganizationId -ne $tenantId -and $_.AppOwnerOrganizationId -notin @('f8cdef31-a31e-4b4a-93e4-5f571e91255a','72f988bf-86f1-41af-91ab-2d7cd011db47') }).Count
$appsWithoutOwners = @($report | Where-Object { $_.HasOwners -eq $false }).Count
$appsWithOpenAccess = @($report | Where-Object { $_.AssignmentRequired -eq $false }).Count
$appsWithOwnershipGaps = @($report | Where-Object { $_.OwnershipGap -eq $true }).Count
$disabledApps = @($report | Where-Object { $_.IsEnabled -eq $false }).Count
$appsWithSPOwnersOnly = @($report | Where-Object { $_.HasServicePrincipalOwners -eq $true -and $_.HasAppRegistrationOwners -eq $false -and $_.HasAppRegistration -eq $true }).Count
$appsWithAppRegOwnersOnly = @($report | Where-Object { $_.HasServicePrincipalOwners -eq $false -and $_.HasAppRegistrationOwners -eq $true }).Count

# Generate simplified HTML report

# Load the header logo (Enterprise Applications.svg) from the script directory and inline it.
# Falls back to an empty string if the file is not found so the report still renders.
$logoFile = Join-Path $PSScriptRoot 'Enterprise Applications.svg'
$logoSvg = if (Test-Path -LiteralPath $logoFile) {
    Get-Content -LiteralPath $logoFile -Raw -Encoding UTF8
} else {
    Write-Warning "Logo file not found: $logoFile"
    ''
}

$html = @"
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Entra ID Service Principals (Enterprise Applications) Report</title>
    <style>
        /* -- Light Theme Variables -- */
        :root {
            --blue:        #0078d4;
            --blue-dark:   #005a9e;
            --blue-light:  #cce4f6;
            --blue-xs:     #f0f6fc;
            --text:        #1a1a1a;
            --text-muted:  #888;
            --gray:        #666;
            --gray-dark:   #444;
            --bg-page:     #edf2f7;
            --bg-panel:    #ffffff;
            --bg-header:   #0078d4;
            --bg-input:    #ffffff;
            --bg-subtle:   #f7fafc;
            --border:      #ddd;
            --border-row:  #e2e8f0;
            --shadow:      0 2px 10px rgba(0,0,0,0.08);
            --radius:      8px;

            --risk-critical-bg:   #fed7d7;
            --risk-critical-text: #c53030;
            --risk-high-bg:       #feebc8;
            --risk-high-text:     #dd6b20;
            --risk-medium-bg:     #fefcbf;
            --risk-medium-text:   #b7791f;
            --risk-low-bg:        #c6f6d5;
            --risk-low-text:      #2f855a;

            --internal:      #2b6cb0;
            --external:      #c05621;
            --good:          #2f855a;
            --bad:           #c53030;
            --warn:          #b7791f;
            --app-perm-text: #c53030;
        }

        /* -- Dark Theme Variables -- */
        [data-theme="dark"] {
            --blue:        #3aa0f3;
            --blue-dark:   #2b8fd4;
            --blue-light:  #1a3a55;
            --blue-xs:     #152030;
            --text:        #e2e8f0;
            --text-muted:  #6a7585;
            --gray:        #9aa5b3;
            --gray-dark:   #c8d0da;
            --bg-page:     #111520;
            --bg-panel:    #1c1f2e;
            --bg-header:   #0d1117;
            --bg-input:    #252840;
            --bg-subtle:   #232738;
            --border:      #343848;
            --border-row:  #2a2e3e;
            --shadow:      0 2px 12px rgba(0,0,0,0.35);

            --risk-critical-bg:   #3a1518;
            --risk-critical-text: #f98a8a;
            --risk-high-bg:       #3a2410;
            --risk-high-text:     #f0a868;
            --risk-medium-bg:     #332b0d;
            --risk-medium-text:   #e6c45c;
            --risk-low-bg:        #122a1a;
            --risk-low-text:      #6ee7a0;

            --internal:      #63b3ed;
            --external:      #f6ad55;
            --good:          #68d391;
            --bad:           #f98a8a;
            --warn:          #e6c45c;
            --app-perm-text: #f98a8a;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            font-size: 14px;
            color: var(--text);
            background: var(--bg-page);
            min-height: 100vh;
            transition: background 0.25s, color 0.25s;
        }

        a { color: var(--blue); }

        /* -- Header -- */
        header {
            background: var(--bg-header);
            color: #fff;
            padding: 16px 32px;
            display: flex;
            align-items: center;
            gap: 16px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.3);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        header .header-logo { flex-shrink: 0; opacity: 0.95; line-height: 0; }
        header .header-logo svg { width: 34px; height: 34px; }
        header .header-text { flex: 1; }
        header h1 { font-size: 16px; font-weight: 600; letter-spacing: 0.2px; }
        header .meta { font-size: 11px; opacity: 0.75; margin-top: 1px; line-height: 1.7; }
        header .meta strong { font-weight: 600; }

        #themeToggle {
            background: rgba(255,255,255,0.12);
            border: 1px solid rgba(255,255,255,0.25);
            color: #fff;
            font-size: 17px;
            width: 36px; height: 36px;
            border-radius: 50%;
            cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            transition: background 0.2s, transform 0.2s;
            flex-shrink: 0;
            line-height: 1;
        }
        #themeToggle:hover { background: rgba(255,255,255,0.25); transform: rotate(20deg); }

        /* -- Layout -- */
        .container { max-width: 1600px; margin: 24px auto; padding: 0 24px 48px; }

        /* -- Summary cards -- */
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .summary-card {
            background: var(--bg-panel);
            padding: 18px 20px;
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            border-top: 4px solid var(--blue);
            text-align: center;
            cursor: pointer;
            transition: background 0.25s, box-shadow 0.25s, transform 0.15s;
        }
        .summary-card:hover { transform: translateY(-2px); box-shadow: 0 4px 14px rgba(0,0,0,0.12); }
        .summary-card h3 { margin: 0 0 6px; color: var(--gray-dark); font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .summary-card .number { font-size: 30px; font-weight: 700; color: var(--blue); margin: 6px 0; }
        /* Number colors matching badge colors per card type */
        .summary-card[data-fv="Critical"] .number { color: #c50f1f; }
        .summary-card[data-fv="High"]     .number { color: #d83b01; }
        .summary-card[data-fv="Medium"]   .number { color: #b06000; }
        .summary-card[data-fv="Low"]      .number { color: #107c10; }
        .summary-card[data-fv="internal"] .number { color: #107c10; }
        .summary-card[data-fv="microsoft"].number  { color: #0078d4; }
        .summary-card[data-fv="third-party"] .number { color: #c50f1f; }
        .summary-card[data-fv="gap"]      .number { color: #b06000; }
        .summary-card[data-fv="not-required"] .number { color: #767676; }
        .summary-card[data-fv="no"][data-fg="enabled"] .number { color: #767676; }
        /* Border colors matching number colors */
        .summary-card[data-fv="Critical"]            { border-top-color: #c50f1f; }
        .summary-card[data-fv="High"]                { border-top-color: #d83b01; }
        .summary-card[data-fv="Medium"]              { border-top-color: #b06000; }
        .summary-card[data-fv="Low"]                 { border-top-color: #107c10; }
        .summary-card[data-fv="internal"]            { border-top-color: #107c10; }
        .summary-card[data-fv="microsoft"]           { border-top-color: #0078d4; }
        .summary-card[data-fv="third-party"]         { border-top-color: #c50f1f; }
        .summary-card[data-fv="gap"]                 { border-top-color: #b06000; }
        .summary-card[data-fv="not-required"]        { border-top-color: #767676; }
        .summary-card[data-fv="no"][data-fg="enabled"] { border-top-color: #767676; }
        [data-theme="dark"] .summary-card[data-fv="Critical"] .number { color: #e3223a; }
        [data-theme="dark"] .summary-card[data-fv="High"]     .number { color: #f0571f; }
        [data-theme="dark"] .summary-card[data-fv="Medium"]   .number { color: #c87000; }
        [data-theme="dark"] .summary-card[data-fv="Low"]      .number { color: #2a9d2a; }
        [data-theme="dark"] .summary-card[data-fv="internal"] .number { color: #2a9d2a; }
        [data-theme="dark"] .summary-card[data-fv="third-party"] .number { color: #e3223a; }
        [data-theme="dark"] .summary-card[data-fv="Critical"]  { border-top-color: #e3223a; }
        [data-theme="dark"] .summary-card[data-fv="High"]      { border-top-color: #f0571f; }
        [data-theme="dark"] .summary-card[data-fv="Medium"]    { border-top-color: #c87000; }
        [data-theme="dark"] .summary-card[data-fv="Low"]       { border-top-color: #2a9d2a; }
        [data-theme="dark"] .summary-card[data-fv="internal"]  { border-top-color: #2a9d2a; }
        [data-theme="dark"] .summary-card[data-fv="third-party"] { border-top-color: #e3223a; }
        .summary-card .subtitle { color: var(--text-muted); font-size: 12.5px; }

        /* -- Controls -- */
        .controls {
            background: var(--bg-panel);
            padding: 20px;
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            margin-bottom: 24px;
            transition: background 0.25s, box-shadow 0.25s;
        }
        .controls h3 { margin: 0 0 12px; font-size: 14px; color: var(--gray-dark); }
        .controls input, .controls select {
            margin: 4px; padding: 9px 11px;
            border: 1px solid var(--border);
            border-radius: 5px;
            font-size: 13px;
            color: var(--text);
            background: var(--bg-input);
            transition: border-color 0.15s, box-shadow 0.15s;
        }
        .controls input:focus, .controls select:focus {
            outline: none; border-color: var(--blue);
            box-shadow: 0 0 0 2px var(--blue-light);
        }
        .controls button {
            background: var(--blue); color: #fff; border: none;
            padding: 9px 18px; border-radius: 5px; cursor: pointer; margin: 4px;
            font-size: 13px; transition: background 0.2s;
        }
        .controls button:hover { background: var(--blue-dark); }

        /* -- Tag filters -- */
        .filter-bar { display: flex; align-items: center; gap: 12px; margin: 4px 0 8px; }
        .filter-toggle-btn {
            display: inline-flex; align-items: center; gap: 8px;
            background: var(--bg-panel); border: 1px solid var(--border); color: var(--text);
            padding: 8px 16px; border-radius: 6px;
            font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
            cursor: pointer;
            transition: background 0.15s, border-color 0.15s;
        }
        .filter-toggle-btn:hover { border-color: var(--blue); background: var(--blue-xs); }
        .filter-toggle-btn[aria-expanded="true"] { border-color: var(--blue); }
        .filter-toggle-btn .caret { font-size: 10px; color: var(--gray); transition: transform 0.15s; }
        .filter-summary { font-size: 13px; font-weight: 600; color: var(--blue); }

        .clickable-badge { cursor: pointer; transition: filter 0.15s, box-shadow 0.15s; }
        .clickable-badge:hover { filter: brightness(1.15); }

        .filter-search {
            width: 100%;
            margin: 4px 0 16px;
            padding: 11px 14px;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 14px;
            color: var(--text);
            background: var(--bg-input);
            transition: border-color 0.15s, box-shadow 0.15s;
        }
        .filter-search:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 2px var(--blue-light); }

        .filter-group { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
        .filter-group-label {
            font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
            color: var(--gray); width: 130px; flex-shrink: 0;
        }
        .filter-tag {
            display: inline-flex; align-items: center; gap: 5px;
            padding: 4px 12px; border: 1px solid var(--border); border-radius: 14px;
            background: var(--bg-panel); color: var(--text); font-size: 12px; font-weight: 600;
            cursor: pointer; user-select: none;
            transition: background 0.15s, border-color 0.15s, color 0.15s;
        }
        .filter-tag:hover { border-color: var(--blue); background: var(--blue-xs); }
        .filter-tag .cnt { font-size: 10px; font-weight: 600; color: var(--text-muted); }
        .filter-tag.active { color: #fff; border-color: transparent; }
        .filter-tag.active .cnt { color: rgba(255,255,255,0.85); }

        .filter-tag.active.c-blue   { background: #0078d4; }
        .filter-tag.active.c-amber  { background: #b06000; }
        .filter-tag.active.c-red    { background: #c50f1f; }
        .filter-tag.active.c-orange { background: #d83b01; }
        .filter-tag.active.c-green  { background: #107c10; }
        .filter-tag.active.c-purple { background: #7054a0; }
        .filter-tag.active.c-gray   { background: #767676; }

        [data-theme="dark"] .filter-tag.active.c-green  { background: #2a9d2a; }
        [data-theme="dark"] .filter-tag.active.c-red    { background: #e3223a; }
        [data-theme="dark"] .filter-tag.active.c-orange { background: #f0571f; }

        .filter-results {
            display: flex; align-items: center; flex-wrap: wrap; gap: 8px;
            margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--border);
        }
        .result-count { font-size: 13px; font-weight: 600; color: var(--gray-dark); margin-right: 4px; }
        .active-chips { display: inline-flex; flex-wrap: wrap; gap: 6px; }
        .chip {
            display: inline-flex; align-items: center; gap: 4px;
            background: var(--blue-xs); color: var(--blue); border: 1px solid var(--blue-light);
            padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; cursor: pointer;
        }
        .chip:hover { background: var(--blue-light); }
        .clear-all {
            background: none; border: none; color: var(--blue); cursor: pointer;
            font-size: 12px; font-weight: 600; text-decoration: underline; padding: 0; margin-left: auto;
        }

        /* -- Table -- */
        .table-wrap {
            background: var(--bg-panel);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            overflow: auto;
            transition: background 0.25s, box-shadow 0.25s;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 11px 12px; text-align: left; border-bottom: 1px solid var(--border-row); vertical-align: top; }
        td { font-size: 11px; font-weight: 400; color: var(--gray-dark); letter-spacing: 0.5px; }
        th {
            background: var(--bg-subtle); font-weight: 700; cursor: pointer; user-select: none;
            position: sticky; top: 0; z-index: 1; color: var(--gray-dark);
            text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px;
        }
        th:hover { background: var(--blue-xs); }
        tbody tr { transition: background 0.12s; }
        tbody tr:hover { background: var(--bg-subtle); }

        /* -- Risk row tints -- */
        .risk-critical { background: var(--risk-critical-bg) !important; color: var(--risk-critical-text); }
        .risk-high     { background: var(--risk-high-bg) !important; color: var(--risk-high-text); }
        .risk-medium   { background: var(--risk-medium-bg) !important; color: var(--risk-medium-text); }
        .risk-low      { background: var(--risk-low-bg) !important; color: var(--risk-low-text); }

        /* -- Badges (pattern-badge style from Name Codex) -- */
        .badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: #767676;
            color: #fff;
            font-size: 9px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            vertical-align: middle;
            text-align: center;
            line-height: 1.3;
            white-space: nowrap;
        }
        .badge.green   { background: #107c10; }
        .badge.red     { background: #c50f1f; }
        .badge.orange  { background: #d83b01; }
        .badge.amber   { background: #b06000; }
        .badge.blue    { background: #0078d4; }
        .badge.teal    { background: #00827f; }
        .badge.purple  { background: #7054a0; }
        .badge.gray    { background: #767676; }

        [data-theme="dark"] .badge.green  { background: #2a9d2a; }
        [data-theme="dark"] .badge.red    { background: #e3223a; }
        [data-theme="dark"] .badge.orange { background: #f0571f; }
        [data-theme="dark"] .badge.amber  { background: #c87000; }
        [data-theme="dark"] .badge.purple { background: #9070c0; }

        .perm-badges { display: inline-flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }

        .has-app-reg, .sp-only { color: var(--gray); }
        .internal-app { color: var(--internal); font-weight: 600; }
        .external-app { color: var(--external); font-weight: 600; }
        .assignment-required { color: var(--good); }
        .assignment-not-required { color: var(--bad); }
        .has-owners { color: var(--good); }
        .no-owners { color: var(--bad); }
        .ownership-gap { color: var(--warn); }

        .mono { font-family: 'Inter', sans-serif; font-size: 11px; font-weight: 400; color: var(--gray-dark); letter-spacing: 0.5px; }
        .muted { color: var(--text-muted); }
        .tiny { font-family: 'Inter', sans-serif; font-size: 11px; font-weight: 400; color: var(--gray-dark); letter-spacing: 0.5px; }
        .app-name { font-family: 'Inter', sans-serif; font-size: 11px; font-weight: 400; color: var(--gray-dark); letter-spacing: 0.5px; text-decoration: none; }
        .app-name:hover { text-decoration: underline; color: var(--blue); }
        .cell-sm { font-size: 11px; }

        .permission-list { max-height: none; overflow-y: visible; font-size: 11px; }
        .permission-item { margin: 2px 5px 2px 0; padding: 2px 6px; border-radius: 3px; display: inline-block; }
        .app-permission { color: var(--app-perm-text); }
        .delegated-permission { color: var(--gray); }
        .directory-role { color: var(--external); }

        details summary { cursor: pointer; color: var(--gray-dark); font-size: 11px; font-weight: 400; text-transform: uppercase; letter-spacing: 0.5px; }

        /* -- Footer -- */
        footer.report-footer {
            text-align: center;
            background: var(--bg-header);
            color: rgba(255,255,255,0.85);
            font-size: 11px;
            padding: 16px 24px;
            margin-top: 0;
        }
        footer.report-footer a { color: rgba(255,255,255,0.85); text-decoration: none; }
        footer.report-footer a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <header>
        <span class="header-logo">
            $logoSvg
        </span>
        <div class="header-text">
            <h1>Microsoft Entra ID Service Principals (Enterprise Applications) Report</h1>
            <div class="meta">
                <strong>Tenant:</strong> $(ConvertTo-HtmlSafe $tenantName) &nbsp;&middot;&nbsp;
                <strong>Tenant ID:</strong> $tenantId &nbsp;&middot;&nbsp;
                <strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            </div>
        </div>
        <button id="themeToggle" onclick="toggleTheme()" title="Toggle dark / light mode">&#127769;</button>
    </header>

    <div class="container">

    <div class="summary">
        <div class="summary-card" data-clear="1" title="Clear all filters">
            <h3>Total Applications</h3>
            <div class="number">$totalApps</div>
            <div class="subtitle">Enterprise Applications analyzed</div>
        </div>
        <div class="summary-card" data-fg="risk" data-fv="Critical" title="Critical risk apps require immediate review. They have a combination of high privilege permissions, active credentials and missing controls. Click to filter.">
            <h3>Critical Risk</h3>
            <div class="number">$criticalRiskApps</div>
            <div class="subtitle">Applications requiring immediate attention</div>
        </div>
        <div class="summary-card" data-fg="risk" data-fv="High" title="High risk apps have elevated permissions or missing security controls that should be reviewed. Click to filter.">
            <h3>High Risk</h3>
            <div class="number">$highRiskApps</div>
            <div class="subtitle">Applications with elevated risk scores</div>
        </div>
        <div class="summary-card" data-fg="risk" data-fv="Medium" title="Medium risk apps have some risk factors present. Review the risk analysis for details. Click to filter.">
            <h3>Medium Risk</h3>
            <div class="number">$mediumRiskApps</div>
            <div class="subtitle">Applications with moderate risk scores</div>
        </div>
        <div class="summary-card" data-fg="risk" data-fv="Low" title="Low risk apps have no significant security concerns detected. Click to filter.">
            <h3>Low Risk</h3>
            <div class="number">$lowRiskApps</div>
            <div class="subtitle">Applications with minimal risk</div>
        </div>
        <div class="summary-card" data-fg="ownership" data-fv="internal" title="Apps registered in this tenant and owned by your organization. Click to filter.">
            <h3>Internal Apps</h3>
            <div class="number">$internalApps</div>
            <div class="subtitle">Apps owned by your organization</div>
        </div>
        <div class="summary-card" data-fg="ownership" data-fv="microsoft" title="First party Microsoft applications. These are owned and operated by Microsoft. Click to filter.">
            <h3>Microsoft Apps</h3>
            <div class="number">$microsoftApps</div>
            <div class="subtitle">First-party Microsoft services</div>
        </div>
        <div class="summary-card" data-fg="ownership" data-fv="third-party" title="Apps registered in another tenant by a third party. Click to filter.">
            <h3>Third-Party Apps</h3>
            <div class="number">$externalApps</div>
            <div class="subtitle">Third-party external applications</div>
        </div>
        <div class="summary-card" data-fg="owners" data-fv="gap" title="Not all owners are assigned to both the Service Principal and the App Registration. Click to filter.">
            <h3>Ownership Gaps</h3>
            <div class="number">$appsWithOwnershipGaps</div>
            <div class="subtitle">Apps with ownership inconsistencies</div>
        </div>
        <div class="summary-card" data-fg="assignment" data-fv="not-required" title="All users in the tenant can access this app without explicit assignment. Click to filter.">
            <h3>Open Access</h3>
            <div class="number">$appsWithOpenAccess</div>
            <div class="subtitle">Apps with no assignment required</div>
        </div>
        <div class="summary-card" data-fg="enabled" data-fv="no" title="User sign-in is blocked for these applications. They are visible in the tenant but cannot be used. Click to filter.">
            <h3>Disabled Apps</h3>
            <div class="number">$disabledApps</div>
            <div class="subtitle">Apps with sign-in disabled</div>
        </div>
    </div>

    <div class="filter-bar">
        <button id="filterToggle" class="filter-toggle-btn" onclick="toggleFilterPanel()" aria-expanded="false">
            <span class="caret">&#9656;</span> Search &amp; Filter
        </button>
        <span id="filterSummary" class="filter-summary"></span>
    </div>

    <div class="controls" id="controlsPanel" hidden>
        <input type="text" id="searchInput" class="filter-search" placeholder="Search by application name..." onkeyup="applyFilters()">

        <div class="filter-group">
            <span class="filter-group-label">Ownership</span>
            <span class="filter-tag c-green" data-group="ownership" data-value="internal"    onclick="toggleTag(this)">Internal <span class="cnt"></span></span>
            <span class="filter-tag c-blue"  data-group="ownership" data-value="microsoft"   onclick="toggleTag(this)">Microsoft <span class="cnt"></span></span>
            <span class="filter-tag c-red"   data-group="ownership" data-value="third-party" onclick="toggleTag(this)">Third-Party <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Enabled</span>
            <span class="filter-tag c-green" data-group="enabled" data-value="yes" onclick="toggleTag(this)">Enabled <span class="cnt"></span></span>
            <span class="filter-tag c-gray"  data-group="enabled" data-value="no"  onclick="toggleTag(this)">Disabled <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Risk Level</span>
            <span class="filter-tag c-red"    data-group="risk" data-value="Critical" onclick="toggleTag(this)">Critical <span class="cnt"></span></span>
            <span class="filter-tag c-orange" data-group="risk" data-value="High"     onclick="toggleTag(this)">High <span class="cnt"></span></span>
            <span class="filter-tag c-amber"  data-group="risk" data-value="Medium"   onclick="toggleTag(this)">Medium <span class="cnt"></span></span>
            <span class="filter-tag c-green"  data-group="risk" data-value="Low"      onclick="toggleTag(this)">Low <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">App Registration</span>
            <span class="filter-tag c-green" data-group="appreg" data-value="yes" onclick="toggleTag(this)">Yes <span class="cnt"></span></span>
            <span class="filter-tag c-gray" data-group="appreg" data-value="no"  onclick="toggleTag(this)">No <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Assignment</span>
            <span class="filter-tag c-green" data-group="assignment" data-value="required"     onclick="toggleTag(this)">Required <span class="cnt"></span></span>
            <span class="filter-tag c-gray" data-group="assignment" data-value="not-required" onclick="toggleTag(this)">Open Access <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Owners</span>
            <span class="filter-tag c-green" data-group="owners" data-value="has"      onclick="toggleTag(this)">Has Owners <span class="cnt"></span></span>
            <span class="filter-tag c-gray" data-group="owners" data-value="noowners" onclick="toggleTag(this)">No Owners <span class="cnt"></span></span>
            <span class="filter-tag c-amber" data-group="owners" data-value="gap"     onclick="toggleTag(this)">Ownership Gap <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Permissions</span>
            <span class="filter-tag c-red"    data-group="permissions" data-value="application" onclick="toggleTag(this)">Application <span class="cnt"></span></span>
            <span class="filter-tag c-blue"   data-group="permissions" data-value="delegated"   onclick="toggleTag(this)">Delegated <span class="cnt"></span></span>
            <span class="filter-tag c-purple" data-group="permissions" data-value="roles"       onclick="toggleTag(this)">Roles <span class="cnt"></span></span>
            <span class="filter-tag c-gray"   data-group="permissions" data-value="none"        onclick="toggleTag(this)">None <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Credentials</span>
            <span class="filter-tag c-green" data-group="credentials" data-value="active" onclick="toggleTag(this)">Active <span class="cnt"></span></span>
            <span class="filter-tag c-gray"  data-group="credentials" data-value="none"   onclick="toggleTag(this)">None <span class="cnt"></span></span>
            <span class="filter-tag c-amber" data-group="credentials" data-value="expiring" onclick="toggleTag(this)">Expiring <span class="cnt"></span></span>
        </div>

        <div class="filter-results">
            <span id="resultCount" class="result-count"></span>
            <span id="activeChips" class="active-chips"></span>
            <button id="clearAll" class="clear-all" onclick="clearAllFilters()" style="display:none;">Clear all</button>
        </div>
    </div>

    <div class="table-wrap">
    <table id="reportTable">
        <thead>
            <tr>
                <th onclick="sortTable(0, 'string')">Application Name</th>
                <th onclick="sortTable(1, 'string')">Enabled</th>
                <th onclick="sortTable(2, 'string')">App ID</th>
                <th onclick="sortTable(3, 'string')">App Ownership</th>
                <th onclick="sortTable(4, 'string')">Has App Registration</th>
                <th onclick="sortTable(5, 'string')">Assignment Required</th>
                <th onclick="sortTable(6, 'string')">Owners</th>
                <th onclick="sortTable(7, 'string')">Risk Level</th>
                <th>Permissions</th>
                <th>Permissions Detail</th>
                <th onclick="sortTable(10, 'string')">Active Credentials</th>
                <th>Risk Factors</th>
            </tr>
        </thead>
        <tbody>
"@

# Sort by risk score (descending), then by total permissions (descending)
$sortedReport = $report | Sort-Object @{Expression="RiskScore"; Descending=$true}, @{Expression="TotalPermissions"; Descending=$true}

foreach ($app in $sortedReport) {
    $riskClass = "risk-" + $app.RiskLevel.ToLower()
    $appRegClass = if ($app.HasAppRegistration) { "has-app-reg" } else { "sp-only" }
    $appRegText = if ($app.HasAppRegistration) { "<span class='badge green clickable-badge' data-fg='appreg' data-fv='yes' title='This service principal has a linked App Registration in this tenant'>Yes</span>" } else { "<span class='badge gray clickable-badge' data-fg='appreg' data-fv='no' title='Service principal only with no App Registration found in this tenant'>No</span>" }
    $enabledText = if ($app.IsEnabled) { "<span class='badge green clickable-badge' data-fg='enabled' data-fv='yes' title='Users can sign in and the application is active in this tenant'>Yes</span>" } else { "<span class='badge gray clickable-badge' data-fg='enabled' data-fv='no' title='User sign-in is blocked for this application. It is visible in the tenant but cannot be used'>No</span>" }
    $portalUrl = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$($app.ServicePrincipalId)/appId/$($app.AppId)"
    $enabledClass = if ($app.IsEnabled) { "app-enabled" } else { "app-disabled" }
    
    # Determine app ownership
    $isInternal = $app.AppOwnerOrganizationId -eq $tenantId
    $isMicrosoft = $app.AppOwnerOrganizationId -in @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
    $ownershipType = if ($isInternal) { "internal" } elseif ($isMicrosoft) { "microsoft" } else { "third-party" }
    $ownershipText = switch ($ownershipType) {
        "internal"    { "<span class='badge green clickable-badge' data-fg='ownership' data-fv='internal' title='App registered in this tenant and owned by your organization'>Internal</span>" }
        "microsoft"   { "<span class='badge blue clickable-badge' data-fg='ownership' data-fv='microsoft' title='App owned by Microsoft. This is a first party Microsoft service'>Microsoft</span>" }
        "third-party" { "<span class='badge red clickable-badge' data-fg='ownership' data-fv='third-party' title='App registered in another tenant. This is a third party service'>Third-Party</span>" }
    }
    $ownershipClass = switch ($ownershipType) {
        "internal"    { "internal-app" }
        "microsoft"   { "microsoft-app" }
        "third-party" { "external-app" }
    }
    
    # Determine assignment requirement
    $assignmentRequiredText = if ($app.AssignmentRequired) { "<span class='badge green clickable-badge' data-fg='assignment' data-fv='required' title='Users and groups must be explicitly assigned to access this app'>Yes</span>" } else { "<span class='badge gray clickable-badge' data-fg='assignment' data-fv='not-required' title='All users in the tenant can access this app without explicit assignment'>No</span>" }
    $assignmentRequiredClass = if ($app.AssignmentRequired) { "assignment-required" } else { "assignment-not-required" }
    
    # Format owners with enhanced information
    $ownersText = if ($app.HasOwners) {
        $spOwnerCount = $app.ServicePrincipalOwners.Count
        $appRegOwnerCount = $app.AppRegistrationOwners.Count
        
        $ownerDisplay = "<span class='badge blue clickable-badge' data-fg='owners' data-fv='has' title='Users or service principals responsible for managing this app'>$($app.Owners.Count) owner(s)</span> "
        
        $isInternalApp = $app.AppOwnerOrganizationId -eq $tenantId
        if (($app.OwnershipGap -or ($spOwnerCount -ne $appRegOwnerCount)) -and $isInternalApp -and $app.HasAppRegistration) {
            $ownerDisplay += "<span class='badge amber clickable-badge' data-fg='owners' data-fv='gap' title='Not all owners are assigned to both the Service Principal and the App Registration'>Ownership Gap</span>"
        }
        $ownerDisplay
    } else {
        "<span class='badge gray clickable-badge' data-fg='owners' data-fv='noowners' title='No owner is assigned. Changes can only be made by a privileged administrator'>No owners</span>"
    }
    
    # Determine ownership CSS class
    $isInternalApp = $app.AppOwnerOrganizationId -eq $tenantId
    $hasLegitimateOwnershipGap = $app.OwnershipGap -and $isInternalApp -and $app.HasAppRegistration

    $ownersClass = if ($app.HasOwners) { 
        if ($hasLegitimateOwnershipGap) { "ownership-gap" } else { "has-owners" }
    } else { 
        "no-owners" 
    }
    
    $credentialsInfo = "$($app.ActiveSecrets) secrets, $($app.ActiveCertificates) certs"
    $expiringBadge = ""
    if ($app.ExpiringCredentials -gt 0) {
        $expiringBadge = "<span class='badge amber clickable-badge' data-fg='credentials' data-fv='expiring' title='Credentials expiring within 30 days. Renew them to avoid authentication failures'>$($app.ExpiringCredentials) expiring</span>"
    }
    $credentialStatus = if ($app.HasActiveCredentials) { "<span class='badge green clickable-badge' data-fg='credentials' data-fv='active' title='App has active secrets or certificates used for authentication'>Active</span>" } else { "<span class='badge gray clickable-badge' data-fg='credentials' data-fv='none' title='No active credentials found. The app may use federated identity or may be inactive'>None</span>" }
    $credStatusValue = if ($app.HasActiveCredentials) { "active" } else { "none" }
    $expiringValue = if ($app.ExpiringCredentials -gt 0) { "yes" } else { "no" }
    
    # Build permission details with clear type indicators
    $permissionDetails = ""
    foreach ($perm in $app.Permissions) {
        $permClass = switch ($perm.Type) {
            "Application"    { "app-permission" }
            "Delegated"      { "delegated-permission" }
            "Directory Role" { "directory-role" }
        }
        if ($perm.Type -ne "Directory Role") {
            $permLink = "<a href='https://graphpermissions.merill.net/permission/$($perm.Permission)' target='_blank' title='View $($perm.Permission) on Graph Permissions Explorer' style='color:inherit;text-decoration:underline dotted;'>$($perm.Permission)</a>"
        } else {
            $permLink = $perm.Permission
        }
        $permissionDetails += "<div class='permission-item $permClass'><strong>[$($perm.Type)]</strong> $permLink on <em>$($perm.Resource)</em></div>"
    }
    
    # Build risk factors - the array should already be deduplicated from Get-RiskScore function
    $riskFactorsHtml = if ($app.RiskFactors.Count -gt 0) {
        $riskFactorItems = ($app.RiskFactors | ForEach-Object { "<li>$_</li>" }) -join ""
        "<ul style='margin:5px 0; padding-left: 20px;'>$riskFactorItems</ul>"
    } else {
        "No specific risk factors identified"
    }
    
    # Risk level badge colour
    $riskBadgeColor = switch ($app.RiskLevel) {
        "Critical" { "red" }
        "High"     { "orange" }
        "Medium"   { "amber" }
        "Low"      { "green" }
        default    { "gray" }
    }
    
    # Permission breakdown badges
    $appPermBadge = if ($app.ApplicationPermissions -gt 0) { "<span class='badge orange clickable-badge' data-fg='permissions' data-fv='application' title='Application permissions grant access without a signed-in user and are typically high privilege'>App: $($app.ApplicationPermissions)</span>" } else { "<span class='badge gray'>App: 0</span>" }
    $delegatedPermBadge = if ($app.DelegatedPermissions -gt 0) { "<span class='badge blue clickable-badge' data-fg='permissions' data-fv='delegated' title='Delegated permissions act on behalf of a signed-in user'>Delegated: $($app.DelegatedPermissions)</span>" } else { "<span class='badge gray'>Delegated: 0</span>" }
    $rolePermBadge = if ($app.DirectoryRoles -gt 0) { "<span class='badge red clickable-badge' data-fg='permissions' data-fv='roles' title='App has been assigned Entra ID directory roles which grant broad administrative capabilities'>Roles: $($app.DirectoryRoles)</span>" } else { "<span class='badge gray'>Roles: 0</span>" }
    $permissionSummary = "$appPermBadge $delegatedPermBadge $rolePermBadge"
    $riskTitle = switch ($app.RiskLevel) {
        "Critical" { "Critical risk. Immediate review required. This app has a combination of high privilege permissions, active credentials and missing controls" }
        "High"     { "High risk. This app has elevated permissions or missing security controls that should be reviewed" }
        "Medium"   { "Medium risk. Some risk factors are present. Review the risk analysis for details" }
        "Low"      { "Low risk. No significant security concerns detected at this time" }
        default    { "Risk level not calculated" }
    }

    
    $safeDisplayName = ConvertTo-HtmlSafe $app.DisplayName
    $html += @"
            <tr class="$riskClass" data-name="$safeDisplayName" data-risk="$($app.RiskLevel)" data-appreg="$(if ($app.HasAppRegistration) { 'yes' } else { 'no' })" data-apppermcount="$($app.ApplicationPermissions)" data-delegatedpermcount="$($app.DelegatedPermissions)" data-rolecount="$($app.DirectoryRoles)" data-credstatus="$credStatusValue" data-expiring="$expiringValue" data-owners="$(if ($app.HasOwners) { 'yes' } else { 'no' })" data-ownershipgap="$(if ($app.OwnershipGap) { 'yes' } else { 'no' })" data-ownership="$ownershipType" data-assignment="$(if ($app.AssignmentRequired) { 'required' } else { 'not-required' })" data-enabled="$(if ($app.IsEnabled) { 'yes' } else { 'no' })">
                <td><a class="app-name" href="$portalUrl" target="_blank" title="Open in Entra portal">$safeDisplayName</a></td>
                <td class="$enabledClass">$enabledText</td>
                <td><code class="mono">$($app.AppId)</code></td>
                <td class="$ownershipClass">$ownershipText<br><small class="muted tiny">$($app.AppOwnerOrganizationId)</small></td>
                <td class="$appRegClass">$appRegText</td>
                <td class="$assignmentRequiredClass">$assignmentRequiredText</td>
                <td class="$ownersClass cell-sm">$ownersText</td>
                <td><span class="badge $riskBadgeColor clickable-badge" data-fg="risk" data-fv="$($app.RiskLevel)" title="$riskTitle">$($app.RiskLevel)</span></td>
                <td><span class="perm-badges">$permissionSummary</span></td>
                <td class="cell-sm">
                    <details>
                        <summary>View Permissions ($($app.TotalPermissions))</summary>
                        <div class="permission-list">$permissionDetails</div>
                    </details>
                </td>
                <td class="cell-sm">
                    $credentialStatus<br>
                    $(if ($expiringBadge) { "$expiringBadge<br>" })$credentialsInfo
                </td>
                <td class="cell-sm">
                    <details>
                        <summary>Risk Analysis ($($app.RiskFactors.Count))</summary>
                        $riskFactorsHtml
                    </details>
                </td>
            </tr>
"@
}

$html += @"
        </tbody>
    </table>
    </div>

    <script>
        // Active filters: group -> Set of selected values (OR within a group, AND across groups)
        const activeFilters = {};
        const groupLabels = {
            ownership: 'Ownership', risk: 'Risk', appreg: 'App Reg',
            assignment: 'Assignment', owners: 'Owners', permissions: 'Permissions', credentials: 'Credentials', enabled: 'Enabled'
        };
        const valueLabels = {
            internal: 'Internal', external: 'External', microsoft: 'Microsoft', 'third-party': 'Third-Party',
            Critical: 'Critical', High: 'High', Medium: 'Medium', Low: 'Low',
            yes: 'Yes', no: 'No',
            required: 'Required', 'not-required': 'Open Access',
            has: 'Has Owners', noowners: 'No Owners', gap: 'Ownership Gap',
            application: 'Application', delegated: 'Delegated', roles: 'Roles', none: 'None',
            active: 'Active', expiring: 'Expiring'
        };

        function rowMatchesTag(row, group, value) {
            switch (group) {
                case 'ownership':   return row.dataset.ownership === value;
                case 'risk':        return row.dataset.risk === value;
                case 'appreg':      return row.dataset.appreg === value;
                case 'assignment':  return row.dataset.assignment === value;
                case 'owners':
                    if (value === 'has')      return row.dataset.owners === 'yes';
                    if (value === 'noowners') return row.dataset.owners === 'no';
                    if (value === 'gap')      return row.dataset.ownershipgap === 'yes';
                    return false;
                case 'credentials': return value === 'expiring' ? row.dataset.expiring === 'yes' : row.dataset.credstatus === value;
                case 'enabled':     return row.dataset.enabled === value;
                case 'permissions': {
                    const a = parseInt(row.dataset.apppermcount) || 0;
                    const d = parseInt(row.dataset.delegatedpermcount) || 0;
                    const r = parseInt(row.dataset.rolecount) || 0;
                    if (value === 'application') return a > 0;
                    if (value === 'delegated')   return d > 0;
                    if (value === 'roles')       return r > 0;
                    if (value === 'none')        return a === 0 && d === 0 && r === 0;
                }
            }
            return false;
        }

        function rowVisible(row) {
            const search = document.getElementById('searchInput').value.toLowerCase().trim();
            if (search && !(row.dataset.name || '').toLowerCase().includes(search)) return false;
            for (const group in activeFilters) {
                const vals = activeFilters[group];
                if (!vals || vals.size === 0) continue;
                let any = false;
                vals.forEach(v => { if (rowMatchesTag(row, group, v)) any = true; });
                if (!any) return false;
            }
            return true;
        }

        function applyFilters() {
            const rows = document.querySelectorAll('#reportTable tbody tr');
            let shown = 0;
            rows.forEach(row => {
                const ok = rowVisible(row);
                row.style.display = ok ? '' : 'none';
                if (ok) shown++;
            });
            document.getElementById('resultCount').textContent =
                'Showing ' + shown + ' of ' + rows.length + ' applications';
            renderActiveChips();

            const search = document.getElementById('searchInput').value.trim();
            let activeCount = (search ? 1 : 0);
            for (const g in activeFilters) activeCount += activeFilters[g].size;
            const summary = document.getElementById('filterSummary');
            if (activeCount > 0) {
                summary.textContent = activeCount + ' filter' + (activeCount > 1 ? 's' : '') +
                    ' \u00b7 showing ' + shown + ' of ' + rows.length;
                summary.style.display = '';
            } else {
                summary.style.display = 'none';
            }
        }

        function toggleFilterPanel(forceShow) {
            const panel = document.getElementById('controlsPanel');
            const btn = document.getElementById('filterToggle');
            const show = forceShow === true ? true : panel.hasAttribute('hidden');
            if (show) { panel.removeAttribute('hidden'); } else { panel.setAttribute('hidden', ''); }
            btn.setAttribute('aria-expanded', show ? 'true' : 'false');
            btn.querySelector('.caret').innerHTML = show ? '&#9662;' : '&#9656;';
        }

        function addFilter(group, value) {
            if (!activeFilters[group]) activeFilters[group] = new Set();
            if (!activeFilters[group].has(value)) {
                activeFilters[group].add(value);
                const tag = document.querySelector('.filter-tag[data-group="' + group + '"][data-value="' + value + '"]');
                if (tag) tag.classList.add('active');
            }
            applyFilters();
        }

        function toggleTag(el) {
            const group = el.dataset.group, value = el.dataset.value;
            if (!activeFilters[group]) activeFilters[group] = new Set();
            if (activeFilters[group].has(value)) {
                activeFilters[group].delete(value);
                el.classList.remove('active');
            } else {
                activeFilters[group].add(value);
                el.classList.add('active');
            }
            applyFilters();
        }

        function renderActiveChips() {
            const wrap = document.getElementById('activeChips');
            const chips = [];
            for (const group in activeFilters) {
                activeFilters[group].forEach(v => {
                    chips.push('<span class="chip" onclick="removeFilter(\'' + group + '\',\'' + v + '\')">'
                        + groupLabels[group] + ': ' + (valueLabels[v] || v) + ' &times;</span>');
                });
            }
            wrap.innerHTML = chips.join('');
            document.getElementById('clearAll').style.display = chips.length ? '' : 'none';
        }

        function removeFilter(group, value) {
            if (activeFilters[group]) activeFilters[group].delete(value);
            const el = document.querySelector('.filter-tag[data-group="' + group + '"][data-value="' + value + '"]');
            if (el) el.classList.remove('active');
            applyFilters();
        }

        function clearAllFilters() {
            for (const group in activeFilters) activeFilters[group].clear();
            document.querySelectorAll('.filter-tag.active').forEach(el => el.classList.remove('active'));
            document.getElementById('searchInput').value = '';
            applyFilters();
        }

        function computeTagCounts() {
            const rows = Array.from(document.querySelectorAll('#reportTable tbody tr'));
            document.querySelectorAll('.filter-tag').forEach(el => {
                const group = el.dataset.group, value = el.dataset.value;
                const n = rows.filter(r => rowMatchesTag(r, group, value)).length;
                el.querySelector('.cnt').textContent = '(' + n + ')';
            });
        }

        function sortTable(columnIndex, type) {
            const table = document.getElementById('reportTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            rows.sort((a, b) => {
                let aVal = a.cells[columnIndex].textContent.trim();
                let bVal = b.cells[columnIndex].textContent.trim();
                
                if (type === 'number') {
                    aVal = parseInt(aVal.replace(/[^0-9]/g, '')) || 0;
                    bVal = parseInt(bVal.replace(/[^0-9]/g, '')) || 0;
                    return bVal - aVal; // Descending for numbers
                }
                
                return aVal.localeCompare(bVal);
            });
            
            rows.forEach(row => tbody.appendChild(row));
        }

        function toggleTheme() {
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            const next = isDark ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            document.getElementById('themeToggle').innerHTML = next === 'dark' ? '&#9728;&#65039;' : '&#127769;';
            localStorage.setItem('entra-report-theme', next);
        }

        (function () {
            const saved = localStorage.getItem('entra-report-theme') || 'light';
            document.documentElement.setAttribute('data-theme', saved);
            document.getElementById('themeToggle').innerHTML = saved === 'dark' ? '&#9728;&#65039;' : '&#127769;';

            document.getElementById('reportTable').addEventListener('click', function (e) {
                const badge = e.target.closest('.clickable-badge');
                if (!badge) return;
                const group = badge.dataset.fg, value = badge.dataset.fv;
                if (!group || !value) return;
                addFilter(group, value);
                toggleFilterPanel(true);
            });

            document.querySelector('.summary').addEventListener('click', function (e) {
                const card = e.target.closest('.summary-card');
                if (!card) return;
                if (card.dataset.clear) { clearAllFilters(); return; }
                const group = card.dataset.fg, value = card.dataset.fv;
                if (!group || !value) return;
                addFilter(group, value);
                toggleFilterPanel(true);
                document.getElementById('reportTable').scrollIntoView({ behavior: 'smooth', block: 'start' });
            });

            computeTagCounts();
            applyFilters();
        })();
    </script>
    </div>

    <footer class="report-footer">
        Found this tool helpful? Subscribe to my blog at <a href="https://www.matej.guru" target="_blank" rel="noopener">www.matej.guru</a>. This script is provided "as is", without any warranty.
    </footer>
</body>
</html>
"@

# Save the HTML report
$html | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "Report generated successfully: $OutputPath" -ForegroundColor Green

# Open the report in default browser (interactive mode only)
if (-not $NonInteractive) {
    Write-Host "Opening report in default browser..." -ForegroundColor Green
    Start-Process $OutputPath
}

# Display summary statistics in console
Write-Host "`n=== REPORT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Applications: $totalApps" -ForegroundColor White
Write-Host "  - Internal Apps (Your Org): $internalApps" -ForegroundColor Blue
Write-Host "  - External Apps (Third-party): $externalApps" -ForegroundColor DarkYellow
Write-Host "  - With App Registrations: $appsWithRegistrations" -ForegroundColor Green
Write-Host "  - Service Principals Only: $servicePrincipalsOnly" -ForegroundColor Yellow
Write-Host "`nPermission Analysis:" -ForegroundColor White
Write-Host "  - Apps with Application Permissions: $appsWithApplicationPerms (Total: $totalApplicationPerms)" -ForegroundColor Red
Write-Host "  - Apps with Delegated Permissions: $appsWithDelegatedPerms (Total: $totalDelegatedPerms)" -ForegroundColor Green
Write-Host "`nRisk Assessment:" -ForegroundColor White
Write-Host "  - Critical Risk: $criticalRiskApps" -ForegroundColor Red
Write-Host "  - High Risk: $highRiskApps" -ForegroundColor DarkYellow
Write-Host "  - Medium Risk: $(($report | Where-Object { $_.RiskLevel -eq "Medium" }).Count)" -ForegroundColor Yellow
Write-Host "  - Low Risk: $(($report | Where-Object { $_.RiskLevel -eq "Low" }).Count)" -ForegroundColor Green
Write-Host "`nGovernance Analysis:" -ForegroundColor White
Write-Host "  - Apps without owners: $appsWithoutOwners" -ForegroundColor Red
Write-Host "  - Apps with open access (Assignment Required = No): $appsWithOpenAccess" -ForegroundColor DarkYellow
Write-Host "`nCredential Analysis:" -ForegroundColor White
Write-Host "  - Apps with active credentials: $(($report | Where-Object { $_.HasActiveCredentials -eq $true }).Count)" -ForegroundColor Green
Write-Host "  - Apps without credentials: $appsWithoutCredentials" -ForegroundColor DarkYellow
Write-Host "  - Apps with expiring credentials (30 days): $(($report | Where-Object { $_.ExpiringCredentials -gt 0 }).Count)" -ForegroundColor Yellow

# Performance summary
if ($OnlyWithPermissions -or $MinimumPermissions -gt 0 -or $OnlyWithAppRegistrations -or $OnlyServicePrincipals) {
    Write-Host "`n⚡ Performance Optimization:" -ForegroundColor Green
    Write-Host "  - Pre-filtering optimization was applied" -ForegroundColor Green
    Write-Host "  - Analysis was only performed on filtered applications" -ForegroundColor Green
}

# Disconnect from Microsoft Graph
Disconnect-MgGraph

Write-Host "`nScript completed successfully!" -ForegroundColor Green
Write-Host "Check the HTML report for detailed analysis focused on reliable data." -ForegroundColor Cyan
Write-Host "For usage verification, manually review sign-in logs in the Azure portal." -ForegroundColor Yellow
