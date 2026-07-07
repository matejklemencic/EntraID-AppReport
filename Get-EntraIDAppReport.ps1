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
    Version:        1.5
    Last Modified:  2026-06-28

    Installation: Install the required Microsoft Graph modules (install each separately to use -MinimumVersion):
    @('Microsoft.Graph.Authentication','Microsoft.Graph.Applications','Microsoft.Graph.Identity.SignIns','Microsoft.Graph.Identity.DirectoryManagement','Microsoft.Graph.Users') | ForEach-Object { Install-Module $_ -MinimumVersion '2.0.0' -Scope CurrentUser -AllowClobber }
    Or install the full umbrella module:
    Install-Module -Name Microsoft.Graph -MinimumVersion '2.0.0' -Scope CurrentUser -AllowClobber
.OUTPUTS
    None. Writes an HTML report to the file specified by -OutputPath.
.PARAMETER OutputPath
    Path to save the generated HTML report. Defaults to "EntraIDAppReport__{TenantName}_{Date}.html".
.PARAMETER TenantId
    Optional. The Entra ID tenant ID to connect to. Required when using Service Principal authentication.
.PARAMETER AccessToken
    Optional. A pre-acquired Microsoft Graph access token (SecureString). Use this when the pipeline
    already has an authenticated Az context (e.g. AzurePowerShell@5 with azureSubscription).
    Obtain with: ConvertTo-SecureString (Get-AzAccessToken -ResourceTypeName MSGraph).Token -AsPlainText -Force
.PARAMETER ClientId
    Optional. The Application (client) ID of a Service Principal for unattended/pipeline authentication.
    Must be combined with either -ClientSecret or -CertificateThumbprint and -TenantId.
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
    Expected JSON schema:
    {
        "HighRiskPermissions":    [ "<permission>", ... ],
        "MediumRiskPermissions":  [ "<permission>", ... ],
        "HighRiskDirectoryRoles": [ "<role name>", ... ],
        "SuspiciousKeywords":     [ "<keyword>", ... ]
    }
.PARAMETER OnlyWithAppRegistrations
    Include only applications that have a corresponding App Registration in the tenant.
.PARAMETER OnlyServicePrincipals
    Include only service principals without an App Registration (e.g. gallery or legacy apps).
.PARAMETER DryRun
    Optional. When set, skips writing the HTML report to disk and skips launching the browser.
    Useful for testing parameter validation and authentication without side effects.
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
    #>

[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [string]$TenantId = "",
    # Pre-acquired token (e.g. from Get-AzAccessToken in AzurePowerShell@5 task)
    [System.Security.SecureString]$AccessToken,
    # Service Principal / pipeline authentication
    [string]$ClientId = "",
    [string]$CertificateThumbprint = "",
    [switch]$UseManagedIdentity,
    [switch]$NonInteractive,
    # Filtering
    [switch]$OnlyWithPermissions,
    [ValidateRange(0, [int]::MaxValue)]
    [int]$MinimumPermissions = 0,
    [ValidateScript({ -not $_ -or (Test-Path $_ -PathType Leaf) })]
    [string]$RiskConfigPath = $null,
    [switch]$OnlyWithAppRegistrations,
    [switch]$OnlyServicePrincipals,
    [switch]$DryRun
)

# Validate mutually exclusive parameters
if ($OnlyWithAppRegistrations -and $OnlyServicePrincipals) {
    Write-Error "-OnlyWithAppRegistrations and -OnlyServicePrincipals are mutually exclusive. Use one or the other."
    exit 1
}
if (($ClientId -or $CertificateThumbprint) -and -not $TenantId) {
    Write-Error "-TenantId is required when using Service Principal authentication (-ClientId/-CertificateThumbprint)."
    exit 1
}

# Make all unhandled errors terminating so they propagate through the try/catch/finally structure
$ErrorActionPreference = 'Stop'

# Microsoft first-party tenant IDs — used to classify Microsoft-owned apps
$script:MicrosoftTenantIds = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a',  # Microsoft Services
    '72f988bf-86f1-41af-91ab-2d7cd011db47',  # Microsoft
    'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'   # Microsoft Azure
)

# High-value first-party apps (CLI / automation tooling) that are common targets for token theft,
# illicit consent and lateral movement. Most users never need them and some need only occasional access.
# When such an app does NOT require assignment (open to every user in the tenant), it is flagged Critical.
# Add more 'appId' = 'friendly name' entries here as needed.
$script:HighValueTargetApps = @{
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Microsoft Azure CLI'
    '1950a258-227b-4e31-a9cf-717495945fc2' = 'Azure PowerShell'
    '1b730954-1685-4b74-9bfd-dac224a7b894' = 'Azure Active Directory PowerShell'
    'fb78d390-0c51-40cd-8e17-fdbfab77341b' = 'Exchange Online PowerShell'
    '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'Microsoft Graph Command Line Tools'
    '09abbdfd-ed23-44ee-a2d9-a627aa1c90f3' = 'Microsoft Graph PowerShell'
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
        'Agent ID Administrator', 'AI Administrator', 'AI Reader',
        'Application Administrator', 'Application Developer', 'Attribute Provisioning Administrator',
        'Attribute Provisioning Reader', 'Authentication Administrator', 'Authentication Extensibility Administrator',
        'Authentication Extensibility Password Administrator', 'B2C IEF Keyset Administrator', 'Cloud Application Administrator',
        'Cloud Device Administrator', 'Conditional Access Administrator', 'Directory Writers',
        'Domain Name Administrator', 'External Identity Provider Administrator', 'Global Administrator',
        'Global Reader', 'Helpdesk Administrator', 'Hybrid Identity Administrator',
        'Identity Governance Administrator', 'Intune Administrator', 'Lifecycle Workflows Administrator',
        'Partner Tier1 Support', 'Partner Tier2 Support', 'Password Administrator',
        'Privileged Authentication Administrator', 'Privileged Role Administrator', 'Security Administrator',
        'Security Operator', 'Security Reader', 'User Administrator'
    )
    SuspiciousKeywords = @(
        'test', 'demo', 'temp', 'old', 'backup', 'legacy', 'dev', 'staging', 'admin', 'service', 'support', 'update', 'security', 'patch',
        'token', 'authentication', 'auth', 'credential', 'sync', 'connector', 'monitor', 'gateway', 'agent', 'portal', 'framework'
    )
}

# Load external risk configuration if provided
if ($RiskConfigPath -and (Test-Path $RiskConfigPath)) {
    try {
        $externalConfig = Get-Content $RiskConfigPath -Encoding UTF8 | ConvertFrom-Json
        $requiredKeys = @('HighRiskPermissions', 'MediumRiskPermissions', 'HighRiskDirectoryRoles', 'SuspiciousKeywords')
        $missingKeys = $requiredKeys | Where-Object { $externalConfig.PSObject.Properties.Name -notcontains $_ }
        if ($missingKeys) {
            Write-Warning "External risk config is missing required keys: $($missingKeys -join ', '). Using default settings."
        } else {
            $riskConfig = $externalConfig
            Write-Host "Loaded external risk configuration from $RiskConfigPath" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Failed to load external risk configuration: $($_.Exception.Message). Using default settings."
    }
}

# Function to safely import modules
function Import-GraphModuleSafely {
    param([string]$ModuleName)

    # Reuse an already-loaded module if it meets the minimum version requirement
    $loaded = Get-Module -Name $ModuleName
    if ($loaded) {
        if ($loaded.Version -ge [version]'2.0.0') {
            Write-Verbose "$ModuleName $($loaded.Version) already loaded — skipping re-import"
            return
        }
        Write-Warning "$ModuleName $($loaded.Version) is loaded but v2.0.0+ is required — re-importing"
    }

    try {
        Import-Module $ModuleName -MinimumVersion '2.0.0' -ErrorAction Stop
        Write-Host "Successfully imported $ModuleName" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not import $ModuleName v2+. Attempting Microsoft.Graph umbrella module..."
        try {
            $umbrella = Get-Module -Name 'Microsoft.Graph'
            if (-not $umbrella -or $umbrella.Version -lt [version]'2.0.0') {
                Import-Module Microsoft.Graph -MinimumVersion '2.0.0' -ErrorAction Stop
            }
        }
        catch {
            Write-Error "Failed to import required Graph modules (v2.0.0+).`nRun: Install-Module Microsoft.Graph -MinimumVersion '2.0.0' -Scope CurrentUser -AllowClobber"
            exit 1
        }
    }
}

# Retry wrapper for Graph API calls that may be throttled (HTTP 429).
# Reads the Retry-After response header when available; falls back to exponential back-off.
function Invoke-MgWithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3
    )
    $attempt = 0
    while ($true) {
        try {
            return (& $ScriptBlock)
        }
        catch {
            $attempt++
            $statusCode = $null
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
            if ($statusCode -eq 429 -and $attempt -le $MaxRetries) {
                $retryAfter = $null
                try { $retryAfter = [int]$_.Exception.Response.Headers['Retry-After'] } catch {}
                $delay = if ($retryAfter -gt 0) { $retryAfter } else { [Math]::Pow(2, $attempt) * 2 }
                Write-Warning "Graph API throttled (429). Retrying in $delay s (attempt $attempt/$MaxRetries)..."
                Start-Sleep -Seconds $delay
            } else {
                throw
            }
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
    
    # Resolve a raw owner DirectoryObject (returned by Graph) into a typed hashtable.
    # Uses @odata.type from AdditionalProperties — no extra API calls per owner.
    function Resolve-OwnerObject {
        param($Owner, [string]$Source)
        $odataType   = $Owner.AdditionalProperties['@odata.type']
        $displayName = $Owner.AdditionalProperties['displayName']
        if (-not $displayName) { $displayName = 'Unknown' }
        switch ($odataType) {
            '#microsoft.graph.user' {
                return @{
                    Id = $Owner.Id
                    DisplayName = $displayName
                    UserPrincipalName = $Owner.AdditionalProperties['userPrincipalName']
                    Type = 'User'
                    Source = $Source
                }
            }
            '#microsoft.graph.servicePrincipal' {
                return @{
                    Id = $Owner.Id
                    DisplayName = $displayName
                    UserPrincipalName = $Owner.AdditionalProperties['appId']
                    Type = 'ServicePrincipal'
                    Source = $Source
                }
            }
            default {
                return @{
                    Id = $Owner.Id
                    DisplayName = $displayName
                    UserPrincipalName = ''
                    Type = 'Unknown'
                    Source = $Source
                }
            }
        }
    }

    # Get Service Principal owners — request display fields so no per-owner API call is needed
    try {
        $spOwners = Get-MgServicePrincipalOwner -ServicePrincipalId $ServicePrincipalId -All `
            -Property 'id,displayName,userPrincipalName,appId' -ErrorAction SilentlyContinue
        $spOwnerDetails = @()
        foreach ($owner in $spOwners) {
            $spOwnerDetails += Resolve-OwnerObject -Owner $owner -Source 'ServicePrincipal'
        }
        $allOwners.ServicePrincipalOwners = $spOwnerDetails
        $allOwners.HasServicePrincipalOwners = $spOwnerDetails.Count -gt 0
    }
    catch {
        Write-Verbose "Could not retrieve Service Principal owners for '$ServicePrincipalId': $($_.Exception.Message)"
    }

    # Get App Registration owners (if an App Registration exists in this tenant)
    try {
        $app = Get-MgApplication -Filter "appId eq '$AppId'" -Property 'id' -ErrorAction SilentlyContinue
        if ($app) {
            $appOwners = Get-MgApplicationOwner -ApplicationId $app.Id -All `
                -Property 'id,displayName,userPrincipalName,appId' -ErrorAction SilentlyContinue
            $appOwnerDetails = @()
            foreach ($owner in $appOwners) {
                $appOwnerDetails += Resolve-OwnerObject -Owner $owner -Source 'AppRegistration'
            }
            $allOwners.AppRegistrationOwners = $appOwnerDetails
            $allOwners.HasAppRegistrationOwners = $appOwnerDetails.Count -gt 0
        }
    }
    catch {
        Write-Verbose "Could not retrieve App Registration owners for AppId '$AppId': $($_.Exception.Message)"
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
        [bool]$HasLongLivedCredentials,
        [bool]$IsEnabled = $true,
        [bool]$IsVerifiedPublisher = $false,
        [bool]$IsHighValueTargetApp = $false,
        [string]$HighValueTargetName = $null
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
            $score += 15
            $uniqueHighRiskPerms += $perm.Permission
            $riskFactors += [PSCustomObject]@{ Text = "High-risk permission: $($perm.Permission)"; Points = 15; Permission = $perm.Permission }
        }
        elseif ($perm.Permission -in $riskConfig.MediumRiskPermissions -and $perm.Permission -notin $uniqueMediumRiskPerms) {
            $score += 5
            $uniqueMediumRiskPerms += $perm.Permission
            $riskFactors += [PSCustomObject]@{ Text = "Medium-risk permission: $($perm.Permission)"; Points = 5; Permission = $perm.Permission }
        }
    }
    
    # Application permissions bonus (only once, not per permission)
    if ($hasApplicationPerms) {
        $score += 5
        $riskFactors += [PSCustomObject]@{ Text = "Has application permissions"; Points = 5 }
    }
    
    # Directory role scoring - only count unique roles
    $uniqueRoles = @()
    foreach ($role in $DirectoryRoles) {
        if ($role.Permission -notin $uniqueRoles) {
            $uniqueRoles += $role.Permission
            if ($role.Permission -in $riskConfig.HighRiskDirectoryRoles) {
                $score += 15
                $riskFactors += [PSCustomObject]@{ Text = "High-risk directory role: $($role.Permission)"; Points = 15 }
            }
            else {
                $score += 5
                $riskFactors += [PSCustomObject]@{ Text = "Directory role: $($role.Permission)"; Points = 5 }
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
        $score += 2
        $riskFactors += [PSCustomObject]@{ Text = "Suspicious name contains: $($suspiciousKeywords -join ', ')"; Points = 2 }
    }
    
    # High user count with sensitive permissions (only check once)
    if ($TotalUsers -eq "All Users" -and ($uniqueHighRiskPerms.Count -gt 0 -or $uniqueMediumRiskPerms.Count -gt 0)) {
        $score += 5
        $riskFactors += [PSCustomObject]@{ Text = "Sensitive permissions with all users access"; Points = 5 }
    }
    elseif ($TotalUsers -is [int] -and $TotalUsers -gt 50 -and ($uniqueHighRiskPerms.Count -gt 0 -or $uniqueMediumRiskPerms.Count -gt 0)) {
        $score += 3
        $riskFactors += [PSCustomObject]@{ Text = "Sensitive permissions affecting many users ($TotalUsers users)"; Points = 3 }
    }
        
    # Enhanced ownership checks
    if (-not $HasAnyOwners) {
        $score += 4
        $riskFactors += [PSCustomObject]@{ Text = "No owners assigned (neither Service Principal nor App Registration)"; Points = 4 }
    }
    elseif (-not $HasServicePrincipalOwners -and $HasAppRegistration) {
        $score += 2
        $riskFactors += [PSCustomObject]@{ Text = "No Service Principal owners (only App Registration owners)"; Points = 2 }
    }
    elseif (-not $HasAppRegistrationOwners -and $HasAppRegistration) {
        $score += 2
        $riskFactors += [PSCustomObject]@{ Text = "No App Registration owners (only Service Principal owners)"; Points = 2 }
    }
    
    # Ownership gap detection (only for internal applications)
    if ($HasAppRegistration -and $isInternalApp -and ($HasServicePrincipalOwners -ne $HasAppRegistrationOwners)) {
        $score += 1
        $riskFactors += [PSCustomObject]@{ Text = "Ownership gap - owners differ between Service Principal and App Registration"; Points = 1 }
    }
    
    # Assignment not required (open access risk).
    # High-value first-party tooling apps (Azure CLI, Azure/AzureAD PowerShell, Exchange PowerShell,
    # Graph CLI/PowerShell) are prime targets for token theft, illicit consent and lateral movement.
    # When such an app doesn't require assignment, EVERY user in the tenant can use it — record only the
    # single highest factor (+30) instead of also adding the generic +4.
    if (-not $AssignmentRequired) {
        if ($IsHighValueTargetApp) {
            $score += 50
            $riskFactors += [PSCustomObject]@{ Text = "Assignment not required for high-value app"; Points = 50; Detail = "Rarely needed by users and a frequent abuse target. Lock it down with Assignment Required option" }
        } else {
            $score += 5
            $riskFactors += [PSCustomObject]@{ Text = "Assignment not required"; Points = 5 }
        }
    }

    # Credential type: secrets are less secure than certificates
    if ($UsesPasswordSecrets) {
        $score += 5
        $riskFactors += [PSCustomObject]@{ Text = "Uses password secrets (certificates preferred)"; Points = 5 }
    }

    # Multiple secrets increase attack surface
    if ($SecretCount -gt 1) {
        $score += 5
        $riskFactors += [PSCustomObject]@{ Text = "Multiple secrets configured ($SecretCount) - reduces auditability"; Points = 5 }
    }

    # Long-lived credentials (> 1 year) are harder to rotate and track
    if ($HasLongLivedCredentials) {
        $score += 5
        $riskFactors += [PSCustomObject]@{ Text = "Long-lived credentials (expiry > 1 year)"; Points = 5 }
    }

    # External apps are registered in another tenant. No control over registration or credential rotation
    # Microsoft owned apps are excluded as they are trusted first-party services
    if (-not $IsInternalApp -and -not $IsMicrosoftApp) {
        $score += 5
        $riskFactors += [PSCustomObject]@{ Text = "External application registered in another tenant"; Points = 5 }

        # An external app without a Microsoft-verified publisher has an unverified developer identity
        if (-not $IsVerifiedPublisher) {
            $score += 5
            $riskFactors += [PSCustomObject]@{ Text = "External application has no verified publisher"; Points = 5 }
        }
    }

    # Disabled apps keep their full inherent risk score — a disabled app can be
    # re-enabled with a single admin toggle, so an over-privileged dormant app is
    # still a real risk. The Enabled column / filter indicates current exploitability.
    if (-not $IsEnabled) {
        $riskFactors += [PSCustomObject]@{ Text = "App is disabled (inherent risk shown; not currently exploitable until re-enabled)"; Points = 0 }
    }

    # Score thresholds:
    #   Low < 15 ≤ Medium < 35 ≤ High < 50 ≤ Critical
    # Calibration reference points:
    #   Assignment not required + no owners (5+4) → Low
    #   One medium-risk perm + app-type + open access + secrets (5+5+5+5) → Medium
    #   Two high-risk perms + app-type + open access + secrets + long-lived (20+5+5+5+5) → High
    #   Two high-risk perms + app-type + high-value open access + secrets + long-lived (20+5+15+5+5) → Critical
    return @{
        Score  = $score
        Level  = if ($score -ge 50) { "Critical" } elseif ($score -ge 35) { "High" } elseif ($score -ge 15) { "Medium" } else { "Low" }
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
    catch {
        Write-Verbose "Could not retrieve App Registration credentials for AppId '$AppId': $($_.Exception.Message)"
    }

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
        ActiveCertificateList = @($spActiveCerts) + @($appActiveCerts)
        ActiveSecretList      = @($spActiveSecrets) + @($appActiveSecrets)
    }
}

# Function to get and process permissions for filtering
function Get-ServicePrincipalPermissions {
    param($ServicePrincipal)
    
    # Get delegated permissions
    $delegatedGrants = Invoke-MgWithRetry { Get-MgOauth2PermissionGrant -Filter "clientId eq '$($ServicePrincipal.Id)'" -All }

    # Get application permissions
    $appRoleAssignments = Invoke-MgWithRetry { Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -All }
    
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
Import-GraphModuleSafely "Microsoft.Graph.Authentication"
Import-GraphModuleSafely "Microsoft.Graph.Applications"
Import-GraphModuleSafely "Microsoft.Graph.Identity.SignIns"
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
try {
    if ($AccessToken) {
        # Token passed in — e.g. from AzurePowerShell@5 azureSubscription task
        Write-Host "  Auth method: Pre-acquired access token" -ForegroundColor Cyan
        Connect-MgGraph -AccessToken $AccessToken -NoWelcome -ErrorAction Stop
    } elseif ($ClientId -and $CertificateThumbprint) {
        # Service Principal with certificate — recommended for pipelines
        Write-Host "  Auth method: Service Principal (certificate)" -ForegroundColor Cyan
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    } elseif ($UseManagedIdentity) {
        # Managed Identity — for Azure DevOps / Azure-hosted agents
        Write-Host "  Auth method: Managed Identity" -ForegroundColor Cyan
        Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
    } elseif ($TenantId) {
        Connect-MgGraph -Scopes $scopes -TenantId $TenantId -NoWelcome -ErrorAction Stop
    } else {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
    }
    if (-not (Get-MgContext)) {
        throw 'Connect-MgGraph returned no context — authentication may have been cancelled or denied.'
    }
}
catch {
    Write-Error "Authentication failed: $($_.Exception.Message)"
    exit 1
}

try {

Write-Host "Gathering Enterprise Applications..." -ForegroundColor Green

# Cache once — avoids repeated Get-MgContext calls inside loops
$currentTenantId = (Get-MgContext).TenantId

# Get service principals that match the Entra ID portal "Enterprise Applications" filter
$servicePrincipals = Get-MgServicePrincipal -All -Property @(
    "Id", "AppId", "DisplayName", "AppOwnerOrganizationId",
    "ServicePrincipalType", "AppRoles", "Oauth2PermissionScopes", "SignInAudience",
    "Tags", "AppDisplayName", "CreatedDateTime", "Owners", "AppRoleAssignmentRequired", "AccountEnabled",
    "PasswordCredentials", "KeyCredentials", "VerifiedPublisher"
) | Where-Object {
    $_.ServicePrincipalType -eq "Application" -and
    #$_.AppOwnerOrganizationId -ne "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -and
    $_.AppId -notin @(
        "00000003-0000-0000-c000-000000000000", # Microsoft Graph
        "00000002-0000-0ff1-ce00-000000000000", # Office 365 Exchange Online
        "00000003-0000-0ff1-ce00-000000000000", # Office 365 SharePoint Online
        "c5393580-f805-4401-95e8-94b7a6ef2fc2", # Office 365 Management APIs
        "d3590ed6-52b3-4102-aeff-aad2292ab01c", # Microsoft Office
        "797f4846-ba00-4fd7-ba43-dac1f8f63013"  # Windows Azure Service Management API
        # NOTE: Azure PowerShell (1950a258...), Azure AD PowerShell (1b730954...) and Microsoft Graph
        # PowerShell (09abbdfd...) are intentionally NOT excluded so they can be surfaced and
        # risk-scored as high-value target apps.
    ) -and
    ($_.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp" -or
     $_.AppOwnerOrganizationId -eq $currentTenantId -or
     $_.SignInAudience -in @("AzureADMyOrg", "AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"))
}

Write-Host "Found $($servicePrincipals.Count) Enterprise Applications" -ForegroundColor Green

# Caches populated during pre-filtering and reused in the main processing loop
$credentialCache  = @{}
$permissionCache  = @{}

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

        # Check App Registration filter first (fastest check); cache result for main loop
        if ($OnlyWithAppRegistrations -or $OnlyServicePrincipals) {
            $credentials = Get-ApplicationCredentials -AppId $sp.AppId -ServicePrincipal $sp
            $credentialCache[$sp.Id] = $credentials

            if ($OnlyWithAppRegistrations -and -not $credentials.HasAppRegistration) {
                $shouldInclude = $false
            }
            elseif ($OnlyServicePrincipals -and $credentials.HasAppRegistration) {
                $shouldInclude = $false
            }
        }

        # Check permissions filter (more expensive); cache result for main loop
        if ($shouldInclude -and ($OnlyWithPermissions -or $MinimumPermissions -gt 0)) {
            $permissionInfo = Get-ServicePrincipalPermissions -ServicePrincipal $sp
            $permissionCache[$sp.Id] = $permissionInfo

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
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        exit 0
    }
} else {
    Write-Host "Processing $($servicePrincipals.Count) applications (non-interactive mode)..." -ForegroundColor Cyan
}

Write-Host "`nProceeding with analysis..." -ForegroundColor Green

# Cache resource Service Principals to avoid redundant Graph calls across apps
$resourceSpCache = @{}

$report = @()
$processedCount = 0

foreach ($sp in $servicePrincipals) {
    $processedCount++
    Write-Progress -Activity "Processing applications" -Status "Processing $($sp.DisplayName)" -PercentComplete (($processedCount / $servicePrincipals.Count) * 100)
    Write-Verbose "Processing: $($sp.DisplayName) ($processedCount/$($servicePrincipals.Count))"

    # Reuse pre-filtering result if available; otherwise fetch now
    $permissionInfo = if ($permissionCache.ContainsKey($sp.Id)) {
        $permissionCache[$sp.Id]
    } else {
        Get-ServicePrincipalPermissions -ServicePrincipal $sp
    }

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

        if (-not $resourceSpCache.ContainsKey($grant.ResourceId)) {
            $resourceSpCache[$grant.ResourceId] = Invoke-MgWithRetry { Get-MgServicePrincipal -ServicePrincipalId $grant.ResourceId -ErrorAction SilentlyContinue }
        }
        $resourceSP = $resourceSpCache[$grant.ResourceId]
        $resourceName = if ($resourceSP) { $resourceSP.DisplayName } else { "Unknown" }

        if ($grant.Scope) {
            $scopeTokens = $grant.Scope.Split(' ') | Where-Object { $_ -ne '' }
            foreach ($scope in $scopeTokens) {
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
        if (-not $resourceSpCache.ContainsKey($assignment.ResourceId)) {
            $resourceSpCache[$assignment.ResourceId] = Invoke-MgWithRetry { Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -ErrorAction SilentlyContinue }
        }
        $resourceSP = $resourceSpCache[$assignment.ResourceId]
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

    # Reuse pre-filtering credential result if available; otherwise fetch now
    $credentials = if ($credentialCache.ContainsKey($sp.Id)) {
        $credentialCache[$sp.Id]
    } else {
        Get-ApplicationCredentials -AppId $sp.AppId -ServicePrincipal $sp
    }
    
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
    $isInternalApp = $sp.AppOwnerOrganizationId -eq $currentTenantId
    $isMicrosoftApp = $sp.AppOwnerOrganizationId -in $script:MicrosoftTenantIds

    # Verified publisher — a Microsoft-verified developer identity (mainly relevant for external apps)
    $isVerifiedPublisher = [bool]($sp.VerifiedPublisher -and $sp.VerifiedPublisher.DisplayName)
    $verifiedPublisherName = if ($isVerifiedPublisher) { $sp.VerifiedPublisher.DisplayName } else { $null }

    # High-value target app — first-party CLI/automation apps that are common abuse targets
    $isHighValueTargetApp = $script:HighValueTargetApps.ContainsKey($sp.AppId)
    $highValueTargetName = if ($isHighValueTargetApp) { $script:HighValueTargetApps[$sp.AppId] } else { $null }

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
        -HasLongLivedCredentials $credentials.HasLongLivedCredentials `
        -IsEnabled $isEnabled `
        -IsVerifiedPublisher $isVerifiedPublisher `
        -IsHighValueTargetApp $isHighValueTargetApp `
        -HighValueTargetName $highValueTargetName
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
        OwnershipGap = $credentials.HasAppRegistration -and (($ownerInfo.CombinedOwners | Where-Object { $_.Source -ne 'Both' }).Count -gt 0)
        AssignmentRequired = $assignmentRequired
        IsEnabled = $isEnabled
        IsVerifiedPublisher = $isVerifiedPublisher
        VerifiedPublisherName = $verifiedPublisherName
        
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
        ActiveCertificateList   = $credentials.ActiveCertificateList
        ActiveSecretList        = $credentials.ActiveSecretList
        
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
$appsWithoutCredentials  = @($report | Where-Object { $_.HasActiveCredentials -eq $false -and $_.HasAppRegistration -eq $true }).Count
$appsWithActiveCredentials = @($report | Where-Object { $_.HasActiveCredentials -eq $true }).Count
$appsWithExpiringCredentials = @($report | Where-Object { $_.ExpiringCredentials -gt 0 }).Count

# Get tenant information
$tenantInfo = Get-MgOrganization | Select-Object -First 1
$tenantName = $tenantInfo.DisplayName
$tenantId = $tenantInfo.Id

if (-not $OutputPath) {
    $safeName = $tenantName -replace '[^\w]', '_'
    $OutputPath = "EntraIDAppReport__${safeName}_$(Get-Date -Format 'yyyy-MM-dd').html"
}

# Resolve a relative output path against the current PowerShell location.
# .NET file APIs (WriteAllText / Path.GetFullPath) resolve relative paths against
# [Environment]::CurrentDirectory (the process start directory, e.g. C:\Windows\System32
# for elevated shells), NOT PowerShell's $PWD. Making the path absolute here ensures the
# report is written where the user expects — next to their current location.
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path (Get-Location).Path $OutputPath
}

# Ensure output directory exists
$outputDir = Split-Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    Write-Host "Created output directory: $outputDir" -ForegroundColor Cyan
}

# Verify the output path is writable before spending time on HTML generation
$_writeTestDir  = if ($outputDir) { $outputDir } else { '.' }
$_writeTestFile = Join-Path $_writeTestDir ([System.IO.Path]::GetRandomFileName())
try {
    [System.IO.File]::WriteAllText($_writeTestFile, '')
    Remove-Item $_writeTestFile -Force -ErrorAction SilentlyContinue
} catch {
    Write-Error "Output path '$OutputPath' is not writable: $($_.Exception.Message)"
    exit 1
}

# Calculate additional statistics for internal vs external apps and ownership
$internalApps   = @($report | Where-Object { $_.AppOwnerOrganizationId -eq $tenantId }).Count
$microsoftApps  = @($report | Where-Object { $_.AppOwnerOrganizationId -in $script:MicrosoftTenantIds }).Count
$externalApps   = @($report | Where-Object { $_.AppOwnerOrganizationId -ne $tenantId -and $_.AppOwnerOrganizationId -notin $script:MicrosoftTenantIds }).Count
$appsWithoutOwners = @($report | Where-Object { $_.HasOwners -eq $false }).Count
$appsWithOpenAccess = @($report | Where-Object { $_.AssignmentRequired -eq $false }).Count
$appsWithOwnershipGaps = @($report | Where-Object { $_.OwnershipGap -eq $true }).Count
$disabledApps = @($report | Where-Object { $_.IsEnabled -eq $false }).Count
$appsWithSPOwnersOnly = @($report | Where-Object { $_.HasServicePrincipalOwners -eq $true -and $_.HasAppRegistrationOwners -eq $false -and $_.HasAppRegistration -eq $true }).Count
$appsWithAppRegOwnersOnly = @($report | Where-Object { $_.HasServicePrincipalOwners -eq $false -and $_.HasAppRegistrationOwners -eq $true }).Count

# Generate simplified HTML report

# Enterprise Applications logo — inlined so the script has no external file dependency
$logoSvg = '<svg id="a760b6f1-1e55-4349-bcad-563b81ab52cb" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 18 18"><defs><linearGradient id="b715ec20-95db-414c-982b-71456fb0c9ab" x1="-6784.85" y1="1118.78" x2="-6784.85" y2="1089.98" gradientTransform="matrix(0.5, 0, 0, -0.5, 3400.41, 559.99)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#5ea0ef" /><stop offset="0.18" stop-color="#589eed" /><stop offset="0.41" stop-color="#4897e9" /><stop offset="0.66" stop-color="#2e8ce1" /><stop offset="0.94" stop-color="#0a7cd7" /><stop offset="1" stop-color="#0078d4" /></linearGradient><linearGradient id="f7e46209-f134-49aa-a850-2e9a1b04fba6" x1="-1.47" y1="14.91" x2="17.16" y2="14.8" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#449cdd" stop-opacity="0.15" /><stop offset="0.16" stop-color="#2870ab" stop-opacity="0" /><stop offset="0.18" stop-color="#2469a3" stop-opacity="0.06" /><stop offset="0.23" stop-color="#1a5991" stop-opacity="0.19" /><stop offset="0.28" stop-color="#144f86" stop-opacity="0.27" /><stop offset="0.34" stop-color="#124c82" stop-opacity="0.3" /><stop offset="0.76" stop-color="#002851" stop-opacity="0.35" /><stop offset="0.9" stop-color="#2f7ab6" stop-opacity="0" /><stop offset="1" stop-color="#449cdd" stop-opacity="0" /></linearGradient><clipPath id="b36c7b72-34c8-47c6-ac8b-a96783f174f2"><circle cx="13.26" cy="13.27" r="4.16" fill="none" /></clipPath></defs><title>Icon-identity-225</title><path d="M5.61,10.65H9.94V15H5.61Zm-5-5.76H4.89V.57H1.17a.6.6,0,0,0-.6.6ZM1.17,15H4.89V10.65H.57v3.72A.6.6,0,0,0,1.17,15Zm-.6-5H4.89V5.61H.57Zm10.09,5h3.72a.6.6,0,0,0,.6-.6V10.65H10.66Zm-5-5H9.94V5.61H5.61Zm5.05,0H15V5.61H10.66Zm0-9.36V4.89H15V1.17a.6.6,0,0,0-.6-.6Zm-5,4.32H9.94V.57H5.61Z" fill="url(#b715ec20-95db-414c-982b-71456fb0c9ab)" /><path d="M10.66,15h4.15a.59.59,0,0,1-.18-.29h-4Z" opacity="0.95" fill="url(#f7e46209-f134-49aa-a850-2e9a1b04fba6)" /><circle cx="13.26" cy="13.27" r="4.16" fill="#32bedd" /><g clip-path="url(#b36c7b72-34c8-47c6-ac8b-a96783f174f2)"><path d="M17.06,13.87c-.21.11-.51.05-.65.16a1.6,1.6,0,0,0-.63.66c0,.06,0,.15-.07.18-.28.19-.56.39-.3.81-.3,0-.2-.27-.34-.35a.77.77,0,0,0-1.06.54.34.34,0,0,0,.16.37.26.26,0,0,0,.36-.12.18.18,0,0,1,.26-.06c0,.16-.28.45.18.46.12,0,.09.14.06.23s.06.24.19.3,0,0,0,.05,0,0,0,0c-.37,0-.45-.45-.81-.5a4.28,4.28,0,0,1-.43-.14c-.27-.09-.58-.14-.64-.54a.77.77,0,0,0-.36-.49c-.12-.08-.19-.23-.31-.32a1,1,0,0,0-.22-.36.94.94,0,0,1-.14-.87,2.32,2.32,0,0,0-.1-1.68c-.1-.32-.12-.65-.48-.86s-.3.12-.44.05-.22.13-.26.15c-.29.08-.54.33-.91.29.14-.07.25-.11.35-.17s.29-.14.07-.38-.14-.59.45-.83c-.05-.14-.41-.11-.25-.37s.28-.13.43,0c.1-.19-.12-.43.05-.54a2.86,2.86,0,0,1,.72-.29.25.25,0,0,1,.34.11c.18.28.54.33.72.61.05.09.15,0,.22,0,.41-.14.68.12,1,.33s.27.34.53.31a.49.49,0,0,1,.21,0c.16.07.31.11.43-.06a.3.3,0,0,0,.26-.23c.06-.09.09-.22.24-.16A1.15,1.15,0,0,0,16,11c.13-.1.26-.16.11-.39a.37.37,0,0,1,.25-.56.54.54,0,0,1,.63.23c.19.34.25.73.47,1,.07.09,0,.13,0,.2s-.18,0-.28-.06l.07.43a.66.66,0,0,1-.82-.25c0-.12,0-.17.12-.23s.19-.11.19-.24a.19.19,0,0,0-.1-.2c-.08,0-.13,0-.15.09s-.33.25-.28.53-.19.22-.33.14c-.33-.17-.45.13-.59.29s0,.34.16.46.31.21.37.4a.88.88,0,0,0,.29-.58c0-.18.07-.43.32-.46a.43.43,0,0,1,.44.28c.05.11.13.12.23.13a8.79,8.79,0,0,1,.54,1.52l-.37-.05c0-.29-.25-.16-.39-.22C16.84,13.64,17.07,13.69,17.06,13.87Z" fill="#b4ec36" /><path d="M15.62,10.27c-.13-.12-.27-.23-.06-.4s.2-.29.3,0A.37.37,0,0,1,15.62,10.27Z" fill="#b4ec36" /><path d="M15.93,9.87c.11-.11.25-.1.27,0s-.13.19-.26.23S15.85,10,15.93,9.87Z" fill="#b4ec36" /><path d="M15.16,8.94,14.81,9c0-.25.25-.27.42-.23S15.21,8.89,15.16,8.94Z" fill="#b4ec36" /></g></svg>'

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
        .export-csv-btn {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 8px 14px; border-radius: 6px; border: 2px solid var(--blue);
            font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
            cursor: pointer; background: transparent; color: var(--blue);
            transition: background 0.15s; margin-left: auto;
        }
        .export-csv-btn:hover { background: var(--blue-xs); }
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
        th.sort-asc::after  { content: ' ▲'; font-size: 0.8em; opacity: 0.7; }
        th.sort-desc::after { content: ' ▼'; font-size: 0.8em; opacity: 0.7; }
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

        .perm-badges { display: flex; flex-direction: column; align-items: flex-start; gap: 4px; }

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

        /* -- Modal -- */
        .modal-overlay {
            display: none; position: fixed; inset: 0;
            background: rgba(0,0,0,0.55); z-index: 1000;
            align-items: center; justify-content: center;
        }
        .modal-overlay.active { display: flex; }
        .modal-box {
            position: relative;
            background: var(--bg-panel); color: var(--text);
            border: 1px solid var(--border); border-radius: 10px;
            max-width: 720px; width: 90%; max-height: 80vh;
            overflow-y: auto; padding: 24px 28px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.35);
        }
        .modal-box h3 { color: var(--text); margin: 0 0 14px 0; padding-right: 30px; font-size: 15px; }
        .modal-close {
            position: absolute; top: 12px; right: 14px;
            background: none; border: none; color: var(--text-muted);
            font-size: 22px; cursor: pointer; line-height: 1; padding: 0;
        }
        .modal-close:hover { color: var(--text); }
        #detailModalBody .permission-item { display: block; }
        @media (max-width: 600px) { .modal-box { width: 95%; max-height: 90vh; padding: 18px; } }

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
                <strong>Tenant ID:</strong> $(ConvertTo-HtmlSafe $tenantId) &nbsp;&middot;&nbsp;
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
        <button class="export-csv-btn" onclick="exportCsv()" title="Download visible rows as CSV">&#8595; Export CSV</button>
        <span id="filterSummary" class="filter-summary"></span>
    </div>

    <div class="controls" id="controlsPanel" hidden>
        <input type="text" id="searchInput" class="filter-search" placeholder="Search by application name, App ID, owner or permission..." oninput="queueApplyFilters()">

        <div class="filter-group">
            <span class="filter-group-label">Ownership</span>
            <span class="filter-tag c-green" data-group="ownership" data-value="internal"    onclick="toggleTag(this)">Internal <span class="cnt"></span></span>
            <span class="filter-tag c-blue"  data-group="ownership" data-value="microsoft"   onclick="toggleTag(this)">Microsoft <span class="cnt"></span></span>
            <span class="filter-tag c-red"   data-group="ownership" data-value="third-party" onclick="toggleTag(this)">Third-Party <span class="cnt"></span></span>
        </div>
        <div class="filter-group">
            <span class="filter-group-label">Publisher</span>
            <span class="filter-tag c-green" data-group="publisher" data-value="verified"   onclick="toggleTag(this)">Verified <span class="cnt"></span></span>
            <span class="filter-tag c-gray"  data-group="publisher" data-value="unverified" onclick="toggleTag(this)">Unverified <span class="cnt"></span></span>
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
            <span class="filter-tag c-green" data-group="credentials" data-value="certs"    onclick="toggleTag(this)">Has Certs <span class="cnt"></span></span>
            <span class="filter-tag c-amber" data-group="credentials" data-value="secrets"  onclick="toggleTag(this)">Has Secrets <span class="cnt"></span></span>
            <span class="filter-tag c-red"   data-group="credentials" data-value="expiring" onclick="toggleTag(this)">Expiring <span class="cnt"></span></span>
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
                <th onclick="sortTable(9, 'string')">Credentials</th>
            </tr>
        </thead>
        <tbody>
"@

# Sort by risk score (descending), then by total permissions (descending)
$sortedReport = $report | Sort-Object @{Expression="RiskScore"; Descending=$true}, @{Expression="TotalPermissions"; Descending=$true}
$modalDataEntries = [System.Collections.Generic.List[string]]::new()

foreach ($app in $sortedReport) {
    $riskClass = "risk-" + $app.RiskLevel.ToLower()
    $appRegClass = if ($app.HasAppRegistration) { "has-app-reg" } else { "sp-only" }
    $appRegText = if ($app.HasAppRegistration) { "<span class='badge green clickable-badge' data-fg='appreg' data-fv='yes' title='This service principal has a linked App Registration in this tenant'>Yes</span>" } else { "<span class='badge gray clickable-badge' data-fg='appreg' data-fv='no' title='Service principal only with no App Registration found in this tenant'>No</span>" }
    $enabledText = if ($app.IsEnabled) { "<span class='badge green clickable-badge' data-fg='enabled' data-fv='yes' title='Users can sign in and the application is active in this tenant'>Yes</span>" } else { "<span class='badge gray clickable-badge' data-fg='enabled' data-fv='no' title='User sign-in is blocked for this application. It is visible in the tenant but cannot be used'>No</span>" }
    $portalUrl = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$($app.ServicePrincipalId)/appId/$($app.AppId)"
    $enabledClass = if ($app.IsEnabled) { "app-enabled" } else { "app-disabled" }
    
    # Determine app ownership
    $isInternal = $app.AppOwnerOrganizationId -eq $tenantId
    $isMicrosoft = $app.AppOwnerOrganizationId -in $script:MicrosoftTenantIds
    $ownershipType = if ($isInternal) { "internal" } elseif ($isMicrosoft) { "microsoft" } else { "third-party" }
    $ownershipText = switch ($ownershipType) {
        "internal"    { "<span class='badge green' onclick=`"openDetailModal(reportDetails['$($app.AppId)'].ownershipTitle,reportDetails['$($app.AppId)'].ownershipHtml)`" style='cursor:pointer' title='App registered in this tenant and owned by your organization'>Internal</span>" }
        "microsoft"   { "<span class='badge blue' onclick=`"openDetailModal(reportDetails['$($app.AppId)'].ownershipTitle,reportDetails['$($app.AppId)'].ownershipHtml)`" style='cursor:pointer' title='App owned by Microsoft. This is a first party Microsoft service'>Microsoft</span>" }
        "third-party" { "<span class='badge red' onclick=`"openDetailModal(reportDetails['$($app.AppId)'].ownershipTitle,reportDetails['$($app.AppId)'].ownershipHtml)`" style='cursor:pointer' title='App registered in another tenant. This is a third party service'>Third-Party</span>" }
    }
    $ownershipClass = switch ($ownershipType) {
        "internal"    { "internal-app" }
        "microsoft"   { "microsoft-app" }
        "third-party" { "external-app" }
    }

    # For external third-party apps, show whether the developer has a Microsoft-verified publisher
    if ($ownershipType -eq "third-party") {
        if ($app.IsVerifiedPublisher) {
            $vpName = ConvertTo-HtmlSafe $app.VerifiedPublisherName
            $ownershipText += "<div style='margin-top:4px'><span class='badge green clickable-badge' data-fg='publisher' data-fv='verified' title='Microsoft-verified publisher: $vpName. Click to filter'>Verified Publisher</span></div>"
        } else {
            $ownershipText += "<div style='margin-top:4px'><span class='badge gray clickable-badge' data-fg='publisher' data-fv='unverified' title='No Microsoft-verified publisher. The developer identity behind this app has not been verified. Click to filter'>Unverified Publisher</span></div>"
        }
    }

    # Publisher filter value — only meaningful for third-party apps ('na' excludes internal/Microsoft from the filter)
    $verifiedPublisherValue = if ($ownershipType -eq "third-party") {
        if ($app.IsVerifiedPublisher) { "verified" } else { "unverified" }
    } else {
        "na"
    }
    
    # Determine assignment requirement
    $assignmentRequiredText = if ($app.AssignmentRequired) { "<span class='badge green clickable-badge' data-fg='assignment' data-fv='required' title='Users and groups must be explicitly assigned to access this app'>Yes</span>" } else { "<span class='badge gray clickable-badge' data-fg='assignment' data-fv='not-required' title='All users in the tenant can access this app without explicit assignment'>No</span>" }
    $assignmentRequiredClass = if ($app.AssignmentRequired) { "assignment-required" } else { "assignment-not-required" }
    
    # Format owners with enhanced information
    $ownersText = if ($app.HasOwners) {
        $spOwnerCount = $app.ServicePrincipalOwners.Count
        $appRegOwnerCount = $app.AppRegistrationOwners.Count

        $ownerDisplay = "<span class='badge blue' onclick=`"openDetailModal(reportDetails['$($app.AppId)'].ownersTitle,reportDetails['$($app.AppId)'].ownersHtml)`" style='cursor:pointer' title='Users or service principals responsible for managing this app — click to view details'>$($app.Owners.Count) owner(s)</span> "

        $isInternalApp = $app.AppOwnerOrganizationId -eq $tenantId
        if ($app.OwnershipGap -and $isInternalApp) {
            $ownerDisplay += "<span class='badge amber' onclick=`"openDetailModal(reportDetails['$($app.AppId)'].ownershipGapTitle,reportDetails['$($app.AppId)'].ownershipGapHtml)`" style='cursor:pointer' title='Not all owners are assigned to both the Service Principal and the App Registration — click to view details'>Ownership Gap</span>"
        }
        $ownerDisplay
    } else {
        "<span class='badge gray' title='No owner is assigned. Changes can only be made by a privileged administrator'>No owners</span>"
    }
    
    # Determine ownership CSS class
    $isInternalApp = $app.AppOwnerOrganizationId -eq $tenantId
    $hasLegitimateOwnershipGap = $app.OwnershipGap -and $isInternalApp -and $app.HasAppRegistration

    $ownersClass = if ($app.HasOwners) { 
        if ($hasLegitimateOwnershipGap) { "ownership-gap" } else { "has-owners" }
    } else { 
        "no-owners" 
    }
    
    if ($app.ActiveCertificates -gt 0) {
        $certsBadge = "<span class='badge green' onclick=`"openDetailModal(reportDetails['$($app.AppId)'].certsTitle,reportDetails['$($app.AppId)'].certsHtml)`" style='cursor:pointer' title='Active certificate credentials — click to view details'>Certs: $($app.ActiveCertificates)</span>"
    } else {
        $certsBadge = "<span class='badge gray' title='No active certificates'>Certs: 0</span>"
    }
    if ($app.ActiveSecrets -gt 0) {
        $secretsBadge = "<span class='badge amber' onclick=`"openDetailModal(reportDetails['$($app.AppId)'].secretsTitle,reportDetails['$($app.AppId)'].secretsHtml)`" style='cursor:pointer' title='Active client secret credentials — click to view details'>Secrets: $($app.ActiveSecrets)</span>"
    } else {
        $secretsBadge = "<span class='badge gray' title='No active secrets'>Secrets: 0</span>"
    }
    $expiringBadgeHtml = ""
    if ($app.ExpiringCredentials -gt 0) {
        $expiringBadgeHtml = "<span class='badge red' title='Credentials expiring within 30 days. Renew them to avoid authentication failures'>Expiring: $($app.ExpiringCredentials)</span>"
    }
    $hasCertsValue = if ($app.ActiveCertificates -gt 0) { "yes" } else { "no" }
    $hasSecretsValue = if ($app.ActiveSecrets -gt 0) { "yes" } else { "no" }
    $expiringValue = if ($app.ExpiringCredentials -gt 0) { "yes" } else { "no" }
    
    # Build scoped permission HTML — one accumulator per type (single pass)
    $appPermItems       = ""
    $delegatedPermItems = ""
    $rolePermItems      = ""
    foreach ($perm in $app.Permissions) {
        $permClass = switch ($perm.Type) {
            "Application"    { "app-permission" }
            "Delegated"      { "delegated-permission" }
            "Directory Role" { "directory-role" }
        }
        $safePermName = ConvertTo-HtmlSafe $perm.Permission
        $safeResource = ConvertTo-HtmlSafe $perm.Resource
        if ($perm.Type -ne "Directory Role") {
            $urlPermName = [Uri]::EscapeDataString($perm.Permission)
            $permLink = "<a href='https://graphpermissions.merill.net/permission/$urlPermName' target='_blank' title='View $safePermName on Graph Permissions Explorer' style='color:inherit;text-decoration:underline dotted;'>$safePermName</a>"
        } else {
            $permLink = $safePermName
        }
        $item = "<div class='permission-item $permClass'><strong>[$($perm.Type)]</strong> $permLink on <em>$safeResource</em></div>"
        switch ($perm.Type) {
            "Application"    { $appPermItems       += $item }
            "Delegated"      { $delegatedPermItems += $item }
            "Directory Role" { $rolePermItems      += $item }
        }
    }
    if (-not $appPermItems)       { $appPermItems       = "No application permissions assigned" }
    if (-not $delegatedPermItems) { $delegatedPermItems = "No delegated permissions assigned" }
    if (-not $rolePermItems)      { $rolePermItems      = "No directory roles assigned" }

    # Build risk factors — escape each item as it may contain API-sourced permission/app names
    # Points are shown on the left (red, fixed-width) and factors are sorted highest-to-lowest,
    # with 0-point informational items last. An optional Detail renders as a hover tooltip.
    $riskFactorsHtml = if ($app.RiskFactors.Count -gt 0) {
        # Stable sort: descending by points, preserving original order within equal points.
        # (Windows PowerShell 5.1 Sort-Object is not stable, so use an index tiebreaker.)
        $factorIndex = 0
        $sortedFactors = $app.RiskFactors |
            ForEach-Object { [PSCustomObject]@{ Factor = $_; Order = $factorIndex++ } } |
            Sort-Object -Property @{ Expression = { $_.Factor.Points }; Descending = $true }, @{ Expression = { $_.Order }; Ascending = $true } |
            ForEach-Object { $_.Factor }
        $riskFactorItems = ($sortedFactors | ForEach-Object {
            $factorText = ConvertTo-HtmlSafe $_.Text
            # Linkify the permission name to the Graph Permissions Explorer (same as the permission modals)
            if ($_.Permission) {
                $safePerm = ConvertTo-HtmlSafe $_.Permission
                $urlPerm  = [Uri]::EscapeDataString($_.Permission)
                $permLink = "<a href='https://graphpermissions.merill.net/permission/$urlPerm' target='_blank' title='View $safePerm on Graph Permissions Explorer' style='color:inherit;text-decoration:underline dotted;'>$safePerm</a>"
                $factorText = $factorText.Replace($safePerm, $permLink)
            }
            $detailMarker = if ($_.Detail) { " <span title='$(ConvertTo-HtmlSafe $_.Detail)' style='cursor:help;color:var(--blue)'>&#9432;</span>" } else { "" }
            $pointsCell = if ($_.Points -gt 0) {
                "<span style='color:var(--bad);font-weight:600'>+$($_.Points)</span>"
            } else {
                "<span style='color:var(--text-muted)'>&mdash;</span>"
            }
            "<li style='display:flex;gap:8px;align-items:baseline;margin:2px 0'><span style='flex:0 0 42px;text-align:right;font-variant-numeric:tabular-nums'>$pointsCell</span><span>$factorText$detailMarker</span></li>"
        }) -join ""
        "<div style='margin:0 0 12px 0;font-size:14px;font-weight:600'>Total Risk Score: <span style='color:var(--bad)'>$($app.RiskScore)</span> ($($app.RiskLevel))</div><ul style='margin:5px 0; padding-left: 4px; list-style:none'>$riskFactorItems</ul>"
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
    
    $safeDisplayName = ConvertTo-HtmlSafe $app.DisplayName
    $ownerSearchText = if ($app.Owners -and $app.Owners.Count -gt 0) {
        ($app.Owners | ForEach-Object { "$($_.DisplayName) $($_.UserPrincipalName) $($_.Type)" }) -join ' '
    } else {
        ''
    }
    $permissionSearchText = if ($app.Permissions -and $app.Permissions.Count -gt 0) {
        ($app.Permissions | ForEach-Object { "$($_.Type) $($_.Permission) $($_.Resource)" }) -join ' '
    } else {
        ''
    }
    $safeOwnerSearchText = ConvertTo-HtmlSafe $ownerSearchText
    $safePermissionSearchText = ConvertTo-HtmlSafe $permissionSearchText
    $safeKey = $app.AppId

    # Permission badges — badge itself is the modal trigger when count > 0
    $appPermBadge = if ($app.ApplicationPermissions -gt 0) {
        "<span class='badge orange' onclick=`"openDetailModal(reportDetails['$safeKey'].appPermsTitle,reportDetails['$safeKey'].appPermsHtml)`" style='cursor:pointer' title='Application permissions grant access without a signed-in user and are typically high privilege'>App: $($app.ApplicationPermissions)</span>"
    } else { "<span class='badge gray'>App: 0</span>" }
    $delegatedPermBadge = if ($app.DelegatedPermissions -gt 0) {
        "<span class='badge blue' onclick=`"openDetailModal(reportDetails['$safeKey'].delegatedPermsTitle,reportDetails['$safeKey'].delegatedPermsHtml)`" style='cursor:pointer' title='Delegated permissions act on behalf of a signed-in user'>Delegated: $($app.DelegatedPermissions)</span>"
    } else { "<span class='badge gray'>Delegated: 0</span>" }
    $rolePermBadge = if ($app.DirectoryRoles -gt 0) {
        "<span class='badge red' onclick=`"openDetailModal(reportDetails['$safeKey'].rolePermsTitle,reportDetails['$safeKey'].rolePermsHtml)`" style='cursor:pointer' title='App has been assigned Entra ID directory roles which grant broad administrative capabilities'>Roles: $($app.DirectoryRoles)</span>"
    } else { "<span class='badge gray'>Roles: 0</span>" }
    $permissionSummary = "$appPermBadge $delegatedPermBadge $rolePermBadge"
    $riskTitle = switch ($app.RiskLevel) {
        "Critical" { "Critical risk. Immediate review required. This app has a combination of high privilege permissions, active credentials and missing controls" }
        "High"     { "High risk. This app has elevated permissions or missing security controls that should be reviewed" }
        "Medium"   { "Medium risk. Some risk factors are present. Review the risk analysis for details" }
        "Low"      { "Low risk. No significant security concerns detected at this time" }
        default    { "Risk level not calculated" }
    }
    $riskBadge = if ($app.RiskFactors.Count -gt 0) {
        "<span class='badge $riskBadgeColor' onclick=`"openDetailModal(reportDetails['$safeKey'].riskTitle,reportDetails['$safeKey'].riskHtml)`" style='cursor:pointer' title='$riskTitle'>$($app.RiskLevel)</span>"
    } else {
        "<span class='badge $riskBadgeColor' title='$riskTitle'>$($app.RiskLevel)</span>"
    }
    $appPermsModalTitle       = "Application Permissions for $($app.DisplayName) ($($app.ApplicationPermissions))"
    $delegatedPermsModalTitle = "Delegated Permissions for $($app.DisplayName) ($($app.DelegatedPermissions))"
    $rolePermsModalTitle      = "Directory Roles for $($app.DisplayName) ($($app.DirectoryRoles))"
    $riskModalTitle           = "Risk Analysis for $($app.DisplayName) ($($app.RiskFactors.Count) factors)"
    # Certificate modal
    $certsModalTitle = "Certificates for $($app.DisplayName) ($($app.ActiveCertificates) active)"
    if ($app.ActiveCertificateList -and $app.ActiveCertificateList.Count -gt 0) {
        $certRows = ($app.ActiveCertificateList | ForEach-Object {
            $cName  = if ($_.DisplayName) { ConvertTo-HtmlSafe $_.DisplayName } else { "<em>(no name)</em>" }
            $cStart = if ($_.StartDateTime) { $_.StartDateTime.ToString("yyyy-MM-dd") } else { "—" }
            $cEnd   = if ($_.EndDateTime)   { $_.EndDateTime.ToString("yyyy-MM-dd") }   else { "—" }
            $cKeyId = ConvertTo-HtmlSafe "$($_.KeyId)"
            "<tr><td style='padding:4px 8px'>$cName</td><td style='padding:4px 8px'>$cStart</td><td style='padding:4px 8px'>$cEnd</td><td style='padding:4px 8px'><code>$cKeyId</code></td></tr>"
        }) -join ""
        $certsModalHtml = "<table style='width:100%;border-collapse:collapse;font-size:13px'><thead><tr><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Display Name</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Start</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Expires</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Key ID</th></tr></thead><tbody>$certRows</tbody></table>"
    } else {
        $certsModalHtml = "No active certificates"
    }
    # Secret modal
    $secretsModalTitle = "Client Secrets for $($app.DisplayName) ($($app.ActiveSecrets) active)"
    if ($app.ActiveSecretList -and $app.ActiveSecretList.Count -gt 0) {
        $secretRows = ($app.ActiveSecretList | ForEach-Object {
            $sName  = if ($_.DisplayName) { ConvertTo-HtmlSafe $_.DisplayName } else { "<em>(no name)</em>" }
            $sStart = if ($_.StartDateTime) { $_.StartDateTime.ToString("yyyy-MM-dd") } else { "—" }
            $sEnd   = if ($_.EndDateTime)   { $_.EndDateTime.ToString("yyyy-MM-dd") }   else { "—" }
            $sKeyId = ConvertTo-HtmlSafe "$($_.KeyId)"
            "<tr><td style='padding:4px 8px'>$sName</td><td style='padding:4px 8px'>$sStart</td><td style='padding:4px 8px'>$sEnd</td><td style='padding:4px 8px'><code>$sKeyId</code></td></tr>"
        }) -join ""
        $secretsModalHtml = "<table style='width:100%;border-collapse:collapse;font-size:13px'><thead><tr><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Display Name</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Start</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Expires</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Key ID</th></tr></thead><tbody>$secretRows</tbody></table>"
    } else {
        $secretsModalHtml = "No active secrets"
    }
    # Ownership modal
    $ownershipLabel = switch ($ownershipType) {
        "internal"    { "Internal (registered in this tenant)" }
        "microsoft"   { "Microsoft (first-party service)" }
        "third-party" { "Third-Party (registered in external tenant)" }
    }
    $safeOrgId = ConvertTo-HtmlSafe "$($app.AppOwnerOrganizationId)"
    # Publisher row — only shown for third-party apps
    $publisherRow = ""
    if ($ownershipType -eq "third-party") {
        if ($app.IsVerifiedPublisher) {
            $vpNameSafe = ConvertTo-HtmlSafe $app.VerifiedPublisherName
            $publisherRow = "<tr><td style='padding:6px 8px;font-weight:bold'>Publisher</td><td style='padding:6px 8px'><span style='color:var(--good);font-weight:600'>Verified</span> &mdash; $vpNameSafe</td></tr>"
        } else {
            $publisherRow = "<tr><td style='padding:6px 8px;font-weight:bold'>Publisher</td><td style='padding:6px 8px'><span style='color:var(--bad);font-weight:600'>Unverified</span></td></tr>"
        }
    }
    $ownershipModalTitle = "App Ownership for $($app.DisplayName)"
    $ownershipModalHtml = "<table style='width:100%;border-collapse:collapse;font-size:13px'><tbody><tr><td style='padding:6px 8px;font-weight:bold;width:40%'>Ownership Type</td><td style='padding:6px 8px'>$ownershipLabel</td></tr>$publisherRow<tr><td style='padding:6px 8px;font-weight:bold'>Owner Tenant ID</td><td style='padding:6px 8px'><code>$safeOrgId</code></td></tr></tbody></table>"
    # Owners modal — all owners with Enterprise App / App Registration coverage
    $ownersModalTitle = "Owners for $($app.DisplayName) ($($app.Owners.Count) total)"
    if ($app.Owners -and $app.Owners.Count -gt 0) {
        $ownerRows = ($app.Owners | ForEach-Object {
            $oName = ConvertTo-HtmlSafe $_.DisplayName
            $oUpn  = ConvertTo-HtmlSafe "$($_.UserPrincipalName)"
            $oType = ConvertTo-HtmlSafe $_.Type
            $onSp  = if ($_.Source -eq 'ServicePrincipal' -or $_.Source -eq 'Both') { "&#10003;" } else { "&#8212;" }
            $onApp = if ($_.Source -eq 'AppRegistration'  -or $_.Source -eq 'Both') { "&#10003;" } else { "&#8212;" }
            "<tr><td style='padding:4px 8px'>$oName</td><td style='padding:4px 8px'>$oType</td><td style='padding:4px 8px'><small>$oUpn</small></td><td style='padding:4px 8px;text-align:center'>$onSp</td><td style='padding:4px 8px;text-align:center'>$onApp</td></tr>"
        }) -join ""
        $ownersModalHtml = "<table style='width:100%;border-collapse:collapse;font-size:13px'><thead><tr><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Name</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Type</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>UPN / App ID</th><th style='text-align:center;padding:4px 8px;border-bottom:1px solid var(--border)'>Enterprise App</th><th style='text-align:center;padding:4px 8px;border-bottom:1px solid var(--border)'>App Registration</th></tr></thead><tbody>$ownerRows</tbody></table>"
    } else {
        $ownersModalHtml = "No owners assigned"
    }
    # Ownership Gap modal — owners not present on both sides
    $ownershipGapModalTitle = "Ownership Gap for  $($app.DisplayName)"
    $gapOwners = @($app.Owners | Where-Object { $_.Source -ne 'Both' })
    if ($gapOwners.Count -gt 0) {
        $gapRows = ($gapOwners | ForEach-Object {
            $gName  = ConvertTo-HtmlSafe $_.DisplayName
            $gUpn   = ConvertTo-HtmlSafe "$($_.UserPrincipalName)"
            $gType  = ConvertTo-HtmlSafe $_.Type
            $gWhere = switch ($_.Source) {
                'ServicePrincipal' { "Enterprise App only" }
                'AppRegistration'  { "App Registration only" }
                default            { ConvertTo-HtmlSafe $_.Source }
            }
            "<tr><td style='padding:4px 8px'>$gName</td><td style='padding:4px 8px'>$gType</td><td style='padding:4px 8px'><small>$gUpn</small></td><td style='padding:4px 8px'>$gWhere</td></tr>"
        }) -join ""
        $ownershipGapModalHtml = "<p style='margin:0 0 10px 0;font-size:13px'>Owners not assigned to both the Enterprise App and the App Registration:</p><table style='width:100%;border-collapse:collapse;font-size:13px'><thead><tr><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Name</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Type</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>UPN / App ID</th><th style='text-align:left;padding:4px 8px;border-bottom:1px solid var(--border)'>Assigned To</th></tr></thead><tbody>$gapRows</tbody></table>"
    } else {
        $ownershipGapModalHtml = "No ownership gap detected. All owners are assigned to both the Enterprise App and App Registration."
    }
    $modalDataEntries.Add("`"$safeKey`": { appPermsTitle: $(ConvertTo-Json $appPermsModalTitle -Compress), appPermsHtml: $(ConvertTo-Json $appPermItems -Compress), delegatedPermsTitle: $(ConvertTo-Json $delegatedPermsModalTitle -Compress), delegatedPermsHtml: $(ConvertTo-Json $delegatedPermItems -Compress), rolePermsTitle: $(ConvertTo-Json $rolePermsModalTitle -Compress), rolePermsHtml: $(ConvertTo-Json $rolePermItems -Compress), riskTitle: $(ConvertTo-Json $riskModalTitle -Compress), riskHtml: $(ConvertTo-Json $riskFactorsHtml -Compress), certsTitle: $(ConvertTo-Json $certsModalTitle -Compress), certsHtml: $(ConvertTo-Json $certsModalHtml -Compress), secretsTitle: $(ConvertTo-Json $secretsModalTitle -Compress), secretsHtml: $(ConvertTo-Json $secretsModalHtml -Compress), ownershipTitle: $(ConvertTo-Json $ownershipModalTitle -Compress), ownershipHtml: $(ConvertTo-Json $ownershipModalHtml -Compress), ownersTitle: $(ConvertTo-Json $ownersModalTitle -Compress), ownersHtml: $(ConvertTo-Json $ownersModalHtml -Compress), ownershipGapTitle: $(ConvertTo-Json $ownershipGapModalTitle -Compress), ownershipGapHtml: $(ConvertTo-Json $ownershipGapModalHtml -Compress) }")
    $html += @"
            <tr class="$riskClass" data-name="$safeDisplayName" data-appid="$($app.AppId)" data-ownertext="$safeOwnerSearchText" data-permtext="$safePermissionSearchText" data-risk="$($app.RiskLevel)" data-appreg="$(if ($app.HasAppRegistration) { 'yes' } else { 'no' })" data-apppermcount="$($app.ApplicationPermissions)" data-delegatedpermcount="$($app.DelegatedPermissions)" data-rolecount="$($app.DirectoryRoles)" data-hascerts="$hasCertsValue" data-hassecrets="$hasSecretsValue" data-expiring="$expiringValue" data-owners="$(if ($app.HasOwners) { 'yes' } else { 'no' })" data-ownershipgap="$(if ($app.OwnershipGap) { 'yes' } else { 'no' })" data-ownership="$ownershipType" data-verifiedpublisher="$verifiedPublisherValue" data-assignment="$(if ($app.AssignmentRequired) { 'required' } else { 'not-required' })" data-enabled="$(if ($app.IsEnabled) { 'yes' } else { 'no' })">
                <td><a class="app-name" href="$portalUrl" target="_blank" title="Open in Entra portal">$safeDisplayName</a></td>
                <td class="$enabledClass">$enabledText</td>
                <td><code class="mono">$($app.AppId)</code></td>
                <td class="$ownershipClass">$ownershipText</td>
                <td class="$appRegClass">$appRegText</td>
                <td class="$assignmentRequiredClass">$assignmentRequiredText</td>
                <td class="$ownersClass cell-sm">$ownersText</td>
                <td class="cell-sm">$riskBadge</td>
                <td class="cell-sm"><span class="perm-badges">$permissionSummary</span></td>
                <td class="cell-sm">$certsBadge $secretsBadge$(if ($expiringBadgeHtml) { " $expiringBadgeHtml" })</td>
            </tr>
"@
}

$reportDetailsBlock = "const reportDetails = {`n" + ($modalDataEntries -join ",`n") + "`n};"
# PS 5.1 ConvertTo-Json does not escape < or >, so </script> inside a string value would
# break out of the <script> block. Replace </ with <\/ (valid in JSON) to prevent this.
$reportDetailsBlock = $reportDetailsBlock -replace '</', '<\/'

$html += @"
        </tbody>
    </table>
    </div>

    <script>
        $reportDetailsBlock

        // Active filters: group -> Set of selected values (OR within a group, AND across groups)
        const activeFilters = {};
        const groupLabels = {
            ownership: 'Ownership', risk: 'Risk', appreg: 'App Reg',
            assignment: 'Assignment', owners: 'Owners', permissions: 'Permissions', credentials: 'Credentials', enabled: 'Enabled', publisher: 'Publisher'
        };
        const valueLabels = {
            internal: 'Internal', external: 'External', microsoft: 'Microsoft', 'third-party': 'Third-Party',
            Critical: 'Critical', High: 'High', Medium: 'Medium', Low: 'Low',
            yes: 'Yes', no: 'No',
            required: 'Required', 'not-required': 'Open Access',
            has: 'Has Owners', noowners: 'No Owners', gap: 'Ownership Gap',
            application: 'Application', delegated: 'Delegated', roles: 'Roles', none: 'None',
            certs: 'Has Certs', secrets: 'Has Secrets', expiring: 'Expiring',
            verified: 'Verified', unverified: 'Unverified'
        };

        function rowMatchesTag(row, group, value) {
            switch (group) {
                case 'ownership':   return row.dataset.ownership === value;
                case 'publisher':
                    if (value === 'verified')   return row.dataset.verifiedpublisher === 'verified';
                    if (value === 'unverified') return row.dataset.verifiedpublisher === 'unverified';
                    return false;
                case 'risk':        return row.dataset.risk === value;
                case 'appreg':      return row.dataset.appreg === value;
                case 'assignment':  return row.dataset.assignment === value;
                case 'owners':
                    if (value === 'has')      return row.dataset.owners === 'yes';
                    if (value === 'noowners') return row.dataset.owners === 'no';
                    if (value === 'gap')      return row.dataset.ownershipgap === 'yes';
                    return false;
                case 'credentials':
                    if (value === 'certs')    return row.dataset.hascerts === 'yes';
                    if (value === 'secrets')  return row.dataset.hassecrets === 'yes';
                    if (value === 'expiring') return row.dataset.expiring === 'yes';
                    return false;
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

        let _searchDebounceHandle = null;

        function queueApplyFilters() {
            if (_searchDebounceHandle) {
                clearTimeout(_searchDebounceHandle);
            }
            _searchDebounceHandle = setTimeout(applyFilters, 150);
        }

        function rowVisible(row) {
            const search = document.getElementById('searchInput').value.toLowerCase().trim();
            if (search) {
                const nameMatch  = (row.dataset.name  || '').toLowerCase().includes(search);
                const appIdMatch = (row.dataset.appid || '').toLowerCase().includes(search);
                const ownerMatch = (row.dataset.ownertext || '').toLowerCase().includes(search);
                const permMatch  = (row.dataset.permtext  || '').toLowerCase().includes(search);
                if (!nameMatch && !appIdMatch && !ownerMatch && !permMatch) return false;
            }
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

        let _sortCol = -1, _sortAsc = true;
        function sortTable(columnIndex, type) {
            if (_sortCol === columnIndex) {
                _sortAsc = !_sortAsc;
            } else {
                _sortCol = columnIndex;
                _sortAsc = type !== 'number';
            }
            const dir = _sortAsc ? 1 : -1;
            const table = document.getElementById('reportTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));

            rows.sort((a, b) => {
                let aVal = a.cells[columnIndex].textContent.trim();
                let bVal = b.cells[columnIndex].textContent.trim();
                if (type === 'number') {
                    aVal = parseInt(aVal.replace(/[^0-9]/g, '')) || 0;
                    bVal = parseInt(bVal.replace(/[^0-9]/g, '')) || 0;
                    return (aVal - bVal) * dir;
                }
                return aVal.localeCompare(bVal) * dir;
            });

            rows.forEach(row => tbody.appendChild(row));

            document.querySelectorAll('#reportTable thead th').forEach(th => {
                th.classList.remove('sort-asc', 'sort-desc');
            });
            document.querySelectorAll('#reportTable thead th')[columnIndex]
                ?.classList.add(_sortAsc ? 'sort-asc' : 'sort-desc');
        }

        function exportCsv() {
            const headers = Array.from(document.querySelectorAll('#reportTable thead th'))
                .map(th => th.textContent.replace(/[▲▼]/g, '').trim());

            const visibleRows = Array.from(document.querySelectorAll('#reportTable tbody tr'))
                .filter(tr => tr.style.display !== 'none');

            const esc = v => '"' + String(v).replace(/"/g, '""') + '"';

            const lines = [headers.map(esc).join(',')];
            visibleRows.forEach(tr => {
                const cells = Array.from(tr.cells).map(td => {
                    const clone = td.cloneNode(true);
                    clone.querySelectorAll('.csv-exclude').forEach(n => n.remove());
                    return esc(clone.textContent.trim().replace(/\s+/g, ' '));
                });
                lines.push(cells.join(','));
            });

            // UTF-8 BOM ensures Excel opens the file with correct encoding
            const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
            const url  = URL.createObjectURL(blob);
            const a    = document.createElement('a');
            a.href     = url;
            a.download = 'EntraIDReport_' + new Date().toISOString().slice(0, 10) + '.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        let _modalTrigger = null;

        function openDetailModal(title, html) {
            _modalTrigger = document.activeElement;
            document.getElementById('detailModalTitle').textContent = title;
            document.getElementById('detailModalBody').innerHTML = html;
            document.getElementById('detailModalOverlay').classList.add('active');
            document.querySelector('#detailModalOverlay .modal-box').scrollTop = 0;
            document.querySelector('.modal-close').focus();
        }

        function closeDetailModal() {
            document.getElementById('detailModalOverlay').classList.remove('active');
            if (_modalTrigger) { _modalTrigger.focus(); _modalTrigger = null; }
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

            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') closeDetailModal();
            });

            computeTagCounts();
            applyFilters();
        })();
    </script>

    <div id="detailModalOverlay" class="modal-overlay" onclick="if(event.target===this) closeDetailModal()">
        <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="detailModalTitle" aria-describedby="detailModalBody">
            <button class="modal-close" onclick="closeDetailModal()" aria-label="Close">&times;</button>
            <h3 id="detailModalTitle"></h3>
            <div id="detailModalBody"></div>
        </div>
    </div>
    </div>

    <footer class="report-footer">
        Found this tool helpful? Subscribe to my blog at <a href="https://www.matej.guru" target="_blank" rel="noopener">www.matej.guru</a>. This script is provided "as is", without any warranty.
    </footer>
</body>
</html>
"@

# Save the HTML report — UTF-8 without BOM for consistent output across PS 5.1 and PS 7
if ($DryRun) {
    Write-Host "DryRun: skipping report write to '$OutputPath'" -ForegroundColor Yellow
} else {
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Report generated successfully: $OutputPath" -ForegroundColor Green

    # Open the report in default browser (interactive mode only)
    if (-not $NonInteractive) {
        Write-Host "Opening report in default browser..." -ForegroundColor Green
        Start-Process ([System.IO.Path]::GetFullPath($OutputPath))
    }
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
Write-Host "  - Medium Risk: $mediumRiskApps" -ForegroundColor Yellow
Write-Host "  - Low Risk: $lowRiskApps" -ForegroundColor Green
Write-Host "`nGovernance Analysis:" -ForegroundColor White
Write-Host "  - Apps without owners: $appsWithoutOwners" -ForegroundColor Red
Write-Host "  - Apps with open access (Assignment Required = No): $appsWithOpenAccess" -ForegroundColor DarkYellow
Write-Host "`nCredential Analysis:" -ForegroundColor White
Write-Host "  - Apps with active credentials: $appsWithActiveCredentials" -ForegroundColor Green
Write-Host "  - Apps without credentials: $appsWithoutCredentials" -ForegroundColor DarkYellow
Write-Host "  - Apps with expiring credentials (30 days): $appsWithExpiringCredentials" -ForegroundColor Yellow

# Performance summary
if ($OnlyWithPermissions -or $MinimumPermissions -gt 0 -or $OnlyWithAppRegistrations -or $OnlyServicePrincipals) {
    Write-Host "`n⚡ Performance Optimization:" -ForegroundColor Green
    Write-Host "  - Pre-filtering optimization was applied" -ForegroundColor Green
    Write-Host "  - Analysis was only performed on filtered applications" -ForegroundColor Green
}

    Write-Host "`nScript completed successfully!" -ForegroundColor Green
    Write-Host "Check the HTML report for detailed analysis focused on reliable data." -ForegroundColor Cyan
    Write-Host "For usage verification, manually review sign-in logs in the Azure portal." -ForegroundColor Yellow

} finally {
    # Guaranteed to run even if the script throws — keeps Graph sessions clean
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

exit 0
