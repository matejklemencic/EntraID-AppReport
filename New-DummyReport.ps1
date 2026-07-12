<#
.SYNOPSIS
    Generates a DUMMY Microsoft Entra ID App Report using mock data (no Graph connection).
.DESCRIPTION
    This helper reuses the exact HTML/CSS/JS rendering block from Get-EntraIDAppReport.ps1
    but feeds it hand-crafted mock data. Use it to preview and iterate on the HTML report
    experience without connecting to Microsoft Graph.

    It works by extracting the rendering region of the main script (from the $logoSvg line
    up to, but not including, the "# Save the HTML report" line) and invoking it against the
    mock $report and summary variables defined below. This keeps the dummy report visually
    identical to a real one and automatically in sync with the template.
.PARAMETER OutputPath
    Path to save the generated dummy HTML report. Defaults to "DummyReport.html".
.PARAMETER NoLaunch
    Do not open the report in the default browser after generation.
.EXAMPLE
    .\New-DummyReport.ps1
.EXAMPLE
    .\New-DummyReport.ps1 -OutputPath "C:\Temp\preview.html" -NoLaunch
#>
[CmdletBinding()]
param(
    [string]$OutputPath = "DummyReport.html",
    [switch]$NoLaunch
)

# ---------------------------------------------------------------------------
# Helper functions copied from Get-EntraIDAppReport.ps1 (needed by the template)
# ---------------------------------------------------------------------------
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}

function Get-EntraRoleLearnUrl {
    param([string]$RoleName)
    $anchor = (($RoleName.ToLower() -replace '[^a-z0-9 -]', '') -replace '\s+', '-')
    return "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#$anchor"
}

$script:MicrosoftTenantIds = @(
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a',
    '72f988bf-86f1-41af-91ab-2d7cd011db47',
    '9188040d-6c67-4c5b-b112-36a304b66dad',
    'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'
)

# ---------------------------------------------------------------------------
# Mock tenant + application data
# ---------------------------------------------------------------------------
$tenantName = "Contoso (Demo Tenant)"
$tenantId   = "11111111-2222-3333-4444-555555555555"
$microsoftOrgId  = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
$thirdPartyOrgId = '99999999-8888-7777-6666-555555555555'

# Small helpers to build owner / credential / permission objects concisely
function New-Owner {
    param([string]$Name, [string]$Upn, [string]$Type = 'User', [string]$Source = 'Both')
    [PSCustomObject]@{ DisplayName = $Name; UserPrincipalName = $Upn; Type = $Type; Source = $Source }
}
function New-Cred {
    param([string]$Name, [int]$StartOffsetDays, [int]$EndOffsetDays, [string]$KeyId)
    [PSCustomObject]@{
        DisplayName   = $Name
        StartDateTime = (Get-Date).AddDays($StartOffsetDays)
        EndDateTime   = (Get-Date).AddDays($EndOffsetDays)
        KeyId         = $KeyId
    }
}
function New-Perm {
    param(
        [string]$Type,
        [string]$Permission,
        [string]$Resource,
        [string]$ConsentType,
        $UserCount
    )
    # Defaults keep older/simpler mock entries working unchanged: Application/Directory Role
    # permissions are always admin-governed by definition; Delegated permissions default to
    # tenant-wide Admin Consent unless a scenario explicitly overrides it to show User Consent.
    if (-not $ConsentType) {
        $ConsentType = if ($Type -eq "Directory Role") { "Admin Assignment" } else { "Admin Consent" }
    }
    if ($null -eq $UserCount) {
        $UserCount = if ($ConsentType -eq "Admin Consent" -and $Type -eq "Delegated") { "All Users" } else { "N/A" }
    }
    [PSCustomObject]@{ Type = $Type; Permission = $Permission; Resource = $Resource; ConsentType = $ConsentType; UserCount = $UserCount }
}

$report = @(

    # 1) Internal, Critical, open access, app permissions, expiring secret, ownership gap
    [PSCustomObject]@{
        DisplayName = "Contoso Automation Runner"
        AppId = "a1a1a1a1-0000-0000-0000-000000000001"
        ServicePrincipalId = "sp-0000-0000-0000-000000000001"
        AppOwnerOrganizationId = $tenantId
        HasAppRegistration = $true
        Owners = @(
            (New-Owner "Alice Admin" "alice@contoso.com" "User" "ServicePrincipal"),
            (New-Owner "Bob Builder" "bob@contoso.com"   "User" "Both")
        )
        ServicePrincipalOwners = @('Alice Admin','Bob Builder')
        AppRegistrationOwners  = @('Bob Builder')
        HasOwners = $true
        HasServicePrincipalOwners = $true
        HasAppRegistrationOwners  = $true
        OwnershipGap = $true
        AssignmentRequired = $false
        IsEnabled = $true
        IsVerifiedPublisher = $false
        VerifiedPublisherName = ""
        TotalPermissions = 3
        ApplicationPermissions = 2
        DelegatedPermissions = 1
        DirectoryRoles = 0
        Permissions = @(
            (New-Perm "Application" "Directory.ReadWrite.All" "Microsoft Graph"),
            (New-Perm "Application" "Mail.Read"               "Microsoft Graph"),
            (New-Perm "Delegated"   "User.Read"               "Microsoft Graph")
        )
        HasActiveCredentials = $true
        ActiveCertificates = 0
        ActiveSecrets = 2
        ExpiringCredentials = 1
        ExpiredCredentials = 1
        ActiveCertificateList = @()
        ActiveSecretList = @(
            (New-Cred "CI Pipeline Secret" -300 20  "key-1111"),
            (New-Cred "Legacy Secret"      -700 -5  "key-1112")
        )
        RiskScore = 120
        RiskLevel = "Critical"
        RiskFactors = @(
            [PSCustomObject]@{ Text = "High-risk permission: Directory.ReadWrite.All"; Points = 15; Permission = "Directory.ReadWrite.All" },
            [PSCustomObject]@{ Text = "Assignment not required"; Points = 5; Url = "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/application-properties#assignment-required" },
            [PSCustomObject]@{ Text = "Uses password secrets (certificates preferred)"; Points = 5; Detail = "Microsoft recommends that you use a certificate instead of a client secret before moving the application to a production environment." },
            [PSCustomObject]@{ Text = "Multiple secrets configured (2) - reduces auditability"; Points = 5 },
            [PSCustomObject]@{ Text = "Ownership gap - owners differ between Service Principal and App Registration"; Points = 1 }
        )
    }

    # 2) Microsoft first-party app, low risk, no credentials
    [PSCustomObject]@{
        DisplayName = "Microsoft Graph Command Line Tools"
        AppId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
        ServicePrincipalId = "sp-0000-0000-0000-000000000002"
        AppOwnerOrganizationId = $microsoftOrgId
        HasAppRegistration = $false
        Owners = @()
        ServicePrincipalOwners = @()
        AppRegistrationOwners  = @()
        HasOwners = $false
        HasServicePrincipalOwners = $false
        HasAppRegistrationOwners  = $false
        OwnershipGap = $false
        AssignmentRequired = $false
        IsEnabled = $true
        IsVerifiedPublisher = $false
        VerifiedPublisherName = ""
        TotalPermissions = 1
        ApplicationPermissions = 0
        DelegatedPermissions = 1
        DirectoryRoles = 0
        Permissions = @(
            (New-Perm "Delegated" "User.Read" "Microsoft Graph")
        )
        HasActiveCredentials = $false
        ActiveCertificates = 0
        ActiveSecrets = 0
        ExpiringCredentials = 0
        ExpiredCredentials = 0
        ActiveCertificateList = @()
        ActiveSecretList = @()
        RiskScore = 0
        RiskLevel = "Low"
        RiskFactors = @()
    }

    # 3) Third-party, verified publisher, high risk, has certs + directory role
    [PSCustomObject]@{
        DisplayName = "Acme SaaS Connector"
        AppId = "b2b2b2b2-0000-0000-0000-000000000003"
        ServicePrincipalId = "sp-0000-0000-0000-000000000003"
        AppOwnerOrganizationId = $thirdPartyOrgId
        HasAppRegistration = $false
        Owners = @(
            (New-Owner "Carol Cloud" "carol@contoso.com" "User" "ServicePrincipal")
        )
        ServicePrincipalOwners = @('Carol Cloud')
        AppRegistrationOwners  = @()
        HasOwners = $true
        HasServicePrincipalOwners = $true
        HasAppRegistrationOwners  = $false
        OwnershipGap = $false
        AssignmentRequired = $true
        IsEnabled = $true
        IsVerifiedPublisher = $true
        VerifiedPublisherName = "Acme Corporation"
        TotalPermissions = 3
        ApplicationPermissions = 1
        DelegatedPermissions = 1
        DirectoryRoles = 1
        Permissions = @(
            (New-Perm "Application"    "Sites.Read.All"       "SharePoint"),
            (New-Perm "Delegated"      "Files.ReadWrite.All"  "Microsoft Graph"),
            (New-Perm "Directory Role" "Application Administrator" "Entra ID")
        )
        HasActiveCredentials = $true
        ActiveCertificates = 1
        ActiveSecrets = 0
        ExpiringCredentials = 0
        ExpiredCredentials = 0
        ActiveCertificateList = @(
            (New-Cred "Acme Signing Cert" -30 400 "cert-3331")
        )
        ActiveSecretList = @()
        RiskScore = 35
        RiskLevel = "High"
        RiskFactors = @(
            [PSCustomObject]@{ Text = "High-risk directory role: Application Administrator"; Points = 15; Role = "Application Administrator" },
            [PSCustomObject]@{ Text = "Has application permissions"; Points = 5 },
            [PSCustomObject]@{ Text = "External application registered in another tenant"; Points = 5 }
        )
    }

    # 4) Third-party, unverified publisher, medium risk
    [PSCustomObject]@{
        DisplayName = "QuickForms Free"
        AppId = "c3c3c3c3-0000-0000-0000-000000000004"
        ServicePrincipalId = "sp-0000-0000-0000-000000000004"
        AppOwnerOrganizationId = $thirdPartyOrgId
        HasAppRegistration = $false
        Owners = @()
        ServicePrincipalOwners = @()
        AppRegistrationOwners  = @()
        HasOwners = $false
        HasServicePrincipalOwners = $false
        HasAppRegistrationOwners  = $false
        OwnershipGap = $false
        AssignmentRequired = $false
        IsEnabled = $true
        IsVerifiedPublisher = $false
        VerifiedPublisherName = ""
        TotalPermissions = 1
        ApplicationPermissions = 0
        DelegatedPermissions = 1
        DirectoryRoles = 0
        Permissions = @(
            (New-Perm "Delegated" "openid" "Microsoft Graph")
        )
        HasActiveCredentials = $false
        ActiveCertificates = 0
        ActiveSecrets = 0
        ExpiringCredentials = 0
        ExpiredCredentials = 0
        ActiveCertificateList = @()
        ActiveSecretList = @()
        RiskScore = 14
        RiskLevel = "Medium"
        RiskFactors = @(
            [PSCustomObject]@{ Text = "External application registered in another tenant"; Points = 5 },
            [PSCustomObject]@{ Text = "External application has no verified publisher"; Points = 5; Url = "https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview" },
            [PSCustomObject]@{ Text = "No owners assigned (neither Service Principal nor App Registration)"; Points = 4 }
        )
    }

    # 5) Internal, disabled, healthy ownership, has certs
    [PSCustomObject]@{
        DisplayName = "Legacy Intranet Portal"
        AppId = "d4d4d4d4-0000-0000-0000-000000000005"
        ServicePrincipalId = "sp-0000-0000-0000-000000000005"
        AppOwnerOrganizationId = $tenantId
        HasAppRegistration = $true
        Owners = @(
            (New-Owner "Dave DevOps" "dave@contoso.com" "User" "Both"),
            (New-Owner "Automation SP" "svc-legacy@contoso.com" "ServicePrincipal" "Both")
        )
        ServicePrincipalOwners = @('Dave DevOps','Automation SP')
        AppRegistrationOwners  = @('Dave DevOps','Automation SP')
        HasOwners = $true
        HasServicePrincipalOwners = $true
        HasAppRegistrationOwners  = $true
        OwnershipGap = $false
        AssignmentRequired = $true
        IsEnabled = $false
        IsVerifiedPublisher = $false
        VerifiedPublisherName = ""
        TotalPermissions = 0
        ApplicationPermissions = 0
        DelegatedPermissions = 0
        DirectoryRoles = 0
        Permissions = @()
        HasActiveCredentials = $true
        ActiveCertificates = 1
        ActiveSecrets = 0
        ExpiringCredentials = 0
        ExpiredCredentials = 0
        ActiveCertificateList = @(
            (New-Cred "Portal TLS Cert" -100 260 "cert-5551")
        )
        ActiveSecretList = @()
        RiskScore = 2
        RiskLevel = "Low"
        RiskFactors = @(
            [PSCustomObject]@{ Text = "Suspicious name contains: legacy"; Points = 2 }
        )
    }

    # 6) Internal, high value target, no owners, open access
    [PSCustomObject]@{
        DisplayName = "Reporting Data Sync"
        AppId = "e5e5e5e5-0000-0000-0000-000000000006"
        ServicePrincipalId = "sp-0000-0000-0000-000000000006"
        AppOwnerOrganizationId = $tenantId
        HasAppRegistration = $true
        Owners = @()
        ServicePrincipalOwners = @()
        AppRegistrationOwners  = @()
        HasOwners = $false
        HasServicePrincipalOwners = $false
        HasAppRegistrationOwners  = $false
        OwnershipGap = $false
        AssignmentRequired = $true
        IsEnabled = $true
        IsVerifiedPublisher = $false
        VerifiedPublisherName = ""
        TotalPermissions = 2
        ApplicationPermissions = 2
        DelegatedPermissions = 0
        DirectoryRoles = 0
        Permissions = @(
            (New-Perm "Application" "Reports.Read.All"  "Microsoft Graph"),
            (New-Perm "Application" "AuditLog.Read.All" "Microsoft Graph")
        )
        HasActiveCredentials = $true
        ActiveCertificates = 0
        ActiveSecrets = 1
        ExpiringCredentials = 0
        ExpiredCredentials = 0
        ActiveCertificateList = @()
        ActiveSecretList = @(
            (New-Cred "Sync Secret" -10 700 "key-6661")
        )
        RiskScore = 22
        RiskLevel = "Medium"
        RiskFactors = @(
            [PSCustomObject]@{ Text = "Has application permissions"; Points = 5 },
            [PSCustomObject]@{ Text = "No owners assigned (neither Service Principal nor App Registration)"; Points = 4 },
            [PSCustomObject]@{ Text = "Uses password secrets (certificates preferred)"; Points = 5; Detail = "Microsoft recommends that you use a certificate instead of a client secret before moving the application to a production environment." },
            [PSCustomObject]@{ Text = "Long-lived credentials (expiry > 1 year)"; Points = 5 }
        )
    }

    # 7) Internal, self-service consent governance blind spot (User Consent, no admin review)
    [PSCustomObject]@{
        DisplayName = "Personal File Sync Tool"
        AppId = "f6f6f6f6-0000-0000-0000-000000000007"
        ServicePrincipalId = "sp-0000-0000-0000-000000000007"
        AppOwnerOrganizationId = $tenantId
        HasAppRegistration = $false
        Owners = @()
        ServicePrincipalOwners = @()
        AppRegistrationOwners  = @()
        HasOwners = $false
        HasServicePrincipalOwners = $false
        HasAppRegistrationOwners  = $false
        OwnershipGap = $false
        AssignmentRequired = $true
        IsEnabled = $true
        IsVerifiedPublisher = $false
        VerifiedPublisherName = ""
        TotalPermissions = 3
        ApplicationPermissions = 0
        DelegatedPermissions = 3
        DirectoryRoles = 0
        Permissions = @(
            # Same permission consented to individually by three separate users — the Permissions
            # modal aggregates these into a single "3 users consented" row instead of duplicates.
            (New-Perm "Delegated" "Mail.Read" "Microsoft Graph" -ConsentType "User Consent" -UserCount 1),
            (New-Perm "Delegated" "Mail.Read" "Microsoft Graph" -ConsentType "User Consent" -UserCount 1),
            (New-Perm "Delegated" "Mail.Read" "Microsoft Graph" -ConsentType "User Consent" -UserCount 1)
        )
        HasActiveCredentials = $false
        ActiveCertificates = 0
        ActiveSecrets = 0
        ExpiringCredentials = 0
        ExpiredCredentials = 0
        ActiveCertificateList = @()
        ActiveSecretList = @()
        RiskScore = 7
        RiskLevel = "Low"
        RiskFactors = @(
            [PSCustomObject]@{ Text = "Medium-risk permission: Mail.Read"; Points = 5; Permission = "Mail.Read" },
            [PSCustomObject]@{ Text = "Sensitive permission granted via User Consent, no admin review (governance blind spot)"; Points = 2 }
        )
    }

    # 8) Internal, tenant-wide Admin Consent grant of a high-risk permission
    [PSCustomObject]@{
        DisplayName = "Company-Wide Calendar Assistant"
        AppId = "07070707-0000-0000-0000-000000000008"
        ServicePrincipalId = "sp-0000-0000-0000-000000000008"
        AppOwnerOrganizationId = $tenantId
        HasAppRegistration = $true
        Owners = @(
            (New-Owner "Erin Ops" "erin@contoso.com" "User" "Both")
        )
        ServicePrincipalOwners = @('Erin Ops')
        AppRegistrationOwners  = @('Erin Ops')
        HasOwners = $true
        HasServicePrincipalOwners = $true
        HasAppRegistrationOwners  = $true
        OwnershipGap = $false
        AssignmentRequired = $true
        IsEnabled = $true
        IsVerifiedPublisher = $false
        VerifiedPublisherName = ""
        TotalPermissions = 1
        ApplicationPermissions = 0
        DelegatedPermissions = 1
        DirectoryRoles = 0
        Permissions = @(
            (New-Perm "Delegated" "Calendars.ReadWrite" "Microsoft Graph" -ConsentType "Admin Consent" -UserCount "All Users")
        )
        HasActiveCredentials = $false
        ActiveCertificates = 0
        ActiveSecrets = 0
        ExpiringCredentials = 0
        ExpiredCredentials = 0
        ActiveCertificateList = @()
        ActiveSecretList = @()
        RiskScore = 20
        RiskLevel = "Medium"
        RiskFactors = @(
            [PSCustomObject]@{ Text = "High-risk permission: Calendars.ReadWrite"; Points = 15; Permission = "Calendars.ReadWrite" },
            [PSCustomObject]@{ Text = "Sensitive permission granted via Admin Consent, tenant-wide (all users exposed)"; Points = 5 }
        )
    }

    # 9) Kitchen Sink: every distinct risk factor text/hint in a single app, for review purposes.
    # NOTE: Some factors are mutually exclusive in the real Get-RiskScore engine (e.g. ownership
    # variants, or the two "Assignment not required" variants) and could never all fire together
    # on one real app. This entry hardcodes every distinct factor line so all text/tooltips can be
    # reviewed side by side in a single Risk Analysis modal.
    [PSCustomObject]@{
        DisplayName = "Legacy Test Sync Connector (Kitchen Sink - All Risk Factors)"
        AppId = "99999999-0000-0000-0000-000000000009"
        ServicePrincipalId = "sp-0000-0000-0000-000000000009"
        AppOwnerOrganizationId = $thirdPartyOrgId
        HasAppRegistration = $true
        Owners = @(
            (New-Owner "Frank Ops" "frank@contoso.com" "User" "ServicePrincipal")
        )
        ServicePrincipalOwners = @('Frank Ops')
        AppRegistrationOwners  = @()
        HasOwners = $true
        HasServicePrincipalOwners = $true
        HasAppRegistrationOwners  = $false
        OwnershipGap = $true
        AssignmentRequired = $false
        IsEnabled = $true
        IsVerifiedPublisher = $false
        VerifiedPublisherName = ""
        TotalPermissions = 5
        ApplicationPermissions = 1
        DelegatedPermissions = 2
        DirectoryRoles = 2
        Permissions = @(
            (New-Perm "Application" "Application.ReadWrite.All" "Microsoft Graph"),
            (New-Perm "Delegated"   "Directory.ReadWrite.All"   "Microsoft Graph" -ConsentType "Admin Consent" -UserCount "All Users"),
            (New-Perm "Delegated"   "Mail.Read"                 "Microsoft Graph" -ConsentType "User Consent" -UserCount 1),
            (New-Perm "Delegated"   "Mail.Read"                 "Microsoft Graph" -ConsentType "User Consent" -UserCount 1),
            (New-Perm "Directory Role" "Global Administrator" "Entra ID"),
            (New-Perm "Directory Role" "Reports Reader"        "Entra ID")
        )
        HasActiveCredentials = $true
        ActiveCertificates = 0
        ActiveSecrets = 3
        ExpiringCredentials = 1
        ExpiredCredentials = 0
        ActiveCertificateList = @()
        ActiveSecretList = @(
            (New-Cred "Sync Secret 1" -400 800 "key-9991"),
            (New-Cred "Sync Secret 2" -300 20  "key-9992"),
            (New-Cred "Sync Secret 3" -100 500 "key-9993")
        )
        RiskScore = 144
        RiskLevel = "Critical"
        RiskFactors = @(
            [PSCustomObject]@{ Text = "High-risk permission: Directory.ReadWrite.All"; Points = 15; Permission = "Directory.ReadWrite.All" },
            [PSCustomObject]@{ Text = "Medium-risk permission: Mail.Read"; Points = 5; Permission = "Mail.Read" },
            [PSCustomObject]@{ Text = "Has application permissions"; Points = 5 },
            [PSCustomObject]@{ Text = "High-risk directory role: Global Administrator"; Points = 15; Role = "Global Administrator" },
            [PSCustomObject]@{ Text = "Directory role: Reports Reader"; Points = 5; Role = "Reports Reader" },
            [PSCustomObject]@{ Text = "Suspicious name contains: test, legacy, sync"; Points = 2 },
            [PSCustomObject]@{ Text = "Sensitive permission granted via Admin Consent, tenant-wide (all users exposed)"; Points = 5 },
            [PSCustomObject]@{ Text = "Sensitive permission granted via User Consent, no admin review (governance blind spot)"; Points = 3 },
            [PSCustomObject]@{ Text = "No owners assigned (neither Service Principal nor App Registration)"; Points = 4 },
            [PSCustomObject]@{ Text = "No Service Principal owners (only App Registration owners)"; Points = 2 },
            [PSCustomObject]@{ Text = "No App Registration owners (only Service Principal owners)"; Points = 2 },
            [PSCustomObject]@{ Text = "Ownership gap - owners differ between Service Principal and App Registration"; Points = 1 },
            [PSCustomObject]@{ Text = "Assignment not required for high-value app"; Points = 50; Detail = "Rarely needed by users and a frequent abuse target. Lock it down with Assignment Required option"; Url = "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/application-properties#assignment-required" },
            [PSCustomObject]@{ Text = "Assignment not required"; Points = 5; Url = "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/application-properties#assignment-required" },
            [PSCustomObject]@{ Text = "Uses password secrets (certificates preferred)"; Points = 5; Detail = "Microsoft recommends that you use a certificate instead of a client secret before moving the application to a production environment." },
            [PSCustomObject]@{ Text = "Multiple secrets configured (3) - reduces auditability"; Points = 5 },
            [PSCustomObject]@{ Text = "Long-lived credentials (expiry > 1 year)"; Points = 5 },
            [PSCustomObject]@{ Text = "External application registered in another tenant"; Points = 5 },
            [PSCustomObject]@{ Text = "External application has no verified publisher"; Points = 5; Url = "https://learn.microsoft.com/en-us/entra/identity-platform/publisher-verification-overview" }
        )
    }
)

# ---------------------------------------------------------------------------
# Compute summary statistics (mirrors Get-EntraIDAppReport.ps1)
# ---------------------------------------------------------------------------
$totalApps             = @($report).Count
$criticalRiskApps      = @($report | Where-Object { $_.RiskLevel -eq "Critical" }).Count
$highRiskApps          = @($report | Where-Object { $_.RiskLevel -eq "High" }).Count
$mediumRiskApps        = @($report | Where-Object { $_.RiskLevel -eq "Medium" }).Count
$lowRiskApps           = @($report | Where-Object { $_.RiskLevel -eq "Low" }).Count
$internalApps          = @($report | Where-Object { $_.AppOwnerOrganizationId -eq $tenantId }).Count
$microsoftApps         = @($report | Where-Object { $_.AppOwnerOrganizationId -in $script:MicrosoftTenantIds }).Count
$externalApps          = @($report | Where-Object { $_.AppOwnerOrganizationId -ne $tenantId -and $_.AppOwnerOrganizationId -notin $script:MicrosoftTenantIds }).Count
$appsWithUnverifiedPublisher = @($report | Where-Object { $_.AppOwnerOrganizationId -ne $tenantId -and $_.AppOwnerOrganizationId -notin $script:MicrosoftTenantIds -and $_.IsVerifiedPublisher -eq $false }).Count
$appsWithOwnershipGaps = @($report | Where-Object { $_.OwnershipGap -eq $true }).Count
$appsWithExpiringCredentials = @($report | Where-Object { $_.ExpiringCredentials -gt 0 }).Count
$appsWithOpenAccess    = @($report | Where-Object { $_.AssignmentRequired -eq $false }).Count
$disabledApps          = @($report | Where-Object { $_.IsEnabled -eq $false }).Count

# ---------------------------------------------------------------------------
# Extract the rendering block from the main script and run it against mock data
# ---------------------------------------------------------------------------
$mainScript = Join-Path $PSScriptRoot "Get-EntraIDAppReport.ps1"
if (-not (Test-Path $mainScript)) {
    Write-Error "Cannot find Get-EntraIDAppReport.ps1 next to this script."
    exit 1
}

$lines = Get-Content -LiteralPath $mainScript
$startIdx = ($lines | Select-String -SimpleMatch '$logoSvg = ' | Select-Object -First 1).LineNumber
$endMatch = ($lines | Select-String -SimpleMatch '# Save the HTML report' | Select-Object -First 1).LineNumber
if (-not $startIdx -or -not $endMatch) {
    Write-Error "Could not locate the rendering block markers in the main script."
    exit 1
}

# LineNumber is 1-based; take from the $logoSvg line up to the line before the save comment
$renderBlock = ($lines[($startIdx - 1)..($endMatch - 2)]) -join "`n"

# Execute the extracted block; it builds $html using the mock variables above
. ([ScriptBlock]::Create($renderBlock))

# ---------------------------------------------------------------------------
# Write and (optionally) open the dummy report
# ---------------------------------------------------------------------------
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path (Get-Location).Path $OutputPath
}
[System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))
Write-Host "Dummy report generated: $OutputPath" -ForegroundColor Green

if (-not $NoLaunch) {
    Start-Process ([System.IO.Path]::GetFullPath($OutputPath))
}
