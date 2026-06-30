# Entra ID App Report

Generates an interactive, self-contained HTML security report for all Enterprise Applications (Service Principals) in a Microsoft Entra ID tenant. Designed for security reviews, governance audits, and weekly automated reporting via Azure DevOps.

## What it does

The script connects to Microsoft Graph, retrieves every Enterprise Application registered or consented to in the tenant, and analyses each one across several dimensions:

- **Permissions**: application permissions (app roles) and delegated permissions (OAuth2 grants), including the resource they are granted against
- **Directory roles**: Entra ID directory roles assigned directly to the service principal
- **Ownership**: owners on both the Service Principal and its backing App Registration, with gap detection when the two ownership sets diverge
- **Credentials**: secrets and certificates on the App Registration, including expiry, type (secret vs certificate), and long-lived credential detection
- **Risk scoring**: a weighted score per app based on the above signals, producing a Critical / High / Medium / Low classification
- **Governance signals**: whether assignment is required, whether the app is enabled or disabled, whether it is internal, Microsoft-owned, or third-party

The output is a single `.html` file that works offline with no external dependencies and no server required.

## Report features

| Feature | Detail |
|---------|--------|
| Summary cards | Clickable cards for risk levels, ownership, registration type, and assignment, each filtering the table |
| Search | Real-time text search across application names |
| Filter panel | Multi-dimensional filter tags for ownership, risk, credentials, permissions, assignment, and enabled state |
| Column sort | Click any sortable column header to sort ascending; click again to reverse |
| Export CSV | Downloads the currently visible (filtered) rows as a `.csv` file, UTF-8 with BOM for correct Excel rendering |
| Dark / light mode | Toggle persisted to `localStorage` |
| Portal deep links | Application name links directly to the Entra portal entry for that app |
| Risk factors | Expandable per-app list of every signal that contributed to the risk score |

## Example

![Entra ID App Report example screenshot](EntraIDAppReport_Example.png)

## Prerequisites

### PowerShell version

PowerShell 5.1 or PowerShell 7+. Both are supported; the script is tested on both.

### Microsoft Graph modules

The following modules are required at version 2.0.0 or later:

```powershell
@(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Users'
) | ForEach-Object {
    Install-Module -Name $_ -MinimumVersion '2.0.0' -Scope CurrentUser -AllowClobber
}
```

Or install the full umbrella module:

```powershell
Install-Module -Name Microsoft.Graph -MinimumVersion '2.0.0' -Scope CurrentUser -AllowClobber
```

### Entra ID permissions

The identity used to run the script (user, service principal, or managed identity) needs the following **Microsoft Graph application permissions** with admin consent:

| Permission | Purpose |
|------------|---------|
| `Application.Read.All` | Read service principals and app registrations |
| `Directory.Read.All` | Read directory objects and owners |
| `DelegatedPermissionGrant.Read.All` | Read OAuth2 delegated permission grants |
| `RoleManagement.Read.Directory` | Read directory role assignments |

For **interactive (user) runs**, these are requested as delegated scopes during the sign-in browser prompt.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OutputPath` | String | Auto-generated | Path for the HTML report. Defaults to `EntraIDReport_{TenantName}_{Date}.html` in the current directory. |
| `-TenantId` | String | None | Entra ID tenant ID. Required for Service Principal authentication. Used when targeting a specific tenant. |
| `-AccessToken` | SecureString | None | Pre-acquired Microsoft Graph token. Used in Azure DevOps pipelines via `Get-AzAccessToken`. |
| `-ClientId` | String | None | App (client) ID for Service Principal authentication. Must be combined with `-CertificateThumbprint` and `-TenantId`. |
| `-CertificateThumbprint` | String | None | Certificate thumbprint for Service Principal authentication. |
| `-UseManagedIdentity` | Switch | None | Authenticate using the Managed Identity of the hosting environment (Azure VM, Function, DevOps hosted agent). |
| `-NonInteractive` | Switch | None | Suppress all prompts and skip automatic browser launch. Required for unattended or pipeline runs. |
| `-OnlyWithPermissions` | Switch | None | Include only apps that have at least one permission (delegated, application, or directory role). |
| `-MinimumPermissions` | Int | `0` | Include only apps with a total permission count at or above this threshold. |
| `-RiskConfigPath` | String | None | Path to a JSON file that overrides the built-in risk scoring rules. See [Custom risk configuration](#custom-risk-configuration). |
| `-OnlyWithAppRegistrations` | Switch | None | Include only apps that have a corresponding App Registration in this tenant. Mutually exclusive with `-OnlyServicePrincipals`. |
| `-OnlyServicePrincipals` | Switch | None | Include only service principals without an App Registration (gallery apps, legacy apps). Mutually exclusive with `-OnlyWithAppRegistrations`. |
| `-DryRun` | Switch | None | Run the full analysis but skip writing the report to disk and skip opening the browser. Useful for testing auth and parameters. |

## Manual usage

### Interactive sign-in (default tenant)

```powershell
.\Get-EntraIDAppReport.ps1
```

A browser window opens for Microsoft sign-in. The report is saved to the current directory and opened automatically when complete.

### Interactive sign-in for a specific tenant

Use this when you need to target a specific Entra ID tenant:

```powershell
.\Get-EntraIDAppReport.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

The sign-in prompt will target the specified tenant.

### Service Principal with certificate

```powershell
.\Get-EntraIDAppReport.ps1 `
    -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ClientId "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
    -CertificateThumbprint "ABCDEF1234567890ABCDEF1234567890ABCDEF12" `
    -NonInteractive `
    -OutputPath "C:\Reports\EntraReport.html"
```

The certificate must be installed in the current user's or local machine's certificate store.

### Managed Identity

```powershell
.\Get-EntraIDAppReport.ps1 -UseManagedIdentity -NonInteractive -OutputPath ".\report.html"
```

### Filter to high-signal apps only

```powershell
# Only apps that have at least one permission
.\Get-EntraIDAppReport.ps1 -OnlyWithPermissions

# Only apps with 5 or more permissions
.\Get-EntraIDAppReport.ps1 -MinimumPermissions 5

# Only apps that have an App Registration in this tenant
.\Get-EntraIDAppReport.ps1 -OnlyWithAppRegistrations
```

### Dry run (validate auth without writing a file)

```powershell
.\Get-EntraIDAppReport.ps1 -DryRun -Verbose
```

## Risk scoring

Every app receives a numeric risk score. The score drives the **Critical / High / Medium / Low** classification shown in the report.

### Thresholds

| Level | Score range |
|-------|-------------|
| Low | 0 to 9 |
| Medium | 10 to 19 |
| High | 20 to 29 |
| Critical | 30 and above |

### Scoring factors

| Signal | Points |
|--------|--------|
| Each unique high-risk permission (e.g. `Directory.ReadWrite.All`, `User.ReadWrite.All`) | +10 |
| Each unique medium-risk permission (e.g. `Directory.Read.All`, `Mail.Send`) | +5 |
| Has any application permissions (bonus, counted once) | +5 |
| Each unique high-risk directory role (e.g. Global Administrator, Security Administrator) | +15 |
| Each other directory role | +8 |
| Suspicious keyword in display name (e.g. `test`, `admin`, `temp`, `legacy`) | +5 |
| Sensitive permissions assigned to all users | +5 |
| Sensitive permissions affecting more than 50 users | +3 |
| No active credentials on an app with an App Registration | +4 |
| No owners on either Service Principal or App Registration | +5 |
| No Service Principal owners (App Registration owners only) | +3 |
| No App Registration owners (Service Principal owners only) | +2 |
| Ownership gap (SP and App Reg owner sets differ) | +2 |
| Assignment not required (open access) | +4 |
| Uses password secrets instead of certificates | +5 |
| Multiple secrets configured | +2 |
| Long-lived credentials (expiry > 1 year) | +3 |
| External application (registered in another tenant, not Microsoft) | +5 |

### Disabled app adjustment

If an app is disabled (`AccountEnabled = false`), its raw score is multiplied by **0.3** (rounded up). Disabled apps cannot be exploited while disabled, so they are de-prioritised without being completely hidden.

## Custom risk configuration

You can override the built-in permission lists, role lists, and suspicious keywords by supplying a JSON file:

```powershell
.\Get-EntraIDAppReport.ps1 -RiskConfigPath ".\my-risk-config.json"
```

The file must be valid JSON with all four required keys:

```json
{
    "HighRiskPermissions": [
        "Directory.ReadWrite.All",
        "User.ReadWrite.All"
    ],
    "MediumRiskPermissions": [
        "Directory.Read.All",
        "User.Read.All"
    ],
    "HighRiskDirectoryRoles": [
        "Global Administrator",
        "Security Administrator"
    ],
    "SuspiciousKeywords": [
        "test", "temp", "legacy", "admin"
    ]
}
```

If the file is missing any of the four keys, the script falls back to the built-in defaults and logs a warning. The file must exist at the path provided; the parameter validates this at startup.

## Azure DevOps pipeline

The included `azure-pipelines.yml` automates weekly report generation using a federated Azure service connection. No secrets or passwords are stored in ADO.

### How it works

1. The pipeline runs on a schedule (every Monday at 06:00 UTC) and on every push to `main`.
2. The `AzurePowerShell@5` task authenticates using the ADO service connection (`azureSubscription`). The service connection uses **Workload Identity Federation**. The Azure service principal behind it is granted the required Graph permissions.
3. The task obtains a Graph access token from the authenticated Az context and passes it to the script via `-AccessToken`.
4. The HTML report is saved to `$(Build.ArtifactStagingDirectory)` and published as a pipeline artifact named `EntraIDAppReport`.

### Setup steps

**1. Create an Azure service connection in ADO**

In your ADO project: **Project Settings → Service Connections → New service connection → Azure Resource Manager**.

Select **Workload Identity Federation** as the authentication method. The connection does not need any Azure subscription role. It only needs Entra ID Graph permissions.

**2. Grant the service principal Graph permissions**

Find the service principal created for your service connection in Entra ID (**App registrations** or **Enterprise applications**) and add these **Application permissions** with admin consent:

- `Application.Read.All`
- `Directory.Read.All`
- `DelegatedPermissionGrant.Read.All`
- `RoleManagement.Read.Directory`

**3. Update the pipeline file**

Edit `azure-pipelines.yml` and set `azureSubscription` to the name of your service connection:

```yaml
azureSubscription: "Your-Service-Connection-Name"
```

**4. Run or schedule**

Push to `main` to trigger immediately, or let the Monday schedule run automatically. The report artifact is available under the pipeline run's **Artifacts** tab.

### Schedule

```yaml
schedules:
  - cron: "0 6 * * 1"   # Every Monday at 06:00 UTC
    always: true          # Run even if no code changes
```

To change the schedule, update the `cron` expression. To disable the schedule and run on push only, remove the `schedules` block.

### Pipeline output

The artifact `EntraIDAppReport` contains:

```
EntraIDReport_YYYY-MM-DD.html
```

Download the artifact from the pipeline run, open the HTML file in any browser. No internet connection is required.

## File reference

| File | Purpose |
|------|---------|
| `Get-EntraIDAppReport.ps1` | Main script |
| `azure-pipelines.yml` | Azure DevOps pipeline definition |

## Author

[Matej Klemencic](https://www.matej.guru)
