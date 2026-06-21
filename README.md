# EntraID-AppReport

> **PowerShell script that generates an interactive HTML security report for Microsoft Entra ID Enterprise Applications.**

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-SDK%20v2-0078d4?logo=microsoft)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 📋 Overview

`Get-EntraIDAppReport.ps1` connects to Microsoft Graph, retrieves all Enterprise Applications (Service Principals) in your Entra ID tenant, analyzes their permissions, credentials and ownership, calculates a risk score for each app and outputs a fully self-contained, interactive HTML report.

The report includes:

- 🔴 **Risk scoring** — Critical / High / Medium / Low with per-app risk factor breakdown
- 🔑 **Credential tracking** — active secrets and certificates, expiry warnings (30-day window), long-lived credential detection
- 👥 **Ownership analysis** — owner counts across both Service Principal and App Registration, ownership gap detection
- 🔐 **Permission analysis** — Application, Delegated and Directory Role permissions with links to [Graph Permissions Explorer](https://graphpermissions.merill.net)
- 🏷️ **App classification** — Internal, Microsoft, and Third-Party with deep links to the Entra portal
- 🔍 **Interactive filtering** — filter by risk level, ownership, credentials, permissions, enabled status and more
- 🌙 **Dark mode** support

---

## 📸 Screenshots

> *TBA*

---

## ⚙️ Requirements

### PowerShell
- PowerShell 5.1 or PowerShell 7+

### Microsoft Graph Modules

Install the required modules (only the ones needed — faster than the full umbrella):

```powershell
Install-Module -Name Microsoft.Graph.Authentication,
  Microsoft.Graph.Applications,
  Microsoft.Graph.Identity.DirectoryManagement,
  Microsoft.Graph.Users `
  -Scope CurrentUser -AllowClobber
```

Or install the full umbrella module:

```powershell
Install-Module -Name Microsoft.Graph -Scope CurrentUser -AllowClobber
```

### Required Permissions

The account or service principal running the script needs these **read-only** permissions:

| Permission | Type | Purpose |
|---|---|---|
| `Application.Read.All` | Application | Read service principals and app registrations |
| `Directory.Read.All` | Application | Read owners and tenant information |
| `DelegatedPermissionGrant.Read.All` | Application | Read OAuth2 delegated permission grants |
| `RoleManagement.Read.Directory` | Application | Read directory role assignments |

For **interactive runs**, Delegated permissions are sufficient. For **pipeline/unattended runs**, Application permissions with admin consent are required.

---

## 🚀 Usage

### Interactive (local run)

```powershell
# Basic — connects to your default tenant
.\Get-EntraIDAppReport.ps1

# Specific tenant
.\Get-EntraIDAppReport.ps1 -TenantId "your-tenant-id"

# Custom output path
.\Get-EntraIDAppReport.ps1 -OutputPath "C:\Reports\MyReport.html"

# Only apps with at least one permission
.\Get-EntraIDAppReport.ps1 -OnlyWithPermissions

# Only apps with at least 5 permissions
.\Get-EntraIDAppReport.ps1 -MinimumPermissions 5

# Only apps that have an App Registration in this tenant
.\Get-EntraIDAppReport.ps1 -OnlyWithAppRegistrations

# Verbose logging
.\Get-EntraIDAppReport.ps1 -Verbose
```

The report is saved as `EntraIDReport_{TenantName}_{Date}.html` by default and opens automatically in your browser.

---

## 📊 Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | String | Auto-generated | Path to save the HTML report. Defaults to `EntraIDReport_{TenantName}_{Date}.html` |
| `-TenantId` | String | — | Entra ID tenant ID. Required for Service Principal auth. Optional for interactive. |
| `-AccessToken` | SecureString | — | Pre-acquired Graph access token. Use with `AzurePowerShell@5` pipelines. |
| `-ClientId` | String | — | App (client) ID for Service Principal authentication. |
| `-ClientSecret` | String | — | Client secret for Service Principal authentication. |
| `-CertificateThumbprint` | String | — | Certificate thumbprint for Service Principal authentication (recommended over secret). |
| `-UseManagedIdentity` | Switch | — | Use Azure Managed Identity (for Azure-hosted agents or VMs). |
| `-NonInteractive` | Switch | — | Suppress all prompts and browser launch. Required for pipelines. |
| `-OnlyWithPermissions` | Switch | — | Include only apps with at least one permission. |
| `-MinimumPermissions` | Int | `0` | Include only apps with at least this many permissions. |
| `-OnlyWithAppRegistrations` | Switch | — | Include only apps with a linked App Registration in this tenant. |
| `-OnlyServicePrincipals` | Switch | — | Include only service principals with no App Registration. |
| `-RiskConfigPath` | String | — | Path to a JSON file with custom risk scoring rules. |
| `-Verbose` | Switch | — | Enable verbose logging. |

---

## 🏗️ Azure DevOps Integration

The script is built for unattended pipeline runs. The recommended approach uses an **Azure service connection** (`azureSubscription`) — no secrets stored in ADO variables.

### Prerequisites

1. **Create an Azure service connection** in ADO pointing to your Entra ID tenant.

2. **Grant the service principal** behind the connection these Entra ID **Application permissions** (admin consent required):
   - `Application.Read.All`
   - `Directory.Read.All`
   - `DelegatedPermissionGrant.Read.All`
   - `RoleManagement.Read.Directory`

3. **Add the pipeline file** (`azure-pipelines.yml`) to your repository and update `azureSubscription` to match your service connection name.

### Pipeline YAML

A ready-to-use pipeline file is included: [`azure-pipelines.yml`](azure-pipelines.yml)

The pipeline:
- Runs on a schedule (weekly by default — adjust the cron as needed)
- Installs Graph modules on the agent
- Acquires a Graph token from the Az service connection context
- Runs the report script with `-NonInteractive`
- Publishes the HTML report as a pipeline artifact

```yaml
steps:
  - task: AzurePowerShell@5
    displayName: "Generate Entra ID App Report"
    inputs:
      azureSubscription: "YOUR-SERVICE-CONNECTION-NAME"
      pwsh: true
      azurePowerShellVersion: LatestVersion
      ScriptType: InlineScript
      Inline: |
        Install-Module Microsoft.Graph.Authentication,Microsoft.Graph.Applications,
          Microsoft.Graph.Identity.DirectoryManagement,Microsoft.Graph.Users `
          -Force -AllowClobber -Scope CurrentUser

        $rawToken = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
        $graphToken = if ($rawToken -is [System.Security.SecureString]) {
            $rawToken
        } else {
            ConvertTo-SecureString $rawToken -AsPlainText -Force
        }

        .\Get-EntraIDAppReport.ps1 `
          -AccessToken $graphToken `
          -NonInteractive `
          -OutputPath "$(Build.ArtifactStagingDirectory)/EntraIDReport_$(Get-Date -Format 'yyyy-MM-dd').html"

  - publish: $(Build.ArtifactStagingDirectory)
    artifact: EntraIDAppReport
    condition: always()
```

### Alternative: Service Principal with Certificate

If you prefer direct SP authentication without an Azure service connection:

```powershell
.\Get-EntraIDAppReport.ps1 `
  -TenantId "your-tenant-id" `
  -ClientId "your-app-id" `
  -CertificateThumbprint "your-cert-thumbprint" `
  -NonInteractive `
  -OutputPath "report.html"
```

### Alternative: Managed Identity

For Azure-hosted agents or VMs with a Managed Identity:

```powershell
.\Get-EntraIDAppReport.ps1 -UseManagedIdentity -NonInteractive -OutputPath "report.html"
```

---

## 🎯 Risk Scoring

Each application receives a risk score based on weighted factors. The score maps to a risk level:

| Score | Level |
|---|---|
| ≥ 30 | 🔴 Critical |
| ≥ 20 | 🟠 High |
| ≥ 10 | 🟡 Medium |
| < 10 | 🟢 Low |

### Risk Factors

| Factor | Points |
|---|---|
| High-risk permission (e.g. `Directory.ReadWrite.All`) | +10 per unique permission |
| Medium-risk permission (e.g. `Directory.Read.All`) | +5 per unique permission |
| Has Application permissions | +5 (once) |
| High-risk directory role (e.g. Global Administrator) | +15 per role |
| Other directory role | +8 per role |
| No owners assigned | +5 |
| No Service Principal owners (only App Reg owners) | +3 |
| No App Registration owners (only SP owners) | +2 |
| Ownership gap (SP vs App Reg owners differ) | +2 |
| Assignment not required (open access) | +4 |
| Uses password secrets instead of certificates | +5 |
| Multiple secrets configured | +2 |
| Long-lived credentials (expiry > 1 year) | +3 |
| No active credentials (app has App Registration) | +4 |
| External / third-party application | +5 |
| Sensitive permissions + all-users access | +5 |
| Suspicious name keywords | +5 |

### Custom Risk Configuration

Override the default risk rules by providing a JSON file:

```powershell
.\Get-EntraIDAppReport.ps1 -RiskConfigPath "my-risk-config.json"
```

Example JSON structure:
```json
{
  "HighRiskPermissions": ["Directory.ReadWrite.All", "User.ReadWrite.All"],
  "MediumRiskPermissions": ["Directory.Read.All", "User.Read.All"],
  "HighRiskDirectoryRoles": ["Global Administrator", "Security Administrator"],
  "SuspiciousKeywords": ["test", "temp", "legacy", "backup"]
}
```

---

## 🏷️ App Classification

Apps are classified into three ownership types:

| Type | Description |
|---|---|
| 🟢 **Internal** | App registered in your own tenant |
| 🔵 **Microsoft** | First-party Microsoft service (Microsoft Corporation or Microsoft Services tenant) |
| 🔴 **Third-Party** | App registered in another organization's tenant |

> **Note:** Microsoft-owned apps are excluded from the external-app risk penalty since they are trusted first-party services.

---

## 🔍 Excluded Applications

The following internal Microsoft platform services are excluded from the report to reduce noise:

| App | App ID |
|---|---|
| Microsoft Graph | `00000003-0000-0000-c000-000000000000` |
| Office 365 Exchange Online | `00000002-0000-0ff1-ce00-000000000000` |
| Office 365 SharePoint Online | `00000003-0000-0ff1-ce00-000000000000` |
| Office 365 Management APIs | `c5393580-f805-4401-95e8-94b7a6ef2fc2` |
| Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
| Microsoft Graph PowerShell | `09abbdfd-ed23-44ee-a2d9-a627aa1c90f3` |
| Azure Active Directory PowerShell | `1b730954-1685-4b74-9bfd-dac224a7b894` |
| Microsoft Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` |
| Windows Azure Service Management API | `797f4846-ba00-4fd7-ba43-dac1f8f63013` |

---

## 📁 Repository Structure

```
EntraID-AppReport/
├── Get-EntraIDAppReport.ps1     # Main script
├── azure-pipelines.yml          # Azure DevOps pipeline
├── Enterprise Applications.svg  # Logo used in the HTML report
└── README.md
```

---

## 🤝 Contributing

Contributions, issues and feature requests are welcome. Please open an issue before submitting a pull request.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ✍️ Author

**Matej Klemencic** — [www.matej.guru](https://www.matej.guru)

Found this tool helpful? Subscribe to the blog for more Microsoft 365 and Entra ID content.
