# LeafIT Naming Automation

Reusable LeafIT artwork and guarded Microsoft cloud naming automation. This publication contains the naming package and its shared dependencies only, not the separate Azure foundation, domain-controller, NMe, or endpoint policy/package workstreams.

**This is not a fully automated tenant rebuild.** Supported naming owners have preview, apply, readback and repeat-run checks. The Entra organization display name is read-only through Microsoft Graph, Microsoft 365 themes/arbitrary content are not implemented, and a second clean tenant has not passed acceptance. Those limits are returned explicitly, never hidden behind a successful owner result.

## Quick Start

Use PowerShell **7.6 on Windows**, Git, Az.Accounts **5.3.3+**, Microsoft.Graph.Authentication **2.37.0+**, ExchangeOnlineManagement **3.9.2+**, and the native Windows certificate cmdlets. Native SharePoint uses Microsoft.Online.SharePoint.PowerShell **16.0.27709.12000**. Install prerequisites for the execution account before running live commands; no script silently installs modules or switches tenants.

```powershell
Install-Module Az.Accounts -MinimumVersion 5.3.3 -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -MinimumVersion 2.37.0 -Scope CurrentUser
Install-Module ExchangeOnlineManagement -MinimumVersion 3.9.2 -Scope CurrentUser
Install-Module Microsoft.Online.SharePoint.PowerShell -RequiredVersion 16.0.27709.12000 -Scope CurrentUser
& ./branding/Deploy.ps1 -CheckOnly
& ./branding/Build.ps1 -CheckOnly
```

Create only local, ignored `.env` inputs using the following placeholder shape. Do not execute the file as a script or publish actual values:

```dotenv
TARGET_TENANT_ID=<target-tenant-guid>
TARGET_SUBSCRIPTION_ID=<target-subscription-guid>
TARGET_DNS_ZONE_NAME=example.com
```

The custom domain must already be owned, verified in Entra, and authoritative in Exchange. Keep each target in its own checkout with separate private inputs/evidence. Never copy an old target's plans, credentials or recovery artifacts into a new one. The native `.onmicrosoft.com` domain and SharePoint URLs remain unless a separate hostname migration is explicitly selected.

Authenticate the authorized bootstrap operator to those private target IDs, without changing saved defaults:

```powershell
. ./identity/Target.ps1
$settings = Read-LeafPrivateTarget $PWD.Path
Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount -Tenant $settings.TARGET_TENANT_ID -Subscription $settings.TARGET_SUBSCRIPTION_ID -UseDeviceAuthentication -Scope Process
Assert-LeafTargetContext $settings (Get-AzContext)
& ./branding/Deploy.ps1 -Bootstrap -Apply
& ./branding/Deploy.ps1
& ./branding/Deploy.ps1 -Apply
& ./branding/Deploy.ps1 -Apply
```

The bootstrap step creates/reuses a dedicated single-tenant naming app, grants only the documented permission definition and service roles, and generates a nonexportable six-month RSA/CSP certificate in the current-user Windows store. It captures the previous organization name privately when absent. Later runs authenticate by certificate without a browser. Another execution account or certificate renewal requires authorized bootstrap, not a copied private key.

The bootstrap operator needs existing application/grant/role-management authority and Azure access to the configured subscription. Azure RBAC and Graph consent are separate prerequisites. Application permission names and their tenant-wide scope are documented in [branding/README.md](branding/README.md#automated-permissions) and defined in [branding/permissions.json](branding/permissions.json). Grant approval is not permission to change licenses, security policies, devices or unrelated objects.

## Coverage

| Owner | Implemented Behavior | Boundary |
| --- | --- | --- |
| [branding/Deploy.ps1](branding/Deploy.ps1) | One preview/apply entry point and private combined outcome | Reports blocked/unsupported surfaces explicitly; not a generic orchestration engine. |
| [identity/entra/Deploy-Branding.ps1](identity/entra/Deploy-Branding.ps1) | Default and English sign-in branding, byte-verified assets, organization-name readback | `-NameOnly` is read-only. A mismatch returns `BlockedReadOnlyOrganizationName`; broader grants cannot make the Graph field writable. |
| [collaboration/groups/Deploy.ps1](collaboration/groups/Deploy.ps1) | Literal group name/description replacement and native Exchange Unified-group SMTP/alias migration | Preserves IDs, old SMTP/MOERA and other address types, membership, owners and unrelated settings. Resource recipients are excluded. |
| [endpoint/intune/Deploy-Branding.ps1](endpoint/intune/Deploy-Branding.ps1) | Company Portal names and exact preserved-setting/assignment checks | Explicit beta API; not an Intune policy, application, enrollment or device deployer. |
| [collaboration/sharepoint/Deploy.ps1](collaboration/sharepoint/Deploy.ps1) | Native site/OneDrive inventory and literal old-brand title replacement | URLs stay unchanged by default. Hostname migration is optional, separately gated and not currently required. |
| [infra/Set-SubscriptionName.ps1](infra/Set-SubscriptionName.ps1) | Cosmetic existing subscription-label replacement and readback | No Azure resource changes; accepted-but-unconverged writes are not blindly resubmitted. |

An `IncompleteWithExplicitBlockers` result is expected while unsupported requested surfaces remain. Individual supported owners must return `NoChange` on repeated apply. This does not prove real Outlook, Teams, OneDrive/mobile behavior, device acceptance, data recovery or a second tenant's readiness.

## Licensing

For eligible commercial knowledge workers within the Business-family seat limit, the narrow sign-in/group/mail/SharePoint baseline is **Microsoft 365 Business Basic (Exchange Online Plan 1, SharePoint Online Plan 1 company-branding entitlement, Microsoft Entra ID Free)**. An enterprise-family alternative is **Office 365 E1 (Exchange Online Plan 1, SharePoint Online Plan 1, Microsoft Entra ID Free)**, not a universally required larger bundle. Company Portal additionally requires **Microsoft Intune Plan 1**, separately or through a qualifying bundle. Verify actual user eligibility, enabled service plans and current terms before use; do not assign or purchase licenses merely to run these scripts. Frontline and education eligibility require their own review.

Sources reviewed 2026-10-15: [Microsoft 365 plan options](https://learn.microsoft.com/office365/servicedescriptions/office-365-platform-service-description/office-365-plan-options), [company-branding entitlements](https://learn.microsoft.com/entra/fundamentals/how-to-customize-branding), and [Intune licensing](https://learn.microsoft.com/intune/fundamentals/licensing). Bootstrap permissions, domain verification and subscription RBAC are not product licenses.

## Safety And Recovery

Actual tenant/subscription IDs, domains, support details and credential references belong only in ignored `.env`. Minimized plans, before-state and readback belong under ignored `private/`. No certificates/private keys, passwords, tokens, raw inventories or tenant operating records belong in Git. Every script checks the private Git boundary and configured target; an unrelated cached session is rejected.

Company Portal's beta PATCH resets three fields when omitted. The writer carries their exact previous values and verifies every other setting and assignment. A preservation stop blocks further applies. After explicit operator review, `& ./endpoint/intune/Deploy-Branding.ps1 -ResumeVerifiedStop` checks the original saved baseline read-only before marking it resolved; it never silently deletes evidence or accepts a new baseline. An interrupted update is not an automatic rollback. Keep current original evidence and inspect the owned fields before resuming.

Existing source-brand text is a literal match, not a whole-tenant search-and-replace. Preserve the protected administrator, retained aliases, original native domain, security settings, licenses and unrelated content. User UPN reversal or a configuration replay does not restore data, device trust, MFA/passwords, OneDrive links or client sessions.

## Optional Employee Migration

[identity/users/desired.json](identity/users/desired.json) contains portable fictional alias keys, not a tenant roster export. [identity/users/Deploy.ps1](identity/users/Deploy.ps1) is a separate pilot/bulk user UPN/company/mail workflow; it is not called by the naming runner. It requires the reviewed personas and cloud mailboxes to exist first, appropriate user/Exchange authority, and either real client acceptance or a separately recorded unverified-client risk decision before pending bulk writes. The naming certificate app deliberately has no user-write permission. Never run an unrelated user session or grant user-write capability as a hidden naming side effect.

## Layout And Checks

The naming runbook and remaining limits are in [branding/README.md](branding/README.md). Artwork is rebuilt with [branding/Build.ps1](branding/Build.ps1); the pinned bundled font and its redistribution notice remain in [branding/source/OFL.txt](branding/source/OFL.txt). Asset generation is offline and does not publish files to a tenant or anonymous hosting.

```powershell
& ./branding/Deploy.ps1 -CheckOnly
& ./branding/Build.ps1 -CheckOnly
& ./identity/users/Deploy.ps1 -CheckOnly
& ./identity/users/Test-Pilot.ps1 -CheckOnly
```

Offline checks use synthetic data and do not read `.env`, request consent, sign in or change a tenant. For a new eligible tenant, additionally prove bootstrap, preview/apply, actual selected client journeys and no-change repeat apply with its own private evidence. Configuration portability is not a verified complete-tenant rebuild.