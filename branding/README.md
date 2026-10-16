# LeafIT Brand And Naming Runbook

[The root quick start](../README.md) owns prerequisites, licensing, private target inputs and the supported publication scope. This guide owns artwork, naming behavior, permission details and recovery. It contains no tenant inventory or deployment record.

## Brand Source

[brand.json](brand.json) owns the LeafIT name, descriptor, palette and typography. [Build.ps1](Build.ps1) creates the reviewed artwork using the bundled, checksum-pinned Source Sans 3 font and Windows System.Drawing; it does not install fonts globally or contact a tenant. Preserve [the font redistribution notice](source/OFL.txt).

```powershell
& ./branding/Build.ps1
& ./branding/Build.ps1 -CheckOnly
```

| Surface | Exports |
| --- | --- |
| Entra | [Banner](exports/entra/banner.png), light/dark square logos, favicon and background under `exports/entra/` |
| Company Portal | Light/theme logos and brand image under `exports/intune/` |
| Microsoft 365 | Light/dark artwork under `exports/microsoft-365/`; publishing the organization theme is not implemented |
| Collaboration | Avatar and meeting background under `exports/collaboration/`; no global avatar/cache rewrite |
| Windows/collateral | Wallpaper, logos and letterhead; no device delivery or endpoint policy writer in this publication |

The offline build checks source hashes, contrast, image dimensions/size limits, nonblank imagery and SVG self-containment. Same-environment repeated asset builds are byte-identical; cross-platform raster equivalence and real service crops are not promised. Asset approval does not authorize tenant writes, public image hosting or licensing changes.

## One Naming Entry Point

[Deploy.ps1](Deploy.ps1) runs the existing feature owners and records one minimized combined result under ignored `private/branding/`. Preview is the default. It neither creates permissions nor schedules hostnames unless the corresponding explicit bootstrap/scheduling option is selected.

```powershell
& ./branding/Deploy.ps1 -CheckOnly
& ./branding/Deploy.ps1
& ./branding/Deploy.ps1 -Apply
& ./branding/Deploy.ps1 -Apply
```

For an authorized new target, `-Bootstrap -Apply` adds the documented naming app/grants and a current-user nonexportable certificate, captures the current source organization name privately when absent, and uses certificate authentication afterward. A new execution account or expired/missing local key requires authorized bootstrap. It does not recover identities, mailbox data, passwords/MFA, device enrollment or client sessions.

`TARGET_DNS_ZONE_NAME` is the custom sign-in/email domain. Preserve the original `.onmicrosoft.com` domain and its routing addresses. A new native-domain prefix or SharePoint maintenance window is not a prerequisite for moving mail/sign-in addresses to the custom domain. With no separately selected hostname migration, SharePoint reports `NotRequested` and keeps its native URLs.

The combined status remains `IncompleteWithExplicitBlockers` for a read-only organization-name mismatch, a failed owner, explicitly selected but unready hostname migration, or an unimplemented surface. A supported owner's `NoChange` does not mean all requested service surfaces or a clean tenant are verified. Read the per-surface result, not only whether PowerShell returned without an exception.

## Automated Permissions

[permissions.json](permissions.json) is the reviewed definition; [Initialize-Session.ps1](Initialize-Session.ps1) owns preview, approved bootstrap and certificate authentication. It resolves the current target, rejects duplicate/unmanaged same-name apps, adds only missing grants/roles, preserves unrelated public keys and grants, and verifies readback. The RSA/CSP private key stays in the Windows current-user store; only client ID/thumbprint references go into ignored `.env`. No client secret or PFX export is created.

| Service | Grant | Purpose And Scope |
| --- | --- | --- |
| Graph organization | `Organization.ReadWrite.All` | Sign-in branding and organization readback. The organization display name remains service-read-only despite the generated SDK parameter. |
| Graph groups | `Group.ReadWrite.All` | Supported metadata writes and membership/owner preservation reads; code never writes group membership. |
| Graph discovery | `Application.Read.All`, `Sites.ReadWrite.All` | Dependency/site reads and supported collaboration operations; not permission to rewrite arbitrary content. |
| Graph Intune | `DeviceManagementServiceConfig.ReadWrite.All` | Target Company Portal customization/readback; no policy, enrollment, assignment or device writer is selected. |
| Exchange | `Exchange.ManageAsApp` and **Exchange Recipient Administrator** | Native certificate-authenticated group recipient management. Technically broad recipient capability; the writer is scoped to reviewed cloud Unified groups. |
| SharePoint | Native SharePoint `Sites.FullControl.All` and **SharePoint Administrator** | Native site/tenant inventory, title management and separately selected hostname operations; tenant-wide capabilities, not object-scoped consent. |

The bootstrap operator needs documented delegated `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All` and `RoleManagement.ReadWrite.Directory` capabilities plus administrator authority and Azure access. The runtime app receives neither `RoleManagement.ReadWrite.Directory` nor `Directory.ReadWrite.All`, no Global Administrator role, and no user-write permission. Existing legacy delegated authority may satisfy the API, but is not newly granted by this workflow. Bootstrap is an explicit change, not a side effect of ordinary preview.

```powershell
& ./branding/Initialize-Session.ps1 -CheckOnly
& ./branding/Initialize-Session.ps1
& ./branding/Initialize-Session.ps1 -Apply
& ./branding/Initialize-Session.ps1 -Connect
```

Sources: [Graph application grants](https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments), [directory role assignments](https://learn.microsoft.com/graph/api/rbacapplication-post-roleassignments), [Exchange certificate authentication and supported roles](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2), and [SharePoint certificate connection](https://learn.microsoft.com/powershell/module/microsoft.online.sharepoint.powershell/connect-sposervice).

## Feature Owners

| Owner | Behavior And Preservation |
| --- | --- |
| [Entra](../identity/entra/Deploy-Branding.ps1) | Default and existing English sign-in text/colors plus six image streams, with byte-hash readback. Other locales/unrelated properties remain. `-NameOnly` verifies the tenant display name without attempting an unsupported write. |
| [Groups](../collaboration/groups/Deploy.ps1) | Literal old-brand metadata replacement and native Exchange primary SMTP/alias coordination. Preserve IDs, old SMTP/MOERA and non-SMTP addresses, memberships, owners, group type/security/visibility and rules. `-NamesOnly` excludes mail. |
| [Exchange session](../collaboration/exchange/Initialize-Session.ps1) | Reuses verified connections or the naming certificate; validates native tenant and authoritative accepted domain. Records whether organization-config or native-connection/domain readback was used. Explicit interactive Edge Beta sign-in remains available, never a hidden fallback. |
| [Company Portal](../endpoint/intune/Deploy-Branding.ps1) | Existing-profile name-only beta updates, complete unrelated-setting comparison and sorted assignment comparison. No policy/device action or assignment write. |
| [SharePoint](../collaboration/sharepoint/Deploy.ps1) | Pinned native module, exact-path compatibility import and certificate resolution inside that process. Discover sites/OneDrives; replace literal old-brand titles, preserving URL/group/template/lock state. No arbitrary page/document/app URL rewrite. |
| [Subscription label](../infra/Set-SubscriptionName.ps1) | Replace literal brand text in the existing label through the documented native rename operation, preserving ID, tenant, state and policies. `-VerifyOnly` checks pending readback without repeating a write. |

Source-brand input is private and literal, not a regex or a tenant-wide replacement engine. Missing or ambiguous ownership, address collisions, synchronization, role-assignable mail groups and concurrent changes stop the affected owner. Resource accounts and the protected administrator are excluded. Native clients may take time to show cosmetic updates; API readback is not interactive-client acceptance.

## Company Portal Recovery

The beta endpoint can reset `showConfigurationManagerApps`, `showDisplayNameNextToLogo` and `companyPortalBlockedActions` when omitted. The writer carries their exact old values with the name update and checks every other field. Do not resubmit unrelated image/default-profile objects or relax preservation to force success. This entity is not exposed by current service metadata, so current schema/readback tests remain important.

A private `branding-preservation-stop.json` blocks applies until reviewed recovery. Retain the original profile and assignment proof; do not accept a fresh baseline or silently delete the stop. After explicit operator approval:

```powershell
& ./endpoint/intune/Deploy-Branding.ps1 -ResumeVerifiedStop
& ./endpoint/intune/Deploy-Branding.ps1 -Apply
& ./endpoint/intune/Deploy-Branding.ps1 -Apply
```

Resume reads the target and original proof only, checks restored fields/names/assignments, and marks the retained record `ResolvedAfterReadback`. Missing proof fails closed. Assignment verification serializes explicit arrays, including `[]`, and detects missing/changed targets. Repeated apply must be NoChange. A failure is not a transactional rollback; inspect the exact owned fields before resuming.

## Optional Employee Migration

[The persona definition](../identity/users/desired.json) contains approved fictional alias keys. [The separate user deployer](../identity/users/Deploy.ps1) requires ready unique licensed cloud users and cloud-owned user mailboxes. It performs a pilot before any pending bulk write, preserves SMTP aliases, licenses/roles and protected-admin identity, and supports distinct client-tested versus explicitly risk-accepted acknowledgement. Real sign-in, Outlook, Teams, OneDrive/mobile and admin acceptance are not inferred from API success. The naming app has no user-write permission: use a separately authorized correct-target operator session for this optional workflow.

## Remaining Limits

Graph rejects `organization.displayName` as read-only. A mismatch is reported automatically; the supported Entra properties UI remains necessary to change it. Do not request broader directory privileges, use retired Azure AD Graph, or invoke an undocumented portal endpoint to conceal the limitation.

SharePoint hostname migration is not part of normal custom-domain naming. If explicitly selected later, reviewed private `TARGET_SHAREPOINT_DOMAIN_PREFIX` and timezone-explicit `TARGET_SHAREPOINT_RENAME_AT` inputs are needed, along with a verified destination native domain, native eligibility/dependency review and maintenance approval. No prefix/window is guessed. Native WhatIf is not full eligibility, client or recovery acceptance. Only `-Apply -ScheduleHostnameRename` submits a job; intent is written privately first and prevents blind resubmission. An accepted submission is not authoritative hostname convergence, and changing back is unsupported. No hostname job is part of this publication's normal replay contract.

Microsoft 365 organization themes, arbitrary pages/documents/messages, avatars/signatures, device branding delivery and resource-account conversion are not implemented here. Licensing, persona/mailbox and verified-domain bootstrap, real client acceptance and a second clean tenant remain separate gates. Shared DNS/AD resources and vendor-owned workloads are outside this package.