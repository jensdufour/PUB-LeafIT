# LeafIT

A public, tenant-independent definition of a Microsoft cloud environment that can be recreated from versioned configuration and private local inputs.

**Status:** shared-infrastructure/public-DNS automation is implemented, including optional reviewed named TXT records. Default Entra branding and coordinated cloud-only user UPN/Exchange SMTP customization have versioned preview/apply/check scripts. Self-managed domain-controller definitions include AD bootstrap, protected backups, and weekday operating schedules. NMe has pinned Marketplace deployment, guarded native/private-worker initialization, access verification, and delegated AD/workload-network preparation. Authentication, registrar delegation, licensing/vendor activation, persona/mailbox bootstrap, and Entra domain verification remain separate per-target steps. Scheduled cold-start, forest recovery, second-tenant acceptance, and full deployment repeatability remain separate gates; do not infer them from compilation or one successful service apply. Other showcase workloads are not implemented. A fresh clone cannot deploy the complete showcase today.

**House brand and tenant customization:** the approved artwork, ownership boundaries, actual script coverage, and [new-target reapply procedure](branding/README.md#remaining-limits) are in [branding/README.md](branding/README.md). Live target state, approvals, previews, and verification remain private. Asset generation is offline; tenant mutations require the selected script's explicit `-Apply` and reviewed target scope. Public asset hosting is not implemented.

**Manual tenant name:** set **Entra ID > Overview > Properties > Name** to the complete desired name from [branding/brand.json](branding/brand.json) for every new tenant, regardless of its initial name. Follow the [manual step and read-only verification](branding/README.md#manual-tenant-name); tenant-name writes are intentionally not automated.


## Showcase Goals

The intended end state showcases **Windows 365**, **Windows 365 for Agents**, **Azure Virtual Desktop (AVD)**, **AVD Hybrid**, **Azure Local**, **Windows 365 Link**, **Microsoft Intune**, and **Microsoft Defender for Endpoint**. The selected hybrid tracks are AVD Hybrid, Azure Local, and AVD hosted on Azure with hybrid identities. AVD Hybrid is a distinct product in this roadmap, not shorthand for hybrid-joined AVD or an assumed Azure Local deployment. Defender primarily means Defender for Endpoint; other Defender products are not implied.

Keep each scenario's desired state, dependencies, ownership, assignments, and acceptance checks distinct, sharing foundation and policy definitions only where appropriate. Windows 365 for Agents has a separate [agent provisioning and pool model](https://learn.microsoft.com/windows-365/agents/introduction-windows-365-for-agents). Verify current architecture, availability, licensing, and supported automation for each product before implementation; AVD Hybrid details remain unverified here. Physical Link devices require their own setup and enrollment steps.

The goal is to reapply the selected scenarios to any eligible clean tenant using this repository plus new private inputs and documented bootstrap steps. Product entitlements, gated availability, hardware, external DNS access, and initial consent remain prerequisites, not things an apply command can guarantee. No scenario is considered reproducible until its clean-tenant acceptance test and no-change repeated apply pass.

## TODO

- [x] Implement the **Azure foundation and public-DNS deployment workflow**: target guards, reviewed naming/region/ownership, shared-group and zone Bicep, record merge/readback, and documented registrar/Entra steps. Each new target still requires the manual [DNS bootstrap and recovery](#dns-bootstrap-and-recovery) gates.
- [x] Implement **two Azure domain-controller definitions**, AD bootstrap, protected backup, and weekday power schedules under [identity/](identity/main.bicep). Full recovery, scheduled cold-start, and clean-tenant acceptance remain separate gates.
- [x] Implement **NMe deployment and linking prerequisites** through the [NMe workflow](nme/README.md). Vendor registration/activation, Install ID handoff, post-install hardening acceptance, and actual desktop workloads remain separate steps.
- [ ] Add **Login VSI Hydra in Azure**. Verify vendor-supported deployment and licensing, define its management ownership, and document rebuild and verification steps.

These are the immediate foundation/enabler tasks; implementation of the broader [showcase goals](#showcase-goals) is deferred until each scenario is selected. This backlog is not approval to deploy resources or incur charges. Work only against the LeafIT environment identified by the private `TARGET_` settings; this repo is the single source of truth for desired state.

## Azure Foundation

**Implemented foundation definition; target state is private.** Public DNS is the first service in the shared infrastructure resource group; it does not require a VNet, domain controllers, or either management product. Use `infra` as the shared-foundation workload identifier, not `dns`. Add other persistent shared services to that group when ownership, access, and lifecycle align. Do not pre-create empty groups for future products.

### Subscription And Naming

Start with one explicitly verified target subscription and one environment. Additional subscriptions, management groups, and a full landing-zone hierarchy are deferred until isolation, policy, or billing requirements justify them. The subscription must belong to `TARGET_TENANT_ID`; Graph sign-in alone does not establish Azure subscription access. A tenant display name is a label, not an identity key: validate IDs and resolve any naming discrepancy with the operator before writes.

**Always follow the Microsoft Cloud Adoption Framework (CAF) [Define your naming convention](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming).** This is the naming authority for all Azure resource groups and resources in this repository. Do not introduce a competing project-specific naming scheme or copy an illustrative group list into deployment code.

- Select the applicable CAF name components, such as resource type, workload/application, environment, region, and instance, and use a consistent documented order. Use the [CAF resource abbreviations](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations), including `rg` for resource groups. Concrete names and component values must be reviewed before deployment; this design does not prescribe a universal string format for every resource type.
- For this single-environment showcase, omit the redundant environment token. The selected shared-infrastructure resource-group components are resource type, workload, region, and instance, in that order. Do not add an environment label to names, required inputs, or tags solely to describe this showcase; revisit that choice only if independently managed environments are introduced.
- Keep names stable. Put mutable ownership, cost, and operational metadata in tags rather than names. Keep private tenant identifiers and secrets out of names, examples, and public configuration.
- Validate each resource type against its [Azure naming restrictions](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules), including length, characters, uniqueness scope, and any distinct guest-computer-name limits. A DNS zone's resource name is its actual domain FQDN, not a prefixed CAF label.
- Treat location separately from naming. Every resource group needs a real metadata region; a public DNS zone uses resource location `global`. That service property does not automatically become a resource-group suffix. Document service-generated or vendor-required naming constraints explicitly instead of silently replacing CAF or renaming vendor-managed resources.

Before the first deployment, set these additional private inputs in `.env`; no defaults or fallback to unprefixed settings:

| Input | Meaning |
| --- | --- |
| `TARGET_WORKLOAD` | Parent workload identifier used in the selected CAF name components; `infra` for this shared foundation, not the child service or tenant display name |
| `TARGET_LOCATION` | Azure region for resource-group metadata and the initial regional workloads, subject to their availability requirements |
| `TARGET_REGION_CODE` | Short naming code mapped to that region |
| `TARGET_INSTANCE` | Instance identifier where required by the selected naming convention |
| `TARGET_DNS_ZONE_NAME` | Actual registered domain; the DNS zone resource name must be this FQDN, not an Azure naming prefix |

These inputs must be supplied and validated per target; listing them does not establish deployment or access. Workloads can use distinct logical identifiers while sharing the same CAF convention; no single tenant name or hard-coded resource ID may determine the structure.

### Regional Policy

The project's default region for Cloud Endpoint compute is **Sweden Central** (`swedencentral`). Set the explicit private `TARGET_LOCATION` input to this region and `TARGET_REGION_CODE` to `swc`; there is no fallback for missing inputs.

| Workload | Regional baseline |
| --- | --- |
| AVD session hosts and other showcase compute | Sweden Central, subject to current product availability, SKU restrictions, capacity, and quota |
| Supporting Azure infrastructure | Sweden Central where supported; public DNS remains `global`, while its group and deployment metadata use Sweden Central |
| Windows 365 Azure network/VNet scenarios | Sweden Central, after checking current Windows 365 networking and region support |
| Intune | Not an Azure-region selection; this setting does not relocate the tenant service |

**Germany West Central** (`germanywestcentral`, naming code `gwc`) is the alternative only after explicitly reviewing current product constraints, subscription restrictions, and SKU availability. Never switch automatically. West Europe and North Europe are not standard deployment regions for this showcase. These are project placement choices, not claims that every listed product or SKU is available in either region. AVD Hybrid placement still requires its own architecture review.

The two short codes are documented CAF naming components, not official Azure location identifiers. [infra/main.bicep](infra/main.bicep) permits only the two selected metadata regions. The prerequisites command checks region membership in the subscription's location catalog; that check does not prove workload eligibility, regional SKU availability, quota, or capacity.

### Resource Groups

CAF naming guidance does not prescribe a fixed number of resource groups or one resource group per product. The selected baseline is one shared `infra` group for persistent foundation services, not a group for every service. Separate disposable showcase resources, vendor-managed deployments, or other resources when lifecycle, ownership, or access requires it. Review concrete CAF names before deployment; there is no fixed total group count.

| Design boundary | Grouping and ownership rule |
| --- | --- |
| Persistent shared services | Public DNS starts in the shared `infra` group. Shared networking and persistent identity infrastructure can join it when ownership, access, and lifecycle align. Bicep owns the Azure resources; service modules do not create a group of their own. Never delete the shared group to reset a showcase. |
| Scenario infrastructure | Group related Azure resources by the selected scenario and lifecycle. Separate replaceable session hosts from persistent profile data where required. Give each object one owner: Bicep, NMe, or the supported product deployment mechanism. Derive AVD Hybrid placement from its own verified architecture. |
| Tenant services and devices | Windows 365 service-managed resources, Intune policies, Defender for Endpoint settings, and physical Link devices are not made into customer Azure resources merely to fit a resource-group diagram. Keep their portable configuration, assignments, supported APIs, and hardware/bootstrap steps in distinct scenario definitions. |

Group by lifecycle and owner, not one group per resource type or VM. Resource groups are not network security boundaries. Begin with one shared VNet and workload subnets when regional workloads are implemented; do not introduce hub-spoke networking without a requirement. Keep domain-controller NICs private, and decide administrative access, egress, address space, and AD DNS forwarding before VM deployment. Public authoritative DNS, AD-integrated DNS, and Azure Private DNS serve different purposes; never publish internal AD records in the public zone.

Workload-specific monitoring, secrets, and storage stay with their workload unless sharing is justified. Backups that must survive workload deletion need a separately protected recovery lifecycle and, when implemented, a separate recovery group. Do not put a recovery vault in a disposable VM group. Create scenario resource groups and test agents only when their implementation is selected; choose owners and verify CAF names first. NMe and Hydra remain independently managed enablers, not mandatory dependencies for every showcase.

### Repository Layout

Organize Azure definitions as **top-level workload/group, then service**. The parent entry point owns the resource-group declaration, its reviewed CAF name and common settings, and module composition. Each child service module receives the parent's resource-group scope and defines only its service resources.

```text
infra/
	Initialize-Prerequisites.ps1  Provider check/apply and offline checks
	Deploy-Foundation.ps1         Guarded shared-foundation deployment
	main.bicep                    Shared group, naming input, and composition
	dns/
		zone.bicep                 Public zone and verification TXT in the parent group
```

Folder names are stable logical names, not tenant IDs or fully expanded Azure resource names. `resourceGroupName` remains an explicit reviewed deployment parameter; folders do not silently choose Azure names. Keep service modules separate for clarity without treating every module or folder as a separate resource group. Add future service folders only with implemented services; add a new top-level group only for a distinct approved workload/lifecycle boundary. Do not add empty scaffold folders, a generic naming engine, or competing definitions of the shared group. Keep tenant-level Graph policy definitions outside an artificial Azure resource-group hierarchy.

### Governance

- Apply the reviewed `project`, `workload`, `managed-by`, and `owner` tags to groups and supported resources where relevant. Use a team/function for `owner`, not personal or confidential details. Tags are not inherited automatically; templates or the owning product must apply them. Do not overwrite vendor-required tags or add a redundant environment tag.
- Scope runtime access to the owned resources. Use **DNS Zone Contributor** at the zone for record maintenance; creating the group/zone and assigning RBAC require separate bootstrap rights. Graph `Domain.ReadWrite.All` covers domain registration/verification, not Azure DNS or registrar access; delegated operations also require a supported Entra role. Do not grant broad Owner access just to manage DNS.
- After validation, protect the public zone with a reviewed **CanNotDelete** lock. It does not prevent record edits and can block child record-set deletion; deliberate deletions require a controlled unlock. Keep it out of workload teardown, and do not add locks to vendor-managed resources without checking compatibility. Locks are not backups.
- Define subscription cost alerts and workload budgets privately before paid resources are deployed. Budget alerts do not impose a spending cap. No amounts or commercial approvals belong in this README.

These choices follow Microsoft's [resource-group lifecycle guidance](https://learn.microsoft.com/azure/azure-resource-manager/management/overview#what-is-a-resource-group), [naming guidance](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming), [tag inheritance rules](https://learn.microsoft.com/azure/azure-resource-manager/management/tag-resources), and [resource-lock behavior](https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources).

### DNS Bootstrap And Recovery

Creating an Azure DNS zone neither registers the domain nor restores its records or registrar delegation. A recreated zone can receive different authoritative name servers. A successfully verified Entra domain also does not prove that web or mail routing works.

1. **Preflight:** verify target tenant/subscription, Azure permissions, registrar access, current parent NS delegation, and any parent DNSSEC DS record. Establish the required records from reviewed definitions, a protected export, or the service owners. Public DNS queries cannot enumerate every record; if a zone is unavailable and no complete inventory exists, document the gaps rather than claiming restoration.
2. **Define and preview:** use the subscription-scoped infrastructure parent for the shared resource group and a resource-group-scoped child module for the public zone and owned record sets. Keep the zone name and tenant-specific values private; obtain the Entra verification TXT value from the current target. Treat Azure-generated apex NS/SOA as service-managed, not copied desired-state records. Preview with Azure what-if; registrar and Graph actions need their own explicit preview.
3. **Create and populate:** after the implementation preview is approved, create the DNS group/zone and add the current verification TXT plus reviewed service records. Use ignored `private/dns/records.json` for the target-specific MX, CNAME, and apex TXT source inventory. Merge existing apex TXT/MX values; fail closed on conflicting CNAME targets. Do not invent SPF, MX, DKIM, DMARC, CAA, or application targets. Query each newly assigned Azure name server directly before switching delegation. A partial record inventory is not a recovered production DNS service.
4. **Delegate:** obtain all four name servers from the newly created zone and update the domain registrar's nameserver settings with explicit approval. Editing only the child zone's NS record does not change parent delegation. Preserve valid DNSSEC or perform a separately reviewed DS/key transition; a stale parent DS record can cause DNSSEC validation failures. Do not assume former name servers or keys are reusable. Keep any still-working delegation until the replacement records are ready; rollback is possible only to a working authoritative service.
5. **Verify:** check parent delegation, authoritative SOA/NS, the verification TXT through public resolvers, and DNSSEC validation where applicable. Call Graph domain verification only after the correct TXT is publicly resolvable, then read back `isVerified`. Keep the existing tenant default, user sign-ins, and mail-routing targets unchanged unless separately approved. Validate selected web/mail services independently, prove a no-change repeated Bicep apply, and retain minimized target evidence under `private/`.

Azure DNS is the owner of public records; Graph owns Entra domain registration/verification; the registrar owns delegation and parent DS changes. Future workload scripts must not recreate or delete the shared zone. Keep protected record exports and registrar recovery access outside workload teardown, while recognizing that configuration definitions do not back up hosted application or mailbox data.

Official procedures: [host and delegate a domain in Azure DNS](https://learn.microsoft.com/azure/dns/dns-delegate-domain-azure-dns), [zone and name-server behavior](https://learn.microsoft.com/azure/dns/dns-zones-records#dns-zones), [Azure DNSSEC](https://learn.microsoft.com/azure/dns/dnssec), and [verify a domain with Graph](https://learn.microsoft.com/graph/api/domain-verify?view=graph-rest-1.0). Foundation guidance checked 2026-10-08; require deployment, delegation, domain verification, and recovery evidence separately for every target.

### Target Sign-In

Use PowerShell **7.6 on Windows** (`pwsh`), Git, Azure CLI with Bicep, Az.Accounts, Az.Resources, Az.Dns, Az.Network, Az.Compute, Az.Automation, and Az.RecoveryServices. Identity automation uses PowerShell 7.6 timestamp parsing and Windows DPAPI. Run all following commands in the same authenticated PowerShell process; deployment scripts never sign in or switch context themselves.

For an explicitly approved interactive deployment, read only the target IDs from ignored `.env` and use device authentication. No application registration or certificate is needed for this delegated sign-in; Azure RBAC must still authorize the selected operations.

```powershell
$target = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $PWD '.env'))) {
	$entry = [regex]::Match($line, '^\s*(?<key>TARGET_(?:TENANT_ID|SUBSCRIPTION_ID))\s*=\s*(?<value>.*)$')
	if (-not $entry.Success) { continue }
	$key = $entry.Groups['key'].Value
	if ($target.ContainsKey($key)) { throw 'Duplicate target identity input.' }
	$target[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
foreach ($key in @('TARGET_TENANT_ID', 'TARGET_SUBSCRIPTION_ID')) {
	$parsed = [guid]::Empty
	if (-not [guid]::TryParse($target[$key], [ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Invalid target identity input.' }
}
Disable-AzContextAutosave -Scope Process | Out-Null
$signIn = Connect-AzAccount -UseDeviceAuthentication -Tenant $target.TARGET_TENANT_ID -Subscription $target.TARGET_SUBSCRIPTION_ID -Scope Process
$context = Get-AzContext
if (-not $context -or $context.Tenant.Id -ne $target.TARGET_TENANT_ID -or $context.Subscription.Id -ne $target.TARGET_SUBSCRIPTION_ID) { throw 'Authenticated target mismatch.' }
```

Complete authentication directly in Microsoft's sign-in flow; never put passwords, tokens, or MFA responses in chat. Unattended certificate authentication is a separate bootstrap: it needs populated `TARGET_CLIENT_ID` and `TARGET_CERTIFICATE_THUMBPRINT`, an accessible private key in the execution account's certificate store, and reviewed grants. Never invent these inputs, copy legacy identities, or create an app merely to perform an interactive check.

### Infrastructure Entry Point

[infra/main.bicep](infra/main.bicep) is the subscription-scoped entry point and sole owner of the shared infrastructure resource group; [infra/dns/zone.bicep](infra/dns/zone.bicep) creates the public zone and the declared apex TXT, MX, and CNAME record sets within that group. It does not register a domain in Entra, change the tenant default, alter registrar delegation, or imply that unlisted website/mail records have been restored.

Use [infra/Initialize-Prerequisites.ps1](infra/Initialize-Prerequisites.ps1) for the implemented subscription dependency, **Microsoft.Network**. It parses only the required private target identity and regional fields as data, verifies the current Azure context and enabled subscription ownership, and refuses ambiguous states. It does not sign in, switch subscriptions, grant permissions, register unrelated providers, or deploy resources. Use Git, PowerShell 7, Az.Accounts 5.3.3 or later, and Az.Resources 9.0.3 or later. Registration requires subscription-level `Microsoft.Network/register/action`; do not broaden RBAC automatically.

Run these in the **same PowerShell process as the retained target Azure sign-in**, executing `-Apply` only after registration approval:

```powershell
& ./infra/Initialize-Prerequisites.ps1 -CheckOnly
& ./infra/Initialize-Prerequisites.ps1
& ./infra/Initialize-Prerequisites.ps1 -Apply
& ./infra/Initialize-Prerequisites.ps1
```

`-CheckOnly` runs offline checks without loading private inputs or contacting Azure. The default command is read-only and reports `WouldRegister`, `InProgress`, or `NoChange`. `-Apply` sends a registration request only for `NotRegistered`; `Registering` and `Registered` never send duplicate requests. Registration is asynchronous: `Ready = false` is not completed registration. Re-run the read-only command to verify `Registered` and then repeat `-Apply` to prove `NoChange`. A failed request may have been accepted server-side; inspect state before retrying. Provider registration and resource deployment are separate approvals. See the native [Register-AzResourceProvider](https://learn.microsoft.com/powershell/module/az.resources/register-azresourceprovider) command.

Use [infra/Deploy-Foundation.ps1](infra/Deploy-Foundation.ps1) for a fresh, target-guarded preview and approved apply. Pass the current Graph verification TXT value explicitly; the script never invents or logs it:

```powershell
& ./infra/Deploy-Foundation.ps1 -VerificationTxtValue '<TARGET_DNS_VERIFICATION_TXT>'
& ./infra/Deploy-Foundation.ps1 -VerificationTxtValue '<TARGET_DNS_VERIFICATION_TXT>' -Apply
```

The default is read-only. It loads desired MX, CNAME, and apex TXT record objects from ignored `private/dns/records.json`, merges the supplied token and non-empty existing apex TXT values, and preserves non-conflicting existing MX entries. Conflicting CNAME targets fail closed. With an existing, correctly tagged group and zone, it previews the record-set operations, deploys the DNS service module through Bicep, and reads back TXT, MX, and CNAME records and TTLs. For a clean foundation, it uses the subscription-scoped parent and requires the full expected create set. Neither path changes registrar delegation or Entra domain state. Review the preview before `-Apply`; keep all target values and deployment evidence private.

| Template parameter | Target input or required preparation |
| --- | --- |
| `resourceGroupName` | Reviewed shared-group CAF name from `rg`, `TARGET_WORKLOAD` (`infra`), `TARGET_REGION_CODE`, and `TARGET_INSTANCE`; no environment token |
| `location` | `TARGET_LOCATION`; verify the subscription permits the region |
| `zoneName` | `TARGET_DNS_ZONE_NAME` |
| `verificationTxtValues` | Supply the current target's Graph verification TXT value; automation merges it with private apex TXT inputs and existing non-empty apex TXT values |
| `mxRecords`, `cnameRecords` | Sanitized source inventory in ignored `private/dns/records.json`; preserve non-conflicting existing MX records and fail on conflicting CNAME targets |
| `tags` | Explicit reviewed non-sensitive string values, applied to both group and zone |

Local compilation was validated with Bicep **0.42.1** through Azure CLI and **0.47.16** through the Bicep tooling. A runnable local check is `az bicep build --file infra/main.bicep --stdout`; compilation does not deploy resources. Use a compatible tested Bicep version for deployment. The prerequisites command loads only its required fields; there is no automatic Bicep parameter loader. Read the remaining required `TARGET_` fields as data and supply deployment parameters explicitly. Keep target parameter files and what-if output under ignored `private/`, not beside the public templates. Reload private inputs and regenerate the compiled template and preview after a naming, region, or layout change; do not reuse stale session variables or deployment artifacts. A preview using a placeholder TXT value is never an apply candidate.

Before apply, confirm the Azure context matches both private target IDs and inspect existing groups, zones, and TXT values. The guarded script chooses the subscription-scoped parent for a clean foundation or the resource-group-scoped DNS service module when the shared group and zone already exist. Require a fresh, reviewed preview before `-Apply`. Use incremental deployment; the template replaces the owned TXT record set with the supplied complete values, so the automation merges existing non-empty apex TXT values before applying. Deployment outputs the assigned `nameServers`; compare them with actual parent delegation rather than assuming an earlier Azure name-server set is reusable. Keep any working delegation until the verified zone is ready, and require explicit approval before registrar changes. Recheck the resulting TXT through authoritative/public DNS, verify the domain in Graph, and repeat preview to prove no unintended changes.

## Domain Controllers

**Demo milestone:** public DNS, two working DC VMs, and automatic weekday startup. One real scheduled start plus a basic AD/DNS check establishes demo readiness; forest-recovery and clean-tenant rebuild acceptance are separate future exercises, not blockers for this milestone.

The self-managed AD DS implementation is under [identity/main.bicep](identity/main.bicep), separate from the shared public-DNS foundation. Its own group has a workload rebuild lifecycle; never reset it by deleting the shared `infra` group. [identity/recovery/resources.bicep](identity/recovery/resources.bicep) puts recovery services in a separately retained group owned by the parent template. Neither workload nor recovery teardown is automatic.

The candidate configuration uses two private Windows Server 2025 Datacenter: Azure Edition Core VMs, a pinned small-disk image, `Standard_B2s_v2`, persistent 64-GiB OS and 32-GiB AD data disks, and separate availability zones. Data-disk caching is disabled. The deployment refuses unavailable zones rather than silently choosing an availability set or another region. Static private addresses are assigned on Azure NICs; guest IP configuration remains DHCP. The VNet and NIC DNS settings are bootstrapped from Azure DNS to the first DC and then to both DCs. Guest promotion uses protected Run Command parameters and rejects mismatched existing domains or initialized data disks.

The dedicated AD subnet denies interactive RDP/WinRM and other unsolicited inbound traffic. Native VM Run Command is the initial administration interface; future client subnets require reviewed AD protocol rules before onboarding. A shared NAT Gateway provides explicit outbound connectivity, not inbound access. This is not a firewall or a complete enterprise landing zone.

Use PowerShell 7.6 on Windows and an explicitly authenticated Azure target matching private inputs, as described in [Target Sign-In](#target-sign-in). These commands separate offline checks, provider readiness, private input preview, deployment preview, and approved apply:

```powershell
& ./identity/Deploy.ps1 -CheckOnly
& ./identity/Initialize-Prerequisites.ps1
& ./identity/Initialize-Prerequisites.ps1 -Apply
& ./identity/Initialize-PrivateInputs.ps1
& ./identity/Initialize-PrivateInputs.ps1 -Apply
& ./identity/Deploy.ps1
& ./identity/Deploy.ps1 -Apply
```

For provisioning-only troubleshooting, use `& ./identity/Deploy.ps1 -Apply -ResourcesOnly`. This still applies the reviewed VMs, disks, and networking, but returns before AD promotion, backup setup, or schedule publication. It requires explicit `-Apply`; use the default command for read-only preview. Add `-ExplainPreview` to report change types and property paths without exposing private values or resource IDs. Provider-populated defaults can produce what-if differences; compare actual owned properties before claiming a no-change result.

Use `& ./identity/Deploy.ps1 -Apply -DnsOnly` for an approved guest DNS refresh without resource deployment, promotion, backup setup, or scheduling. It checks Azure NIC DNS order, selects the unique IPv4-configured guest interface, and skips renewal when the guest already matches. Ambiguous interfaces fail closed.

Use `& ./identity/Deploy.ps1 -OperationsOnly` for an Azure read-only scheduling preview after the DCs and backups are configured; add `-Apply` only after review. This skips VM provisioning, AD promotion, guest DNS changes, and backup-job creation. It requires existing backup protection to be Protected/Healthy with the last backup Completed, but does not require a fresh application-consistent recovery point or change backup configuration. Stop any previous local apply before using this mode; never run overlapping applies.

**Scheduler migration:** preview legacy Health retirement with the first command below; run the second only after migration and deletion approval. Apply checks for active jobs and shared schedules, pauses the owned schedules, removes their old bindings, publishes the runbook and creates the two scalar-input bindings, retires Health, then resumes Start/Stop. Existing schedule definitions are not redeployed, so their timings and paused state are preserved during migration. On failure, the script attempts to keep owned schedules paused for operator review; it does not start or stop VMs.

```powershell
& ./identity/Deploy.ps1 -OperationsOnly -RetireHealthSchedule
& ./identity/Deploy.ps1 -OperationsOnly -RetireHealthSchedule -Apply
```

The retirement switch is required when legacy Health exists. Incremental deployment alone does not delete omitted resources, and local source edits do not change live Automation resources.

Execute mutation switches only after their preview is reviewed and the selected workload is approved. The prerequisite script registers only Compute, Automation, and Recovery Services, and never duplicates pending registration. The private initializer adds missing reviewed inputs without replacing existing values. It creates unique Windows-DPAPI encrypted passwords in ignored `.env`; decrypt them only in memory for secure ARM parameters. The ciphertext is tied to the Windows execution account and is not a portable credential backup. A different account or machine needs an approved credential recovery or bootstrap process. No passwords belong in templates, parameter artifacts, runbook inputs, or logs.

If Azure explicitly rejects a normal public-IP request with `Microsoft.Network/AllowBringYourOwnPublicIpAddress`, first inspect the submitted template for accidental BYOIP properties. `& ./identity/Initialize-Prerequisites.ps1 -PublicIpFeature` reads only that feature's state. Adding `-Apply` is a separately approved, subscription-wide registration workaround, not a normal Standard IPv4 prerequisite or a guaranteed fix. This opt-in mode does not register other providers or import IP ranges. Pending registration is not ready and is never resent; require `Ready=true` before retrying deployment.

[identity/dc/Invoke-Schedule.ps1](identity/dc/Invoke-Schedule.ps1) is a managed-identity power-control runbook. The desired configuration has two weekday schedules: start at 06:00 and deallocate at 18:00 in Brussels local time, including DST. Both use plain `VmName1` and `VmName2` inputs. Target and schedule-window guards remain, and running/deallocated states are no-ops. The scheduler's VM-scoped role permits power control and status reads, not guest Run Command execution. Publication verifies the source, published state, and existing PowerShell 7.6/Az 15.1.0 runtime; there is no scheduled AD diagnostic or additional smoke-test job.

Nightly deallocation of every DC is an accepted demo availability limitation, not a reliable AD DS recovery design. Check basic AD/DNS before a demo; failed startup requires operator review, not automatic AD repair. Respect inherited governance automation; do not continuously restart VMs, renew one-time exemption tags, or remove policies to keep the domain running. Underlying governance may also affect permissions and runtime configuration, so verify effective state rather than assuming an initial deployment persists.

Daily Azure VM backup is scheduled at 14:00 UTC while weekday VMs are operating, with seven-day retention and locally redundant vault storage. Initial full deployment still requires an application-consistent recovery point from the last 24 hours for each DC before scheduling proceeds; a completed job alone is insufficient for that gate. Scheduler-only migration checks existing protection and last-backup completion without a freshness prerequisite. Verify recovery procedures independently. Weekend backups of deallocated VMs must not be assumed application-consistent. Backup retention is not identity preservation through a new forest: recreating AD changes SIDs and device trust. A passing initial AD readback does not prove nightly cold-start reliability or forest recovery.

The DC implementation is defined, but its reproducibility TODO remains open until deployment/readback, healthy DNS and replication, protected backups, scheduler bindings, a no-change repeated apply, and a clean-tenant acceptance test have their own evidence. Scheduling-only success does not prove that the full fresh-deployment path has passed. Azure Automation what-if can report provider defaults, timestamp representation differences, and unresolved identity/job-schedule expressions; compare actual owned state and check for duplicate bindings instead of treating those differences as proof of drift or claiming a zero-change preview. Keep all target evidence under ignored `private/identity/`. Check the current [AD DS Azure architecture](https://learn.microsoft.com/azure/architecture/example-scenario/identity/adds-extend-domain), [AD backup and restore guidance](https://learn.microsoft.com/azure/backup/active-directory-backup-restore), and [Automation schedule guidance](https://learn.microsoft.com/azure/automation/shared-resources/schedules).

Server licensing baseline: **Azure pay-as-you-go Windows Server VM (Windows Server operating-system license and AD DS role)**. No Microsoft 365 bundle is required just to run these DCs. Use Azure Hybrid Benefit only with separately verified qualifying Windows Server licenses; review applicable access licensing and downstream workload entitlements separately. The VM charge does not cover backup, managed disks, NAT, public IP allocation, Automation execution, or other paid services. See [Microsoft server software support and licensing on Azure VMs](https://learn.microsoft.com/troubleshoot/azure/virtual-machines/windows/server-software-support) and [Azure Hybrid Benefit requirements](https://learn.microsoft.com/windows-server/get-started/azure-hybrid-benefit). Guidance checked 2026-10-09; commercial prerequisites must be reviewed per target.

## Nerdio Manager for Enterprise

**Implementation entry point:** [nme/README.md](nme/README.md) documents target-guarded Marketplace discovery, pinned vendor artifacts, provider registration, what-if, automated resource deployment, and the separately approved storage-only compatibility workflow. [nme/main.bicep](nme/main.bicep) creates the workload group and composes the unmodified vendor template with private core backends and a public portal. The existing brand owner supplies the LeafIT identity. No manual wizard/template export is required. Actual deployment, initialization, consent, entitlement, and readback evidence stay private; ARM success does not establish activation or completed application setup.

### Infrastructure Fit

| Boundary | Placement and owner |
| --- | --- |
| Shared foundation | Keep public DNS in the existing shared `infra` group, owned by [infra/main.bicep](infra/main.bicep). NMe installation must not redeploy, move, or delete it. |
| Identity | Use the existing AD DS domain and both DCs as NMe's directory/DNS foundation for hybrid workloads. Keep the DCs, their private networking, backups, and power schedules under the existing identity definitions; connecting the directory to NMe does not transfer their lifecycle to Nerdio or make them session hosts. |
| NMe management plane | Selected: a dedicated `nme` workload group because the vendor requires a new or empty group and owns a separate application lifecycle. Review a CAF name of the form `rg-nme-<region-code>-<instance>`, without an environment token. Marketplace/Nerdio owns its application resources; do not reproduce its SQL, App Service, Key Vault, storage, or Automation resources in the foundation template. |

**Selected region: Sweden Central** for the NMe management plane, subject to the current Marketplace offer, App Service quota, and all required service availability. Germany West Central remains an explicitly reviewed alternative, never an automatic fallback. NMe's own region does not select the region of future session hosts. Review the installer resource-name prefix and any vendor-generated naming constraints before deployment.

**Selected access model: public HTTPS with NMe's own Entra sign-in.** Use the application's supported authentication and administrator roles; do not separately enable App Service Authentication, which the vendor does not support for NMe. Public administration does not authorize public DCs, public AD/DNS traffic, or anonymous resource access. Keep domain connectivity private as described below.

Confirm Azure policy permits this model before installation, including any documented, approved temporary exceptions required by the tenant's cost and security controls. Do not disable governance, create blanket exemptions, or silently make the management portal private if it is blocked. Private backend connectivity is now selected through Nerdio's documented hardening; this does not authorize unrelated networking, a custom DNS name, or optional Insights components. No AVD host pools, session hosts, profile storage, Windows 365 configuration, or Intune changes are part of this installation milestone.

### Selected Hardening

Bootstrap selects private endpoints in the vendor Marketplace template while keeping `privateWebApp=false`. Complete and verify installed component coverage through Nerdio's built-in **Enable Private Endpoints** action, documented in [Harden Nerdio Manager](https://nmehelp.getnerdio.com/hc/en-us/articles/26124315691149) and its [current parameter reference](https://nmehelp.getnerdio.com/hc/en-us/articles/26124385359757). NMe owns its endpoints, VNet integration, and private DNS; the Bicep wrapper must not reimplement them.

| Area | Selected behavior |
| --- | --- |
| Backend network | Harden installed core SQL, Key Vault, Automation, DPS storage, and scripted-action storage through private connectivity. Review non-overlapping private endpoint/App Service subnets, private DNS, and required outbound licensing/Azure access. The vendor action must pass its worker-side connectivity checks before disabling public backend access. |
| Public portal | Keep `MakeAppServicePrivate=false`, preserving the existing public HTTPS endpoint and NMe's Entra authentication. Setting it to `true` makes the portal private and conflicts with this access requirement. Disable FTP as documented. App/SCM IP allowlists require approved source ranges before applying deny rules; no addresses are inferred. |
| Scripted-action storage | Select `CssaStorageAccount=Private`. Set Azure Runbook Execution Mode to **Inline Script before hardening**, so Automation does not depend on downloading scripts from storage that becomes private. Verify the installed action/version supports this mode; do not add a Hybrid Worker VM merely because an older overview mentions one. |
| DNS and reachability | Keep `SkipDNS=false`; review reuse of any existing private zones. Peer only explicitly selected workload VNets when required, never all linked VNets by default. Every required storage consumer must have a private route. Existing public DNS, AD DNS, DC networking, and DC power control are not replaced by this action. |
| Authentication and feature support | Use the documented Entra-only SQL configuration and private Key Vault access; private networking alone does not prove shared-key-free storage support. Accept normal downsizing, but test that the resulting App Service tier retains VNet integration, a functional requirement for private backends. Do not create optional modules merely to harden them. |

**Execution boundary:** the vendor action requires an existing installation and reviewed target/network inputs. This profile is not evidence of applied hardening. It does not make Azure Monitor, Log Analytics, or Application Insights private; the current vendor action explicitly excludes them. Making the portal private or inventing administrator IP allowlists is not included in preserving public access. Governance can still restrict the public app independently of this configuration, so backend hardening does not guarantee continued internet access after exception expiry.

### Governance And Expiry

Managed tenants may require temporary cost-control and security-control exception tags for the installer and its resources. Verify the current approved mechanism, exact keys/values, eligible controls, resource or group scope, activation behavior, and expiration before running even the vendor's resource-creating readiness test. A governance service can honor a group-scoped exception for contained resources without Azure copying tags to those resources; verify that coverage explicitly rather than treating ordinary tag inheritance as the mechanism. Do not assume a subscription tag is effective or that a visible tag proves an effective exception.

Keep internal governance guidance, source links, and minimized readback evidence under ignored `private/`; keep target-specific tag inputs, approvals, and actual expiry values in ignored `.env`. This public plan deliberately does not prescribe internal tag names, values, or a lifetime. Selecting the group and region does not approve applying exception tags or deploying resources.

Include exception expiry in the installation and NVP-waiting plan: establish what normal controls will enforce after expiry and whether that affects application availability or required configuration. Do not assume that reapplying a tag resets its validity window, or that a short reapplication window is a sustainable operating model. Recheck effective validity before deployment and later demo use; do not implement automatic renewal, retagging loops, or permanent ignore tags. Existing DNS/DC resources and their governance remain outside this NMe exception scope.

**Operating boundary:** use the supplied governance guidance and actual policy/readback results, without a speculative external-confirmation gate. Installation success is insufficient if normal automation later breaks public portal access or required functionality. Sizing recommendations alone are not a blocker. A deny-policy exclusion is not assumed to cover separate scheduled automation. Stop on a concrete policy or required-function failure rather than disabling controls, applying unapproved tags, or changing the selected access model.

### Vendor Compatibility

Documentation review checked 2026-10-15; this is not an installed-instance test or confirmation that the selected environment's controls are compatible. The detailed governance comparison remains private.

| Area | Documented path and remaining check |
| --- | --- |
| Network access | The [installation guide](https://nmehelp.getnerdio.com/hc/en-us/articles/26124313550477) and [security FAQ](https://nmehelp.getnerdio.com/hc/en-us/articles/43762191552909) document private endpoints, including temporary installation connectivity requirements. The selected profile now hardens backends while leaving the public portal unchanged with `MakeAppServicePrivate=false`. An ongoing management access path must remain usable under normal governance. |
| SQL and application identity | The pinned template configures Entra-only SQL with the web app's managed identity. The [older conversion procedure](https://nmehelp.getnerdio.com/hc/en-us/articles/26124311294733) uses a client secret and is not the current bootstrap contract. Verify the installed connection rather than assuming all other credentials also disappear. |
| Storage authentication | The [reference architecture](https://nmehelp.getnerdio.com/hc/en-us/articles/26124355756941) lists several consumers. The reviewed template still uses SAS/key operations; private endpoints do not establish shared-key-free compatibility. Test the actual selected consumers under normal governance. |
| Installation and updates | Automated bootstrap uses the exact vendor package and its MSDeploy extension; verify the actual result. [Vendor updates](https://nmehelp.getnerdio.com/hc/en-us/articles/26124297553677) include Azure CLI deployment with current Entra-authentication support. Initial deployment and update authentication are separate checks. |
| App Service sizing | The [preparation guide](https://nmehelp.getnerdio.com/hc/en-us/articles/44411071090317) identifies B3 as the main-app deployment baseline, not a requirement to preserve that size throughout the demo. Accept normal automated downsizing without a sizing exemption or automatic scale-back-up. Investigate only if the smaller SKU actually prevents the selected demo functions; reduced performance or departure from best-practice sizing alone is acceptable. Runtime behavior at the smaller SKU is not yet verified. Optional Insights components remain unselected. |

**Outcome:** automate the selected package and test its behavior under the supplied governance rules. Keep unresolved functional checks explicit. No blanket external-confirmation gate, automatic retagging, or security relaxation is part of this workflow.

### Hybrid Identity

**Linking prerequisites implemented; NMe link remains separate:** [identity/Initialize-NmeDirectory.ps1](identity/Initialize-NmeDirectory.ps1) prepares a dedicated workload subnet in the existing AD-connected VNet and a computer OU with a non-privileged delegated join account. See [NMe linking](nme/README.md#network-and-directory-linking) for the guarded commands and private wizard inputs. It reuses the existing domain rather than creating a second forest, does not redeploy the DCs, and leaves identity synchronization/profile storage unchanged. The intended dependency remains NMe-managed hybrid workloads using repository-managed AD DS/DNS; separate resource groups preserve ownership, not disconnected services.

- **Directory and DNS:** configure NMe's supported directory integration with the existing AD DS domain. Selected domain-joined workload networks must resolve the domain through both DCs; public Azure DNS remains authoritative public DNS only.
- **Private connectivity:** link the appropriate workload network/subnet in NMe and review private routing plus required AD/DNS firewall rules to the DC subnet. Verify which provisioning components need connectivity; do not assume a public NMe web endpoint provides domain reachability or open the AD subnet broadly.
- **Join and synchronization:** select a dedicated computer OU and a least-privilege delegated join account, with credentials kept in the supported private secret store. Review the vendor's documented AD DS-to-Entra synchronization requirement and the selected workload's device-registration requirements. Domain join and Microsoft Entra hybrid join are different; deploying DCs alone establishes neither synchronization nor hybrid device registration.
- **Operating hours:** the weekday 06:00-18:00 DC schedule is a demo constraint. Domain-dependent provisioning, authentication, and DNS require DC availability; coordinate workload activity with that window. NMe must not silently take over DC power control. Review availability again before relying on this domain for services that run outside demo hours.
- **Platform-specific validation:** assess each selected track's hardware, identity, routing, WAN-outage behavior, licensing, and Nerdio support separately. AVD Hybrid is a distinct product, not shorthand for Entra hybrid-joined AVD or an assumed Azure Local deployment; nightly stopped Azure DCs must not be assumed sufficient for every platform.

### Hybrid Scenarios

All three tracks are in scope for planning. They share the intended AD DS/DNS foundation where supported, not an assumed common deployment architecture or permission to provision resources.

| Selected track | Integration to define before implementation |
| --- | --- |
| AVD Hybrid | Verify this product's architecture, supported placement, identity model, availability, and NMe support. Do not substitute ordinary Azure-hosted AVD with hybrid-joined devices for this track. |
| Azure Local | Define the on-premises platform and hardware boundary, supported identity integration, private connectivity to the domain, and required local identity availability during WAN or Azure outages. Verify NMe support for the selected platform/version. |
| AVD on Azure with hybrid identities | Use Azure-hosted session hosts with the existing AD DS/DNS foundation and the supported Entra synchronization path. Explicitly choose the host join model: hybrid user identities do not automatically mean Microsoft Entra hybrid-joined devices. Define the workload subnet, delegated join OU, and profile storage when this track is implemented. |

After NVP onboarding, the next integration milestone is NMe directory/network configuration against the existing domain and a basic AD/DNS reachability check from the selected workload path. It does not authorize synchronization changes, domain-join accounts, firewall changes, desktop provisioning, or a change to DC operating hours without review.

### Installation And Handoff

1. **Review and approve inputs.** Confirm the private target tenant/subscription, empty-group name, region, resource-name prefix, policy support for the selected public-HTTPS access model, and Marketplace terms. Check the vendor's current quotas and bootstrap permissions: subscription Owner plus Global Administrator, or Privileged Role Administrator combined with Cloud Application Administrator. These are installer privileges, not blanket grants to the repository's automation app. The vendor readiness test creates and removes temporary Azure resources; it requires its own approval and is not read-only discovery.
2. **Deploy Marketplace through automation after approval.** Use [nme/Initialize.ps1](nme/Initialize.ps1) for package discovery, explicit required-provider registration, what-if, and `-Apply`. No manual wizard or template export is part of this route. Review vendor initialization/consent separately; use vendor-created identities rather than repurposing the generic repository identity or inventing a replacement template.
3. **Obtain the Install ID privately.** The documented location is **System > Updates > Install ID**, not an assumed ARM deployment output. Keep the actual ID only in ignored `.env` as `TARGET_NME_INSTALLATION_ID`; keep minimized installation evidence under ignored `private/`. If registration prevents access to that page, stop and ask Nerdio for the supported onboarding order rather than assuming an ID is available earlier.
4. **Operator hands off to Nerdio.** The operator sends the Install ID through the agreed private Nerdio channel for NVP onboarding. Wait for Nerdio to confirm the installation's applicable entitlement, edition/features, and activation. Partner eligibility, correspondence, terms, and approvals stay private; do not assume that partner onboarding makes Azure infrastructure free or that a Marketplace installation is already activated.
5. **Integrate the existing hybrid identity foundation.** First verify administrator sign-in, the registered installation, and its entitlement. Then review and configure the existing AD DS directory, selected workload network, DNS reachability, and delegated join inputs described above. Verify the actual Nerdio MCP connection and supported operations at this stage; missing MCP access need not block Marketplace installation or the manual ID handoff. Implementing each of the three hybrid tracks, provisioning desktops, and enabling Windows 365/Intune features still require their own reviewed implementation; initialization and directory integration do not prove a complete environment rebuild.

**Remaining steering:** implementation order for the three selected hybrid tracks, followed by review of concrete installation inputs and any required temporary governance exceptions. The dedicated empty NMe group in Sweden Central, public HTTPS with NMe Entra sign-in, and reuse of the existing AD DS domain are selected in the plan; these choices do not authorize installation or other Azure changes. The list above does not set a rollout order. The first checkpoint remains an accessible NMe installation plus the private Install ID handoff; directory/network integration follows onboarding, before desktop provisioning. The application can incur Azure charges while onboarding is pending. Confirm the minimum NMe entitlement with Nerdio; select minimum qualifying Microsoft bundles separately when a concrete workload is chosen. AD-based workload setup can need Entra synchronization and profile storage; do not add those prerequisites merely to obtain the installation ID without checking the supported onboarding sequence.

Sources checked 2026-10-15: [Nerdio installation guide](https://nmehelp.getnerdio.com/hc/en-us/articles/26124313550477), [installation preparation, resources, and permissions](https://nmehelp.getnerdio.com/hc/en-us/articles/44411071090317), and [finding the Install ID](https://nmehelp.getnerdio.com/hc/en-us/articles/43762239569037). These document product installation and ID retrieval; NVP-specific enrollment and commercial terms must be confirmed directly with Nerdio.

## Management Approach

Use native tools with one management owner per resource or setting:

All repeatable changes, including approved subscription prerequisites, must execute through versioned automation. Do not perform a one-off portal or shell mutation and leave only prose behind. Where a supported automation interface is unavailable, document the boundary and obtain approval for the manual step; do not claim it is automated. Authentication, registration, deployment, and external delegation remain distinct authorization boundaries.

| Area | Default tool | Reproducible source |
| --- | --- | --- |
| Azure infrastructure | Bicep, deployed with Azure CLI or Azure PowerShell | Parameterized Bicep templates; suitable Azure Verified Modules where they reduce work |
| Entra ID | Microsoft Graph PowerShell; Graph Bicep for supported resources where simpler | Declarative resource definitions or reviewed JSON settings with small, repeatable apply scripts |
| Intune | Microsoft Graph PowerShell | Reviewed JSON policy definitions, assignments, and narrowly scoped apply scripts |
| Nerdio Manager for Enterprise (NMe) | Azure Marketplace/vendor initialization for installation; Nerdio MCP for supported post-install management | Reviewed installation inputs, manual Install ID/partner handoff, then sanitized desired configuration and readback checks |

The [Graph PowerShell SDK](https://learn.microsoft.com/powershell/microsoftgraph/overview) is the supported replacement for AzureAD/MSOnline modules. [Intune exposes management APIs through Graph](https://learn.microsoft.com/graph/api/resources/intune-graph-overview?view=graph-rest-1.0). Prefer stable APIs; document any necessary beta dependency and its recovery path.

The [Graph Bicep extension](https://learn.microsoft.com/graph/templates/bicep/overview-bicep-templates-for-graph) covers a limited set of Entra resources, not all tenant settings. Its [documented limitations](https://learn.microsoft.com/graph/templates/bicep/limitations) include no what-if or deployment-stack support for Graph resources. Never mistake an Azure what-if result for an Entra change preview.

Nerdio owns the lifecycle of objects delegated to it. Bicep or Graph may reference those objects but must not independently reconcile the same settings. MCP executes operations; it is not a backup or source of truth. Verify the available Nerdio MCP operations, bootstrap requirements, permissions, and license tier before claiming that a workload is reproducible.

Start without Terraform state infrastructure, an always-on DSC runner, a custom MCP, or CI deployment credentials. [Microsoft365DSC](https://microsoft365dsc.com/) is an option for a concrete configuration workload when its tested resource coverage removes more code than its dependencies add; do not build a generic Graph reconciliation framework instead. Microsoft's [Tenant Configuration Management APIs](https://learn.microsoft.com/graph/unified-tenant-configuration-management-concept-overview) currently document snapshots and drift monitoring. Those capabilities alone do not provide a rebuild engine. Recheck coverage and release status when selecting a workload.

## Prerequisites

### Product Licensing

Document only the minimum qualifying bundle for the selected features and eligible users, not the larger license inventory a particular tenant happens to own. Use this format:

**Minimum qualifying bundle (required included components).** Add separate product licenses or add-ons only when the selected scenario actually requires them.

For the selected commercial knowledge-worker **branding and full Exchange mailbox customization** baseline, the minimum Business-family bundle is **Microsoft 365 Business Basic (Exchange Online Plan 1, SharePoint Online Plan 1 company-branding entitlement, Microsoft Entra ID Free)**, subject to the Business family's 300-user limit. This does not include desktop Office, Intune, Windows 365, or AVD entitlements. An eligible enterprise population can use **Office 365 E1 (Exchange Online Plan 1, SharePoint Online Plan 1, Microsoft Entra ID Free)** for this narrow baseline; it is an Enterprise-family alternative, not the universal minimum. Review qualifying frontline, education, and standalone combinations separately against the actual user eligibility and mailbox features rather than assigning knowledge-worker licenses or requiring P1/P2 universally. Existing target licenses are preserved, not selected or assigned by the customization scripts. Sources checked 2026-10-15: [plan options and seat limits](https://learn.microsoft.com/office365/servicedescriptions/office-365-platform-service-description/office-365-plan-options), [Exchange service description](https://learn.microsoft.com/office365/servicedescriptions/exchange-online-service-description/exchange-online-service-description), and [company-branding qualifying entitlements](https://learn.microsoft.com/entra/fundamentals/how-to-customize-branding). Permissions, consent, domain ownership, and mailbox provisioning are separate bootstrap requirements.

For the **proposed Intune/endpoint-security phase**, not an instruction to purchase or deploy, use these feature-qualified prerequisites:

| Proposed Feature / Eligible Population | Minimum Qualifying Route And Separate Entitlements |
| --- | --- |
| Core corporate Windows device/app management and Defender protection, commercial knowledge workers within the Business-family limit | **Microsoft 365 Business Premium (Intune Plan 1, Microsoft Entra ID P1, Microsoft Defender for Business)**. Maximum 300 users; qualifying Windows OS licensing/upgrade rights remain required. Business Premium is not a general Windows Enterprise-edition entitlement or permission to bypass Personalization CSP's Pro restrictions. |
| Enterprise-family management with Enterprise OS applicability and baseline endpoint prevention | **Microsoft 365 E3 (Windows Enterprise E3, Intune Plan 1, Microsoft Entra ID P1, Microsoft Defender for Endpoint Plan 1)**, subject to qualifying OS rights. This is the minimum proposed Enterprise-family route, not a universal minimum across all eligible bundles or standalone combinations. Add **Defender for Endpoint Plan 2** only when its EDR features are selected; Defender for Business's qualifying route already includes EDR. E5 is not a blanket prerequisite. |
| Cloud PC/AVD/Link management | The applicable endpoint-management components do not purchase Cloud PC/AVD access. Add the selected **Windows 365 subscription** and verify its qualifying Windows/Intune/Entra rights for user Cloud PCs; verify separate AVD access/OS rights for session hosts and applicable physical Link/service eligibility. Intune policy automation does not provision these entitlements or the hardware. |
| Optional capabilities | Remediations needs its documented Windows Enterprise E3/E5, Education A3/A5, or Windows VDA per-user entitlement; do not assume Intune Plan 1 or Business Premium alone qualifies. Intune Suite/add-ons and premium Teams organization backgrounds are separately reviewed only if selected. A device-only subscription is limited and does not replace all user-based features, MAM or Conditional Access licensing. |

Feature/eligibility sources checked 2026-10-15: [Intune licensing](https://learn.microsoft.com/intune/fundamentals/licensing), [Business Premium components](https://learn.microsoft.com/microsoft-365/admin/security-and-compliance/m365bp-security-faq), [Defender for Business and Plan 1/2 distinctions](https://learn.microsoft.com/defender-business/mdb-faq), [Personalization CSP applicability](https://learn.microsoft.com/windows/client-management/mdm/personalization-csp), [Windows 365 requirements](https://learn.microsoft.com/windows-365/enterprise/requirements), and [Remediations licensing](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations). Confirm the actual chosen feature set, user class, device/OS entitlement and product terms before implementation. Permissions, consent, enrollment/connectors, capacity and manual bootstrap remain separate gates; no licenses are assigned or changed by this plan.

Licensing examples illustrate the notation, not a selected workload or an additional repository prerequisite. Evaluate Business Premium and eligible frontline or education alternatives before declaring a minimum; disclose seat limits, user eligibility, and qualifying OS requirements. Do not assume the minimum E-series tier is the minimum across all eligible bundles.

NMe requires its own applicable entitlement; Azure consumption and separate product add-ons are not included merely because a Microsoft 365 bundle is present. Select and verify the minimum NMe edition against the features actually used. No tenant's purchased licenses, license counts, financial approvals, or spending details belong here.

Add a feature-specific licensing row, official source, and verification date when each workload is implemented. Do not make P2, Intune Suite, or E5 a blanket prerequisite because it is available in one environment.

### Tenant Bootstrap

The goal is licensing plus the smallest documented bootstrap. Licensing alone cannot authorize or guarantee deployment.

1. An existing destination tenant, an authorized sign-in, and an active Azure subscription where the chosen workload needs one.
2. Required least-privilege roles, API consent, and an authenticated Nerdio MCP connection for Nerdio-managed features. Initial consent cannot grant itself.
3. Private environment inputs in local `.env`; verify the configured target tenant and subscription IDs before use.
4. Required regional capacity, quotas, provider registrations, and any external domain verification or vendor enrollment. Prefer cloud-only Entra join and Microsoft-hosted networking where the workload allows it.
5. A documented, version-pinned tool bootstrap for each implemented workload. Install only needed modules; prefer interactive authentication initially and federation or managed identity for later automation.

## Access Setup

Use **one single-tenant app registration in the configured LeafIT tenant** for ongoing automation. Registering it in the Entra portal also creates its service principal under **Enterprise applications**; do not create a separate gallery application.

This section prepares read/write capability only for the configured target. It does not authorize changes to existing resources. No applications, grants, or certificates are created merely by cloning this repo or filling `.env`.

### Local Profile

Keep these values only in local `.env`. Missing values for the chosen operation must block connections, not select a default tenant.

| Value | Target setting |
| --- | --- |
| Directory (tenant) ID | `TARGET_TENANT_ID` |
| Azure subscription ID | `TARGET_SUBSCRIPTION_ID` |
| Application (client) ID | `TARGET_CLIENT_ID` |
| Certificate thumbprint | `TARGET_CERTIFICATE_THUMBPRINT` |

Use the **Application (client) ID**, not either application or enterprise-application object ID. Verify that the subscription belongs to the configured tenant. Existing unprefixed settings such as `SUBSCRIPTION_ID` are not fallback values. `.env` is data and is not automatically loaded by PowerShell; never dot-source it or use `Invoke-Expression` to load it.

The target certificate and private key must be available to the executing Windows account in `Cert:\CurrentUser\My`. A thumbprint alone is not a credential. Keep private keys in the certificate store, not in `.env`, Git, chat, or logs. A new computer needs its own certificate registration or an approved protected credential recovery process.

### Create The Target Identity

Perform these steps only in the target tenant, checking the selected directory before making changes. The bootstrap operator needs permission to register apps, an appropriate role to grant Graph application consent (normally Privileged Role Administrator or Global Administrator), and Azure role-assignment rights at the intended scope. These are operator permissions, not roles to assign to the automation app.

1. In **Microsoft Entra admin center > App registrations > New registration**, use a generic name such as `LeafIT automation`, select **Accounts in this organizational directory only**, leave the redirect URI empty, and register. Record the tenant ID and client ID in the `TARGET_` fields in `.env`.
2. Obtain an authentication certificate for the target app. Prefer an organization-managed certificate for production; the local test-certificate procedure below is an alternative for a lab. The private key stays with the execution account.
3. In the app's **Certificates & secrets > Certificates**, upload only the public `.cer` file. Put its thumbprint in `TARGET_CERTIFICATE_THUMBPRINT` and record the intended Azure subscription ID in `TARGET_SUBSCRIPTION_ID`. Track expiry privately and rotate before expiry; do not create a client secret as well.
4. In **Azure portal > intended subscription or resource group > Access control (IAM) > Add role assignment**, select **Contributor**, then **User, group, or service principal**, and select this tenant's app. Contributor provides resource-management reads and writes, including deletion, but not role assignment. Use subscription scope only if the whole subscription is intended; otherwise scope to the managed resource group. Reader suffices when only discovery is needed. Do not grant Owner by default; handle RBAC assignments and resource data-plane access separately if a selected deployment requires them.
5. In **App registrations > API permissions > Add a permission > Microsoft Graph > Application permissions**, add only the workload permissions selected below, then have the authorized admin **Grant admin consent** in the target tenant. Remove the default delegated `User.Read` permission if present and unused. Consent must show as granted; listing requested permissions is not enough.

Azure Contributor does **not** grant Intune or Entra administration. Conversely, Graph consent does **not** grant Azure subscription access. See Microsoft's [app and service-principal setup](https://learn.microsoft.com/entra/identity-platform/howto-create-service-principal-portal) and [Graph app-only authentication](https://learn.microsoft.com/powershell/microsoftgraph/app-only).

### Local Test Certificates

For a lab, run this once from the repository root in **Windows PowerShell 5.1**. It creates one non-exportable target private key in the current user's certificate store and exports only its public certificate under ignored `private/`. Do not rerun to reconnect; reuse the existing certificate. Use `certmgr.msc` or the certificate upload page to obtain its thumbprint privately.

```powershell
$ErrorActionPreference = 'Stop'
git check-ignore --quiet -- private/leafit-target.cer
if ($LASTEXITCODE -ne 0) { throw 'Certificate output must be ignored by Git.' }
$tracked = @(git ls-files -- private)
if ($LASTEXITCODE -ne 0 -or $tracked.Count -ne 0) { throw 'Private files must not be tracked.' }
New-Item -ItemType Directory -Path private -Force | Out-Null
$certificate = New-SelfSignedCertificate -Subject 'CN=LeafIT-target' `
	-CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy NonExportable `
	-KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 `
	-NotAfter (Get-Date).AddMonths(12)
Export-Certificate -Cert $certificate -FilePath 'private/leafit-target.cer' | Out-Null
```

Upload this public certificate only to the target app. Never upload a private-key export. This follows Microsoft's [certificate-authentication guidance](https://learn.microsoft.com/entra/identity-platform/howto-create-self-signed-certificate).

### Graph Permissions

Select application permissions for the **target app** according to actual operations; this is **not a grant-all checklist**. The read/write permission normally includes the corresponding reads; do not add both automatically. Application permissions can apply across the tenant, not just the named Azure subscription, and some sensitive operations need additional authorization or do not support app-only access.

| Selected operation | Read-only permission | Read/write permission when required |
| --- | --- | --- |
| Organization and license inventory | `Organization.Read.All` | None needed for inventory; license assignment is separate |
| Default company branding | `OrganizationalBranding.Read.All` | `OrganizationalBranding.ReadWrite.All`; a supported branding administrator role is also required for delegated writes |
| Ordinary user management | `User.Read.All` | `User.ReadWrite.All` |
| Read directory roles for migration safety | `RoleManagement.Read.Directory` | No role writes are part of customization |
| Group management | `Group.Read.All` | `Group.ReadWrite.All`; privileged/role-assignable groups need separate review |
| Application configuration | `Application.Read.All` | Prefer `Application.ReadWrite.OwnedBy` for owned apps; broader access needs explicit review |
| Conditional Access | `Policy.Read.All` | `Policy.ReadWrite.ConditionalAccess`; test report-only before enforcement |
| Intune configuration/compliance policies and assignments | `DeviceManagementConfiguration.Read.All` | `DeviceManagementConfiguration.ReadWrite.All` |
| Intune apps and app policies | `DeviceManagementApps.Read.All` | `DeviceManagementApps.ReadWrite.All` |
| Intune enrollment/service configuration | `DeviceManagementServiceConfig.Read.All` | `DeviceManagementServiceConfig.ReadWrite.All` |
| Intune managed-device records | `DeviceManagementManagedDevices.Read.All` | `DeviceManagementManagedDevices.ReadWrite.All`; remote privileged actions are separate |

Check the endpoint's current least-privileged application permission before granting. Avoid blanket `Directory.ReadWrite.All`, directory-role management, admin-consent grants, device wipe permissions, or password/secret retrieval permissions. Additional scopes for scripts, Intune RBAC, other Entra policies, or other products must be justified by a chosen operation. Use the [Microsoft Graph permissions reference](https://learn.microsoft.com/graph/permissions-reference) and each endpoint's permission table. Guidance checked 2026-10-08.

### Connection And Verification

For the target, use `Az.Accounts` for Azure certificate-store authentication: `Connect-AzAccount` with `-ServicePrincipal`, `-Tenant`, `-ApplicationId`, `-Subscription`, and `-CertificateThumbprint`. For Graph use `Microsoft.Graph.Authentication`: `Connect-MgGraph` with `-TenantId`, `-ClientId`, `-CertificateThumbprint`, and `-ContextScope Process`. These are two token contexts even when they use the same app and certificate. Azure PowerShell sessions do not authenticate Azure CLI; use Azure PowerShell for Bicep deployment with this certificate-store setup.

Target management loads only `TARGET_` inputs as data and rejects missing or malformed IDs. For app-only authentication, verify certificate private-key availability and validity before connecting; otherwise use an explicitly targeted authorized interactive sign-in. Use process-scoped contexts and disable Azure context autosave for the process. Privately compare the resulting tenant, authentication identity, and subscription IDs with the target profile before any operation; never use an unrelated cached session. Never print tokens or full contexts to shared logs. [identity/Target.ps1](identity/Target.ps1) supplies narrow shared guards and Graph request/session helpers for the selected customization scripts, not a generic deployment engine. [collaboration/exchange/Initialize-Session.ps1](collaboration/exchange/Initialize-Session.ps1) verifies native Exchange authentication separately. DNS continues to use its guarded Bicep preview/apply workflow. The selected [reapply procedure](branding/README.md#remaining-limits) explains bootstrap and unsupported boundaries.

First validate target access with read-only calls and inspect effective role/consent grants. Authentication success alone does not prove write access. Prove target writes only with an explicitly authorized, scoped workload test. Nerdio MCP authentication and its permissions remain separate from the Azure/Graph profile.

## Rebuild Contract

Separate shared foundation and tenant policy modules from scenario-specific provisioning, assignments, and tests. Use logical resource/group references and resolve newly generated IDs during apply; never replay tenant exports or old onboarding packages as portable desired state. Keep tenant-specific inputs and runtime mappings private, and use synthetic data for demonstrations.

Each implemented showcase must include a prerequisite/license checklist, versioned desired state, its management owner, documented manual bootstrap, acceptance checks, and a scoped reset procedure. Confirm product eligibility and hardware separately. Scenario reset must preserve shared services and retained data; a passing test for one product is not proof for the other scenarios.

This is the acceptance contract for every selected scenario. Concrete commands exist for the foundation, identity infrastructure, and the [implemented customization subset](branding/README.md#remaining-limits); they do not imply that the other showcase scenarios are implemented:

1. **Preflight:** validate licenses, private target identity, permissions, required inputs, tool versions, and API/MCP coverage without making changes.
2. **Preview:** compare live target state against the versioned desired state and show the proposed changes. Use Azure what-if where supported and explicit comparisons for Graph and Nerdio. Flag replacements and deletions.
3. **Apply:** create dependencies in order and update only owned settings. Resolve target IDs from logical references; do not hard-code runtime IDs or rely on non-unique display names. Never prune unmanaged objects implicitly.
4. **Verify:** read back settings, relationships, assignments, and workload health. Handle pagination, throttling, asynchronous jobs, and eventual consistency using bounded, supported behavior.
5. **Rebuild test:** test another eligible clean tenant and a repeated apply with no intended changes, using only versioned definitions, new private target inputs, and documented bootstrap. Verify the selected user, device, and agent journeys as well as resource creation. Keep a scoped recovery procedure and private evidence. Mark unsupported or manual steps explicitly.

User data, mailbox contents, passwords, MFA methods, device enrollment, and service-generated identity IDs are not restored merely by recreating configuration. Backup and recovery for these require a separate plan and authorization. Test Conditional Access in report-only mode with verified emergency access before enforcement.

## Public And Private Files

| Location | Purpose |
| --- | --- |
| Versioned templates, policy definitions, scripts, and documentation | Generic, sanitized desired state and repeatable procedures |
| `.env` (ignored) | Tenant-specific identifiers, credentials or secret references, subscription settings, and private commercial information |
| `private/` (ignored) | Minimized target inventory, raw exports, target-ID mappings, deployment evidence, and recovery notes; restrict access and protect sensitive backups |

Never publish raw exports or assume they contain no secrets. Keep private values out of terminal output, public CI logs, issues, pull requests, examples, skills, and assistant memory. Ignore rules do not protect files already tracked by Git; check both tracking and ignore status before staging. Use an independent, protected backup for private inputs if recovery must survive loss of the local machine.

## Working Conventions

[Repository instructions](.github/copilot-instructions.md) make **Ponytail** and **i-have-adhd** always on: minimal correct changes, native tools first, short actionable updates, and focused verification. No personal plugin installation is required.

- [Environment skill](.github/skills/leafit-environment/SKILL.md): target preflight, ownership, safe deployment, and repeatable rebuild.
- [Licensing skill](.github/skills/leafit-licensing/SKILL.md): feature-specific minimum bundles and required component notation.
