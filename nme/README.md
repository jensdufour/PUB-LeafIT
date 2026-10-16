# Nerdio Manager For Enterprise

Marketplace bootstrap, the private installation-ID handoff, and supported vendor hardening for the LeafIT management plane. This workload has its own dedicated group in Sweden Central; it does not own the shared public DNS zone or the existing DCs.

## Implemented Coverage

[desired.json](desired.json) records portable installation, access, hardening, sizing choices, and the reviewed Marketplace plan/version/template hash. [Initialize.ps1](Initialize.ps1) reuses [identity/Target.ps1](../identity/Target.ps1), resolves the shared brand, discovers the exact vendor package, and separates provider registration, read-only preview, and explicit resource deployment. It never signs in, switches tenants, applies exception tags, or grants consent as a side effect.

Discovery uses the subscription-scoped Microsoft Marketplace Catalog API `2025-05-01`, not the obsolete tenant-root Gallery endpoint. The offer is an Azure Application **Solution Template**. [main.bicep](main.bicep) creates the dedicated group and calls the downloaded vendor template unchanged. No portal wizard or manual template export is required. Application initialization, consent, registration, NVP activation, post-install actions, and native portal branding remain distinct from Azure resource deployment.

## Ownership And Brand

| Owner | Contract |
| --- | --- |
| Shared foundation | [infra/main.bicep](../infra/main.bicep) continues to own public DNS and its shared group. No NMe reset deletes or redeploys it. |
| Identity | Existing identity definitions retain DC networking, guest configuration, backup, and power-schedule ownership. NMe consumes the directory and private DNS for selected hybrid workloads; it does not adopt the DCs as session hosts. |
| NMe | Marketplace and supported Nerdio actions own the application, its dependencies, private endpoints, and vendor-created networking/DNS. Bicep and Graph must not reconcile the same objects independently. |
| LeafIT identity | [branding/brand.json](../branding/brand.json) owns the exact name, descriptor, colors, and typography; [branding/README.md](../branding/README.md) owns the approved service exports. Do not create a second palette, redraw logos, invent partner badges, or patch vendor CSS. |

Use **LeafIT** and **Global IT consultancy** on supported organization-facing surfaces. The prefix defaults to the shared brand name in lowercase. It must contain 2-7 lowercase letters/digits/hyphens, start with a letter, and end with a letter/digit so the vendor-generated Key Vault name fits its limit. The vendor template supplies stable unique suffixes. Group/VNet/subnet names follow CAF; other children follow the vendor's naming contract. Existing identities are not renamed for branding.

Use the existing Entra company-branding owner for Microsoft sign-in. NMe continues to perform its own supported Entra authentication; do not enable a separate App Service authentication provider. Native NMe portal logo/theme customization has not been established by the reviewed guidance: use it only after the actual edition, supported settings, and asset dimensions are verified. Do not assume that NMM white-label features apply to NMe or publish assets anonymously as a shortcut.

The recent cloud UPN/email branding changes do not change the target tenant/subscription IDs or transfer AD ownership. Resolve the intended custom domain and actual administrator identities from the current private target. Preserve the protected Microsoft administrator's initial-domain sign-in and email, current object IDs, consent, aliases, roles, and licenses; NMe onboarding does not run the identity migration again.

## Automated Deployment

Run from the repository root in the retained target PowerShell 7.6 process:

```powershell
& ./nme/Initialize.ps1 -CheckOnly
& ./nme/Initialize.ps1
& ./nme/Initialize.ps1 -RegisterProviders
& ./nme/Initialize.ps1 -Apply
& ./nme/Initialize.ps1 -Verify
```

`-CheckOnly` is offline: target parsing, wrong package/version/URI rejection, network overlap, and deployment-scope checks. The default command is Azure read-only: it verifies the target, retrieves and hashes the vendor template, checks providers/network overlap, compiles the composition, and runs subscription-scoped what-if. Missing providers are reported without registration. All target artifacts stay in ignored `private/nme/`.

`-RegisterProviders` requires approval for the package's exact prerequisites. It registers missing required providers and reads back their state; `Registering` stays pending, without a wait/retry loop. Once Registered, repeat registration is a no-op. `-Apply` repeats the guarded preview and refuses deletion or mutation outside the dedicated group before native Azure deployment. Do not overlap applies.

`-Verify` is the read-only path for an existing installation; it never replays bootstrap or overwrites the installer plan. It checks public management access, HTTPS/FTP/EasyAuth, VNet integration, Entra-only SQL, private backend access, approved endpoints, storage key-authentication state, and an HTTPS response from the ARM-reported app address. Normal Host/SNI and TLS verification remain enabled; system DNS is not modified. Detailed evidence stays in ignored `private/nme/verification.json`.

Existing `.env` inputs are `TARGET_TENANT_ID`, `TARGET_SUBSCRIPTION_ID`, `TARGET_DNS_ZONE_NAME`, `TARGET_LOCATION`, `TARGET_REGION_CODE`, and `TARGET_INSTANCE`. Optional reviewed NMe overrides are `TARGET_NME_RESOURCE_GROUP_NAME` and `TARGET_NME_RESOURCE_NAME_PREFIX`; the group must follow `rg-nme-swc-<instance>`. Keep actual values private. No missing input falls back to another tenant or subscription.

Review the private group/prefix and what-if before creation. The wrapper selects vendor parameters `configurePrivateEndpoints=true` and `privateWebApp=false`, retaining the template's SQL managed-identity/Entra-only configuration and disabled FTP. Vendor address defaults are used only after checking existing subscription VNets for overlap; an overlap stops rather than inventing a new range. No peering or DC/network ownership change is included. Check bootstrap roles, Sweden Central availability/quota, and the [governance rules](../README.md#governance-and-expiry). The vendor readiness test creates resources and is not a read-only check. No sizing exception is selected.

## Marketplace And Onboarding

1. **Resolve and preview automatically.** Use the commands above. The current package must match the reviewed plan/version and SHA-256. A changed or unavailable package stops; there is no portal/export fallback or improvised template.
2. **Deploy after approval.** `-Apply` deploys the exact package into the new/empty group with private core dependencies and the public portal retained. Existing DNS, DCs, accounts, and endpoint policy are outside this deployment. The private plan distinguishes ARM completion from application initialization.
3. **Initialize through the vendor script.** [Initialize-Application.ps1](Initialize-Application.ps1) retrieves and validates the installed portal's native initializer and executes it only with explicit `-Apply`. It preserves vendor configuration/publish hooks, adapts authentication/publishing to the retained target session, and restores approved temporary backend access. Generated secrets belong in the supported secret store, not public artifacts/logs. Resource creation or script completion alone does not prove registration, consent, or entitlement.
4. **Hand off the installation ID.** Read **System > Updates > Install ID** and retain it only as `TARGET_NME_INSTALLATION_ID` in `.env`. The operator provides it to Nerdio through the agreed private channel for NVP onboarding. Vendor confirmation of activation/entitlement is separate from Azure deployment; paid Azure infrastructure can exist while onboarding is pending.
5. **Complete hardening and verify it.** Core private endpoints are selected during deployment. The vendor action below covers installed optional/scripted-action components and verifies their behavior. Use supported NMe MCP operations after actual capability discovery; an unavailable operation is an explicit automation gap, not permission to invent an endpoint or substitute manual setup.

Authentication, consent, and vendor activation are separate boundaries. No script claims those stages have completed. Keep sign-in/MFA directly with Microsoft, never in chat. Catalog, permission, policy, or quota failure stops the workflow without an unsupported fallback.

## Network And Directory Linking

[identity/Initialize-NmeDirectory.ps1](../identity/Initialize-NmeDirectory.ps1) prepares the existing AD foundation for the initial Network/Directory fields. It does not deploy session hosts, profile storage, directory synchronization, host pools, Windows 365, or Intune configuration.

```powershell
& ./identity/Initialize-NmeDirectory.ps1 -CheckOnly
& ./identity/Initialize-NmeDirectory.ps1
& ./identity/Initialize-NmeDirectory.ps1 -Apply
```

Default invocation inspects the existing DC and produces network what-if without changing AD objects or network resources. Apply creates only a non-overlapping `snet-avd` workload subnet and its NSG, using the existing identity VNet, both DC DNS servers, and the existing NAT gateway. The DC NSG allows only required AD TCP/UDP ports from that subnet to the two DC addresses; interactive management remains denied. The NMe management/private-endpoint VNet is not a session-host subnet. No peering, egress-resource changes, DC VM redeployment, backup changes, or power-schedule changes are included.

The existing network owner is [identity/network/resources.bicep](../identity/network/resources.bicep), reused by the full DC deployment and the network-only path. The selected private subnet input is preserved by [identity/Deploy.ps1](../identity/Deploy.ps1) so a later full deployment does not discard it. Azure what-if's omission of one known empty provider array is not treated as functional drift; real subnet/NSG changes remain guarded.

The directory definition creates one protected computer OU and one dedicated, enabled, non-privileged join account with six narrow computer-join rules on that OU. It does not grant Domain Admins, change the domain machine-account quota, relax existing-computer reuse policy, disable password expiry, or migrate cloud identities. The managed account/OU are ownership-marked; unrelated or privileged existing objects are rejected. The generated credential stays DPAPI-protected in ignored `.env`, passes through secure ARM/protected guest parameters only, and is never printed. Verification checks the exact delegation and a signed/sealed authenticated LDAP bind on both DCs. Password rotation and updating the stored NMe credential before expiry remain separate operations.

Actual link values are written only to ignored `private/identity/nme/linking.json`; actual subnet/domain/account/OU inputs and the protected password stay in ignored `.env`. Use those values in the wizard:

1. **Network:** select the prepared `snet-avd` in the existing AD-connected identity VNet, not `snet-adds` or NMe's App Service/private-endpoint subnets.
2. **Directory:** choose existing Active Directory and use the private `domainName`, `joinAccountUpn`, and `computerOuDn` fields. Do not reuse the cloud administrator or the domain recovery credential.
3. **Password:** run `& ./identity/Initialize-NmeDirectory.ps1 -CopyJoinPassword` locally and paste it into NMe. This explicit operation copies the secret without displaying it; clear the clipboard afterward.
4. **File Storage:** choose the vendor's skip-for-now option when no profile store has been selected. No fabricated UNC path or extra storage account is created.

This prepares linkable network/directory infrastructure, not a completed NMe link or an end-to-end domain-joined desktop test. NMe remains the owner of its linked-network/directory configuration; existing AD/DC/network definitions retain their current owner. AD-to-Entra synchronization is unchanged and remains a separate prerequisite for workloads that require hybrid users. The three hybrid product tracks are not made equivalent by this shared preparation. The weekday DC operating window still applies.

## Storage Authentication Compatibility

The pinned vendor template creates SAS/key-based data-protection and locks-storage configuration. Private endpoints restrict network access; they do not replace that authentication. If effective governance sets storage `allowSharedKeyAccess=false`, the application can return HTTP 500 with `KeyBasedAuthenticationNotPermitted` even when every private endpoint is approved. `-Verify` reports the actual storage setting; inspect minimized application-exception evidence privately rather than opening backends or repeatedly redeploying.

The reviewed vendor hardening references do not establish a keyless replacement for this path. Do not invent application settings, rewrite vendor secrets, or weaken policy as an automatic fix. An exception and authentication-setting change require explicit approval, documented scope/expiry, versioned automation, fresh verification, and no automatic renewal. Without approval or a verified supported keyless path, leave the control intact and mark initialization/Install ID retrieval blocked, not completed. NMe Azure resources can incur charges while application setup is blocked.

[Set-StorageCompatibility.ps1](Set-StorageCompatibility.ps1) implements that separately approved, storage-only compatibility change:

```powershell
& ./nme/Set-StorageCompatibility.ps1 -CheckOnly
& ./nme/Set-StorageCompatibility.ps1
& ./nme/Set-StorageCompatibility.ps1 -Apply
& ./nme/Initialize.ps1 -Verify
```

Default invocation is read-only. `-Apply` resolves the single vendor data-protection account from the verified installation, merges only its reviewed security-exception tag, and enables its required key authentication. It refuses public storage access, anonymous blob access, wrong resources, conflicting tags, incomplete private inputs, and expired/overlong windows. Other tags, the workload group, SQL, Key Vault, public DNS, and DCs are not changed. Repeated apply reports `NoChange` and never extends the recorded expiry.

The reviewed internal mechanism stays in ignored `private/nme-governance.json`. On first approved apply, the script records `TARGET_NME_STORAGE_EXCEPTION_TAG_NAME`, `TARGET_NME_STORAGE_EXCEPTION_TAG_VALUE`, `TARGET_NME_STORAGE_EXCEPTION_APPROVED_UTC`, and `TARGET_NME_STORAGE_EXCEPTION_EXPIRES_UTC` only in ignored `.env`. Existing inputs are preserved. These local timestamps bound this automation; they do not independently prove the governance service's effective tracking/expiry. Verify actual behavior after apply. No cost exception, scheduled renewal, or replacement of an already-used exception window is implemented.

## Native Initialization Boundary

The installed portal provides its own bootstrap download at `api/nme-installer/install-scripts`, as referenced by the vendor's application bundle. Its successful JSON envelope exposes `data.cloudShellInstallScriptFull`. Treat the generated script as private: it includes target-specific values and can contain a short-lived signed package URL. Never print its literals or copy them into public documentation; retrieve a fresh script rather than replaying an expired download URL.

Review the generated script before execution. The standard new-application path can switch authentication contexts, register the Entra application, temporarily enable public SQL/Key Vault access, and publish the latest package. A storage-only exception does not approve those temporary network changes. Use the supported existing-application path only when its application/certificate prerequisites are actually in place. Any additional network change needs explicit approval, constrained access, versioned execution, and verified restoration; do not silently weaken the selected private-backend profile. Application initialization, Install ID retrieval, consent, activation, and final hardening remain unverified until their own acceptance checks pass.

### Guarded Application Initializer

```powershell
& ./nme/Initialize-Application.ps1 -CheckOnly
& ./nme/Initialize-Application.ps1 -ProbePrivateWorker
& ./nme/Initialize-Application.ps1 -ConnectGraph
& ./nme/Initialize-Application.ps1 -ConnectGraph -UsePrivateWorker -Apply
& ./nme/Initialize.ps1 -Verify
```

Default invocation is read-only. `-ConnectGraph` explicitly reuses the verified Azure session through the existing secure target helper; it does not silently sign in or grant permissions. The wrapper verifies the authoritative tenant and required bootstrap scopes before temporary access. It validates the generated script's literal installation bindings and refuses ambiguous or unrelated same-name Entra applications. A completed native installation is not replayed.

The small native-source compatibility adapter replaces session-clearing/context-switching calls with target assertions and retains vendor publish hooks while using SCM bearer authentication instead of basic publishing credentials. Newly created bootstrap certificates are limited to one month; continued certificate validity/rotation is a separate requirement. Installed native modules are reused; missing prerequisites come from the official PowerShell Gallery. Generated scripts, signed package URLs, tokens, raw output, and actual target mappings are never published.

Temporary SQL/Key Vault access requires its own approval, recorded only in ignored `.env` as `TARGET_NME_NATIVE_INITIALIZATION_NETWORK_ACCESS_APPROVED_UTC`. The current caller is allowlisted with default deny and no bypass. The current Key Vault API is read back before certificate operations; a successful update response alone does not prove public access persisted or governance permits it. If that readback fails, the initializer stops. Authorization for temporary networking does not implicitly authorize a broader governance exemption.

The original private network snapshot is preserved under ignored `private/nme/`. Cleanup independently attempts to disable both backend public endpoints, restores original firewall/ACL settings, removes the owned temporary caller rule, deletes owned temporary PFX exports, and verifies private access. Redacted stage/error classifications stay private. After failure, inspect actual state and the original recovery evidence before any retry; do not remove governance controls, renew exceptions, or reuse an expired installer URL automatically. Native configuration, application registration, Install ID retrieval, consent, activation, and final hardening remain distinct acceptance checks.

### Private Worker And Publish Resume

`-ProbePrivateWorker` performs read-only DNS/TCP checks on the existing VNet-integrated App Service worker and verifies delegated private certificate access. It does not create compute, assign permissions, or open backend public access. [PrivateWorker.ps1](PrivateWorker.ps1) implements the selected private certificate/SQL adapter. `-UsePrivateWorker` requires that probe and verifies the app's existing managed identity is already SQL administrator; it never adds a new SQL administrator just to make this path work.

Graph application setup and publishing stay local. Only the narrowly allowlisted certificate and SQL operations run through the documented SCM command interface. A one-use, short-lived target-bound credential packet is staged outside the web root and deleted before backend work; the accompanying non-secret script is invoked with a short command and removed as well. Cleanup also runs on the client. Tokens, certificate exports, and raw worker output are not put on command lines or published in logs. SQL identity bytes and connection-string keywords have focused offline regression checks. Private mode leaves SQL and Key Vault public endpoints disabled throughout these operations.

If certificate and SQL setup completed but publishing failed, resume only publishing:

```powershell
& ./nme/Initialize-Application.ps1 -ConnectGraph -UsePrivateWorker -PublishOnly -Apply
```

This mode requires private evidence of completed certificate/SQL work and restored access, verifies the saved native script's exact target bindings, and rejects an expired signed package URL or one with less than fifteen minutes of validity. It retains the vendor package and before/after publishing hooks but excludes already completed application/certificate/SQL configuration. The installer download endpoint can disappear after application configuration; a still-valid reviewed artifact is used only for this guarded recovery. Never infer successful publishing from the absence of that endpoint.

Publisher failures record only stage, HTTP status, and transport exit code privately. A completed native installation is not replayed. Verify that the app and provision job are running, SCM basic authentication remains disabled, backend access remains private, and HTTPS redirects to the intended tenant's Microsoft sign-in. This proves the bootstrap/access path, not a successful authenticated administrator session, vendor registration, NVP activation, post-install action execution, or Install ID retrieval. Those results must be recorded separately and actual IDs remain only in ignored `.env`.

### Vault-Only Bootstrap Exception

[Set-VaultBootstrapException.ps1](Set-VaultBootstrapException.ps1) implements the separately approved, resource-only governance exception when temporary Key Vault public access cannot persist. It merges only the reviewed security-exception tag on the single verified NMe vault; it does not open networking, change SQL/storage, or tag the workload group. Other tags, RBAC, and the approved private endpoint are preserved.

```powershell
& ./nme/Set-VaultBootstrapException.ps1 -CheckOnly
& ./nme/Set-VaultBootstrapException.ps1
& ./nme/Set-VaultBootstrapException.ps1 -Apply
& ./nme/Initialize-Application.ps1 -ConnectGraph -Apply
& ./nme/Initialize.ps1 -Verify
```

The first approved apply records `TARGET_NME_VAULT_EXCEPTION_TAG_NAME`, `TARGET_NME_VAULT_EXCEPTION_TAG_VALUE`, `TARGET_NME_VAULT_EXCEPTION_APPROVED_UTC`, and `TARGET_NME_VAULT_EXCEPTION_EXPIRES_UTC` only in ignored `.env`. The mechanism/window comes from the reviewed ignored governance reference. Repeated apply is `NoChange` and retains the first expiry; unknown existing exceptions, conflicting tags, incomplete inputs, and expired/overlong windows are rejected. No cost exception or automatic renewal is added. A tag readback alone does not prove effective enforcement: the native initializer still verifies actual temporary-access readback and restoration.

Bootstrap must run from a stable egress address or an explicitly reviewed private execution path. A generic public-IP lookup can differ from the address Key Vault observes. The initializer accepts one service-reported IPv4 `/32` correction, preserving default deny and no bypass; it never learns an expanding address list. If subsequent requests use different egress addresses, stop and use a stable supported execution location rather than widening the allowlist, enabling `AzureServices` bypass, or repeatedly reopening the vault. Such a stop leaves application initialization/Install ID retrieval incomplete and restores private backend access.

## Hardening Sequence

1. **Prepare execution and inputs.** Verify the installed release and **Enable Private Endpoints** action; switch Azure Runbook Execution Mode to **Inline Script before** restricting scripted-action storage. Review a non-overlapping VNet, dedicated App Service subnet, private-endpoint subnet, private DNS, outbound licensing/Azure endpoints, and any explicitly required peer networks. Preserve AD subnet ownership and do not peer every linked VNet automatically.
2. **Run the vendor action.** Use `MakeAppServicePrivate=false`, `CssaStorageAccount=Private`, and `SkipDNS=false`. Supply reviewed network/DNS inputs, not the vendor's illustrative address ranges blindly. Confirm that the action's worker-side SQL, Key Vault, and DPS storage probes pass before public backend access is disabled. Do not add optional modules or a Hybrid Worker VM merely to perform the initial hardening.
3. **Complete supported component hardening.** Disable FTP, apply the documented Entra-only SQL configuration after testing the connection, and verify private Key Vault/storage access, TLS, and disabled anonymous blobs. Shared-key authentication is distinct from network hardening and is not assumed solved by private endpoints. Apply app/SCM IP restrictions only with approved source ranges; making the portal itself private conflicts with the selected internet-access requirement.
4. **Verify both network directions.** Confirm public HTTPS reaches NMe's Entra sign-in and an authorized administrator can sign in; confirm unauthenticated access is not granted. Read back private backend access/DNS and run one harmless vendor-supported functional check. The vendor action does not make ARM, Monitor, Log Analytics, or Application Insights private, and does not add every storage sub-resource endpoint.
5. **Retain the actual result privately.** Keep minimized job output, parameter references, source/version/hash, and acceptance results under ignored `private/nme/`. Do not mark hardening, NVP activation, branding, scheduled startup, or clean-tenant rebuild verified merely because a job completed. The action never re-enables public access; `MakeAppServicePrivate=false` does not undo a previous private-portal configuration.

Normal downsizing is accepted. Test that the resulting tier still supports the VNet integration required by hardened backends; investigate actual broken demo functionality, not deviation from recommended sizing. No automatic scale-back-up or recurring ignore-tag renewal is part of this workflow. Public-portal governance remains a separate restriction even when the backends are hardened.

## Repeat And Recovery

Checks/previews are read-only; provider registration is a no-op once Registered. Bootstrap refuses an installed/non-empty group. After successful or partial deployment, inspect the named `nme-bootstrap` subscription deployment and use the vendor repair/update path; never replay or automatically delete the group. The built-in hardening action can be rerun for installed/newly enabled components, but never relaxes restrictions. Verify private reachability before reducing access and retain a reviewed recovery/admin path.

For another eligible tenant, use its own `.env`, current brand source, empty workload group, Marketplace package, consent, new Install ID, and vendor onboarding. Old installation IDs, secret values, or private runtime mappings are not portable. NMe configuration recreation is not data backup or identity preservation. The [three hybrid tracks](../README.md#hybrid-scenarios) remain separate implementations after this management-plane bootstrap.

## Maintenance And Acceptance

Before handing over or archiving a setup session, retain the actual target's minimized results under ignored `private/nme/` and keep secrets/identifiers only in ignored `.env`. User-confirmed wizard completion is not independent API, entitlement, or workload acceptance. Public documentation describes implemented definitions, not a tenant's operating record.

- **Partner handoff:** record `TARGET_NME_INSTALLATION_ID` privately and complete the external NVP handoff. Verify the actual entitlement/edition; completing the setup wizard does not prove activation.
- **Certificates:** new bootstrap certificates are intentionally short-lived. Review their actual expiry privately, use the vendor-supported renewal procedure, and verify the Entra/application and scripted-action dependencies before expiry. Automatic rotation is not implemented here.
- **Join credential:** AD password expiry remains enabled. Rotate through reviewed automation and update the protected local/NMe credential consistently; do not disable expiry or reset an unknown existing account to make a link pass.
- **Exceptions:** retain the original private scope/expiry record and never renew automatically. Reassess and remove an unused bootstrap-only exception when it is no longer required. Storage compatibility still depends on the reviewed SAS/key path; removing that exception without a tested replacement can break the application.
- **Acceptance:** verify actual NMe network/directory linking, administrator access, selected scripted-action hardening and Inline Script mode, then the chosen workload. AD-to-Entra synchronization, FSLogix/profile storage, session hosts, physical devices, forest recovery, and another-tenant reconstruction are not implied by this bootstrap.

Vendor references: [installation](https://nmehelp.getnerdio.com/hc/en-us/articles/26124313550477), [security and permissions](https://nmehelp.getnerdio.com/hc/en-us/articles/43762191552909), [hardening overview](https://nmehelp.getnerdio.com/hc/en-us/articles/26124315691149), [hardening parameters](https://nmehelp.getnerdio.com/hc/en-us/articles/26124385359757), and [Entra-only SQL](https://nmehelp.getnerdio.com/hc/en-us/articles/26124311294733). Recheck the chosen installer/action version before execution.