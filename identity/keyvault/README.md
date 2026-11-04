# Identity Credential Vault

[Deploy-CredentialVault.ps1](../Deploy-CredentialVault.ps1) deploys [resources.bicep](resources.bicep) into an existing identity member VM's resource group. It does not redeploy the VM, domain controllers, networking, schedules, backups or Nerdio resources.

## Private Inputs

Keep these selectors only in the ignored local `.env`, alongside the existing target tenant, subscription and custom-domain inputs:

```dotenv
TARGET_IDENTITY_RESOURCE_GROUP=<existing-identity-resource-group>
TARGET_IDENTITY_KEY_VAULT_NAME=<reviewed-caf-vault-name>
TARGET_IDENTITY_KEY_VAULT_LOCATION=swedencentral
TARGET_IDENTITY_KEY_VAULT_OPERATOR_ID=<signed-in-user-object-id>
TARGET_IDENTITY_KEY_VAULT_CLIENT_IPV4=<operator-public-ipv4-without-cidr>
TARGET_IDENTITY_CREDENTIAL_VM_ID=<original-member-vm-resource-id>
TARGET_IDENTITY_CREDENTIAL_VM_INSTANCE_ID=<original-member-vm-instance-id>
TARGET_IDENTITY_KEY_VAULT_URI=<vault-https-uri>
TARGET_IDENTITY_BASTION_PASSWORD_SECRET_NAME=<reviewed-password-secret-name>
```

The name guards accept the existing `rg-identity-swc-<three-digit-instance>` group, its `vm-identity-swc-<three-digit-instance>-sync` member, and a `kv-identity-swc-<three-digit-instance>` vault with an optional short uniqueness suffix. The retained target user must match the configured operator. An already registered Key Vault provider, pinned API support, Az.Resources and Azure CLI's installed Bicep compiler are required; the command never signs in, switches targets or registers providers.

## Deployment

Run from the repository root in the retained authenticated target PowerShell process:

```powershell
& ./identity/Deploy-CredentialVault.ps1 -CheckOnly
& ./identity/Deploy-CredentialVault.ps1 -Mode Preview
& ./identity/Deploy-CredentialVault.ps1 -Mode Apply
& ./identity/Deploy-CredentialVault.ps1 -Mode Verify
& ./identity/Deploy-CredentialVault.ps1 -Mode Apply
```

The reviewed state is Standard Key Vault, Entra RBAC, purge protection, 90-day soft-delete retention, and disabled public network access, with a default-deny firewall and no trusted-service bypass. The retained operator IPv4 `/32` rule does not enable public access while public networking is disabled. Key Vault Secrets Officer is assigned only to the configured user at this new vault's scope so that user can maintain credentials. No managed identity or Nerdio application receives access.

Preview permits only the new vault and its exact scoped role assignment. Unrelated existing resources marked `Ignore` by ARM are not mutations. Apply requires a fresh matching preview, unchanged target/inputs/source, and the same in-memory compiled template used for its repeated what-if. An existing vault without matching creation evidence cannot be adopted. Existing-vault drift is never automatically corrected. Evidence remains under ignored `private/identity/keyvault/`.

Successful deployment is not acceptance: readback must confirm every owned security property and the exact User role assignment, and repeated Apply must return `NoChange`. ARM may omit `principalType` from what-if; creation still explicitly sets `User` and actual-state verification requires it. This is management-plane acceptance only: `DataPlaneAccessVerified` remains false and does not establish a working password picker, secret retrieval or Bastion session.

For an already created vault with an older public-intent record, explicitly reviewed private tightening can use this read-only reconciliation:

```powershell
& ./identity/Deploy-CredentialVault.ps1 -Mode Verify -ReconcilePrivateIntent
& ./identity/Deploy-CredentialVault.ps1 -Mode Apply
```

Reconciliation permits only the single source change from public access `Enabled` to `Disabled`, an exact already applied source/target/input/vault binding, and fresh complete private-vault/role readback. It writes a separate `private-intent-plan.json`, binds the original creation record's byte hash and leaves that original unchanged. Unrelated source, identity, permission or network changes cannot be adopted through this mode. It performs no Azure mutation and never silently accepts arbitrary drift.

## Network And Credential Gates

### Store A Password Without Opening The Vault

[Set-BastionPasswordSecret.ps1](../Set-BastionPasswordSecret.ps1) uses [secret.bicep](secret.bicep) to create one standalone password secret through the ARM management plane. [Key Vault firewall rules do not block ARM secret deployment](https://learn.microsoft.com/en-us/azure/key-vault/general/network-security#restrictions-and-limitations); this requires the caller's existing deployment/secret-write permissions, not public vault access, a VPN or `enabledForTemplateDeployment` secret-retrieval privileges.

```powershell
& ./identity/Set-BastionPasswordSecret.ps1 -CheckOnly
& ./identity/Set-BastionPasswordSecret.ps1 -Mode Preview
& ./identity/Set-BastionPasswordSecret.ps1 -Mode Apply
& ./identity/Set-BastionPasswordSecret.ps1 -Mode Readback
```

Preview verifies the existing private vault/operator, refuses an already existing secret, and validates only a clearly non-credential placeholder. Apply requires a fresh matching preview and prompts directly in the terminal with hidden input. The password remains a secure ARM parameter; the real request uses the established in-memory native HTTPS pattern without changing SDK tracing or putting the password in arguments, files, receipts or output. Temporary managed strings can exist in memory; complete zeroization is not claimed.

After the prompt, the command rechecks the original operator, private vault/configuration fingerprints, selector, source, preview age and secret absence. A one-use metadata-only submission intent prevents blind replay after interruption or rejection. Readback verifies the exact deployment, expected vault/secret parameters and deployment-reported version against secret metadata. Only the opaque version ID is a deployment output; neither the password nor its URI is output. A matching verified repeat returns `NoChange` without another prompt or write. This is metadata consistency, not proof of password correctness or a Windows logon.

An existing secret is never overwritten or adopted without its matching submission receipt. Rotation, forgotten-password recovery and ambiguous submissions need separate review. Enter only the selected existing VM/Bastion password; this operation does not change the VM password, administrator selector, pilot accounts, vault networking or permissions. Do not send the password through chat or question tools. After an accepted submission, use only `Readback` until its outcome is known.

### Retrieve The Password Through Bastion

Creating the secret and retrieving it later are separate network paths. The browser-visible Bastion password picker still needs an allowed vault data-plane route. The alternatives below concern that optional retrieval workflow, not the initial ARM write; direct username/password Bastion sign-in remains separate.

If an effective setting differs from reviewed intent, stop. Do not retry deployment to defeat policy, add a blanket trusted-service bypass, widen firewall ranges, change Nerdio's vault or upgrade Bastion implicitly. Establish the cause before choosing a supported path. If private access is required, align the definition through the explicit one-field reconciliation above rather than repeatedly requesting a public endpoint.

An approved [private endpoint and private DNS](https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service) must be reachable from the machine performing the vault data-plane operation. Adding an endpoint in the VM's VNet does not itself provide the operator's browser with a route. Do not provision an unusable endpoint, helper VM, VPN or paid Bastion tier merely to satisfy management-plane checks; review the actual client path first.

A supported workstation path is [Microsoft Entra-authenticated point-to-site VPN](https://learn.microsoft.com/en-us/azure/vpn-gateway/point-to-site-entra-gateway), with a compatible non-Basic route-based VPN gateway, the Azure VPN Client, a nonoverlapping client address pool and working private DNS. Review the gateway's recurring cost, identity restrictions, subnet ownership and client-network changes before implementation. This is a separate network scope, not an implicit Bastion upgrade or permission to expose the vault publicly.

For new deployments, the [current gateway SKU guidance](https://learn.microsoft.com/en-us/azure/vpn-gateway/about-gateway-skus) identifies `VpnGw1AZ` Generation 1 as the smallest AZ SKU supporting this design; do not select a non-AZ SKU slated for migration. It requires a Standard public IPv4 address and a dedicated [GatewaySubnet of `/27` or larger](https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings#gateway-subnet), without an NSG or unsupported default route. Review nonoverlap and preserve existing VNet/subnet ownership before choosing addresses. Regional provider or retail-catalog presence is not proof of SKU capacity. A cost review must distinguish gateway, public IP, private endpoint and private DNS fixed charges from data processing, DNS queries, transfer, tax and contract-dependent charges; keep target-specific estimates only in ignored `.env`, never public documentation or chat.

Check profile-generation and download response schemas before invoking them. Az.Network's `New-AzVpnClientConfiguration` declares `PSVpnProfile.VpnProfileSASUrl`; the normal profile workflow can return SAS-bearing material. The device's narrow Intune-upload exception does not cover VPN profiles. If prohibited material cannot be excluded server-side, stop and require a security-approved execution environment; never request it here, hide it in temporary files, disable tracing, or transfer a signed URL through chat. Only policy-approved configuration artifacts may return from that environment.

The [Key Vault firewall applies to the portal and its resource pickers](https://learn.microsoft.com/en-us/azure/key-vault/general/network-security). Seeing the vault through ARM does not prove access to its secrets. [Trusted services](https://learn.microsoft.com/en-us/azure/key-vault/general/overview-vnet-service-endpoints#trusted-services) is not a blanket exception for every Azure service. The browser-visible Bastion option does not itself prove the selected SKU's end-to-end network/credential behavior; verify that workflow separately without silently upgrading it.

The vault deployment command neither stores nor retrieves a password; the separate create-only ARM writer above stores it without opening the vault. When the data-plane route is accepted, select the standalone secret for Bastion's **Password from Azure Key Vault** option and enter the username separately. Never place credential values in plaintext parameter files, command lines, screenshots, logs or plaintext configuration. Do not change the configured AD administrator, reset a password or assume a local VM credential is the domain administrator. Credential validity and rotation remain separate from secret storage. Storage keys, arbitrary SAS and webhook tokens remain prohibited by device policy.