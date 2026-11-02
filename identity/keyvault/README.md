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

The reviewed state is Standard Key Vault, Entra RBAC, purge protection, 90-day soft-delete retention, and a public endpoint restricted by a default-deny firewall to one exact operator IPv4 `/32`, with no trusted-service bypass. Key Vault Secrets Officer is assigned only to the configured user at this new vault's scope so that user can maintain credentials. No managed identity or Nerdio application receives access.

Preview permits only the new vault and its exact scoped role assignment. Unrelated existing resources marked `Ignore` by ARM are not mutations. Apply requires a fresh matching preview, unchanged target/inputs/source, and the same in-memory compiled template used for its repeated what-if. An existing vault without matching creation evidence cannot be adopted. Existing-vault drift is never automatically corrected. Evidence remains under ignored `private/identity/keyvault/`.

Successful deployment is not acceptance: readback must confirm every owned security property and the exact User role assignment, and repeated Apply must return `NoChange`. ARM may omit `principalType` from what-if; creation still explicitly sets `User` and actual-state verification requires it.

## Network And Credential Gates

If an effective setting differs, including public access being disabled, stop. Do not retry deployment to defeat policy, add a blanket trusted-service bypass, widen firewall ranges, change Nerdio's vault or upgrade Bastion implicitly. Establish the cause and an approved network path or separately reviewed exception first. A private endpoint alone does not give the operator's browser private connectivity.

The [Key Vault firewall applies to the portal and its resource pickers](https://learn.microsoft.com/en-us/azure/key-vault/general/network-security); changing client networks requires a reviewed access update. [Trusted services](https://learn.microsoft.com/en-us/azure/key-vault/general/overview-vnet-service-endpoints#trusted-services) is not a blanket exception for every Azure service. The browser-visible Bastion option does not itself prove the selected SKU's end-to-end network/credential behavior; verify that workflow separately without silently upgrading it.

This command neither stores nor retrieves a password. After network and repeat-apply acceptance, enter the existing VM password directly in the Azure portal as one standalone secret for Bastion's **Password from Azure Key Vault** option, and enter the username separately. Never place credential values in template parameters, command lines, screenshots, logs or plaintext configuration. Do not change the configured AD administrator, reset a password or assume a local VM credential is the domain administrator. Credential validity and rotation remain separate from secret storage. Storage keys, arbitrary SAS and webhook tokens remain prohibited by device policy.