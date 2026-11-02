targetScope = 'resourceGroup'

@minLength(3)
@maxLength(24)
param vaultName string

@allowed(['swedencentral'])
param location string

@minLength(36)
@maxLength(36)
param operatorPrincipalId string

@minLength(1)
@maxLength(10)
param allowedIpv4Addresses string[]

resource vault 'Microsoft.KeyVault/vaults@2025-05-01' = {
  name: vaultName
  location: location
  tags: {
    workload: 'identity'
    'managed-by': 'bicep'
  }
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    accessPolicies: []
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
      ipRules: [for address in allowedIpv4Addresses: {
        value: '${address}/32'
      }]
      virtualNetworkRules: []
    }
  }
}

var secretsOfficerRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')

resource operatorSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, operatorPrincipalId, secretsOfficerRoleId)
  scope: vault
  properties: {
    principalId: operatorPrincipalId
    principalType: 'User'
    roleDefinitionId: secretsOfficerRoleId
  }
}