targetScope = 'resourceGroup'

@minLength(3)
@maxLength(24)
param vaultName string

@minLength(1)
@maxLength(127)
param secretName string

@secure()
@minLength(1)
param secretValue string

resource vault 'Microsoft.KeyVault/vaults@2025-05-01' existing = {
  name: vaultName
}

resource password 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = {
  parent: vault
  name: secretName
  properties: {
    value: secretValue
    contentType: 'text/plain'
    attributes: {
      enabled: true
    }
  }
}

output versionId string = last(split(password.properties.secretUriWithVersion, '/'))