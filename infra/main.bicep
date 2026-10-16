targetScope = 'subscription'

type MxRecord = {
  preference: int
  exchange: string
}

type CnameRecord = {
  name: string
  canonicalName: string
}

type NamedTxtRecord = {
  name: string
  @minLength(1)
  values: string[]
}

@description('Reviewed CAF-aligned name of the shared infrastructure resource group.')
@minLength(1)
@maxLength(90)
param resourceGroupName string

@description('Resource-group metadata region: Sweden Central by default; Germany West Central only after explicit availability review. DNS remains global.')
@allowed([
  'swedencentral'
  'germanywestcentral'
])
param location string

@description('Registered domain FQDN from private target inputs.')
@minLength(1)
param zoneName string

@description('Complete intended apex TXT values, including the current Entra verification value and any retained values.')
@minLength(1)
param verificationTxtValues string[]

@minLength(1)
param mxRecords MxRecord[]

@minLength(1)
param cnameRecords CnameRecord[]

@description('Reviewed named TXT records in the persistent public zone; target values remain private.')
param namedTxtRecords NamedTxtRecord[] = []

@description('Reviewed non-sensitive tags applied to the group and zone.')
param tags { *: string }

resource infrastructureResourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module publicDns 'dns/zone.bicep' = {
  scope: infrastructureResourceGroup
  params: {
    zoneName: zoneName
    verificationTxtValues: verificationTxtValues
    mxRecords: mxRecords
    cnameRecords: cnameRecords
    namedTxtRecords: namedTxtRecords
    tags: tags
  }
}

output nameServers string[] = publicDns.outputs.nameServers
