targetScope = 'subscription'

@minLength(1)
param resourceGroupName string

@allowed(['swedencentral'])
param location string

param namePrefix string
param addressPrefix string
param subnetPrefix string
param workloadSubnetPrefix string = ''
param privateIps string[]
param computerNames string[]
param zones string[]
param imageVersion string
param adminUsername string
@allowed(['Azure', 'Primary', 'Both'])
param dnsStage string = 'Azure'

@secure()
param adminPassword string

param tags { *: string }
param enableBackup bool = false
param backupGroupName string

resource identityGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module domainControllers 'dc/resources.bicep' = {
  scope: identityGroup
  params: {
    location: location
    namePrefix: namePrefix
    addressPrefix: addressPrefix
    subnetPrefix: subnetPrefix
    workloadSubnetPrefix: workloadSubnetPrefix
    privateIps: privateIps
    computerNames: computerNames
    zones: zones
    imageVersion: imageVersion
    adminUsername: adminUsername
    dnsStage: dnsStage
    adminPassword: adminPassword
    tags: tags
  }
}

output vmIds string[] = domainControllers.outputs.vmIds

resource recoveryGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = if (enableBackup) {
  name: backupGroupName
  location: location
  tags: { workload: 'recovery', 'managed-by': 'bicep' }
}

module backup 'recovery/resources.bicep' = if (enableBackup) {
  scope: recoveryGroup
  params: {
    location: location
    namePrefix: namePrefix
    identityGroupName: resourceGroupName
    vmNames: ['vm-${namePrefix}-dc1', 'vm-${namePrefix}-dc2']
    vmIds: domainControllers.outputs.vmIds
    tags: { workload: 'recovery', 'managed-by': 'bicep' }
  }
}
