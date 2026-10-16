targetScope = 'resourceGroup'

param location string
param namePrefix string
param identityGroupName string
param vmNames string[]
param vmIds string[]
param tags { *: string }

resource vault 'Microsoft.RecoveryServices/vaults@2023-02-01' = {
  name: 'rsv-${namePrefix}'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  identity: { type: 'SystemAssigned' }
  properties: {
    publicNetworkAccess: 'Enabled'
  }
}

resource storage 'Microsoft.RecoveryServices/vaults/backupstorageconfig@2023-02-01' = {
  parent: vault
  name: 'vaultstorageconfig'
  properties: {
    storageType: 'LocallyRedundant'
    storageTypeState: 'Locked'
    crossRegionRestoreFlag: false
  }
}

resource policy 'Microsoft.RecoveryServices/vaults/backupPolicies@2023-02-01' = {
  parent: vault
  name: 'DcDailySevenDays'
  properties: {
    backupManagementType: 'AzureIaasVM'
    instantRpRetentionRangeInDays: 2
    timeZone: 'UTC'
    schedulePolicy: {
      schedulePolicyType: 'SimpleSchedulePolicy'
      scheduleRunFrequency: 'Daily'
      scheduleRunTimes: ['2026-01-01T14:00:00Z']
    }
    retentionPolicy: {
      retentionPolicyType: 'LongTermRetentionPolicy'
      dailySchedule: {
        retentionTimes: ['2026-01-01T14:00:00Z']
        retentionDuration: { count: 7, durationType: 'Days' }
      }
    }
  }
}

resource fabric 'Microsoft.RecoveryServices/vaults/backupFabrics@2023-02-01' existing = {
  parent: vault
  name: 'Azure'
}

resource containers 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers@2023-02-01' existing = [for name in vmNames: {
  parent: fabric
  name: 'IaasVMContainer;iaasvmcontainerv2;${identityGroupName};${name}'
}]

resource protection 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems@2025-01-01' = [for (name, index) in vmNames: {
  parent: containers[index]
  name: 'VM;iaasvmcontainerv2;${identityGroupName};${name}'
  properties: {
    protectedItemType: 'Microsoft.Compute/virtualMachines'
    sourceResourceId: vmIds[index]
    policyId: policy.id
  }
  dependsOn: [storage]
}]

output vaultName string = vault.name
