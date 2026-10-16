targetScope = 'resourceGroup'

param location string
param namePrefix string
param addressPrefix string
param subnetPrefix string
param workloadSubnetPrefix string = ''

@minLength(2)
@maxLength(2)
param privateIps string[]

@minLength(2)
@maxLength(2)
param computerNames string[]

@minLength(2)
@maxLength(2)
param zones string[]

@description('Exact reviewed Windows Server 2025 Azure Edition Core small-disk image version, not latest.')
param imageVersion string
param adminUsername string
@allowed(['Azure', 'Primary', 'Both'])
param dnsStage string = 'Azure'

@secure()
param adminPassword string

param tags { *: string }

module network '../network/resources.bicep' = {
  params: {
    location: location
    namePrefix: namePrefix
    addressPrefix: addressPrefix
    subnetPrefix: subnetPrefix
    workloadSubnetPrefix: workloadSubnetPrefix
    privateIps: privateIps
    dnsStage: dnsStage
    tags: tags
  }
}

resource interfaces 'Microsoft.Network/networkInterfaces@2024-05-01' = [for index in range(0, 2): {
  name: 'nic-${namePrefix}-dc${index + 1}'
  location: location
  tags: tags
  properties: {
    dnsSettings: { dnsServers: dnsStage == 'Azure' ? [] : dnsStage == 'Primary' ? [privateIps[0]] : [privateIps[1 - index], privateIps[index]] }
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Static'
          privateIPAddress: privateIps[index]
          subnet: { id: network.outputs.adSubnetId }
        }
      }
    ]
  }
}]

resource machines 'Microsoft.Compute/virtualMachines@2024-07-01' = [for index in range(0, 2): {
  name: 'vm-${namePrefix}-dc${index + 1}'
  location: location
  zones: [zones[index]]
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: 'Standard_B2s_v2' }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    osProfile: {
      computerName: computerNames[index]
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        provisionVMAgent: true
        enableAutomaticUpdates: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2025-datacenter-azure-edition-core-smalldisk'
        version: imageVersion
      }
      osDisk: {
        name: 'osdisk-${namePrefix}-dc${index + 1}'
        createOption: 'FromImage'
        diskSizeGB: 64
        caching: 'ReadWrite'
        deleteOption: 'Detach'
        managedDisk: { storageAccountType: 'StandardSSD_LRS' }
      }
      dataDisks: [
        {
          name: 'disk-${namePrefix}-dc${index + 1}-adds'
          lun: 0
          createOption: 'Empty'
          diskSizeGB: 32
          caching: 'None'
          deleteOption: 'Detach'
          managedDisk: { storageAccountType: 'StandardSSD_LRS' }
        }
      ]
    }
    networkProfile: {
      networkInterfaces: [{ id: interfaces[index].id, properties: { primary: true, deleteOption: 'Detach' } }]
    }
    diagnosticsProfile: { bootDiagnostics: { enabled: true } }
  }
}]

output vmIds string[] = [for index in range(0, 2): machines[index].id]
