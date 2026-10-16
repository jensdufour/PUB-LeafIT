targetScope = 'resourceGroup'

param location string
param vmName string
@allowed(['Forest', 'Replica'])
param mode string
param domainName string
param netbiosName string
param adminUsername string
@secure()
param dsrmPassword string
@secure()
param adminPassword string

resource machine 'Microsoft.Compute/virtualMachines@2024-07-01' existing = {
  name: vmName
}

resource promotion 'Microsoft.Compute/virtualMachines/runCommands@2024-07-01' = {
  parent: machine
  name: 'ConfigureDomainController'
  location: location
  properties: {
    asyncExecution: false
    timeoutInSeconds: 1800
    treatFailureAsDeploymentFailure: true
    source: { script: loadTextContent('Configure.ps1') }
    parameters: [
      { name: 'Mode', value: mode }
      { name: 'DomainName', value: domainName }
      { name: 'NetbiosName', value: netbiosName }
      { name: 'AdminUsername', value: adminUsername }
    ]
    protectedParameters: [
      { name: 'DsrmPassword', value: dsrmPassword }
      { name: 'AdminPassword', value: adminPassword }
    ]
  }
}
