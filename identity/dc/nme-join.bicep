targetScope = 'resourceGroup'

param location string
param vmName string
@allowed(['Preview', 'Apply', 'Verify'])
param mode string = 'Preview'
param domainName string
param accountName string
param computerOuName string
param organizationName string

@secure()
param joinPassword string = ''

resource machine 'Microsoft.Compute/virtualMachines@2024-07-01' existing = {
  name: vmName
}

resource joinSetup 'Microsoft.Compute/virtualMachines/runCommands@2024-07-01' = {
  parent: machine
  name: 'ConfigureNmeJoin'
  location: location
  properties: {
    asyncExecution: false
    timeoutInSeconds: 300
    treatFailureAsDeploymentFailure: true
    source: { script: loadTextContent('Configure-NmeJoin.ps1') }
    parameters: [
      { name: 'Mode', value: mode }
      { name: 'DomainName', value: domainName }
      { name: 'AccountName', value: accountName }
      { name: 'ComputerOuName', value: computerOuName }
      { name: 'OrganizationName', value: organizationName }
    ]
    protectedParameters: [
      { name: 'JoinPassword', value: joinPassword }
    ]
  }
}