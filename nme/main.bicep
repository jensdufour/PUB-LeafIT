targetScope = 'subscription'

param resourceGroupName string
param location string
param namePrefix string
param artifactsLocation string

@secure()
param artifactsLocationSasToken string = ''

resource workload 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

module marketplace '../private/nme/marketplace/mainTemplate.json' = {
  scope: workload
  params: {
    location: location
    appName: namePrefix
    configurePrivateEndpoints: true
    privateWebApp: false
    privateEndpointsVnetName: replace(resourceGroupName, 'rg-', 'vnet-')
    privateEndpointsSubnetName: 'snet-nme-private-endpoints'
    appSubnetName: 'snet-nme-app'
    _artifactsLocation: artifactsLocation
    _artifactsLocationSasToken: artifactsLocationSasToken
  }
}

output appUrl string = marketplace.outputs.appUrl