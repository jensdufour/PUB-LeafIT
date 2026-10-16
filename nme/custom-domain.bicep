targetScope = 'resourceGroup'

param webAppName string
param hostName string
param location string
param serverFarmId string
param certificateName string

@allowed([
  'Hostname'
  'Certificate'
  'Secure'
])
param stage string = 'Hostname'

param certificateThumbprint string = ''

resource webApp 'Microsoft.Web/sites@2024-04-01' existing = {
  name: webAppName
}

resource hostNameBinding 'Microsoft.Web/sites/hostNameBindings@2024-04-01' = if (stage != 'Certificate') {
  parent: webApp
  name: hostName
  properties: {
    hostNameType: 'Verified'
    customHostNameDnsRecordType: 'CName'
    sslState: stage == 'Secure' ? 'SniEnabled' : 'Disabled'
    thumbprint: stage == 'Secure' ? certificateThumbprint : null
  }
}

resource managedCertificate 'Microsoft.Web/certificates@2024-04-01' = if (stage == 'Certificate') {
  name: certificateName
  location: location
  properties: {
    canonicalName: hostName
    serverFarmId: serverFarmId
  }
}

output thumbprint string = managedCertificate.?properties.thumbprint ?? ''