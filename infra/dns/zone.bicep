targetScope = 'resourceGroup'

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

@description('Registered domain FQDN from private target inputs.')
@minLength(1)
param zoneName string

@description('Complete intended apex TXT values; callers must preserve unrelated existing values.')
@minLength(1)
param verificationTxtValues string[]

@minLength(1)
param mxRecords MxRecord[]

@minLength(1)
param cnameRecords CnameRecord[]

@description('Complete reviewed values for each owned non-apex TXT set, such as DMARC; omitted sets are not deleted.')
param namedTxtRecords NamedTxtRecord[] = []

param tags { *: string }

resource publicZone 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: zoneName
  location: 'global'
  tags: tags
  properties: {
    zoneType: 'Public'
  }
}

resource verificationTxt 'Microsoft.Network/dnsZones/TXT@2018-05-01' = {
  parent: publicZone
  name: '@'
  properties: {
    TTL: 3600
    TXTRecords: [for txtValue in verificationTxtValues: {
      value: [txtValue]
    }]
  }
}

resource mailExchange 'Microsoft.Network/dnsZones/MX@2018-05-01' = {
  parent: publicZone
  name: '@'
  properties: {
    TTL: 3600
    MXRecords: mxRecords
  }
}

resource cnameRecordsResource 'Microsoft.Network/dnsZones/CNAME@2018-05-01' = [for cnameRecord in cnameRecords: {
  parent: publicZone
  name: cnameRecord.name
  properties: {
    TTL: 3600
    CNAMERecord: {
      cname: cnameRecord.canonicalName
    }
  }
}]

resource namedTxtRecordsResource 'Microsoft.Network/dnsZones/TXT@2018-05-01' = [for record in namedTxtRecords: {
  parent: publicZone
  name: record.name
  properties: {
    TTL: 3600
    TXTRecords: [for value in record.values: {
      value: [value]
    }]
  }
}]

output nameServers string[] = publicZone.properties.nameServers
