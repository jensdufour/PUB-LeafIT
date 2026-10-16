targetScope = 'resourceGroup'

param location string
param namePrefix string
param addressPrefix string
param subnetPrefix string
param privateIps string[]
param tags { *: string }

@allowed(['Azure', 'Primary', 'Both'])
param dnsStage string = 'Both'

param workloadSubnetPrefix string = ''
param manageEgress bool = true

resource outboundIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = if (manageEgress) {
  name: 'pip-${namePrefix}-egress'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource outbound 'Microsoft.Network/natGateways@2024-05-01' = if (manageEgress) {
  name: 'ng-${namePrefix}-egress'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    idleTimeoutInMinutes: 4
    publicIpAddresses: [{ id: outboundIp!.id }]
  }
}

resource existingOutbound 'Microsoft.Network/natGateways@2024-05-01' existing = {
  name: 'ng-${namePrefix}-egress'
}

var domainRules = [
  { name: 'AllowWorkloadDomainTcp', priority: 120, protocol: 'Tcp', ports: ['53', '88', '135', '389', '445', '464', '636', '3268', '3269', '49152-65535'] }
  { name: 'AllowWorkloadDomainUdp', priority: 130, protocol: 'Udp', ports: ['53', '88', '123', '389', '464'] }
]

var workloadDomainRules = [for rule in (empty(workloadSubnetPrefix) ? [] : domainRules): {
  name: rule.name
  properties: {
    priority: rule.priority
    direction: 'Inbound'
    access: 'Allow'
    protocol: rule.protocol
    sourceAddressPrefix: workloadSubnetPrefix
    sourcePortRange: '*'
    destinationAddressPrefixes: privateIps
    destinationPortRanges: rule.ports
  }
}]

resource securityGroup 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: 'nsg-${namePrefix}-adds'
  location: location
  tags: tags
  properties: {
    securityRules: concat([
      {
        name: 'DenyInteractiveManagement'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Deny'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: ['3389', '5985', '5986']
        }
      }
      {
        name: 'AllowDomainControllerSubnet'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: subnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: subnetPrefix
          destinationPortRange: '*'
        }
      }
      {
        name: 'DenyOtherInbound'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ], workloadDomainRules)
  }
}

resource workloadSecurity 'Microsoft.Network/networkSecurityGroups@2024-05-01' = if (!empty(workloadSubnetPrefix)) {
  name: 'nsg-${namePrefix}-avd'
  location: location
  tags: union(tags, { purpose: 'avd-domain-network' })
  properties: {
    securityRules: [
      {
        name: 'DenyInbound'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource network 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'vnet-${namePrefix}'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [addressPrefix] }
    dhcpOptions: { dnsServers: dnsStage == 'Azure' ? [] : dnsStage == 'Primary' ? [privateIps[0]] : privateIps }
    subnets: concat([
      {
        name: 'snet-adds'
        properties: {
          addressPrefix: subnetPrefix
          defaultOutboundAccess: false
          networkSecurityGroup: { id: securityGroup.id }
          natGateway: { id: manageEgress ? outbound!.id : existingOutbound.id }
        }
      }
    ], empty(workloadSubnetPrefix) ? [] : [
      {
        name: 'snet-avd'
        properties: {
          addressPrefix: workloadSubnetPrefix
          defaultOutboundAccess: false
          networkSecurityGroup: { id: workloadSecurity!.id }
          natGateway: { id: manageEgress ? outbound!.id : existingOutbound.id }
        }
      }
    ])
  }
}

output adSubnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', network.name, 'snet-adds')
output workloadSubnetId string = empty(workloadSubnetPrefix) ? '' : resourceId('Microsoft.Network/virtualNetworks/subnets', network.name, 'snet-avd')