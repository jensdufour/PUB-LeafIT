targetScope = 'resourceGroup'

param location string
param namePrefix string
param expectedTenantId string
param expectedSubscriptionId string
@minLength(2)
@maxLength(2)
param vmNames string[]
param scheduleStartTimes {
  Start: string
  Stop: string
}
param jobScheduleIds {
  Start: string
  Stop: string
}
param configureSchedules bool = true
param enableSchedules bool = false
param tags { *: string }

resource automation 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: 'aa-${namePrefix}'
  location: location
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    sku: { name: 'Basic' }
    publicNetworkAccess: true
    disableLocalAuth: true
  }
}

resource schedulerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'dc-schedule-role')
  properties: {
    roleName: '${namePrefix}-dc-schedule'
    description: 'Power control for the two owned DC VMs.'
    type: 'CustomRole'
    assignableScopes: [resourceGroup().id]
    permissions: [
      {
        actions: [
          'Microsoft.Compute/virtualMachines/read'
          'Microsoft.Compute/virtualMachines/instanceView/read'
          'Microsoft.Compute/virtualMachines/start/action'
          'Microsoft.Compute/virtualMachines/powerOff/action'
          'Microsoft.Compute/virtualMachines/deallocate/action'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

resource machines 'Microsoft.Compute/virtualMachines@2024-07-01' existing = [for name in vmNames: {
  name: name
}]

resource permissions 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (name, index) in vmNames: {
  name: guid(machines[index].id, automation.id, schedulerRole.id)
  scope: machines[index]
  properties: {
    principalId: automation.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: schedulerRole.id
  }
}]

resource runtime 'Microsoft.Automation/automationAccounts/runtimeEnvironments@2024-10-23' = {
  parent: automation
  name: 'DcPowerShell76'
  location: location
  tags: tags
  properties: {
    runtime: { language: 'PowerShell', version: '7.6' }
    defaultPackages: { Az: '15.1.0' }
  }
}

resource runbook 'Microsoft.Automation/automationAccounts/runbooks@2024-10-23' = {
  parent: automation
  name: 'InvokeDomainControllerSchedule'
  location: location
  tags: tags
  properties: {
    runbookType: 'PowerShell'
    runtimeEnvironment: runtime.name
    description: 'Weekday DC start and stop. No guest commands or tag exemptions.'
    logProgress: false
    logVerbose: false
  }
}

var operations = [
  { action: 'Start', start: scheduleStartTimes.Start }
  { action: 'Stop', start: scheduleStartTimes.Stop }
]

resource schedules 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = [for operation in operations: if (configureSchedules) {
  parent: automation
  name: 'Dc${operation.action}'
  properties: {
    frequency: 'Week'
    interval: 1
    startTime: operation.start
    timeZone: 'Europe/Brussels'
    advancedSchedule: { weekDays: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'] }
  }
}]

resource bindings 'Microsoft.Automation/automationAccounts/jobSchedules@2023-11-01' = [for (operation, index) in operations: if (enableSchedules) {
  parent: automation
  name: jobScheduleIds[operation.action]
  properties: {
    runbook: { name: runbook.name }
    schedule: { name: 'Dc${operation.action}' }
    parameters: {
      Action: operation.action
      TenantId: expectedTenantId
      SubscriptionId: expectedSubscriptionId
      ResourceGroupName: resourceGroup().name
      VmName1: vmNames[0]
      VmName2: vmNames[1]
    }
  }
  dependsOn: [permissions, schedules]
}]

output automationAccountName string = automation.name
