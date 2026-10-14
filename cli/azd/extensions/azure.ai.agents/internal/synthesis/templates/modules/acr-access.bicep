targetScope = 'resourceGroup'

@description('Name of the existing Azure Container Registry.')
param registryName string

@description('Foundry project managed identity principal ID.')
param projectPrincipalId string

@description('Full role definition ID appropriate for the registry permission mode.')
param roleDefinitionId string

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: registryName
}

resource projectRegistryAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, projectPrincipalId, roleDefinitionId)
  scope: registry
  properties: {
    principalId: projectPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
  }
}
