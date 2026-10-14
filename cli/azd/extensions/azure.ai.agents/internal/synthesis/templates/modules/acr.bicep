// Azure Container Registry for hosted agents that use docker:.
// Wires the registry as a connection on the Foundry project so the
// project's managed identity can pull images.
//
// Premium SKU is intentional: Foundry recommends Premium so the registry
// can support content trust and geo-replication if the user enables them
// post-provision.

// Parameters

@description('Azure region.')
param location string

@description('Tags applied to all resources.')
param tags object = {}

@description('Registry name. 5-50 alphanumeric chars.')
@minLength(5)
@maxLength(50)
param name string

@description('Name of the existing Foundry CognitiveServices account that hosts the project receiving the ACR connection.')
param foundryAccountName string

@description('Name of the existing Foundry project receiving the ACR connection.')
param foundryProjectName string

@description('Principal id of the Foundry project managed identity; receives the registry mode-appropriate read role and is the connection credential identity.')
param foundryProjectPrincipalId string

@description('Existing registry resource ID. Empty creates the registry in this resource group.')
param existingRegistryResourceId string = ''

@description('Full role definition ID granted to the Foundry project identity.')
param projectAcrRoleDefinitionId string

@description('When true, the registry disables public network access to stay inside the isolation boundary.')
param enableNetworkIsolation bool = false

// Variables

var useExistingRegistry = !empty(existingRegistryResourceId)
var existingRegistryParts = split(existingRegistryResourceId, '/')
var existingRegistrySubscription = useExistingRegistry ? existingRegistryParts[2] : subscription().subscriptionId
var existingRegistryResourceGroup = useExistingRegistry ? existingRegistryParts[4] : resourceGroup().name
var existingRegistryName = useExistingRegistry ? existingRegistryParts[8] : name

// Resources

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = if (!useExistingRegistry) {
  name: name
  location: location
  tags: tags
  sku: {
    name: 'Premium'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    adminUserEnabled: false
    // Disable public access when network isolation is enabled so the registry
    // stays inside the VNet boundary. Docker-backed agents in isolated projects
    // must pull via the private endpoint; public access would leave a dependency
    // outside the isolation perimeter and can break pulls in locked-down egress.
    publicNetworkAccess: enableNetworkIsolation ? 'Disabled' : 'Enabled'
    zoneRedundancy: 'Disabled'
  }
}

resource existingRegistry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = if (useExistingRegistry) {
  name: existingRegistryName
  scope: resourceGroup(existingRegistrySubscription, existingRegistryResourceGroup)
}

// Grant the Foundry project's managed identity the registry mode-appropriate
// read role so the hosted agent can pull images using the project identity.
resource foundryAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!useExistingRegistry) {
  name: guid(registry.id, foundryProjectPrincipalId, projectAcrRoleDefinitionId)
  scope: registry
  properties: {
    principalId: foundryProjectPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: projectAcrRoleDefinitionId
  }
}

// Existing parent references so the connection can be nested under the
// project. Pinned to 2025-04-01-preview: GA 2025-06-01 fails to resolve the
// projects/connections ContainerRegistry sub-resource (MissingApiVersionParameter).
resource foundryAccount 'Microsoft.CognitiveServices/accounts@2025-04-01-preview' existing = {
  name: foundryAccountName

  resource project 'projects' existing = {
    name: foundryProjectName

    // Project-scoped connection so Foundry can resolve the registry by name.
    resource acrConnection 'connections' = {
      name: '${name}-conn'
      properties: {
        category: 'ContainerRegistry'
        target: useExistingRegistry ? existingRegistry!.properties.loginServer : registry!.properties.loginServer
        authType: 'ManagedIdentity'
        // RegistryIdentity auth requires both the identity client id (the
        // project principal) and the registry resource id.
        credentials: {
          clientId: foundryProjectPrincipalId
          resourceId: useExistingRegistry ? existingRegistry!.id : registry!.id
        }
        isSharedToAll: true
        metadata: {
          ResourceId: useExistingRegistry ? existingRegistry!.id : registry!.id
        }
      }
      dependsOn: [
        foundryAcrPull
      ]
    }
  }
}

// Outputs

output loginServer string = useExistingRegistry ? existingRegistry!.properties.loginServer : registry!.properties.loginServer
output resourceId string = useExistingRegistry ? existingRegistry!.id : registry!.id
output connectionName string = foundryAccount::project::acrConnection.name
