// Provisioning template for a Foundry project service.
//
// Inputs are derived from the host: azure.ai.project service body in
// azure.yaml by internal/synthesis. This entry point creates a new Foundry
// account and project; existing projects use the separate editable entry point.
//
// Subscription-scoped so the resource group is part of the deployment. This
// keeps `azd provision --preview` side-effect free: the resource group shows
// up as a previewed Create instead of being created up front to satisfy a
// resource-group-scoped what-if.

targetScope = 'subscription'

// User-defined types

@description('Shape of one model deployment entry in azure.yaml.')
type deploymentsType = deploymentType[]

@description('Shape of a single model deployment.')
type deploymentType = {
  name: string
  model: {
    name: string
    format: string
    version: string
  }
  sku: {
    name: string
    capacity: int
  }
}

@description('Shape of a list of Foundry project connections.')
type connectionsType = connectionType[]

@description('Shape of one Foundry project connection (a host: azure.ai.connection service).')
type connectionType = {
  name: string
  category: string
  target: string
  authType: string
  audience: string?
  authorizationUrl: string?
  tokenUrl: string?
  refreshUrl: string?
  scopes: string[]?
  connectorName: string?
  metadata: object?
}

@description('Customer-owned AKS configuration for hosting Foundry agents.')
type agentHostingType = {
  enabled: bool
  hostingType: 'ManagedCluster' | ''
  name: string
  clusterResourceId: string
  agentSubnetResourceId: string
  hostingManagementIdentityResourceId: string
  storageAccountResourceId: string
  workloadIdentityResourceId: string
  containerRegistryResourceId: string
}

// Parameters

@description('Azure region for all resources.')
param location string

@description('Name of the resource group to create and deploy resources into.')
@minLength(1)
@maxLength(90)
param resourceGroupName string

@description('Create the target resource group before deploying resources into it.')
param createResourceGroup bool = true

@description('Tags applied to all resources.')
param tags object = {}

@description('Optional salt to vary resource names across re-provisions.')
param resourceTokenSalt string = ''

@description('Foundry project name. 3-32 alphanumeric/hyphen chars.')
@minLength(3)
@maxLength(32)
param foundryProjectName string

@description('Model deployments to provision on the Foundry account.')
param deployments deploymentsType = []

@description('Include an Azure Container Registry. Set true when any agent uses docker:.')
param includeAcr bool = false

@description('Existing registry prepared for BYO AKS. Empty keeps the template-owned registry behavior.')
param preparedAcrResourceId string = ''

@description('Full role definition ID used by the Foundry project identity on the prepared registry.')
param preparedAcrRoleDefinitionId string = ''

@description('Registry lifecycle mode recorded in azd outputs.')
@allowed([
  'create'
  'reuse-connect'
])
param acrMode string = 'create'

@description('Foundry project connections to create (host: azure.ai.connection services).')
param connections connectionsType = []

@description('Credentials keyed by Foundry project connection name.')
@secure()
param connectionCredentials object = {}

@description('Customer-owned AKS configuration for hosting Foundry agents.')
param agentHosting agentHostingType = {
  enabled: false
  hostingType: ''
  name: ''
  clusterResourceId: ''
  agentSubnetResourceId: ''
  hostingManagementIdentityResourceId: ''
  storageAccountResourceId: ''
  workloadIdentityResourceId: ''
  containerRegistryResourceId: ''
}

@description('Object id of the developer running azd. When set, grants Cognitive Services User on the project. Empty disables the role assignment so headless / CI runs do not fail.')
param principalId string = ''

@description('Principal type used in the developer role assignment.')
param principalType string = 'User'

// Network isolation parameters (see modules/resources.bicep for semantics).
// All default off so an absent network: block yields a public account.

@description('Master switch: when true the account is VNet-bound (private).')
param enableNetworkIsolation bool = false

@description('When true (and isolation on), the agent runtime uses the Microsoft-managed network instead of injecting into a customer subnet.')
param useManagedEgress bool = false

@description('ARM id of the existing customer VNet (byo mode).')
param vnetId string = ''

@description('Agent (delegated) subnet name.')
param agentSubnetName string = 'agent-subnet'

@description('Agent subnet CIDR. Empty derives a /24 from the VNet space.')
param agentSubnetPrefix string = ''

@description('When true, create the agent subnet; when false, reference it.')
param createAgentSubnet bool = false

@description('Private-endpoint subnet name.')
param peSubnetName string = 'pe-subnet'

@description('Private-endpoint subnet CIDR. Empty derives a /24 from the VNet space.')
param peSubnetPrefix string = ''

@description('When true, create the PE subnet; when false, reference it.')
param createPESubnet bool = false

@description('Managed-network isolation mode (managed mode).')
param managedIsolationMode string = ''

@description('Resource group holding existing private DNS zones. Empty creates new zones.')
param dnsZonesResourceGroup string = ''

@description('Subscription holding existing private DNS zones. Empty defaults to this subscription.')
param dnsZonesSubscription string = ''

// Resources

resource resourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' = if (createResourceGroup) {
  name: resourceGroupName
  location: location
  tags: tags
}

module resources 'modules/resources.bicep' = {
  name: 'foundry-resources'
  scope: resourceGroup
  params: {
    location: location
    tags: tags
    resourceTokenSalt: resourceTokenSalt
    foundryProjectName: foundryProjectName
    deployments: deployments
    includeAcr: includeAcr
    preparedAcrResourceId: preparedAcrResourceId
    preparedAcrRoleDefinitionId: preparedAcrRoleDefinitionId
    acrMode: acrMode
    connections: connections
    connectionCredentials: connectionCredentials
    agentHosting: agentHosting
    principalId: principalId
    principalType: principalType
    enableNetworkIsolation: enableNetworkIsolation
    useManagedEgress: useManagedEgress
    vnetId: vnetId
    agentSubnetName: agentSubnetName
    agentSubnetPrefix: agentSubnetPrefix
    createAgentSubnet: createAgentSubnet
    peSubnetName: peSubnetName
    peSubnetPrefix: peSubnetPrefix
    createPESubnet: createPESubnet
    managedIsolationMode: managedIsolationMode
    dnsZonesResourceGroup: dnsZonesResourceGroup
    dnsZonesSubscription: dnsZonesSubscription
  }
}

var usePreparedAcr = includeAcr && !empty(preparedAcrResourceId)
var preparedAcrParts = split(preparedAcrResourceId, '/')
var preparedAcrSubscription = usePreparedAcr ? preparedAcrParts[2] : subscription().subscriptionId
var preparedAcrResourceGroup = usePreparedAcr ? preparedAcrParts[4] : resourceGroupName
var preparedAcrName = usePreparedAcr ? preparedAcrParts[8] : ''

module preparedAcrAccess 'modules/acr-access.bicep' = if (usePreparedAcr && !empty(preparedAcrRoleDefinitionId)) {
  name: 'foundry-acr-access-${uniqueString(preparedAcrResourceId, resourceGroupName, foundryProjectName)}'
  scope: az.resourceGroup(preparedAcrSubscription, preparedAcrResourceGroup)
  params: {
    registryName: preparedAcrName
    projectPrincipalId: resources.outputs.AZURE_AI_PROJECT_PRINCIPAL_ID
    roleDefinitionId: preparedAcrRoleDefinitionId
  }
}

// Outputs

output AZURE_RESOURCE_GROUP string = resourceGroupName
output AZURE_FOUNDRY_RESOURCE_GROUP string = resourceGroupName
output AZURE_AI_PROJECT_ID string = resources.outputs.AZURE_AI_PROJECT_ID
output AZURE_AI_ACCOUNT_NAME string = resources.outputs.AZURE_AI_ACCOUNT_NAME
output AZURE_AI_PROJECT_NAME string = resources.outputs.AZURE_AI_PROJECT_NAME
output AZURE_OPENAI_ENDPOINT string = resources.outputs.AZURE_OPENAI_ENDPOINT
output FOUNDRY_PROJECT_ENDPOINT string = resources.outputs.FOUNDRY_PROJECT_ENDPOINT
output AZURE_CONTAINER_REGISTRY_ENDPOINT string = resources.outputs.AZURE_CONTAINER_REGISTRY_ENDPOINT
output AZURE_CONTAINER_REGISTRY_RESOURCE_ID string = resources.outputs.AZURE_CONTAINER_REGISTRY_RESOURCE_ID
output AZURE_AI_PROJECT_ACR_CONNECTION_NAME string = resources.outputs.AZURE_AI_PROJECT_ACR_CONNECTION_NAME
output AZURE_AI_PROJECT_CONNECTION_NAMES string = resources.outputs.AZURE_AI_PROJECT_CONNECTION_NAMES
output AZURE_AI_PROJECT_CONNECTIONS_PROJECT_ENDPOINT string = resources.outputs.FOUNDRY_PROJECT_ENDPOINT
output AZD_FOUNDRY_ACR_MODE string = resources.outputs.AZD_FOUNDRY_ACR_MODE
output AZURE_FOUNDRY_NETWORK_MODE string = resources.outputs.AZURE_FOUNDRY_NETWORK_MODE
output AZURE_FOUNDRY_MANAGED_ISOLATION_MODE string = resources.outputs.AZURE_FOUNDRY_MANAGED_ISOLATION_MODE
