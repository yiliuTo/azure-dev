// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"azure.ai.projects/internal/exterrors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

const (
	byoAKSSandboxLabel = "agents.ai.azure.com/sandbox-node"
	byoAKSDelegation   = "Microsoft.App/environments"
)

type byoAKSConfig struct {
	Enabled                             bool   `json:"enabled"`
	HostingType                         string `json:"hostingType"`
	ClusterResourceID                   string `json:"clusterResourceId"`
	AgentSubnetResourceID               string `json:"agentSubnetResourceId"`
	HostingManagementIdentityResourceID string `json:"hostingManagementIdentityResourceId"`
	StorageAccountResourceID            string `json:"storageAccountResourceId"`
	WorkloadIdentityResourceID          string `json:"workloadIdentityResourceId"`
}

type byoAKSResources struct {
	cluster, subnet, management, workload, storage *arm.ResourceID
}

type byoAKSSnapshot struct {
	cluster              armcontainerservice.ManagedCluster
	subnet               armnetwork.Subnet
	management, workload armmsi.Identity
	storage              armresources.GenericResource
}

func byoAKSConfigFromParameters(parameters map[string]any) (*byoAKSConfig, error) {
	parameter, exists := parameters["agentHosting"]
	if !exists {
		return nil, nil
	}
	raw, err := json.Marshal(parameter)
	if err != nil {
		return nil, fmt.Errorf("serialize agentHosting parameter: %w", err)
	}
	var envelope struct {
		Value *byoAKSConfig `json:"value"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("decode agentHosting.value: %w", err)
	}
	if envelope.Value == nil {
		return nil, fmt.Errorf("agentHosting.value must be an object")
	}
	if !envelope.Value.Enabled {
		return nil, nil
	}
	return envelope.Value, nil
}

func (c *byoAKSConfig) resources(subscriptionID string) (*byoAKSResources, error) {
	if c.HostingType != "ManagedCluster" {
		return nil, c.invalid("hostingType", c.HostingType, "ManagedCluster",
			"set agentHosting.hostingType to ManagedCluster")
	}
	resources := &byoAKSResources{}
	for _, field := range []struct {
		name, value, resourceType string
		destination               **arm.ResourceID
		sameSubscription          bool
	}{
		{"clusterResourceId", c.ClusterResourceID, "Microsoft.ContainerService/managedClusters", &resources.cluster, true},
		{
			"agentSubnetResourceId", c.AgentSubnetResourceID,
			"Microsoft.Network/virtualNetworks/subnets", &resources.subnet, true,
		},
		{
			"hostingManagementIdentityResourceId", c.HostingManagementIdentityResourceID,
			"Microsoft.ManagedIdentity/userAssignedIdentities", &resources.management, false,
		},
		{
			"workloadIdentityResourceId", c.WorkloadIdentityResourceID,
			"Microsoft.ManagedIdentity/userAssignedIdentities", &resources.workload, false,
		},
		{
			"storageAccountResourceId", c.StorageAccountResourceID,
			"Microsoft.Storage/storageAccounts", &resources.storage, true,
		},
	} {
		id, err := arm.ParseResourceID(field.value)
		if err != nil || strings.ContainsAny(field.value, "?#") ||
			id.SubscriptionID == "" || id.ResourceGroupName == "" || id.Name == "" ||
			!strings.EqualFold(id.ResourceType.String(), field.resourceType) {
			return nil, c.invalid(field.name, "invalid resource ID", field.resourceType+" resource ID",
				"correct the resource ID in agentHosting")
		}
		if field.sameSubscription && !strings.EqualFold(id.SubscriptionID, subscriptionID) {
			return nil, c.invalid(field.name+".subscription", id.SubscriptionID, subscriptionID,
				"use AKS, storage and an agent subnet in the Foundry account subscription")
		}
		*field.destination = id
	}
	if strings.EqualFold(resources.management.String(), resources.workload.String()) {
		return nil, c.invalid("workloadIdentityResourceId", "the hosting management identity",
			"a different user-assigned identity", "provide separate hosting management and workload identities")
	}
	return resources, nil
}

func (c *byoAKSConfig) validate(
	ids *byoAKSResources, state *byoAKSSnapshot, location string,
) (needsDelegation bool, err error) {
	if !strings.EqualFold(byoAKSString(state.cluster.Location), location) {
		return false, c.invalid("location", byoAKSString(state.cluster.Location), location,
			"set AZURE_LOCATION to the AKS region, or select an AKS cluster in the Foundry region")
	}
	if !strings.EqualFold(byoAKSString(state.storage.Location), location) {
		return false, c.invalid("storageAccountResourceId.location", byoAKSString(state.storage.Location), location,
			"use a storage account in the AKS and Foundry region")
	}
	if err := c.validateCluster(state.cluster.Properties); err != nil {
		return false, err
	}
	for _, identity := range []struct {
		name       string
		properties *armmsi.UserAssignedIdentityProperties
		workload   bool
	}{
		{"hostingManagementIdentityResourceId", state.management.Properties, false},
		{"workloadIdentityResourceId", state.workload.Properties, true},
	} {
		if identity.properties == nil || strings.TrimSpace(byoAKSString(identity.properties.PrincipalID)) == "" {
			return false, c.invalid(identity.name+".principalId", "missing", "a resolved Entra principal ID",
				"verify the referenced user-assigned identity exists and has a principalId")
		}
		if identity.workload &&
			(strings.TrimSpace(byoAKSString(identity.properties.ClientID)) == "" ||
				strings.TrimSpace(byoAKSString(identity.properties.TenantID)) == "") {
			return false, c.invalid(identity.name+".clientId/tenantId", "missing", "both clientId and tenantId",
				"use a fully provisioned workload user-assigned identity")
		}
	}
	if strings.EqualFold(*state.management.Properties.PrincipalID, *state.workload.Properties.PrincipalID) {
		return false, c.invalid("workloadIdentityResourceId.principalId", "the management principal",
			"a different principal", "provide separate hosting management and workload identities")
	}
	return c.validateSubnet(ids, state)
}

func (c *byoAKSConfig) validateCluster(properties *armcontainerservice.ManagedClusterProperties) error {
	if properties == nil {
		return c.invalid("properties", "missing", "AKS cluster properties", "verify the AKS resource can be read")
	}
	oidc := properties.OidcIssuerProfile
	if oidc == nil || oidc.Enabled == nil || !*oidc.Enabled {
		return c.invalid("oidcIssuerProfile.enabled", "false or missing", "true", "enable the AKS OIDC issuer")
	}
	if strings.TrimSpace(byoAKSString(oidc.IssuerURL)) == "" {
		return c.invalid("oidcIssuerProfile.issuerURL", "missing", "a non-empty issuer URL",
			"wait for AKS to finish enabling its OIDC issuer, then retry")
	}
	security := properties.SecurityProfile
	if security == nil || security.WorkloadIdentity == nil ||
		security.WorkloadIdentity.Enabled == nil || !*security.WorkloadIdentity.Enabled {
		return c.invalid("securityProfile.workloadIdentity.enabled", "false or missing", "true",
			"enable AKS workload identity")
	}
	if properties.AADProfile == nil || properties.AADProfile.EnableAzureRBAC == nil ||
		!*properties.AADProfile.EnableAzureRBAC {
		return c.invalid("aadProfile.enableAzureRBAC", "false or missing", "true for this demo",
			"use an Azure-RBAC-enabled AKS cluster; native Kubernetes RBAC preparation is outside this demo")
	}
	network := properties.NetworkProfile
	if network == nil || !strings.EqualFold(byoAKSString(network.NetworkPlugin), "azure") {
		plugin := ""
		if network != nil {
			plugin = byoAKSString(network.NetworkPlugin)
		}
		return c.invalid("networkProfile.networkPlugin", plugin, "azure",
			"use Azure CNI with overlay or a pod subnet configured on every node pool")
	}
	pools := properties.AgentPoolProfiles
	if !strings.EqualFold(byoAKSString(network.NetworkPluginMode), "overlay") {
		if len(pools) == 0 {
			return c.invalid("agentPoolProfiles", "empty", "non-empty pools with podSubnetID on every pool",
				"use Azure CNI overlay or configure pod subnets for all pools")
		}
		for i, pool := range pools {
			if pool == nil || pool.PodSubnetID == nil {
				return c.invalid(fmt.Sprintf("agentPoolProfiles[%d].podSubnetID", i), "null", "non-null",
					"use Azure CNI overlay or configure pod subnets for all pools")
			}
		}
	}
	for _, pool := range pools {
		if pool != nil && strings.EqualFold(byoAKSString(pool.WorkloadRuntime), "KataVmIsolation") &&
			byoAKSString(pool.NodeLabels[byoAKSSandboxLabel]) == "true" {
			return nil
		}
	}
	return c.invalid("agentPoolProfiles", "no pool has both required settings",
		"one pool with workloadRuntime=KataVmIsolation and "+byoAKSSandboxLabel+"=true",
		"set the sandbox-node label to the exact value 'true' on a KataVmIsolation pool")
}

func (c *byoAKSConfig) validateSubnet(ids *byoAKSResources, state *byoAKSSnapshot) (bool, error) {
	for i, pool := range state.cluster.Properties.AgentPoolProfiles {
		if pool == nil {
			return false, c.invalid(fmt.Sprintf("agentPoolProfiles[%d]", i), "null", "a node pool",
				"verify the AKS node pool configuration")
		}
		if strings.EqualFold(byoAKSString(pool.VnetSubnetID), ids.subnet.String()) ||
			strings.EqualFold(byoAKSString(pool.PodSubnetID), ids.subnet.String()) {
			return false, c.invalid("agentSubnetResourceId", "an AKS node or pod subnet", "a separate agent subnet",
				"provide a dedicated Foundry/Data Proxy subnet; azd will not modify AKS node or pod subnets")
		}
		nodeSubnet, err := arm.ParseResourceID(byoAKSString(pool.VnetSubnetID))
		if err != nil || nodeSubnet.Parent == nil ||
			!strings.EqualFold(nodeSubnet.ResourceType.String(), "Microsoft.Network/virtualNetworks/subnets") ||
			!strings.EqualFold(nodeSubnet.Parent.String(), ids.subnet.Parent.String()) {
			return false, c.invalid(fmt.Sprintf("agentPoolProfiles[%d].vnetSubnetID", i),
				"missing or in a different VNet", "a node subnet in the agent subnet's VNet",
				"use separate subnets in the same VNet; cross-VNet connectivity is outside this demo")
		}
	}
	properties := state.subnet.Properties
	if properties == nil {
		return false, c.invalid("agentSubnetResourceId.properties", "missing", "subnet properties",
			"verify the agent subnet can be read")
	}
	addressPrefix := byoAKSString(properties.AddressPrefix)
	if addressPrefix == "" && len(properties.AddressPrefixes) > 0 {
		addressPrefix = byoAKSString(properties.AddressPrefixes[0])
	}
	prefix, err := netip.ParsePrefix(addressPrefix)
	if err != nil || !prefix.Addr().Is4() {
		return false, c.invalid("agentSubnetResourceId.addressPrefix", addressPrefix, "an IPv4 CIDR",
			"provide an agent subnet with an IPv4 address prefix beginning with 10, 172 or 192")
	}
	firstOctet := prefix.Addr().As4()[0]
	if firstOctet != 10 && firstOctet != 172 && firstOctet != 192 {
		return false, c.invalid("agentSubnetResourceId.addressPrefix", addressPrefix, "a 10, 172 or 192 IPv4 prefix",
			"select an agent subnet with a supported address prefix; azd will not change its address range")
	}
	delegated := false
	for _, delegation := range properties.Delegations {
		if delegation == nil || delegation.Properties == nil ||
			!strings.EqualFold(byoAKSString(delegation.Properties.ServiceName), byoAKSDelegation) {
			service := "unknown delegation"
			if delegation != nil && delegation.Properties != nil {
				service = byoAKSString(delegation.Properties.ServiceName)
			}
			return false, c.invalid("agentSubnetResourceId.delegations", service, byoAKSDelegation+" or no delegation",
				"use a dedicated agent subnet; azd will not remove or replace another service's delegation")
		}
		delegated = true
	}
	return !delegated, nil
}

func (c *byoAKSConfig) invalid(property, observed, expected, suggestion string) error {
	clusterID := c.ClusterResourceID
	if _, err := arm.ParseResourceID(clusterID); err != nil || strings.ContainsAny(clusterID, "?#") {
		clusterID = "<invalid clusterResourceId>"
	}
	if observed == "" {
		observed = "<missing>"
	}
	return exterrors.Validation(exterrors.CodeBYOAKSPreflightFailed,
		fmt.Sprintf("BYO AKS cluster %q: %s is %q; expected %s", clusterID, property, observed, expected), suggestion)
}

func byoAKSString[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
