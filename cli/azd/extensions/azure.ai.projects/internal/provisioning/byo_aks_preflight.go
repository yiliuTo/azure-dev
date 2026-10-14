// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// cspell:ignore AKSSKU BYOAKS OSSKU armnetwork azurepolicy Kata katagen systemassigned userassigned

package provisioning

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"azure.ai.projects/internal/exterrors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

const (
	byoAKSSandboxLabel        = "agents.ai.azure.com/sandbox-node"
	byoAKSDelegation          = "Microsoft.App/environments"
	byoAKSClusterAdminRoleID  = "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b"
	byoAKSMinimumNodeImage    = "AKSAzureLinux-V3katagen2-202608.14.0"
	byoAKSAgentPoolAPIVersion = "2025-08-01"
)

var byoAKSNodeImagePattern = regexp.MustCompile(
	`^AKSAzureLinux-V3katagen2-([0-9]{6})\.([0-9]+)\.([0-9]+)$`)

type byoAKSAuthorization int

const (
	byoAKSAuthorizationNonEntra byoAKSAuthorization = iota
	byoAKSAuthorizationAzureRBAC
	byoAKSAuthorizationNativeRBAC
)

type byoAKSAgentPool struct {
	name       string
	properties *armcontainerservice.ManagedClusterAgentPoolProfileProperties
	sshAccess  string
}

type byoAKSValidation struct {
	needsDelegation bool
	authorization   byoAKSAuthorization
}

type byoAKSConfig struct {
	Enabled                             bool   `json:"enabled"`
	HostingType                         string `json:"hostingType"`
	ClusterResourceID                   string `json:"clusterResourceId"`
	AgentSubnetResourceID               string `json:"agentSubnetResourceId"`
	HostingManagementIdentityResourceID string `json:"hostingManagementIdentityResourceId"`
	StorageAccountResourceID            string `json:"storageAccountResourceId"`
	WorkloadIdentityResourceID          string `json:"workloadIdentityResourceId"`
	ContainerRegistryResourceID         string `json:"containerRegistryResourceId"`
}

type byoAKSResources struct {
	cluster, subnet, management, workload, storage, registry *arm.ResourceID
}

type byoAKSSnapshot struct {
	cluster              armcontainerservice.ManagedCluster
	agentPools           []*byoAKSAgentPool
	subnet               armnetwork.Subnet
	management, workload armmsi.Identity
	storage              armresources.GenericResource
	network              *byoAKSNetworkSnapshot
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
		optional                  bool
	}{
		{
			"clusterResourceId", c.ClusterResourceID,
			"Microsoft.ContainerService/managedClusters", &resources.cluster, true, false,
		},
		{
			"agentSubnetResourceId", c.AgentSubnetResourceID,
			"Microsoft.Network/virtualNetworks/subnets", &resources.subnet, true, false,
		},
		{
			"hostingManagementIdentityResourceId", c.HostingManagementIdentityResourceID,
			"Microsoft.ManagedIdentity/userAssignedIdentities", &resources.management, false, false,
		},
		{
			"workloadIdentityResourceId", c.WorkloadIdentityResourceID,
			"Microsoft.ManagedIdentity/userAssignedIdentities", &resources.workload, false, false,
		},
		{
			"storageAccountResourceId", c.StorageAccountResourceID,
			"Microsoft.Storage/storageAccounts", &resources.storage, true, false,
		},
		{
			"containerRegistryResourceId", c.ContainerRegistryResourceID,
			"Microsoft.ContainerRegistry/registries", &resources.registry, false, true,
		},
	} {
		if field.optional && strings.TrimSpace(field.value) == "" {
			continue
		}
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
) (*byoAKSValidation, error) {
	if !strings.EqualFold(byoAKSString(state.cluster.Location), location) {
		return nil, c.invalid("location", byoAKSString(state.cluster.Location), location,
			"set AZURE_LOCATION to the AKS region, or select an AKS cluster in the Foundry region")
	}
	if !strings.EqualFold(byoAKSString(state.storage.Location), location) {
		return nil, c.invalid("storageAccountResourceId.location", byoAKSString(state.storage.Location), location,
			"use a storage account in the AKS and Foundry region")
	}
	authorization, err := c.validateCluster(state.cluster, state.agentPools)
	if err != nil {
		return nil, err
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
			return nil, c.invalid(identity.name+".principalId", "missing", "a resolved Entra principal ID",
				"verify the referenced user-assigned identity exists and has a principalId")
		}
		if identity.workload &&
			(strings.TrimSpace(byoAKSString(identity.properties.ClientID)) == "" ||
				strings.TrimSpace(byoAKSString(identity.properties.TenantID)) == "") {
			return nil, c.invalid(identity.name+".clientId/tenantId", "missing", "both clientId and tenantId",
				"use a fully provisioned workload user-assigned identity")
		}
	}
	if strings.EqualFold(*state.management.Properties.PrincipalID, *state.workload.Properties.PrincipalID) {
		return nil, c.invalid("workloadIdentityResourceId.principalId", "the management principal",
			"a different principal", "provide separate hosting management and workload identities")
	}
	needsDelegation, err := c.validateNetwork(ids, state)
	if err != nil {
		return nil, err
	}
	return &byoAKSValidation{needsDelegation: needsDelegation, authorization: authorization}, nil
}

func (c *byoAKSConfig) validateCluster(
	cluster armcontainerservice.ManagedCluster, pools []*byoAKSAgentPool,
) (byoAKSAuthorization, error) {
	properties := cluster.Properties
	if properties == nil {
		return 0, c.invalid("properties", "missing", "AKS cluster properties", "verify the AKS resource can be read")
	}
	if cluster.SKU == nil ||
		!strings.EqualFold(byoAKSString(cluster.SKU.Name), string(armcontainerservice.ManagedClusterSKUNameBase)) ||
		!strings.EqualFold(byoAKSString(cluster.SKU.Tier), string(armcontainerservice.ManagedClusterSKUTierStandard)) {
		return 0, c.invalid("sku", formatAKSSKU(cluster.SKU), "AKS Base SKU with Standard tier",
			"use an AKS Standard cluster; AKS Automatic is unsupported")
	}
	version := byoAKSString(properties.CurrentKubernetesVersion)
	if version == "" {
		version = byoAKSString(properties.KubernetesVersion)
	}
	if !byoAKSKubernetesVersionAtLeast(version, 1, 31) {
		return 0, c.invalid("kubernetesVersion", version, "Kubernetes 1.31 or later",
			"upgrade the AKS cluster to Kubernetes 1.31 or later; 1.36.3 is currently recommended")
	}
	if !strings.EqualFold(byoAKSString(properties.ProvisioningState), "Succeeded") {
		return 0, c.invalid("provisioningState", byoAKSString(properties.ProvisioningState), "Succeeded",
			"wait for the AKS cluster provisioning state to become Succeeded")
	}
	if !byoAKSManagedIdentity(cluster.Identity) {
		return 0, c.invalid("identity.type", clusterIdentityType(cluster.Identity),
			"SystemAssigned or UserAssigned managed identity",
			"migrate the AKS cluster from service-principal authentication to a managed identity")
	}
	oidc := properties.OidcIssuerProfile
	if oidc == nil || oidc.Enabled == nil || !*oidc.Enabled {
		return 0, c.invalid("oidcIssuerProfile.enabled", "false or missing", "true", "enable the AKS OIDC issuer")
	}
	security := properties.SecurityProfile
	if security == nil || security.WorkloadIdentity == nil ||
		security.WorkloadIdentity.Enabled == nil || !*security.WorkloadIdentity.Enabled {
		return 0, c.invalid("securityProfile.workloadIdentity.enabled", "false or missing", "true",
			"enable AKS workload identity")
	}
	var policy *armcontainerservice.ManagedClusterAddonProfile
	for name, profile := range properties.AddonProfiles {
		if strings.EqualFold(name, "azurepolicy") {
			policy = profile
			break
		}
	}
	if policy == nil || policy.Enabled == nil || !*policy.Enabled {
		return 0, c.invalid("addonProfiles.azurepolicy.enabled", "false or missing", "true",
			"enable the Azure Policy add-on on the AKS cluster")
	}
	network := properties.NetworkProfile
	if network == nil || !strings.EqualFold(byoAKSString(network.NetworkPlugin), "azure") {
		plugin := ""
		if network != nil {
			plugin = byoAKSString(network.NetworkPlugin)
		}
		return 0, c.invalid("networkProfile.networkPlugin", plugin, "azure",
			"use Azure CNI Overlay or Azure CNI Pod Subnet")
	}
	if !strings.EqualFold(byoAKSString(network.NetworkPluginMode), "overlay") {
		if len(pools) == 0 {
			return 0, c.invalid("agentPools", "empty", "AgentPool child resources with podSubnetID",
				"use Azure CNI Overlay or Azure CNI Pod Subnet")
		}
		for i, pool := range pools {
			if pool == nil || pool.properties == nil ||
				strings.TrimSpace(byoAKSString(pool.properties.PodSubnetID)) == "" {
				return 0, c.invalid(fmt.Sprintf("agentPools[%d].podSubnetID", i), "null", "non-null",
					"use Azure CNI Pod Subnet; Azure CNI Node Subnet is unsupported")
			}
		}
	}
	if err := c.validateDedicatedPool(pools); err != nil {
		return 0, err
	}
	aad := properties.AADProfile
	if aad == nil {
		return byoAKSAuthorizationNonEntra, nil
	}
	if aad.Managed == nil || !*aad.Managed {
		return 0, c.invalid("aadProfile.managed", "false or missing", "true or no aadProfile",
			"use managed Microsoft Entra authentication, or a non-Entra AKS cluster")
	}
	if aad.EnableAzureRBAC != nil && *aad.EnableAzureRBAC {
		return byoAKSAuthorizationAzureRBAC, nil
	}
	if properties.EnableRBAC == nil || !*properties.EnableRBAC {
		return 0, c.invalid("enableRBAC", "false or missing", "true for managed Entra with native Kubernetes RBAC",
			"enable Kubernetes RBAC, or enable Azure RBAC for Kubernetes authorization")
	}
	return byoAKSAuthorizationNativeRBAC, nil
}

func (c *byoAKSConfig) validateDedicatedPool(pools []*byoAKSAgentPool) error {
	var failures []string
	for i, pool := range pools {
		if pool == nil || pool.properties == nil {
			failures = append(failures, fmt.Sprintf("agentPools[%d] has missing properties", i))
			continue
		}
		properties := pool.properties
		name := pool.name
		if name == "" {
			name = fmt.Sprintf("[%d]", i)
		}
		checks := []struct {
			valid    bool
			property string
			observed string
			expected string
		}{
			{strings.EqualFold(byoAKSString(properties.Mode), "User"), "mode",
				byoAKSString(properties.Mode), "User"},
			{strings.EqualFold(byoAKSString(properties.OSType), "Linux") &&
				strings.EqualFold(byoAKSString(properties.OSSKU), "AzureLinux"), "osType/osSKU",
				byoAKSString(properties.OSType) + "/" + byoAKSString(properties.OSSKU), "Linux/AzureLinux"},
			{strings.EqualFold(byoAKSString(properties.WorkloadRuntime), "KataVmIsolation"), "workloadRuntime",
				byoAKSString(properties.WorkloadRuntime), "KataVmIsolation"},
			{properties.Count != nil && *properties.Count >= 1, "count",
				formatInt32(properties.Count), "at least 1"},
			{strings.TrimSpace(byoAKSString(properties.VMSize)) != "", "vmSize",
				byoAKSString(properties.VMSize), "non-empty"},
			{byoAKSString(properties.NodeLabels[byoAKSSandboxLabel]) == "true", byoAKSSandboxLabel,
				byoAKSString(properties.NodeLabels[byoAKSSandboxLabel]), "true"},
			{byoAKSNodeImageAtLeast(byoAKSString(properties.NodeImageVersion), byoAKSMinimumNodeImage), "nodeImageVersion",
				byoAKSString(properties.NodeImageVersion), byoAKSMinimumNodeImage + " or later"},
			{strings.EqualFold(pool.sshAccess, "Disabled"), "securityProfile.sshAccess",
				pool.sshAccess, "Disabled"},
			{strings.EqualFold(byoAKSString(properties.ProvisioningState), "Succeeded"), "provisioningState",
				byoAKSString(properties.ProvisioningState), "Succeeded"},
		}
		var poolFailures []string
		for _, check := range checks {
			if !check.valid {
				poolFailures = append(poolFailures,
					fmt.Sprintf("%s=%q (expected %s)", check.property, missingValue(check.observed), check.expected))
			}
		}
		if len(poolFailures) == 0 {
			return nil
		}
		failures = append(failures, fmt.Sprintf("%s: %s", name, strings.Join(poolFailures, ", ")))
	}
	return c.invalid("agentPools", strings.Join(failures, "; "),
		"one same User Azure Linux KataVmIsolation pool with count >= 1, non-empty VM size, node image "+
			byoAKSMinimumNodeImage+" or later, "+byoAKSSandboxLabel+"=true, SSH disabled, and Succeeded state",
		"create or update a dedicated agent pool that satisfies every requirement")
}

func byoAKSKubernetesVersionAtLeast(version string, minimumMajor, minimumMinor int) bool {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) < 2 {
		return false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	return majorErr == nil && minorErr == nil &&
		(major > minimumMajor || major == minimumMajor && minor >= minimumMinor)
}

func byoAKSNodeImageAtLeast(version, minimum string) bool {
	parse := func(value string) ([3]int, bool) {
		matches := byoAKSNodeImagePattern.FindStringSubmatch(value)
		if len(matches) != 4 {
			return [3]int{}, false
		}
		var result [3]int
		for i := range result {
			number, err := strconv.Atoi(matches[i+1])
			if err != nil {
				return [3]int{}, false
			}
			result[i] = number
		}
		return result, true
	}
	actual, actualOK := parse(version)
	floor, floorOK := parse(minimum)
	if !actualOK || !floorOK {
		return false
	}
	for i := range actual {
		if actual[i] != floor[i] {
			return actual[i] > floor[i]
		}
	}
	return true
}

func byoAKSManagedIdentity(identity *armcontainerservice.ManagedClusterIdentity) bool {
	if identity == nil || identity.Type == nil {
		return false
	}
	parts := strings.FieldsFunc(string(*identity.Type), func(r rune) bool { return r == ',' })
	hasManaged := false
	for _, part := range parts {
		switch strings.TrimSpace(strings.ToLower(part)) {
		case "systemassigned", "userassigned":
			hasManaged = true
		case "":
		default:
			return false
		}
	}
	return hasManaged
}

func formatAKSSKU(sku *armcontainerservice.ManagedClusterSKU) string {
	if sku == nil {
		return "<missing>"
	}
	return byoAKSString(sku.Name) + "/" + byoAKSString(sku.Tier)
}

func clusterIdentityType(identity *armcontainerservice.ManagedClusterIdentity) string {
	if identity == nil {
		return "<missing>"
	}
	return byoAKSString(identity.Type)
}

func formatInt32(value *int32) string {
	if value == nil {
		return "<missing>"
	}
	return strconv.FormatInt(int64(*value), 10)
}

func missingValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "<missing>"
	}
	return value
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
