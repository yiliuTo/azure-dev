// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"errors"
	"strings"
	"testing"

	"azure.ai.projects/internal/exterrors"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/azure/azure-dev/cli/azd/pkg/azdext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	byoTestSubscription = "00000000-0000-0000-0000-000000000001"
	byoTestScope        = "/subscriptions/" + byoTestSubscription + "/resourceGroups/customer"
	byoTestCluster      = byoTestScope + "/providers/Microsoft.ContainerService/managedClusters/aks"
	byoTestVNet         = byoTestScope + "/providers/Microsoft.Network/virtualNetworks/vnet"
	byoTestNodeSubnet   = byoTestVNet + "/subnets/nodes"
	byoTestAgentSubnet  = byoTestVNet + "/subnets/agents"
	byoTestManagement   = byoTestScope + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/management"
	byoTestWorkload     = byoTestScope + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/workload"
	byoTestStorage      = byoTestScope + "/providers/Microsoft.Storage/storageAccounts/storage"
	byoTestManagementID = "00000000-0000-0000-0000-000000000002"
	byoTestWorkloadID   = "00000000-0000-0000-0000-000000000003"
)

func byoAKSTestConfig() *byoAKSConfig {
	return &byoAKSConfig{
		Enabled: true, HostingType: "ManagedCluster", ClusterResourceID: byoTestCluster,
		AgentSubnetResourceID: byoTestAgentSubnet, HostingManagementIdentityResourceID: byoTestManagement,
		WorkloadIdentityResourceID: byoTestWorkload, StorageAccountResourceID: byoTestStorage,
	}
}

func byoAKSTestSnapshot() *byoAKSSnapshot {
	return &byoAKSSnapshot{
		cluster: armcontainerservice.ManagedCluster{
			ID: new(byoTestCluster), Location: new("eastus2"),
			Properties: &armcontainerservice.ManagedClusterProperties{
				OidcIssuerProfile: &armcontainerservice.ManagedClusterOIDCIssuerProfile{
					Enabled: new(true), IssuerURL: new("https://issuer.example/"),
				},
				SecurityProfile: &armcontainerservice.ManagedClusterSecurityProfile{
					WorkloadIdentity: &armcontainerservice.ManagedClusterSecurityProfileWorkloadIdentity{Enabled: new(true)},
				},
				AADProfile: &armcontainerservice.ManagedClusterAADProfile{EnableAzureRBAC: new(true)},
				NetworkProfile: &armcontainerservice.NetworkProfile{
					NetworkPlugin:     new(armcontainerservice.NetworkPluginAzure),
					NetworkPluginMode: new(armcontainerservice.NetworkPluginModeOverlay),
				},
				AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{{
					Name: new("kata"), WorkloadRuntime: new(armcontainerservice.WorkloadRuntime("KataVmIsolation")),
					VnetSubnetID: new(byoTestNodeSubnet),
					NodeLabels:   map[string]*string{byoAKSSandboxLabel: new("true")},
				}},
			},
		},
		management: armmsi.Identity{Properties: &armmsi.UserAssignedIdentityProperties{
			PrincipalID: new(byoTestManagementID),
		}},
		workload: armmsi.Identity{Properties: &armmsi.UserAssignedIdentityProperties{
			PrincipalID: new(byoTestWorkloadID), ClientID: new("workload-client"), TenantID: new("workload-tenant"),
		}},
		storage: armresources.GenericResource{ID: new(byoTestStorage), Location: new("eastus2")},
		subnet: armnetwork.Subnet{
			ID: new(byoTestAgentSubnet), Name: new("agents"),
			Properties: &armnetwork.SubnetPropertiesFormat{
				AddressPrefix: new("10.20.2.0/28"),
				NetworkSecurityGroup: &armnetwork.SecurityGroup{
					ID: new(byoTestScope + "/providers/Microsoft.Network/networkSecurityGroups/existing"),
				},
				RouteTable: &armnetwork.RouteTable{
					ID: new(byoTestScope + "/providers/Microsoft.Network/routeTables/existing"),
				},
				NatGateway: &armnetwork.SubResource{
					ID: new(byoTestScope + "/providers/Microsoft.Network/natGateways/existing"),
				},
				DefaultOutboundAccess: new(false),
				ServiceEndpoints: []*armnetwork.ServiceEndpointPropertiesFormat{{
					Service: new("Microsoft.Storage"), Locations: []*string{new("eastus2")},
				}},
			},
		},
	}
}

func TestBYOAKSPreflight(t *testing.T) {
	tests := []struct {
		name     string
		change   func(*byoAKSSnapshot)
		property string
	}{
		{"valid overlay with a 10 prefix smaller than /27", func(*byoAKSSnapshot) {}, ""},
		{"case insensitive location and runtime", func(s *byoAKSSnapshot) {
			s.cluster.Location = new("EASTUS2")
			s.storage.Location = new("EastUs2")
			s.cluster.Properties.AgentPoolProfiles[0].WorkloadRuntime =
				new(armcontainerservice.WorkloadRuntime("katavmisolation"))
		}, ""},
		{"no invented version size or ready constraints", func(s *byoAKSSnapshot) {
			s.cluster.Properties.KubernetesVersion = nil
			s.cluster.Properties.ProvisioningState = new("Updating")
			s.cluster.Properties.AgentPoolProfiles[0].Count = nil
			s.cluster.Properties.AgentPoolProfiles[0].VMSize = nil
		}, ""},
		{"non overlay all pools have pod subnets", func(s *byoAKSSnapshot) {
			s.cluster.Properties.NetworkProfile.NetworkPluginMode = nil
			s.cluster.Properties.AgentPoolProfiles[0].PodSubnetID = new(byoTestVNet + "/subnets/pods")
			s.cluster.Properties.AgentPoolProfiles = append(s.cluster.Properties.AgentPoolProfiles,
				&armcontainerservice.ManagedClusterAgentPoolProfile{
					Name: new("system"), VnetSubnetID: new(byoTestNodeSubnet),
					PodSubnetID: new(byoTestVNet + "/subnets/pods2"),
				})
		}, ""},
		{"addressPrefixes fallback", func(s *byoAKSSnapshot) {
			s.subnet.Properties.AddressPrefix = nil
			s.subnet.Properties.AddressPrefixes = []*string{new("192.168.1.0/28")}
		}, ""},
		{"cluster region", func(s *byoAKSSnapshot) { s.cluster.Location = new("westus") }, "location"},
		{"storage region", func(s *byoAKSSnapshot) {
			s.storage.Location = new("westus")
		}, "storageAccountResourceId.location"},
		{"missing AKS properties", func(s *byoAKSSnapshot) { s.cluster.Properties = nil }, "properties"},
		{"disabled OIDC", func(s *byoAKSSnapshot) {
			s.cluster.Properties.OidcIssuerProfile.Enabled = new(false)
		}, "oidcIssuerProfile.enabled"},
		{"missing OIDC issuer", func(s *byoAKSSnapshot) {
			s.cluster.Properties.OidcIssuerProfile.IssuerURL = nil
		}, "oidcIssuerProfile.issuerURL"},
		{"disabled workload identity", func(s *byoAKSSnapshot) {
			s.cluster.Properties.SecurityProfile.WorkloadIdentity.Enabled = new(false)
		}, "securityProfile.workloadIdentity.enabled"},
		{"native Kubernetes RBAC is a demo boundary", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AADProfile.EnableAzureRBAC = new(false)
		}, "aadProfile.enableAzureRBAC"},
		{"kubenet", func(s *byoAKSSnapshot) {
			s.cluster.Properties.NetworkProfile.NetworkPlugin = new(armcontainerservice.NetworkPluginKubenet)
		}, "networkProfile.networkPlugin"},
		{"empty node pools", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AgentPoolProfiles = nil
		}, "agentPoolProfiles"},
		{"non overlay missing pod subnet on second pool", func(s *byoAKSSnapshot) {
			s.cluster.Properties.NetworkProfile.NetworkPluginMode = nil
			s.cluster.Properties.AgentPoolProfiles[0].PodSubnetID = new(byoTestVNet + "/subnets/pods")
			s.cluster.Properties.AgentPoolProfiles = append(s.cluster.Properties.AgentPoolProfiles,
				&armcontainerservice.ManagedClusterAgentPoolProfile{
					Name: new("other"), VnetSubnetID: new(byoTestNodeSubnet),
				})
		}, "agentPoolProfiles[1].podSubnetID"},
		{"Kata and label on different pools", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AgentPoolProfiles[0].NodeLabels = nil
			s.cluster.Properties.AgentPoolProfiles = append(s.cluster.Properties.AgentPoolProfiles,
				&armcontainerservice.ManagedClusterAgentPoolProfile{
					Name: new("other"), VnetSubnetID: new(byoTestNodeSubnet),
					NodeLabels: map[string]*string{byoAKSSandboxLabel: new("true")},
				})
		}, "agentPoolProfiles"},
		{"label value is case sensitive", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AgentPoolProfiles[0].NodeLabels[byoAKSSandboxLabel] = new("True")
		}, "agentPoolProfiles"},
		{"missing management principal", func(s *byoAKSSnapshot) {
			s.management.Properties.PrincipalID = nil
		}, "hostingManagementIdentityResourceId.principalId"},
		{"missing workload client", func(s *byoAKSSnapshot) {
			s.workload.Properties.ClientID = nil
		}, "workloadIdentityResourceId.clientId/tenantId"},
		{"missing workload tenant", func(s *byoAKSSnapshot) {
			s.workload.Properties.TenantID = nil
		}, "workloadIdentityResourceId.clientId/tenantId"},
		{"same identity principal", func(s *byoAKSSnapshot) {
			s.workload.Properties.PrincipalID = new(byoTestManagementID)
		}, "workloadIdentityResourceId.principalId"},
		{"agent subnet is a node subnet", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AgentPoolProfiles[0].VnetSubnetID = new(byoTestAgentSubnet)
		}, "agentSubnetResourceId"},
		{"agent subnet is a pod subnet", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AgentPoolProfiles[0].PodSubnetID = new(byoTestAgentSubnet)
		}, "agentSubnetResourceId"},
		{"different VNet is a demo boundary", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AgentPoolProfiles[0].VnetSubnetID = new(byoTestVNet + "-other/subnets/nodes")
		}, "agentPoolProfiles[0].vnetSubnetID"},
		{"missing subnet properties", func(s *byoAKSSnapshot) {
			s.subnet.Properties = nil
		}, "agentSubnetResourceId.properties"},
		{"unsupported prefix", func(s *byoAKSSnapshot) {
			s.subnet.Properties.AddressPrefix = new("11.0.0.0/24")
		}, "agentSubnetResourceId.addressPrefix"},
		{"conflicting delegation", func(s *byoAKSSnapshot) {
			s.subnet.Properties.Delegations = []*armnetwork.Delegation{{
				Name: new("existing"), Properties: &armnetwork.ServiceDelegationPropertiesFormat{
					ServiceName: new("Microsoft.ContainerInstance/containerGroups"),
				},
			}}
		}, "agentSubnetResourceId.delegations"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, state := byoAKSTestConfig(), byoAKSTestSnapshot()
			tt.change(state)
			ids, err := config.resources(byoTestSubscription)
			require.NoError(t, err)
			needsDelegation, err := config.validate(ids, state, "eastus2")
			if tt.property == "" {
				require.NoError(t, err)
				assert.True(t, needsDelegation)
				return
			}
			require.Error(t, err)
			local, ok := errors.AsType[*azdext.LocalError](err)
			require.True(t, ok)
			assert.Equal(t, exterrors.CodeBYOAKSPreflightFailed, local.Code)
			assert.Contains(t, local.Message, byoTestCluster)
			assert.Contains(t, local.Message, tt.property)
			assert.Contains(t, local.Message, "expected")
			assert.NotEmpty(t, local.Suggestion)
		})
	}
}

func TestBYOAKSResourceConstraints(t *testing.T) {
	for _, tt := range []struct {
		name, property string
		change         func(*byoAKSConfig)
	}{
		{"cluster subscription", "clusterResourceId.subscription", func(c *byoAKSConfig) {
			c.ClusterResourceID = strings.Replace(c.ClusterResourceID, byoTestSubscription, "different", 1)
		}},
		{"storage subscription", "storageAccountResourceId.subscription", func(c *byoAKSConfig) {
			c.StorageAccountResourceID = strings.Replace(c.StorageAccountResourceID, byoTestSubscription, "different", 1)
		}},
		{"subnet subscription", "agentSubnetResourceId.subscription", func(c *byoAKSConfig) {
			c.AgentSubnetResourceID = strings.Replace(c.AgentSubnetResourceID, byoTestSubscription, "different", 1)
		}},
		{"same UAMI", "workloadIdentityResourceId", func(c *byoAKSConfig) {
			c.WorkloadIdentityResourceID = strings.ToUpper(c.HostingManagementIdentityResourceID)
		}},
		{"wrong resource type", "clusterResourceId", func(c *byoAKSConfig) { c.ClusterResourceID = byoTestStorage }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := byoAKSTestConfig()
			tt.change(config)
			_, err := config.resources(byoTestSubscription)
			require.ErrorContains(t, err, tt.property)
		})
	}
}
