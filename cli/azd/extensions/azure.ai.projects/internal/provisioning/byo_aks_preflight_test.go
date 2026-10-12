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
	byoTestFoundryRG    = "/subscriptions/" + byoTestSubscription + "/resourceGroups/foundry"
	byoTestCluster      = byoTestScope + "/providers/Microsoft.ContainerService/managedClusters/aks"
	byoTestVNet         = byoTestScope + "/providers/Microsoft.Network/virtualNetworks/vnet"
	byoTestNodeSubnet   = byoTestVNet + "/subnets/nodes"
	byoTestAgentSubnet  = byoTestVNet + "/subnets/agents"
	byoTestRouteTable   = byoTestScope + "/providers/Microsoft.Network/routeTables/existing"
	byoTestNSG          = byoTestScope + "/providers/Microsoft.Network/networkSecurityGroups/existing"
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
	agentSubnet := armnetwork.Subnet{
		ID: new(byoTestAgentSubnet), Name: new("agents"),
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: new("10.20.2.0/27"),
			NetworkSecurityGroup: &armnetwork.SecurityGroup{
				ID: new(byoTestNSG),
			},
			RouteTable: &armnetwork.RouteTable{
				ID: new(byoTestRouteTable),
			},
			NatGateway: &armnetwork.SubResource{
				ID: new(byoTestScope + "/providers/Microsoft.Network/natGateways/existing"),
			},
			DefaultOutboundAccess: new(false),
			ServiceEndpoints: []*armnetwork.ServiceEndpointPropertiesFormat{{
				Service: new("Microsoft.Storage"), Locations: []*string{new("eastus2")},
			}},
		},
	}
	nodeSubnet := armnetwork.Subnet{
		ID: new(byoTestNodeSubnet), Name: new("nodes"),
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: new("10.20.1.0/24"),
		},
	}
	storage := armresources.GenericResource{
		ID: new(byoTestStorage), Location: new("eastus2"),
		Properties: map[string]any{
			"publicNetworkAccess": "Enabled",
			"primaryEndpoints":    map[string]any{"blob": "https://storage.blob.core.windows.net/"},
			"networkAcls":         map[string]any{"defaultAction": "Allow"},
		},
	}
	return &byoAKSSnapshot{
		cluster: armcontainerservice.ManagedCluster{
			ID: new(byoTestCluster), Location: new("eastus2"),
			SKU: &armcontainerservice.ManagedClusterSKU{
				Name: new(armcontainerservice.ManagedClusterSKUNameBase),
				Tier: new(armcontainerservice.ManagedClusterSKUTierStandard),
			},
			Identity: &armcontainerservice.ManagedClusterIdentity{
				Type: new(armcontainerservice.ResourceIdentityTypeSystemAssigned),
			},
			Properties: &armcontainerservice.ManagedClusterProperties{
				KubernetesVersion: new("1.31.0"),
				ProvisioningState: new("Succeeded"),
				OidcIssuerProfile: &armcontainerservice.ManagedClusterOIDCIssuerProfile{
					Enabled: new(true), IssuerURL: new("https://issuer.example/"),
				},
				SecurityProfile: &armcontainerservice.ManagedClusterSecurityProfile{
					WorkloadIdentity: &armcontainerservice.ManagedClusterSecurityProfileWorkloadIdentity{Enabled: new(true)},
				},
				EnableRBAC: new(true),
				AddonProfiles: map[string]*armcontainerservice.ManagedClusterAddonProfile{
					"azurepolicy": {Enabled: new(true)},
				},
				NetworkProfile: &armcontainerservice.NetworkProfile{
					NetworkPlugin:     new(armcontainerservice.NetworkPluginAzure),
					NetworkPluginMode: new(armcontainerservice.NetworkPluginModeOverlay),
				},
			},
		},
		agentPools: []*byoAKSAgentPool{{
			name: "kata", sshAccess: "Disabled",
			properties: &armcontainerservice.ManagedClusterAgentPoolProfileProperties{
				Mode:            new(armcontainerservice.AgentPoolModeUser),
				OSType:          new(armcontainerservice.OSTypeLinux),
				OSSKU:           new(armcontainerservice.OSSKUAzureLinux),
				WorkloadRuntime: new(armcontainerservice.WorkloadRuntime("KataVmIsolation")),
				Count:           new(int32(1)), VMSize: new("Standard_D4s_v3"),
				VnetSubnetID:      new(byoTestNodeSubnet),
				NodeLabels:        map[string]*string{byoAKSSandboxLabel: new("true")},
				NodeImageVersion:  new(byoAKSMinimumNodeImage),
				ProvisioningState: new("Succeeded"),
			},
		}},
		management: armmsi.Identity{Properties: &armmsi.UserAssignedIdentityProperties{
			PrincipalID: new(byoTestManagementID),
		}},
		workload: armmsi.Identity{Properties: &armmsi.UserAssignedIdentityProperties{
			PrincipalID: new(byoTestWorkloadID), ClientID: new("workload-client"), TenantID: new("workload-tenant"),
		}},
		storage: storage,
		subnet:  agentSubnet,
		network: &byoAKSNetworkSnapshot{
			subnets: map[string]armnetwork.Subnet{
				byoAKSNetworkKey(byoTestAgentSubnet): agentSubnet,
				byoAKSNetworkKey(byoTestNodeSubnet):  nodeSubnet,
			},
			virtualNetworks: map[string]armnetwork.VirtualNetwork{
				byoAKSNetworkKey(byoTestVNet): {
					ID: new(byoTestVNet), Name: new("vnet"),
					Properties: &armnetwork.VirtualNetworkPropertiesFormat{
						ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
					},
				},
			},
			peerings: map[string][]*armnetwork.VirtualNetworkPeering{},
			routeTables: map[string]armnetwork.RouteTable{
				byoAKSNetworkKey(byoTestRouteTable): {
					ID: new(byoTestRouteTable),
					Properties: &armnetwork.RouteTablePropertiesFormat{
						ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
					},
				},
			},
			securityGroups: map[string]armnetwork.SecurityGroup{
				byoAKSNetworkKey(byoTestNSG): {
					ID: new(byoTestNSG),
					Properties: &armnetwork.SecurityGroupPropertiesFormat{
						ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
					},
				},
			},
			privateEndpoints:    map[string]*byoAKSPrivateEndpointSnapshot{},
			privateDNSZoneLinks: map[string][]byoAKSPrivateDNSZoneLink{},
			storage: byoAKSStorageNetwork{
				resourceID:          byoTestStorage,
				publicNetworkAccess: "Enabled",
				defaultAction:       "Allow",
				blobEndpoint:        "https://storage.blob.core.windows.net/",
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
		{"valid non Entra", func(*byoAKSSnapshot) {}, ""},
		{"managed Entra with Azure RBAC", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AADProfile = &armcontainerservice.ManagedClusterAADProfile{
				Managed: new(true), EnableAzureRBAC: new(true),
			}
		}, ""},
		{"Kubernetes 1.31 boundary", func(s *byoAKSSnapshot) {
			s.cluster.Properties.KubernetesVersion = new("1.31")
		}, ""},
		{"Kubernetes 1.36 recommendation is not mandatory", func(s *byoAKSSnapshot) {
			s.cluster.Properties.KubernetesVersion = new("1.35.7")
		}, ""},
		{"system and user assigned identity", func(s *byoAKSSnapshot) {
			s.cluster.Identity.Type = new(armcontainerservice.ResourceIdentityType("SystemAssigned, UserAssigned"))
		}, ""},
		{"native Kubernetes RBAC", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AADProfile = &armcontainerservice.ManagedClusterAADProfile{
				Managed: new(true), EnableAzureRBAC: new(false),
			}
		}, ""},
		{"non overlay all pools have pod subnets", func(s *byoAKSSnapshot) {
			s.cluster.Properties.NetworkProfile.NetworkPluginMode = nil
			podSubnetID := byoTestVNet + "/subnets/pods"
			s.agentPools[0].properties.PodSubnetID = new(podSubnetID)
			s.network.subnets[byoAKSNetworkKey(podSubnetID)] = armnetwork.Subnet{
				ID: new(podSubnetID), Name: new("pods"),
				Properties: &armnetwork.SubnetPropertiesFormat{AddressPrefix: new("10.20.3.0/24")},
			}
		}, ""},
		{"missing issuer URL is allowed", func(s *byoAKSSnapshot) {
			s.cluster.Properties.OidcIssuerProfile.IssuerURL = nil
		}, ""},
		{"addressPrefixes fallback", func(s *byoAKSSnapshot) {
			s.subnet.Properties.AddressPrefix = nil
			s.subnet.Properties.AddressPrefixes = []*string{new("192.168.1.0/27")}
			s.network.subnets[byoAKSNetworkKey(byoTestAgentSubnet)] = s.subnet
		}, ""},
		{"cluster region", func(s *byoAKSSnapshot) { s.cluster.Location = new("westus") }, "location"},
		{"storage region", func(s *byoAKSSnapshot) {
			s.storage.Location = new("westus")
		}, "storageAccountResourceId.location"},
		{"missing AKS properties", func(s *byoAKSSnapshot) { s.cluster.Properties = nil }, "properties"},
		{"Automatic SKU", func(s *byoAKSSnapshot) {
			s.cluster.SKU.Name = new(armcontainerservice.ManagedClusterSKUNameAutomatic)
		}, "sku"},
		{"Free tier", func(s *byoAKSSnapshot) {
			s.cluster.SKU.Tier = new(armcontainerservice.ManagedClusterSKUTierFree)
		}, "sku"},
		{"Kubernetes 1.30", func(s *byoAKSSnapshot) {
			s.cluster.Properties.KubernetesVersion = new("1.30.9")
		}, "kubernetesVersion"},
		{"missing Kubernetes version", func(s *byoAKSSnapshot) {
			s.cluster.Properties.KubernetesVersion = nil
		}, "kubernetesVersion"},
		{"cluster updating", func(s *byoAKSSnapshot) {
			s.cluster.Properties.ProvisioningState = new("Updating")
		}, "provisioningState"},
		{"service principal identity", func(s *byoAKSSnapshot) {
			s.cluster.Identity.Type = new(armcontainerservice.ResourceIdentityTypeNone)
		}, "identity.type"},
		{"unknown combined identity", func(s *byoAKSSnapshot) {
			s.cluster.Identity.Type = new(armcontainerservice.ResourceIdentityType("SystemAssigned, Alien"))
		}, "identity.type"},
		{"disabled OIDC", func(s *byoAKSSnapshot) {
			s.cluster.Properties.OidcIssuerProfile.Enabled = new(false)
		}, "oidcIssuerProfile.enabled"},
		{"disabled workload identity", func(s *byoAKSSnapshot) {
			s.cluster.Properties.SecurityProfile.WorkloadIdentity.Enabled = new(false)
		}, "securityProfile.workloadIdentity.enabled"},
		{"Azure Policy disabled", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AddonProfiles["azurepolicy"].Enabled = new(false)
		}, "addonProfiles.azurepolicy.enabled"},
		{"legacy unmanaged Entra", func(s *byoAKSSnapshot) {
			s.cluster.Properties.AADProfile = &armcontainerservice.ManagedClusterAADProfile{
				Managed: new(false), EnableAzureRBAC: new(false),
			}
		}, "aadProfile.managed"},
		{"kubenet", func(s *byoAKSSnapshot) {
			s.cluster.Properties.NetworkProfile.NetworkPlugin = new(armcontainerservice.NetworkPluginKubenet)
		}, "networkProfile.networkPlugin"},
		{"empty node pools", func(s *byoAKSSnapshot) {
			s.agentPools = nil
		}, "agentPools"},
		{"Azure CNI Node Subnet", func(s *byoAKSSnapshot) {
			s.cluster.Properties.NetworkProfile.NetworkPluginMode = nil
		}, "agentPools[0].podSubnetID"},
		{"system pool", func(s *byoAKSSnapshot) {
			s.agentPools[0].properties.Mode = new(armcontainerservice.AgentPoolModeSystem)
		}, "agentPools"},
		{"Ubuntu pool", func(s *byoAKSSnapshot) {
			s.agentPools[0].properties.OSSKU = new(armcontainerservice.OSSKUUbuntu)
		}, "agentPools"},
		{"non Kata pool", func(s *byoAKSSnapshot) {
			s.agentPools[0].properties.WorkloadRuntime = new(armcontainerservice.WorkloadRuntimeOCIContainer)
		}, "agentPools"},
		{"zero nodes", func(s *byoAKSSnapshot) {
			s.agentPools[0].properties.Count = new(int32(0))
		}, "agentPools"},
		{"missing VM size", func(s *byoAKSSnapshot) {
			s.agentPools[0].properties.VMSize = nil
		}, "agentPools"},
		{"label value is case sensitive", func(s *byoAKSSnapshot) {
			s.agentPools[0].properties.NodeLabels[byoAKSSandboxLabel] = new("True")
		}, "agentPools"},
		{"wrong node image family", func(s *byoAKSSnapshot) {
			s.agentPools[0].properties.NodeImageVersion = new("AKSUbuntu-202608.14.0")
		}, "agentPools"},
		{"older node image", func(s *byoAKSSnapshot) {
			s.agentPools[0].properties.NodeImageVersion = new("AKSAzureLinux-V3katagen2-202608.13.99")
		}, "agentPools"},
		{"SSH enabled", func(s *byoAKSSnapshot) {
			s.agentPools[0].sshAccess = "LocalUser"
		}, "agentPools"},
		{"pool updating", func(s *byoAKSSnapshot) {
			s.agentPools[0].properties.ProvisioningState = new("Updating")
		}, "agentPools"},
		{"multiple pools only one qualifies", func(s *byoAKSSnapshot) {
			bad := *s.agentPools[0]
			badProperties := *bad.properties
			bad.properties = &badProperties
			bad.name = "bad"
			bad.properties.NodeLabels = nil
			s.agentPools = append([]*byoAKSAgentPool{&bad}, s.agentPools...)
		}, ""},
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
			s.agentPools[0].properties.VnetSubnetID = new(byoTestAgentSubnet)
		}, "agentSubnetResourceId"},
		{"agent subnet is a pod subnet", func(s *byoAKSSnapshot) {
			s.agentPools[0].properties.PodSubnetID = new(byoTestAgentSubnet)
		}, "agentSubnetResourceId"},
		{"missing subnet properties", func(s *byoAKSSnapshot) {
			s.subnet.Properties = nil
		}, "agentSubnetResourceId.properties"},
		{"unsupported prefix", func(s *byoAKSSnapshot) {
			s.subnet.Properties.AddressPrefix = new("11.0.0.0/24")
			s.network.subnets[byoAKSNetworkKey(byoTestAgentSubnet)] = s.subnet
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
			validation, err := config.validate(ids, state, "eastus2")
			if tt.property == "" {
				require.NoError(t, err)
				assert.True(t, validation.needsDelegation)
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
		{"Arc connected cluster", "clusterResourceId", func(c *byoAKSConfig) {
			c.ClusterResourceID = byoTestScope + "/providers/Microsoft.Kubernetes/connectedClusters/arc"
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := byoAKSTestConfig()
			tt.change(config)
			_, err := config.resources(byoTestSubscription)
			require.ErrorContains(t, err, tt.property)
		})
	}
}

func TestBYOAKSNodeImageVersion(t *testing.T) {
	for _, tt := range []struct {
		name, version string
		valid         bool
	}{
		{"minimum", byoAKSMinimumNodeImage, true},
		{"later day", "AKSAzureLinux-V3katagen2-202608.15.0", true},
		{"later release", "AKSAzureLinux-V3katagen2-202609.1.0", true},
		{"later patch", "AKSAzureLinux-V3katagen2-202608.14.10", true},
		{"older day", "AKSAzureLinux-V3katagen2-202608.13.99", false},
		{"older release", "AKSAzureLinux-V3katagen2-202607.99.99", false},
		{"wrong family", "AKSAzureLinux-V3-202608.14.0", false},
		{"unparseable", "AKSAzureLinux-V3katagen2-latest", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, byoAKSNodeImageAtLeast(tt.version, byoAKSMinimumNodeImage))
		})
	}
}
