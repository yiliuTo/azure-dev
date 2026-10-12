// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// cspell:ignore BYOAKS privatelink

package provisioning

import (
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/azure/azure-dev/cli/azd/pkg/azdext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validateBYOAKSNetwork(
	t *testing.T, state *byoAKSSnapshot,
) (*byoAKSValidation, error) {
	t.Helper()
	config := byoAKSTestConfig()
	ids, err := config.resources(byoTestSubscription)
	require.NoError(t, err)
	return config.validate(ids, state, "eastus2")
}

func requireBYOAKSNetworkFailure(
	t *testing.T, state *byoAKSSnapshot, property string,
) *azdext.LocalError {
	t.Helper()
	_, err := validateBYOAKSNetwork(t, state)
	require.Error(t, err)
	local, ok := errors.AsType[*azdext.LocalError](err)
	require.True(t, ok)
	assert.Contains(t, local.Message, property)
	assert.NotEmpty(t, local.Suggestion)
	return local
}

func setBYOAKSAgentPrefix(state *byoAKSSnapshot, prefix string) {
	state.subnet.Properties.AddressPrefix = new(prefix)
	state.subnet.Properties.AddressPrefixes = nil
	state.network.subnets[byoAKSNetworkKey(byoTestAgentSubnet)] = state.subnet
}

func TestBYOAKSAgentSubnetCIDR(t *testing.T) {
	for _, tt := range []struct {
		name, prefix string
		valid        bool
	}{
		{"10 private /27", "10.24.0.0/27", true},
		{"172 private /27", "172.16.20.0/27", true},
		{"192 private /27", "192.168.20.0/27", true},
		{"/26 is not exact", "10.24.0.0/26", false},
		{"/28 is not exact", "10.24.0.0/28", false},
		{"172 outside RFC1918", "172.15.20.0/27", false},
		{"192 outside RFC1918", "192.0.2.0/27", false},
		{"carrier grade NAT", "100.64.0.0/27", false},
		{"IPv6", "fd00::/27", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := byoAKSTestSnapshot()
			setBYOAKSAgentPrefix(state, tt.prefix)
			validation, err := validateBYOAKSNetwork(t, state)
			if tt.valid {
				require.NoError(t, err)
				assert.True(t, validation.needsDelegation)
				return
			}
			requireBYOAKSNetworkFailure(t, state, "agentSubnetResourceId.addressPrefix")
		})
	}
}

func TestBYOAKSSubnetCIDROverlap(t *testing.T) {
	t.Run("non-overlapping node subnet", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.network.subnets[byoAKSNetworkKey(byoTestNodeSubnet)].Properties.AddressPrefix =
			new("10.20.2.32/27")
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("overlapping node subnet", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.network.subnets[byoAKSNetworkKey(byoTestNodeSubnet)].Properties.AddressPrefix =
			new("10.20.2.16/28")
		requireBYOAKSNetworkFailure(t, state, "agentSubnetResourceId.addressPrefix")
	})

	t.Run("overlapping non-overlay pod subnet", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		podSubnetID := byoTestVNet + "/subnets/pods"
		state.cluster.Properties.NetworkProfile.NetworkPluginMode = nil
		state.agentPools[0].properties.PodSubnetID = new(podSubnetID)
		state.network.subnets[byoAKSNetworkKey(podSubnetID)] = armnetwork.Subnet{
			ID: new(podSubnetID), Name: new("pods"),
			Properties: &armnetwork.SubnetPropertiesFormat{AddressPrefix: new("10.20.2.0/26")},
		}
		requireBYOAKSNetworkFailure(t, state, "agentSubnetResourceId.addressPrefix")
	})
}

func configureBYOAKSCrossVNet(state *byoAKSSnapshot) (string, string) {
	aksVNet := byoTestScope + "/providers/Microsoft.Network/virtualNetworks/aks-vnet"
	nodeSubnet := aksVNet + "/subnets/nodes"
	delete(state.network.subnets, byoAKSNetworkKey(byoTestNodeSubnet))
	state.agentPools[0].properties.VnetSubnetID = new(nodeSubnet)
	state.network.subnets[byoAKSNetworkKey(nodeSubnet)] = armnetwork.Subnet{
		ID: new(nodeSubnet), Name: new("nodes"),
		Properties: &armnetwork.SubnetPropertiesFormat{AddressPrefix: new("10.30.1.0/24")},
	}
	state.network.virtualNetworks[byoAKSNetworkKey(aksVNet)] = armnetwork.VirtualNetwork{
		ID: new(aksVNet), Name: new("aks-vnet"),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
		},
	}
	peering := func(remote string) *armnetwork.VirtualNetworkPeering {
		return &armnetwork.VirtualNetworkPeering{
			Properties: &armnetwork.VirtualNetworkPeeringPropertiesFormat{
				RemoteVirtualNetwork:      &armnetwork.SubResource{ID: new(remote)},
				AllowVirtualNetworkAccess: new(true),
				AllowForwardedTraffic:     new(false),
				PeerCompleteVnets:         new(true),
				PeeringState:              new(armnetwork.VirtualNetworkPeeringStateConnected),
				PeeringSyncLevel:          new(armnetwork.VirtualNetworkPeeringLevelFullyInSync),
				ProvisioningState:         new(armnetwork.ProvisioningStateSucceeded),
			},
		}
	}
	state.network.peerings[byoAKSNetworkKey(byoTestVNet)] = []*armnetwork.VirtualNetworkPeering{
		peering(aksVNet),
	}
	state.network.peerings[byoAKSNetworkKey(aksVNet)] = []*armnetwork.VirtualNetworkPeering{
		peering(byoTestVNet),
	}
	return aksVNet, nodeSubnet
}

func TestBYOAKSVNetConnectivity(t *testing.T) {
	t.Run("same VNet uses system routing and DNS", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.subnet.Properties.RouteTable = nil
		state.subnet.Properties.NetworkSecurityGroup = nil
		state.network.subnets[byoAKSNetworkKey(byoTestAgentSubnet)] = state.subnet
		clear(state.network.routeTables)
		clear(state.network.securityGroups)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("cross VNet complete", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSCrossVNet(state)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("cross VNet subnet peering", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		aksVNet, _ := configureBYOAKSCrossVNet(state)
		agentToAKS := state.network.peerings[byoAKSNetworkKey(byoTestVNet)][0].Properties
		agentToAKS.PeerCompleteVnets = new(false)
		agentToAKS.LocalSubnetNames = []*string{new("agents")}
		agentToAKS.RemoteSubnetNames = []*string{new("nodes")}
		aksToAgent := state.network.peerings[byoAKSNetworkKey(aksVNet)][0].Properties
		aksToAgent.PeerCompleteVnets = new(false)
		aksToAgent.LocalSubnetNames = []*string{new("nodes")}
		aksToAgent.RemoteSubnetNames = []*string{new("agents")}
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("cross VNet missing reverse peering", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		aksVNet, _ := configureBYOAKSCrossVNet(state)
		delete(state.network.peerings, byoAKSNetworkKey(aksVNet))
		requireBYOAKSNetworkFailure(t, state, "virtualNetworkPeerings")
	})

	t.Run("cross VNet peering not connected", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSCrossVNet(state)
		state.network.peerings[byoAKSNetworkKey(byoTestVNet)][0].Properties.PeeringState =
			new(armnetwork.VirtualNetworkPeeringStateDisconnected)
		requireBYOAKSNetworkFailure(t, state, "virtualNetworkPeerings")
	})

	t.Run("cross VNet attached route table was not read", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSCrossVNet(state)
		delete(state.network.routeTables, byoAKSNetworkKey(byoTestRouteTable))
		requireBYOAKSNetworkFailure(t, state, "routeTable")
	})

	t.Run("cross VNet blackhole route", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSCrossVNet(state)
		state.network.routeTables[byoAKSNetworkKey(byoTestRouteTable)] =
			byoAKSTestRouteTable("10.30.0.0/16", armnetwork.RouteNextHopTypeNone, "")
		requireBYOAKSNetworkFailure(t, state, "routeTable.routes")
	})

	t.Run("cross VNet every destination prefix is checked", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		_, nodeSubnetID := configureBYOAKSCrossVNet(state)
		nodeSubnet := state.network.subnets[byoAKSNetworkKey(nodeSubnetID)]
		nodeSubnet.Properties.AddressPrefix = nil
		nodeSubnet.Properties.AddressPrefixes = []*string{new("10.30.1.0/24"), new("10.31.1.0/24")}
		state.network.subnets[byoAKSNetworkKey(nodeSubnetID)] = nodeSubnet
		table := byoAKSTestRouteTable(
			"10.30.0.0/16",
			armnetwork.RouteNextHopTypeVirtualAppliance,
			"10.20.0.4",
		)
		table.Properties.Routes = append(table.Properties.Routes, &armnetwork.Route{
			Name: new("blackhole-second-prefix"),
			Properties: &armnetwork.RoutePropertiesFormat{
				AddressPrefix: new("10.31.0.0/16"),
				NextHopType:   new(armnetwork.RouteNextHopTypeNone),
			},
		})
		state.network.routeTables[byoAKSNetworkKey(byoTestRouteTable)] = table
		requireBYOAKSNetworkFailure(t, state, "routeTable.routes")
	})

	t.Run("cross VNet virtual appliance requires forwarded traffic", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSCrossVNet(state)
		state.network.routeTables[byoAKSNetworkKey(byoTestRouteTable)] =
			byoAKSTestRouteTable("10.30.0.0/16", armnetwork.RouteNextHopTypeVirtualAppliance, "10.20.0.4")
		requireBYOAKSNetworkFailure(t, state, "allowForwardedTraffic")
		for _, peerings := range state.network.peerings {
			for _, peering := range peerings {
				peering.Properties.AllowForwardedTraffic = new(true)
			}
		}
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("cross VNet DNS mismatch", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		aksVNet, _ := configureBYOAKSCrossVNet(state)
		state.network.virtualNetworks[byoAKSNetworkKey(byoTestVNet)].Properties.DhcpOptions =
			&armnetwork.DhcpOptions{DNSServers: []*string{new("10.20.0.4")}}
		state.network.virtualNetworks[byoAKSNetworkKey(aksVNet)].Properties.DhcpOptions =
			&armnetwork.DhcpOptions{DNSServers: []*string{new("10.30.0.4")}}
		requireBYOAKSNetworkFailure(t, state, "dnsServers")
	})

	t.Run("cross VNet shared custom DNS", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		aksVNet, _ := configureBYOAKSCrossVNet(state)
		state.network.virtualNetworks[byoAKSNetworkKey(byoTestVNet)].Properties.DhcpOptions =
			&armnetwork.DhcpOptions{DNSServers: []*string{new("10.40.0.4")}}
		state.network.virtualNetworks[byoAKSNetworkKey(aksVNet)].Properties.DhcpOptions =
			&armnetwork.DhcpOptions{DNSServers: []*string{new("10.40.0.4"), new("10.40.0.5")}}
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})
}

func byoAKSTestRouteTable(
	prefix string, nextHop armnetwork.RouteNextHopType, nextHopIP string,
) armnetwork.RouteTable {
	return armnetwork.RouteTable{
		ID: new(byoTestRouteTable),
		Properties: &armnetwork.RouteTablePropertiesFormat{
			ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
			Routes: []*armnetwork.Route{{
				Name: new("test-route"),
				Properties: &armnetwork.RoutePropertiesFormat{
					AddressPrefix: new(prefix), NextHopType: new(nextHop), NextHopIPAddress: new(nextHopIP),
				},
			}},
		},
	}
}

func TestBYOAKSConditionalNetworkResources(t *testing.T) {
	t.Run("NSG is not required", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.subnet.Properties.NetworkSecurityGroup = nil
		state.network.subnets[byoAKSNetworkKey(byoTestAgentSubnet)] = state.subnet
		clear(state.network.securityGroups)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("attached NSG must be readable", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		delete(state.network.securityGroups, byoAKSNetworkKey(byoTestNSG))
		requireBYOAKSNetworkFailure(t, state, "networkSecurityGroup")
	})

	t.Run("attached NSG unconditional deny fails", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.network.securityGroups[byoAKSNetworkKey(byoTestNSG)] =
			byoAKSTestNSG(armnetwork.SecurityRuleAccessDeny)
		requireBYOAKSNetworkFailure(t, state, "networkSecurityGroup.securityRules")
	})

	t.Run("attached NSG higher-priority allow passes", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		group := byoAKSTestNSG(armnetwork.SecurityRuleAccessDeny)
		group.Properties.SecurityRules = append([]*armnetwork.SecurityRule{{
			Name: new("allow"),
			Properties: &armnetwork.SecurityRulePropertiesFormat{
				Access: new(armnetwork.SecurityRuleAccessAllow), Direction: new(armnetwork.SecurityRuleDirectionOutbound),
				Priority: new(int32(100)), Protocol: new(armnetwork.SecurityRuleProtocolAsterisk),
				SourceAddressPrefix: new("*"), DestinationAddressPrefix: new("*"),
				SourcePortRange: new("*"), DestinationPortRange: new("*"),
			},
		}}, group.Properties.SecurityRules...)
		state.network.securityGroups[byoAKSNetworkKey(byoTestNSG)] = group
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("node subnet outbound NSG deny fails", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.subnet.Properties.NetworkSecurityGroup = nil
		state.network.subnets[byoAKSNetworkKey(byoTestAgentSubnet)] = state.subnet
		node := state.network.subnets[byoAKSNetworkKey(byoTestNodeSubnet)]
		node.Properties.NetworkSecurityGroup = &armnetwork.SecurityGroup{ID: new(byoTestNSG)}
		state.network.subnets[byoAKSNetworkKey(byoTestNodeSubnet)] = node
		state.network.securityGroups[byoAKSNetworkKey(byoTestNSG)] =
			byoAKSTestNSG(armnetwork.SecurityRuleAccessDeny)
		requireBYOAKSNetworkFailure(t, state, "networkSecurityGroup.securityRules")
	})

	t.Run("agent subnet inbound NSG deny fails", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		group := byoAKSTestNSG(armnetwork.SecurityRuleAccessDeny)
		group.Properties.SecurityRules[0].Properties.Direction =
			new(armnetwork.SecurityRuleDirectionInbound)
		state.network.securityGroups[byoAKSNetworkKey(byoTestNSG)] = group
		requireBYOAKSNetworkFailure(t, state, "networkSecurityGroup.securityRules")
	})
}

func byoAKSTestNSG(access armnetwork.SecurityRuleAccess) armnetwork.SecurityGroup {
	return armnetwork.SecurityGroup{
		ID: new(byoTestNSG),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
			SecurityRules: []*armnetwork.SecurityRule{{
				Name: new("all"),
				Properties: &armnetwork.SecurityRulePropertiesFormat{
					Access: new(access), Direction: new(armnetwork.SecurityRuleDirectionOutbound),
					Priority: new(int32(200)), Protocol: new(armnetwork.SecurityRuleProtocolAsterisk),
					SourceAddressPrefix: new("*"), DestinationAddressPrefix: new("*"),
					SourcePortRange: new("*"), DestinationPortRange: new("*"),
				},
			}},
		},
	}
}

func byoAKSTestStorageNSG(rules ...*armnetwork.SecurityRule) armnetwork.SecurityGroup {
	return armnetwork.SecurityGroup{
		ID: new(byoTestNSG),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
			SecurityRules:     rules,
		},
	}
}

func byoAKSTestStorageNSGRule(
	name, destination string, access armnetwork.SecurityRuleAccess, priority int32,
) *armnetwork.SecurityRule {
	return &armnetwork.SecurityRule{
		Name: new(name),
		Properties: &armnetwork.SecurityRulePropertiesFormat{
			Access: new(access), Direction: new(armnetwork.SecurityRuleDirectionOutbound),
			Priority: new(priority), Protocol: new(armnetwork.SecurityRuleProtocolAsterisk),
			SourceAddressPrefix: new("*"), DestinationAddressPrefix: new(destination),
			SourcePortRange: new("*"), DestinationPortRange: new("*"),
		},
	}
}

func configureBYOAKSStorageServiceEndpoint(state *byoAKSSnapshot) {
	state.network.storage.publicNetworkAccess = "Enabled"
	state.network.storage.defaultAction = "Deny"
	state.network.storage.virtualNetworkRules = nil
	for key, subnet := range state.network.subnets {
		if !strings.EqualFold(key, byoAKSNetworkKey(byoTestAgentSubnet)) &&
			!strings.EqualFold(key, byoAKSNetworkKey(byoTestNodeSubnet)) {
			continue
		}
		subnet.Properties.ServiceEndpoints = []*armnetwork.ServiceEndpointPropertiesFormat{{
			Service:           new("Microsoft.Storage"),
			ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
		}}
		state.network.subnets[key] = subnet
		state.network.storage.virtualNetworkRules = append(
			state.network.storage.virtualNetworkRules,
			byoAKSStorageVirtualNetworkRule{id: byoAKSString(subnet.ID), state: "Succeeded"},
		)
	}
}

func configureBYOAKSStoragePrivateEndpoint(state *byoAKSSnapshot) (string, string) {
	privateEndpointID := byoTestScope + "/providers/Microsoft.Network/privateEndpoints/storage-blob"
	privateEndpointSubnetID := byoTestVNet + "/subnets/private-endpoints"
	zoneID := byoTestScope + "/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
	state.network.storage.publicNetworkAccess = "Disabled"
	state.network.storage.defaultAction = "Deny"
	state.network.storage.virtualNetworkRules = nil
	state.network.storage.privateEndpointReferences = []byoAKSStoragePrivateEndpointReference{{
		id: privateEndpointID, status: "Approved",
	}}
	state.network.subnets[byoAKSNetworkKey(privateEndpointSubnetID)] = armnetwork.Subnet{
		ID: new(privateEndpointSubnetID), Name: new("private-endpoints"),
		Properties: &armnetwork.SubnetPropertiesFormat{AddressPrefix: new("10.20.4.0/27")},
	}
	state.network.privateEndpoints[byoAKSNetworkKey(privateEndpointID)] = &byoAKSPrivateEndpointSnapshot{
		resource: armnetwork.PrivateEndpoint{
			ID: new(privateEndpointID),
			Properties: &armnetwork.PrivateEndpointProperties{
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				Subnet:            &armnetwork.Subnet{ID: new(privateEndpointSubnetID)},
				PrivateLinkServiceConnections: []*armnetwork.PrivateLinkServiceConnection{{
					Properties: &armnetwork.PrivateLinkServiceConnectionProperties{
						PrivateLinkServiceID: new(byoTestStorage),
						GroupIDs:             []*string{new("blob")},
						PrivateLinkServiceConnectionState: &armnetwork.PrivateLinkServiceConnectionState{
							Status: new("Approved"),
						},
					},
				}},
			},
		},
		dnsZoneGroups: []*armnetwork.PrivateDNSZoneGroup{{
			Properties: &armnetwork.PrivateDNSZoneGroupPropertiesFormat{
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				PrivateDNSZoneConfigs: []*armnetwork.PrivateDNSZoneConfig{{
					Properties: &armnetwork.PrivateDNSZonePropertiesFormat{PrivateDNSZoneID: new(zoneID)},
				}},
			},
		}},
	}
	state.network.privateDNSZoneLinks[byoAKSNetworkKey(zoneID)] = []byoAKSPrivateDNSZoneLink{{
		id:               zoneID + "/virtualNetworkLinks/vnet",
		virtualNetworkID: byoTestVNet, provisioningState: "Succeeded", linkState: "Completed",
	}}
	return privateEndpointID, zoneID
}

func TestBYOAKSStorageNetworkAccess(t *testing.T) {
	t.Run("public default Allow needs no private networking", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.network.storage.privateEndpointReferences = nil
		clear(state.network.privateEndpoints)
		clear(state.network.privateDNSZoneLinks)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("public default Allow without NSG passes", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.subnet.Properties.NetworkSecurityGroup = nil
		state.network.subnets[byoAKSNetworkKey(byoTestAgentSubnet)] = state.subnet
		clear(state.network.securityGroups)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("public default Allow fails unconditional Storage deny", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.network.securityGroups[byoAKSNetworkKey(byoTestNSG)] = byoAKSTestStorageNSG(
			byoAKSTestStorageNSGRule("deny-storage", "Storage", armnetwork.SecurityRuleAccessDeny, 100),
		)
		requireBYOAKSNetworkFailure(t, state, "networkSecurityGroup.securityRules")
	})

	t.Run("public default Allow honors higher-priority Storage allow", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.network.securityGroups[byoAKSNetworkKey(byoTestNSG)] = byoAKSTestStorageNSG(
			byoAKSTestStorageNSGRule("allow-storage", "Storage", armnetwork.SecurityRuleAccessAllow, 100),
			byoAKSTestStorageNSGRule("deny-storage", "Storage", armnetwork.SecurityRuleAccessDeny, 200),
		)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("public default Allow blocked by NSG falls back to private endpoint", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSStoragePrivateEndpoint(state)
		state.network.storage.publicNetworkAccess = "Enabled"
		state.network.storage.defaultAction = "Allow"
		state.network.securityGroups[byoAKSNetworkKey(byoTestNSG)] = byoAKSTestStorageNSG(
			byoAKSTestStorageNSGRule("deny-public-storage", "Storage", armnetwork.SecurityRuleAccessDeny, 100),
		)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("restricted public endpoint with complete subnet ACLs", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSStorageServiceEndpoint(state)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("restricted public endpoint honors standard NSG Internet allow", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSStorageServiceEndpoint(state)
		state.network.securityGroups[byoAKSNetworkKey(byoTestNSG)] = armnetwork.SecurityGroup{
			ID: new(byoTestNSG),
			Properties: &armnetwork.SecurityGroupPropertiesFormat{
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				DefaultSecurityRules: []*armnetwork.SecurityRule{
					{
						Name: new("AllowVnetOutBound"),
						Properties: &armnetwork.SecurityRulePropertiesFormat{
							Access:                   new(armnetwork.SecurityRuleAccessAllow),
							Direction:                new(armnetwork.SecurityRuleDirectionOutbound),
							Priority:                 new(int32(65000)),
							Protocol:                 new(armnetwork.SecurityRuleProtocolAsterisk),
							SourceAddressPrefix:      new("VirtualNetwork"),
							DestinationAddressPrefix: new("VirtualNetwork"),
							SourcePortRange:          new("*"), DestinationPortRange: new("*"),
						},
					},
					{
						Name: new("AllowInternetOutBound"),
						Properties: &armnetwork.SecurityRulePropertiesFormat{
							Access:              new(armnetwork.SecurityRuleAccessAllow),
							Direction:           new(armnetwork.SecurityRuleDirectionOutbound),
							Priority:            new(int32(65001)),
							Protocol:            new(armnetwork.SecurityRuleProtocolAsterisk),
							SourceAddressPrefix: new("*"), DestinationAddressPrefix: new("Internet"),
							SourcePortRange: new("*"), DestinationPortRange: new("*"),
						},
					},
					{
						Name: new("DenyAllOutBound"),
						Properties: &armnetwork.SecurityRulePropertiesFormat{
							Access:              new(armnetwork.SecurityRuleAccessDeny),
							Direction:           new(armnetwork.SecurityRuleDirectionOutbound),
							Priority:            new(int32(65500)),
							Protocol:            new(armnetwork.SecurityRuleProtocolAsterisk),
							SourceAddressPrefix: new("*"), DestinationAddressPrefix: new("*"),
							SourcePortRange: new("*"), DestinationPortRange: new("*"),
						},
					},
				},
			},
		}
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("restricted public endpoint requires successful VNet rule", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSStorageServiceEndpoint(state)
		state.network.storage.virtualNetworkRules[0].state = ""
		requireBYOAKSNetworkFailure(t, state, "storageAccountResourceId.networkAccess")
	})

	t.Run("restricted public endpoint missing one subnet ACL", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSStorageServiceEndpoint(state)
		state.network.storage.virtualNetworkRules =
			state.network.storage.virtualNetworkRules[:1]
		requireBYOAKSNetworkFailure(t, state, "storageAccountResourceId.networkAccess")
	})

	t.Run("restricted public endpoint blocked by NSG falls back to private endpoint", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSStoragePrivateEndpoint(state)
		configureBYOAKSStorageServiceEndpoint(state)
		state.network.securityGroups[byoAKSNetworkKey(byoTestNSG)] = byoAKSTestStorageNSG(
			byoAKSTestStorageNSGRule("deny-service-endpoint", "Storage", armnetwork.SecurityRuleAccessDeny, 100),
		)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("disabled public endpoint cannot use only service endpoints", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSStorageServiceEndpoint(state)
		state.network.storage.publicNetworkAccess = "Disabled"
		requireBYOAKSNetworkFailure(t, state, "storageAccountResourceId.networkAccess")
	})

	t.Run("private endpoint and private DNS complete", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSStoragePrivateEndpoint(state)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("private endpoint does not require public Storage NSG access", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		configureBYOAKSStoragePrivateEndpoint(state)
		state.network.securityGroups[byoAKSNetworkKey(byoTestNSG)] = byoAKSTestStorageNSG(
			byoAKSTestStorageNSGRule("deny-public-storage", "Storage", armnetwork.SecurityRuleAccessDeny, 100),
		)
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})

	t.Run("private endpoint DNS zone group missing", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		privateEndpointID, _ := configureBYOAKSStoragePrivateEndpoint(state)
		state.network.privateEndpoints[byoAKSNetworkKey(privateEndpointID)].dnsZoneGroups = nil
		requireBYOAKSNetworkFailure(t, state, "privateDnsZoneGroups")
	})

	t.Run("private endpoint Azure DNS VNet link missing", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		_, zoneID := configureBYOAKSStoragePrivateEndpoint(state)
		delete(state.network.privateDNSZoneLinks, byoAKSNetworkKey(zoneID))
		requireBYOAKSNetworkFailure(t, state, "virtualNetworkLinks")
	})

	t.Run("private endpoint Azure DNS VNet link incomplete", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		_, zoneID := configureBYOAKSStoragePrivateEndpoint(state)
		state.network.privateDNSZoneLinks[byoAKSNetworkKey(zoneID)][0].linkState = "InProgress"
		requireBYOAKSNetworkFailure(t, state, "virtualNetworkLinks")
	})

	t.Run("private endpoint shared custom DNS forwarding configuration", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		_, zoneID := configureBYOAKSStoragePrivateEndpoint(state)
		state.network.virtualNetworks[byoAKSNetworkKey(byoTestVNet)].Properties.DhcpOptions =
			&armnetwork.DhcpOptions{DNSServers: []*string{new("10.20.0.4")}}
		delete(state.network.privateDNSZoneLinks, byoAKSNetworkKey(zoneID))
		_, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
	})
}

func TestBYOAKSDelegationValidation(t *testing.T) {
	t.Run("absent is planned for apply", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		validation, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
		assert.True(t, validation.needsDelegation)
	})

	t.Run("valid is reused", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.subnet.Properties.Delegations = []*armnetwork.Delegation{{
			Properties: &armnetwork.ServiceDelegationPropertiesFormat{ServiceName: new(byoAKSDelegation)},
		}}
		validation, err := validateBYOAKSNetwork(t, state)
		require.NoError(t, err)
		assert.False(t, validation.needsDelegation)
	})

	t.Run("conflicting fails", func(t *testing.T) {
		state := byoAKSTestSnapshot()
		state.subnet.Properties.Delegations = []*armnetwork.Delegation{{
			Properties: &armnetwork.ServiceDelegationPropertiesFormat{
				ServiceName: new("Microsoft.ContainerInstance/containerGroups"),
			},
		}}
		requireBYOAKSNetworkFailure(t, state, "agentSubnetResourceId.delegations")
	})
}
