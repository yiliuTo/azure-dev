// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// cspell:ignore AKSDNS AKSNSG BYOAKS Vnets armnetwork blackhole privatelink vnetlocal
// cspell:ignore virtualappliance virtualnetworkgateway

package provisioning

import (
	"cmp"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
)

type byoAKSNetworkSnapshot struct {
	subnets             map[string]armnetwork.Subnet
	virtualNetworks     map[string]armnetwork.VirtualNetwork
	peerings            map[string][]*armnetwork.VirtualNetworkPeering
	routeTables         map[string]armnetwork.RouteTable
	securityGroups      map[string]armnetwork.SecurityGroup
	privateEndpoints    map[string]*byoAKSPrivateEndpointSnapshot
	privateDNSZoneLinks map[string][]byoAKSPrivateDNSZoneLink
	storage             byoAKSStorageNetwork
}

type byoAKSPrivateEndpointSnapshot struct {
	resource      armnetwork.PrivateEndpoint
	dnsZoneGroups []*armnetwork.PrivateDNSZoneGroup
}

type byoAKSPrivateDNSZoneLink struct {
	id                string
	virtualNetworkID  string
	provisioningState string
	linkState         string
}

type byoAKSStorageNetwork struct {
	resourceID                string
	publicNetworkAccess       string
	defaultAction             string
	blobEndpoint              string
	virtualNetworkRules       []byoAKSStorageVirtualNetworkRule
	privateEndpointReferences []byoAKSStoragePrivateEndpointReference
}

type byoAKSStorageVirtualNetworkRule struct {
	id    string
	state string
}

type byoAKSStoragePrivateEndpointReference struct {
	id     string
	status string
}

type byoAKSSubnetRef struct {
	id       *arm.ResourceID
	resource armnetwork.Subnet
	property string
}

type byoAKSNetworkIssue struct {
	property, observed, expected, suggestion string
}

func (c *byoAKSConfig) validateNetwork(
	ids *byoAKSResources, state *byoAKSSnapshot,
) (bool, error) {
	if state.network == nil {
		return false, c.invalid(
			"network", "missing", "a complete read-only network snapshot",
			"verify the current identity can read the configured AKS, VNet, subnet, and storage network resources",
		)
	}
	agent, aksSubnets, issue := byoAKSNetworkSubnets(ids, state)
	if issue != nil {
		return false, c.networkInvalid(issue)
	}
	agentPrefix, issue := byoAKSAgentSubnetPrefix(agent)
	if issue != nil {
		return false, c.networkInvalid(issue)
	}
	for _, subnet := range aksSubnets {
		prefixes, prefixIssue := byoAKSSubnetPrefixes(subnet)
		if prefixIssue != nil {
			return false, c.networkInvalid(prefixIssue)
		}
		for _, prefix := range prefixes {
			if byoAKSPrefixesOverlap(agentPrefix, prefix) {
				return false, c.invalid(
					"agentSubnetResourceId.addressPrefix", agentPrefix.String(),
					"a non-overlapping RFC1918 IPv4 /27",
					fmt.Sprintf(
						"select a dedicated /27 that does not overlap %s %s (%s); azd will not change address ranges",
						subnet.property, subnet.id, prefix,
					),
				)
			}
		}
		if issue := byoAKSValidateSubnetConnectivity(state.network, agent, subnet); issue != nil {
			return false, c.networkInvalid(issue)
		}
	}
	if issue := byoAKSValidateStorageNetwork(state.network, append([]byoAKSSubnetRef{agent}, aksSubnets...)); issue != nil {
		return false, c.networkInvalid(issue)
	}
	delegated := false
	for _, delegation := range agent.resource.Properties.Delegations {
		if delegation == nil || delegation.Properties == nil ||
			!strings.EqualFold(byoAKSString(delegation.Properties.ServiceName), byoAKSDelegation) {
			service := "unknown delegation"
			if delegation != nil && delegation.Properties != nil {
				service = byoAKSString(delegation.Properties.ServiceName)
			}
			return false, c.invalid(
				"agentSubnetResourceId.delegations", service, byoAKSDelegation+" or no delegation",
				"use a dedicated agent subnet; azd will not remove or replace another service's delegation",
			)
		}
		delegated = true
	}
	return !delegated, nil
}

func (c *byoAKSConfig) networkInvalid(issue *byoAKSNetworkIssue) error {
	return c.invalid(issue.property, issue.observed, issue.expected, issue.suggestion)
}

func byoAKSNetworkSubnets(
	ids *byoAKSResources, state *byoAKSSnapshot,
) (byoAKSSubnetRef, []byoAKSSubnetRef, *byoAKSNetworkIssue) {
	if state.subnet.Properties == nil {
		return byoAKSSubnetRef{}, nil, &byoAKSNetworkIssue{
			property: "agentSubnetResourceId.properties", observed: "missing", expected: "subnet properties",
			suggestion: "verify the agent subnet can be read",
		}
	}
	agent := byoAKSSubnetRef{
		id: ids.subnet, resource: state.subnet, property: "agentSubnetResourceId",
	}
	seen := map[string]struct{}{}
	var result []byoAKSSubnetRef
	overlay := state.cluster.Properties != nil && state.cluster.Properties.NetworkProfile != nil &&
		strings.EqualFold(
			byoAKSString(state.cluster.Properties.NetworkProfile.NetworkPluginMode),
			"overlay",
		)
	for i, pool := range state.agentPools {
		if pool == nil || pool.properties == nil {
			return byoAKSSubnetRef{}, nil, &byoAKSNetworkIssue{
				property: fmt.Sprintf("agentPools[%d]", i), observed: "null",
				expected:   "an AgentPool child resource",
				suggestion: "verify the AKS node pool configuration",
			}
		}
		references := []struct {
			property, value string
			required        bool
		}{
			{fmt.Sprintf("agentPools[%d].vnetSubnetID", i), byoAKSString(pool.properties.VnetSubnetID), true},
			{fmt.Sprintf("agentPools[%d].podSubnetID", i), byoAKSString(pool.properties.PodSubnetID), !overlay},
		}
		for _, reference := range references {
			if !reference.required && strings.TrimSpace(reference.value) == "" {
				continue
			}
			id, err := arm.ParseResourceID(reference.value)
			if err != nil || id.Parent == nil ||
				!strings.EqualFold(id.ResourceType.String(), "Microsoft.Network/virtualNetworks/subnets") {
				return byoAKSSubnetRef{}, nil, &byoAKSNetworkIssue{
					property: reference.property, observed: missingValue(reference.value),
					expected:   "a readable subnet resource ID",
					suggestion: "correct the AKS AgentPool subnet reference",
				}
			}
			if strings.EqualFold(id.String(), ids.subnet.String()) {
				return byoAKSSubnetRef{}, nil, &byoAKSNetworkIssue{
					property: "agentSubnetResourceId", observed: "an AKS node or pod subnet",
					expected:   "a separate agent subnet",
					suggestion: "provide a dedicated Foundry/Data Proxy subnet; azd will not modify AKS node or pod subnets",
				}
			}
			key := byoAKSNetworkKey(id.String())
			if _, exists := seen[key]; exists {
				continue
			}
			subnet, exists := state.network.subnets[key]
			if !exists {
				return byoAKSSubnetRef{}, nil, &byoAKSNetworkIssue{
					property: reference.property + ".resource", observed: "not read",
					expected:   "the referenced subnet child resource",
					suggestion: "verify the current identity can read the AKS node and pod subnet resources",
				}
			}
			seen[key] = struct{}{}
			result = append(result, byoAKSSubnetRef{id: id, resource: subnet, property: reference.property})
		}
	}
	return agent, result, nil
}

func byoAKSAgentSubnetPrefix(subnet byoAKSSubnetRef) (netip.Prefix, *byoAKSNetworkIssue) {
	prefixes, issue := byoAKSSubnetPrefixes(subnet)
	if issue != nil {
		return netip.Prefix{}, issue
	}
	var ipv4 []netip.Prefix
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			ipv4 = append(ipv4, prefix)
		}
	}
	observed := byoAKSSubnetPrefixText(subnet.resource)
	if len(ipv4) != 1 || ipv4[0].Bits() != 27 || !byoAKSPrivateIPv4Prefix(ipv4[0]) {
		return netip.Prefix{}, &byoAKSNetworkIssue{
			property: "agentSubnetResourceId.addressPrefix", observed: missingValue(observed),
			expected:   "exactly one RFC1918 IPv4 /27",
			suggestion: "reserve a dedicated non-overlapping /27 within 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16",
		}
	}
	return ipv4[0].Masked(), nil
}

func byoAKSSubnetPrefixes(subnet byoAKSSubnetRef) ([]netip.Prefix, *byoAKSNetworkIssue) {
	if subnet.resource.Properties == nil {
		return nil, &byoAKSNetworkIssue{
			property: subnet.property + ".properties", observed: "missing", expected: "subnet properties",
			suggestion: "verify the referenced subnet can be read",
		}
	}
	raw := byoAKSSubnetPrefixValues(subnet.resource)
	if len(raw) == 0 {
		return nil, &byoAKSNetworkIssue{
			property: subnet.property + ".addressPrefix", observed: "missing", expected: "at least one CIDR",
			suggestion: "configure an address prefix on the subnet",
		}
	}
	result := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, &byoAKSNetworkIssue{
				property: subnet.property + ".addressPrefix", observed: value, expected: "a valid CIDR",
				suggestion: "correct the subnet address prefix",
			}
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func byoAKSSubnetPrefixValues(subnet armnetwork.Subnet) []string {
	if subnet.Properties == nil {
		return nil
	}
	var result []string
	if value := strings.TrimSpace(byoAKSString(subnet.Properties.AddressPrefix)); value != "" {
		result = append(result, value)
	}
	for _, value := range subnet.Properties.AddressPrefixes {
		if prefix := strings.TrimSpace(byoAKSString(value)); prefix != "" && !slices.Contains(result, prefix) {
			result = append(result, prefix)
		}
	}
	return result
}

func byoAKSSubnetPrefixText(subnet armnetwork.Subnet) string {
	return strings.Join(byoAKSSubnetPrefixValues(subnet), ", ")
}

func byoAKSPrivateIPv4Prefix(prefix netip.Prefix) bool {
	if !prefix.Addr().Is4() {
		return false
	}
	for _, raw := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		private := netip.MustParsePrefix(raw)
		if prefix.Bits() >= private.Bits() && private.Contains(prefix.Masked().Addr()) {
			return true
		}
	}
	return false
}

func byoAKSPrefixesOverlap(left, right netip.Prefix) bool {
	if left.Addr().BitLen() != right.Addr().BitLen() {
		return false
	}
	left, right = left.Masked(), right.Masked()
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func byoAKSValidateSubnetConnectivity(
	network *byoAKSNetworkSnapshot, left, right byoAKSSubnetRef,
) *byoAKSNetworkIssue {
	leftVNet, leftResource, issue := byoAKSSubnetVNet(network, left)
	if issue != nil {
		return issue
	}
	rightVNet, rightResource, issue := byoAKSSubnetVNet(network, right)
	if issue != nil {
		return issue
	}
	crossVNet := !strings.EqualFold(leftVNet.String(), rightVNet.String())
	var leftPeering, rightPeering *armnetwork.VirtualNetworkPeering
	if crossVNet {
		leftPeering, issue = byoAKSValidatePeering(network, leftVNet, rightVNet, left, right)
		if issue != nil {
			return issue
		}
		rightPeering, issue = byoAKSValidatePeering(network, rightVNet, leftVNet, right, left)
		if issue != nil {
			return issue
		}
		if issue := byoAKSValidateDNS(leftVNet, leftResource, rightVNet, rightResource); issue != nil {
			return issue
		}
	}
	leftForwarded, issue := byoAKSValidateRoutes(network, left, right, crossVNet)
	if issue != nil {
		return issue
	}
	rightForwarded, issue := byoAKSValidateRoutes(network, right, left, crossVNet)
	if issue != nil {
		return issue
	}
	if crossVNet && (leftForwarded || rightForwarded) {
		if leftPeering == nil || leftPeering.Properties == nil ||
			leftPeering.Properties.AllowForwardedTraffic == nil || !*leftPeering.Properties.AllowForwardedTraffic ||
			rightPeering == nil || rightPeering.Properties == nil ||
			rightPeering.Properties.AllowForwardedTraffic == nil || !*rightPeering.Properties.AllowForwardedTraffic {
			return &byoAKSNetworkIssue{
				property: "virtualNetworkPeerings.allowForwardedTraffic", observed: "false or missing",
				expected:   "true in both directions when a matching route uses a virtual appliance",
				suggestion: "enable forwarded traffic on both peerings, or remove the virtual-appliance route override",
			}
		}
	}
	if issue := byoAKSValidateNSGs(network, left, right); issue != nil {
		return issue
	}
	return nil
}

func byoAKSSubnetVNet(
	network *byoAKSNetworkSnapshot, subnet byoAKSSubnetRef,
) (*arm.ResourceID, armnetwork.VirtualNetwork, *byoAKSNetworkIssue) {
	if subnet.id == nil || subnet.id.Parent == nil ||
		!strings.EqualFold(subnet.id.Parent.ResourceType.String(), "Microsoft.Network/virtualNetworks") {
		return nil, armnetwork.VirtualNetwork{}, &byoAKSNetworkIssue{
			property: subnet.property, observed: "invalid parent", expected: "a subnet in a readable virtual network",
			suggestion: "correct the subnet resource ID",
		}
	}
	vnetID := subnet.id.Parent
	vnet, exists := network.virtualNetworks[byoAKSNetworkKey(vnetID.String())]
	if !exists {
		return nil, armnetwork.VirtualNetwork{}, &byoAKSNetworkIssue{
			property: subnet.property + ".virtualNetwork", observed: "not read", expected: "the parent virtual network",
			suggestion: "verify the current identity can read the subnet's virtual network",
		}
	}
	provisioningState := ""
	if vnet.Properties != nil {
		provisioningState = byoAKSString(vnet.Properties.ProvisioningState)
	}
	if vnet.Properties == nil ||
		!strings.EqualFold(byoAKSString(vnet.Properties.ProvisioningState), "Succeeded") {
		return nil, armnetwork.VirtualNetwork{}, &byoAKSNetworkIssue{
			property: subnet.property + ".virtualNetwork.provisioningState",
			observed: missingValue(provisioningState), expected: "Succeeded",
			suggestion: "wait for the virtual network provisioning state to become Succeeded",
		}
	}
	return vnetID, vnet, nil
}

func byoAKSValidatePeering(
	network *byoAKSNetworkSnapshot,
	localVNet, remoteVNet *arm.ResourceID,
	localSubnet, remoteSubnet byoAKSSubnetRef,
) (*armnetwork.VirtualNetworkPeering, *byoAKSNetworkIssue) {
	var found *armnetwork.VirtualNetworkPeering
	for _, peering := range network.peerings[byoAKSNetworkKey(localVNet.String())] {
		if peering == nil || peering.Properties == nil ||
			peering.Properties.RemoteVirtualNetwork == nil ||
			!strings.EqualFold(byoAKSString(peering.Properties.RemoteVirtualNetwork.ID), remoteVNet.String()) {
			continue
		}
		found = peering
		break
	}
	property := fmt.Sprintf("virtualNetworkPeerings[%s->%s]", localVNet.Name, remoteVNet.Name)
	if found == nil {
		return nil, &byoAKSNetworkIssue{
			property: property, observed: "missing", expected: "a bidirectional VNet peering",
			suggestion: "create peerings in both directions before validating workloads",
		}
	}
	properties := found.Properties
	if !strings.EqualFold(byoAKSString(properties.PeeringState), "Connected") ||
		!strings.EqualFold(byoAKSString(properties.PeeringSyncLevel), "FullyInSync") ||
		!strings.EqualFold(byoAKSString(properties.ProvisioningState), "Succeeded") ||
		properties.AllowVirtualNetworkAccess == nil || !*properties.AllowVirtualNetworkAccess {
		return nil, &byoAKSNetworkIssue{
			property: property,
			observed: fmt.Sprintf(
				"state=%s sync=%s provisioning=%s allowVirtualNetworkAccess=%t",
				missingValue(byoAKSString(properties.PeeringState)),
				missingValue(byoAKSString(properties.PeeringSyncLevel)),
				missingValue(byoAKSString(properties.ProvisioningState)),
				properties.AllowVirtualNetworkAccess != nil && *properties.AllowVirtualNetworkAccess,
			),
			expected:   "Connected, FullyInSync, Succeeded, with virtual-network access enabled",
			suggestion: "complete and synchronize the peering, then enable virtual-network access",
		}
	}
	complete := properties.PeerCompleteVnets == nil || *properties.PeerCompleteVnets
	if !complete || len(properties.LocalSubnetNames) > 0 || len(properties.RemoteSubnetNames) > 0 {
		if !byoAKSStringSliceContains(properties.LocalSubnetNames, localSubnet.id.Name) ||
			!byoAKSStringSliceContains(properties.RemoteSubnetNames, remoteSubnet.id.Name) {
			return nil, &byoAKSNetworkIssue{
				property: property + ".subnets",
				observed: "the selected subnets are not both included", expected: "both selected subnets in the peering",
				suggestion: "include the agent and AKS subnet names in the subnet peering, or peer the complete VNets",
			}
		}
	}
	return found, nil
}

func byoAKSStringSliceContains(values []*string, expected string) bool {
	return slices.ContainsFunc(values, func(value *string) bool {
		return strings.EqualFold(byoAKSString(value), expected)
	})
}

func byoAKSValidateDNS(
	leftID *arm.ResourceID, left armnetwork.VirtualNetwork,
	rightID *arm.ResourceID, right armnetwork.VirtualNetwork,
) *byoAKSNetworkIssue {
	leftServers, issue := byoAKSDNSServers(leftID, left)
	if issue != nil {
		return issue
	}
	rightServers, issue := byoAKSDNSServers(rightID, right)
	if issue != nil {
		return issue
	}
	if len(leftServers) == 0 && len(rightServers) == 0 {
		return nil
	}
	if len(leftServers) > 0 && len(rightServers) > 0 &&
		slices.ContainsFunc(leftServers, func(server string) bool {
			return slices.Contains(rightServers, server)
		}) {
		return nil
	}
	return &byoAKSNetworkIssue{
		property:   "virtualNetworks.dhcpOptions.dnsServers",
		observed:   fmt.Sprintf("%s=%v, %s=%v", leftID.Name, leftServers, rightID.Name, rightServers),
		expected:   "Azure-provided DNS on both VNets, or at least one shared custom DNS resolver",
		suggestion: "align VNet DNS settings or configure a shared forwarding resolver before validating workloads",
	}
}

func byoAKSDNSServers(
	id *arm.ResourceID, vnet armnetwork.VirtualNetwork,
) ([]string, *byoAKSNetworkIssue) {
	if vnet.Properties == nil || vnet.Properties.DhcpOptions == nil {
		return nil, nil
	}
	var result []string
	for _, raw := range vnet.Properties.DhcpOptions.DNSServers {
		value := strings.TrimSpace(byoAKSString(raw))
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, &byoAKSNetworkIssue{
				property: fmt.Sprintf("virtualNetworks[%s].dhcpOptions.dnsServers", id.Name),
				observed: value, expected: "valid DNS server IP addresses",
				suggestion: "correct the custom DNS server list",
			}
		}
		normalized := address.String()
		if !slices.Contains(result, normalized) {
			result = append(result, normalized)
		}
	}
	return result, nil
}

func byoAKSValidateRoutes(
	network *byoAKSNetworkSnapshot, source, destination byoAKSSubnetRef, crossVNet bool,
) (bool, *byoAKSNetworkIssue) {
	if source.resource.Properties == nil || source.resource.Properties.RouteTable == nil ||
		strings.TrimSpace(byoAKSString(source.resource.Properties.RouteTable.ID)) == "" {
		return false, nil
	}
	rawID := byoAKSString(source.resource.Properties.RouteTable.ID)
	id, err := arm.ParseResourceID(rawID)
	if err != nil || !strings.EqualFold(id.ResourceType.String(), "Microsoft.Network/routeTables") {
		return false, &byoAKSNetworkIssue{
			property: source.property + ".routeTable.id", observed: rawID, expected: "a route table resource ID",
			suggestion: "correct or remove the subnet route-table association",
		}
	}
	table, exists := network.routeTables[byoAKSNetworkKey(id.String())]
	if !exists || table.Properties == nil {
		return false, &byoAKSNetworkIssue{
			property: source.property + ".routeTable", observed: "not read", expected: "the attached route table",
			suggestion: "verify the current identity can read the attached route table",
		}
	}
	if !strings.EqualFold(byoAKSString(table.Properties.ProvisioningState), "Succeeded") {
		return false, &byoAKSNetworkIssue{
			property: source.property + ".routeTable.provisioningState",
			observed: byoAKSString(table.Properties.ProvisioningState), expected: "Succeeded",
			suggestion: "wait for route-table provisioning to complete",
		}
	}
	destPrefixes, issue := byoAKSSubnetPrefixes(destination)
	if issue != nil {
		return false, issue
	}
	forwarded := false
	for _, destinationPrefix := range destPrefixes {
		var selected *armnetwork.Route
		selectedBits := -1
		for _, route := range table.Properties.Routes {
			if route == nil || route.Properties == nil {
				continue
			}
			routePrefix, parseErr := netip.ParsePrefix(byoAKSString(route.Properties.AddressPrefix))
			if parseErr != nil || routePrefix.Addr().BitLen() != destinationPrefix.Addr().BitLen() {
				continue
			}
			routePrefix = routePrefix.Masked()
			if routePrefix.Bits() <= destinationPrefix.Bits() &&
				routePrefix.Contains(destinationPrefix.Masked().Addr()) && routePrefix.Bits() > selectedBits {
				selected, selectedBits = route, routePrefix.Bits()
			}
		}
		if selected == nil {
			continue
		}
		nextHop := strings.ToLower(byoAKSString(selected.Properties.NextHopType))
		switch nextHop {
		case "none", "internet":
			return false, &byoAKSNetworkIssue{
				property: source.property + ".routeTable.routes",
				observed: fmt.Sprintf(
					"%s sends %s to %s", missingValue(byoAKSString(selected.Name)), destinationPrefix, nextHop,
				),
				expected:   "a route that preserves private reachability",
				suggestion: "remove the blackhole/Internet route or replace it with a valid private next hop",
			}
		case "vnetlocal":
			if crossVNet {
				return false, &byoAKSNetworkIssue{
					property: source.property + ".routeTable.routes",
					observed: fmt.Sprintf(
						"%s sends cross-VNet prefix %s to VnetLocal",
						missingValue(byoAKSString(selected.Name)), destinationPrefix,
					),
					expected:   "a cross-VNet route through peering, a gateway, or a virtual appliance",
					suggestion: "remove the VnetLocal override so the peering system route can apply",
				}
			}
		case "virtualappliance":
			address, parseErr := netip.ParseAddr(byoAKSString(selected.Properties.NextHopIPAddress))
			if parseErr != nil || address.BitLen() != destinationPrefix.Addr().BitLen() {
				return false, &byoAKSNetworkIssue{
					property:   source.property + ".routeTable.routes.nextHopIPAddress",
					observed:   missingValue(byoAKSString(selected.Properties.NextHopIPAddress)),
					expected:   "a valid virtual-appliance IP address",
					suggestion: "correct the virtual-appliance next hop",
				}
			}
			forwarded = true
		case "virtualnetworkgateway":
		case "":
			return false, &byoAKSNetworkIssue{
				property: source.property + ".routeTable.routes.nextHopType", observed: "missing",
				expected:   "a supported private next hop",
				suggestion: "correct the route next-hop type",
			}
		default:
			return false, &byoAKSNetworkIssue{
				property: source.property + ".routeTable.routes.nextHopType", observed: nextHop,
				expected:   "VnetLocal, VirtualNetworkGateway, or VirtualAppliance",
				suggestion: "remove the override so Azure system routing applies, or configure a supported private next hop",
			}
		}
	}
	return forwarded, nil
}

func byoAKSValidateNSGs(
	network *byoAKSNetworkSnapshot, left, right byoAKSSubnetRef,
) *byoAKSNetworkIssue {
	if issue := byoAKSValidateNSGDirection(network, left, right, "Outbound"); issue != nil {
		return issue
	}
	if issue := byoAKSValidateNSGDirection(network, right, left, "Inbound"); issue != nil {
		return issue
	}
	if issue := byoAKSValidateNSGDirection(network, right, left, "Outbound"); issue != nil {
		return issue
	}
	return byoAKSValidateNSGDirection(network, left, right, "Inbound")
}

func byoAKSValidateNSGDirection(
	network *byoAKSNetworkSnapshot,
	attached, other byoAKSSubnetRef,
	direction string,
) *byoAKSNetworkIssue {
	if attached.resource.Properties == nil || attached.resource.Properties.NetworkSecurityGroup == nil ||
		strings.TrimSpace(byoAKSString(attached.resource.Properties.NetworkSecurityGroup.ID)) == "" {
		return nil
	}
	rawID := byoAKSString(attached.resource.Properties.NetworkSecurityGroup.ID)
	id, err := arm.ParseResourceID(rawID)
	if err != nil || !strings.EqualFold(id.ResourceType.String(), "Microsoft.Network/networkSecurityGroups") {
		return &byoAKSNetworkIssue{
			property: attached.property + ".networkSecurityGroup.id", observed: rawID,
			expected:   "a network security group resource ID",
			suggestion: "correct or remove the subnet NSG association",
		}
	}
	group, exists := network.securityGroups[byoAKSNetworkKey(id.String())]
	if !exists || group.Properties == nil {
		return &byoAKSNetworkIssue{
			property: attached.property + ".networkSecurityGroup", observed: "not read",
			expected:   "the attached network security group",
			suggestion: "verify the current identity can read the attached network security group",
		}
	}
	if !strings.EqualFold(byoAKSString(group.Properties.ProvisioningState), "Succeeded") {
		return &byoAKSNetworkIssue{
			property: attached.property + ".networkSecurityGroup.provisioningState",
			observed: byoAKSString(group.Properties.ProvisioningState), expected: "Succeeded",
			suggestion: "wait for network security group provisioning to complete",
		}
	}
	source, destination := attached, other
	if strings.EqualFold(direction, "Inbound") {
		source, destination = other, attached
	}
	sourcePrefixes, issue := byoAKSSubnetPrefixes(source)
	if issue != nil {
		return issue
	}
	destinationPrefixes, issue := byoAKSSubnetPrefixes(destination)
	if issue != nil {
		return issue
	}
	rules := append(slices.Clone(group.Properties.SecurityRules), group.Properties.DefaultSecurityRules...)
	slices.SortFunc(rules, func(left, right *armnetwork.SecurityRule) int {
		leftPriority, rightPriority := int32(1<<30), int32(1<<30)
		if left != nil && left.Properties != nil && left.Properties.Priority != nil {
			leftPriority = *left.Properties.Priority
		}
		if right != nil && right.Properties != nil && right.Properties.Priority != nil {
			rightPriority = *right.Properties.Priority
		}
		return cmp.Compare(leftPriority, rightPriority)
	})
	for _, rule := range rules {
		if !byoAKSNSGRuleCovers(rule, direction, sourcePrefixes, destinationPrefixes) {
			continue
		}
		if strings.EqualFold(byoAKSString(rule.Properties.Access), "Deny") {
			return &byoAKSNetworkIssue{
				property: attached.property + ".networkSecurityGroup.securityRules",
				observed: fmt.Sprintf(
					"%s %s rule %s denies all matching protocols and ports",
					id.Name, strings.ToLower(direction), missingValue(byoAKSString(rule.Name)),
				),
				expected:   "no higher-priority unconditional deny for the required subnet path",
				suggestion: "adjust the attached NSG so the agent and AKS network path is not unconditionally denied",
			}
		}
		return nil
	}
	return nil
}

func byoAKSNSGRuleCovers(
	rule *armnetwork.SecurityRule,
	direction string,
	sources, destinations []netip.Prefix,
) bool {
	if rule == nil || rule.Properties == nil ||
		!strings.EqualFold(byoAKSString(rule.Properties.Direction), direction) ||
		byoAKSString(rule.Properties.Protocol) != "*" ||
		!byoAKSPortRangeAll(rule.Properties.SourcePortRange, rule.Properties.SourcePortRanges) ||
		!byoAKSPortRangeAll(rule.Properties.DestinationPortRange, rule.Properties.DestinationPortRanges) {
		return false
	}
	return byoAKSAddressFieldsCover(
		rule.Properties.SourceAddressPrefix, rule.Properties.SourceAddressPrefixes, sources,
	) && byoAKSAddressFieldsCover(
		rule.Properties.DestinationAddressPrefix,
		rule.Properties.DestinationAddressPrefixes,
		destinations,
	)
}

func byoAKSPortRangeAll(single *string, multiple []*string) bool {
	values := multiple
	if single != nil {
		values = append(slices.Clone(multiple), single)
	}
	return slices.ContainsFunc(values, func(value *string) bool {
		normalized := strings.TrimSpace(byoAKSString(value))
		return normalized == "*" || normalized == "0-65535"
	})
}

func byoAKSAddressFieldsCover(
	single *string, multiple []*string, targets []netip.Prefix,
) bool {
	values := multiple
	if single != nil {
		values = append(slices.Clone(multiple), single)
	}
	for _, target := range targets {
		covered := slices.ContainsFunc(values, func(raw *string) bool {
			value := strings.TrimSpace(byoAKSString(raw))
			if value == "*" {
				return true
			}
			if strings.EqualFold(value, "VirtualNetwork") {
				return target.Bits() > 0
			}
			prefix, err := netip.ParsePrefix(value)
			return err == nil && prefix.Addr().BitLen() == target.Addr().BitLen() &&
				prefix.Bits() <= target.Bits() && prefix.Masked().Contains(target.Masked().Addr())
		})
		if !covered {
			return false
		}
	}
	return true
}

func byoAKSValidateStorageNetwork(
	network *byoAKSNetworkSnapshot, sources []byoAKSSubnetRef,
) *byoAKSNetworkIssue {
	publicNetworkAccess := network.storage.publicNetworkAccess
	defaultAction := network.storage.defaultAction
	if !strings.EqualFold(publicNetworkAccess, "Enabled") &&
		!strings.EqualFold(publicNetworkAccess, "Disabled") {
		return &byoAKSNetworkIssue{
			property:   "storageAccountResourceId.properties.publicNetworkAccess",
			observed:   missingValue(publicNetworkAccess),
			expected:   "Enabled or Disabled",
			suggestion: "use a supported Storage public network access policy that azd can validate",
		}
	}
	if !strings.EqualFold(defaultAction, "Allow") &&
		!strings.EqualFold(defaultAction, "Deny") {
		return &byoAKSNetworkIssue{
			property:   "storageAccountResourceId.properties.networkAcls.defaultAction",
			observed:   missingValue(defaultAction),
			expected:   "Allow or Deny",
			suggestion: "use a supported Storage network ACL default action that azd can validate",
		}
	}
	publicEnabled := strings.EqualFold(publicNetworkAccess, "Enabled")
	var publicIssue *byoAKSNetworkIssue
	if publicEnabled && strings.EqualFold(defaultAction, "Allow") {
		publicIssue = byoAKSValidateStorageOutboundNSGs(network, sources)
		if publicIssue == nil {
			return nil
		}
	}
	if publicEnabled && strings.EqualFold(defaultAction, "Deny") {
		if missing := byoAKSMissingStorageServiceEndpoints(network.storage, sources); len(missing) == 0 {
			publicIssue = byoAKSValidateStorageOutboundNSGs(network, sources)
			if publicIssue == nil {
				return nil
			}
		}
	}
	var failures []string
	for _, reference := range network.storage.privateEndpointReferences {
		if !strings.EqualFold(reference.status, "Approved") {
			failures = append(failures, fmt.Sprintf("%s is %s", reference.id, missingValue(reference.status)))
			continue
		}
		endpoint := network.privateEndpoints[byoAKSNetworkKey(reference.id)]
		if endpoint == nil {
			failures = append(failures, fmt.Sprintf("%s was not read", reference.id))
			continue
		}
		if issue := byoAKSValidateStoragePrivateEndpoint(network, endpoint, sources); issue != nil {
			failures = append(failures, issue.property+": "+issue.observed)
			continue
		}
		return nil
	}
	if publicIssue != nil {
		return publicIssue
	}
	observed := "no approved, reachable blob private endpoint"
	if len(failures) > 0 {
		observed = strings.Join(failures, "; ")
	} else if publicEnabled {
		observed = "storage firewall rules do not allow every required subnet and no private endpoint is configured"
	}
	return &byoAKSNetworkIssue{
		property: "storageAccountResourceId.networkAccess", observed: observed,
		expected:   "public access with default Allow, complete Storage service-endpoint ACLs, or an approved reachable blob private endpoint with DNS",
		suggestion: "configure storage network access for the agent and AKS subnets before provisioning; azd does not change storage networking",
	}
}

func byoAKSMissingStorageServiceEndpoints(
	storage byoAKSStorageNetwork, sources []byoAKSSubnetRef,
) []string {
	var missing []string
	for _, source := range sources {
		rule := slices.ContainsFunc(storage.virtualNetworkRules, func(rule byoAKSStorageVirtualNetworkRule) bool {
			return strings.EqualFold(strings.TrimSuffix(rule.id, "/"), source.id.String()) &&
				strings.EqualFold(rule.state, "Succeeded")
		})
		endpoint := source.resource.Properties != nil &&
			slices.ContainsFunc(
				source.resource.Properties.ServiceEndpoints,
				func(endpoint *armnetwork.ServiceEndpointPropertiesFormat) bool {
					return endpoint != nil &&
						(strings.EqualFold(byoAKSString(endpoint.Service), "Microsoft.Storage") ||
							strings.EqualFold(byoAKSString(endpoint.Service), "Microsoft.Storage.Global")) &&
						strings.EqualFold(byoAKSString(endpoint.ProvisioningState), "Succeeded")
				},
			)
		if !rule || !endpoint {
			missing = append(missing, source.id.String())
		}
	}
	return missing
}

func byoAKSValidateStorageOutboundNSGs(
	network *byoAKSNetworkSnapshot, sources []byoAKSSubnetRef,
) *byoAKSNetworkIssue {
	for _, source := range sources {
		if issue := byoAKSValidateStorageOutboundNSG(network, source); issue != nil {
			return issue
		}
	}
	return nil
}

func byoAKSValidateStorageOutboundNSG(
	network *byoAKSNetworkSnapshot, source byoAKSSubnetRef,
) *byoAKSNetworkIssue {
	if source.resource.Properties == nil || source.resource.Properties.NetworkSecurityGroup == nil {
		return nil
	}
	rawID := byoAKSString(source.resource.Properties.NetworkSecurityGroup.ID)
	if rawID == "" {
		return nil
	}
	id, err := arm.ParseResourceID(rawID)
	if err != nil {
		return &byoAKSNetworkIssue{
			property: source.property + ".networkSecurityGroup.id", observed: rawID,
			expected:   "a network security group resource ID",
			suggestion: "correct the subnet NSG association",
		}
	}
	group, exists := network.securityGroups[byoAKSNetworkKey(id.String())]
	if !exists || group.Properties == nil {
		return &byoAKSNetworkIssue{
			property: source.property + ".networkSecurityGroup", observed: "not read",
			expected:   "the attached network security group",
			suggestion: "verify the current identity can read the attached network security group",
		}
	}
	sourcePrefixes, issue := byoAKSSubnetPrefixes(source)
	if issue != nil {
		return issue
	}
	rules := append(slices.Clone(group.Properties.SecurityRules), group.Properties.DefaultSecurityRules...)
	slices.SortFunc(rules, func(left, right *armnetwork.SecurityRule) int {
		leftPriority, rightPriority := int32(1<<30), int32(1<<30)
		if left != nil && left.Properties != nil && left.Properties.Priority != nil {
			leftPriority = *left.Properties.Priority
		}
		if right != nil && right.Properties != nil && right.Properties.Priority != nil {
			rightPriority = *right.Properties.Priority
		}
		return cmp.Compare(leftPriority, rightPriority)
	})
	for _, rule := range rules {
		if rule == nil || rule.Properties == nil ||
			!strings.EqualFold(byoAKSString(rule.Properties.Direction), "Outbound") ||
			byoAKSString(rule.Properties.Protocol) != "*" ||
			!byoAKSPortRangeAll(rule.Properties.SourcePortRange, rule.Properties.SourcePortRanges) ||
			!byoAKSPortRangeAll(rule.Properties.DestinationPortRange, rule.Properties.DestinationPortRanges) ||
			!byoAKSAddressFieldsCover(
				rule.Properties.SourceAddressPrefix,
				rule.Properties.SourceAddressPrefixes,
				sourcePrefixes,
			) ||
			!byoAKSStorageDestinationCovers(
				rule.Properties.DestinationAddressPrefix,
				rule.Properties.DestinationAddressPrefixes,
			) {
			continue
		}
		if strings.EqualFold(byoAKSString(rule.Properties.Access), "Deny") {
			return &byoAKSNetworkIssue{
				property: source.property + ".networkSecurityGroup.securityRules",
				observed: fmt.Sprintf(
					"%s denies all outbound protocols and ports", missingValue(byoAKSString(rule.Name)),
				),
				expected:   "no higher-priority unconditional outbound deny",
				suggestion: "adjust the attached NSG so the storage endpoint is not unconditionally denied",
			}
		}
		return nil
	}
	return nil
}

func byoAKSStorageDestinationCovers(single *string, multiple []*string) bool {
	values := multiple
	if single != nil {
		values = append(slices.Clone(multiple), single)
	}
	return slices.ContainsFunc(values, func(raw *string) bool {
		value := strings.TrimSpace(byoAKSString(raw))
		if value == "*" || value == "0.0.0.0/0" ||
			strings.EqualFold(value, "Internet") || strings.EqualFold(value, "Storage") {
			return true
		}
		return strings.HasPrefix(strings.ToLower(value), "storage.")
	})
}

func byoAKSValidateStoragePrivateEndpoint(
	network *byoAKSNetworkSnapshot,
	endpoint *byoAKSPrivateEndpointSnapshot,
	sources []byoAKSSubnetRef,
) *byoAKSNetworkIssue {
	resource := endpoint.resource
	provisioningState := ""
	if resource.Properties != nil {
		provisioningState = byoAKSString(resource.Properties.ProvisioningState)
	}
	if resource.Properties == nil ||
		!strings.EqualFold(byoAKSString(resource.Properties.ProvisioningState), "Succeeded") {
		return &byoAKSNetworkIssue{
			property: "storageAccountResourceId.privateEndpoint.provisioningState",
			observed: missingValue(provisioningState), expected: "Succeeded",
			suggestion: "wait for private endpoint provisioning to complete",
		}
	}
	if !byoAKSPrivateEndpointTargetsBlob(resource, network.storage) {
		return &byoAKSNetworkIssue{
			property:   "storageAccountResourceId.privateEndpoint.connections",
			observed:   "no approved blob connection to the configured storage account",
			expected:   "an approved blob private-link connection",
			suggestion: "approve the storage blob private endpoint connection",
		}
	}
	rawSubnetID := ""
	if resource.Properties.Subnet != nil {
		rawSubnetID = byoAKSString(resource.Properties.Subnet.ID)
	}
	subnetID, err := arm.ParseResourceID(rawSubnetID)
	if err != nil || subnetID.Parent == nil ||
		!strings.EqualFold(subnetID.ResourceType.String(), "Microsoft.Network/virtualNetworks/subnets") {
		return &byoAKSNetworkIssue{
			property: "storageAccountResourceId.privateEndpoint.subnet", observed: missingValue(rawSubnetID),
			expected:   "a readable subnet resource ID",
			suggestion: "correct the storage private endpoint subnet",
		}
	}
	subnet, exists := network.subnets[byoAKSNetworkKey(subnetID.String())]
	if !exists {
		return &byoAKSNetworkIssue{
			property: "storageAccountResourceId.privateEndpoint.subnet", observed: "not read",
			expected:   "the private endpoint subnet",
			suggestion: "verify the current identity can read the private endpoint subnet",
		}
	}
	target := byoAKSSubnetRef{
		id: subnetID, resource: subnet, property: "storageAccountResourceId.privateEndpoint.subnet",
	}
	for _, source := range sources {
		if issue := byoAKSValidateSubnetConnectivity(network, source, target); issue != nil {
			return issue
		}
	}
	zoneID, issue := byoAKSStoragePrivateDNSZone(endpoint, network.storage)
	if issue != nil {
		return issue
	}
	for _, source := range sources {
		vnetID, vnet, subnetIssue := byoAKSSubnetVNet(network, source)
		if subnetIssue != nil {
			return subnetIssue
		}
		servers, dnsIssue := byoAKSDNSServers(vnetID, vnet)
		if dnsIssue != nil {
			return dnsIssue
		}
		if len(servers) > 0 {
			continue
		}
		linked := slices.ContainsFunc(
			network.privateDNSZoneLinks[byoAKSNetworkKey(zoneID.String())],
			func(link byoAKSPrivateDNSZoneLink) bool {
				return strings.EqualFold(link.virtualNetworkID, vnetID.String()) &&
					strings.EqualFold(link.provisioningState, "Succeeded") &&
					strings.EqualFold(link.linkState, "Completed")
			},
		)
		if !linked {
			return &byoAKSNetworkIssue{
				property:   "storageAccountResourceId.privateDnsZone.virtualNetworkLinks",
				observed:   fmt.Sprintf("%s is not linked to %s", zoneID, vnetID),
				expected:   "a Succeeded, Completed private DNS VNet link for every Azure-DNS source VNet",
				suggestion: "link the storage private DNS zone to the agent and AKS VNets, or configure shared custom DNS forwarding",
			}
		}
	}
	return nil
}

func byoAKSPrivateEndpointTargetsBlob(
	endpoint armnetwork.PrivateEndpoint, storage byoAKSStorageNetwork,
) bool {
	if endpoint.Properties == nil {
		return false
	}
	connections := append(
		slices.Clone(endpoint.Properties.PrivateLinkServiceConnections),
		endpoint.Properties.ManualPrivateLinkServiceConnections...,
	)
	return slices.ContainsFunc(connections, func(connection *armnetwork.PrivateLinkServiceConnection) bool {
		if connection == nil || connection.Properties == nil ||
			!strings.EqualFold(
				strings.TrimSuffix(byoAKSString(connection.Properties.PrivateLinkServiceID), "/"),
				strings.TrimSuffix(storage.resourceID, "/"),
			) ||
			connection.Properties.PrivateLinkServiceConnectionState == nil ||
			!strings.EqualFold(
				byoAKSString(connection.Properties.PrivateLinkServiceConnectionState.Status),
				"Approved",
			) {
			return false
		}
		return slices.ContainsFunc(connection.Properties.GroupIDs, func(group *string) bool {
			return strings.EqualFold(byoAKSString(group), "blob")
		})
	})
}

func byoAKSStoragePrivateDNSZone(
	endpoint *byoAKSPrivateEndpointSnapshot, storage byoAKSStorageNetwork,
) (*arm.ResourceID, *byoAKSNetworkIssue) {
	expected, err := byoAKSStoragePrivateDNSZoneName(storage.blobEndpoint)
	if err != nil {
		return nil, &byoAKSNetworkIssue{
			property: "storageAccountResourceId.primaryEndpoints.blob",
			observed: missingValue(storage.blobEndpoint), expected: "a valid HTTPS blob endpoint",
			suggestion: "verify the storage account blob endpoint can be read",
		}
	}
	for _, group := range endpoint.dnsZoneGroups {
		if group == nil || group.Properties == nil ||
			!strings.EqualFold(byoAKSString(group.Properties.ProvisioningState), "Succeeded") {
			continue
		}
		for _, config := range group.Properties.PrivateDNSZoneConfigs {
			if config == nil || config.Properties == nil {
				continue
			}
			id, parseErr := arm.ParseResourceID(byoAKSString(config.Properties.PrivateDNSZoneID))
			if parseErr == nil &&
				strings.EqualFold(id.ResourceType.String(), "Microsoft.Network/privateDnsZones") &&
				strings.EqualFold(id.Name, expected) {
				return id, nil
			}
		}
	}
	return nil, &byoAKSNetworkIssue{
		property:   "storageAccountResourceId.privateEndpoint.privateDnsZoneGroups",
		observed:   "missing a Succeeded zone group for " + expected,
		expected:   "a private DNS zone group for the storage blob private-link zone",
		suggestion: "attach the blob private DNS zone to the storage private endpoint",
	}
}

func byoAKSStoragePrivateDNSZoneName(blobEndpoint string) (string, error) {
	parsed, err := url.Parse(blobEndpoint)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid blob endpoint")
	}
	parts := strings.Split(parsed.Hostname(), ".")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid blob endpoint host")
	}
	return "privatelink." + strings.Join(parts[1:], "."), nil
}

func byoAKSNetworkKey(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "/"))
}
