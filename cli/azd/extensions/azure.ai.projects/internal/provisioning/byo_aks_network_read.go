// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// cspell:ignore BYOAKS DNSAPI armnetwork privatelink

package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

const byoAKSPrivateDNSAPIVersion = "2018-09-01"

func (p *FoundryProvisioningProvider) readBYOAKSNetwork(
	ctx context.Context,
	ids *byoAKSResources,
	cluster armcontainerservice.ManagedCluster,
	pools []*byoAKSAgentPool,
	agentSubnet armnetwork.Subnet,
	storage armresources.GenericResource,
	options *arm.ClientOptions,
) (*byoAKSNetworkSnapshot, error) {
	storageNetwork, err := byoAKSStorageNetworkFromResource(ids.storage.String(), storage)
	if err != nil {
		return nil, fmt.Errorf("read storage account %s network properties: %w", ids.storage, err)
	}
	network := &byoAKSNetworkSnapshot{
		subnets: map[string]armnetwork.Subnet{
			byoAKSNetworkKey(ids.subnet.String()): agentSubnet,
		},
		virtualNetworks:     map[string]armnetwork.VirtualNetwork{},
		peerings:            map[string][]*armnetwork.VirtualNetworkPeering{},
		routeTables:         map[string]armnetwork.RouteTable{},
		securityGroups:      map[string]armnetwork.SecurityGroup{},
		privateEndpoints:    map[string]*byoAKSPrivateEndpointSnapshot{},
		privateDNSZoneLinks: map[string][]byoAKSPrivateDNSZoneLink{},
		storage:             storageNetwork,
	}
	sourceSubnets := []byoAKSSubnetRef{{
		id: ids.subnet, resource: agentSubnet, property: "agentSubnetResourceId",
	}}
	overlay := cluster.Properties != nil && cluster.Properties.NetworkProfile != nil &&
		strings.EqualFold(byoAKSString(cluster.Properties.NetworkProfile.NetworkPluginMode), "overlay")
	for i, pool := range pools {
		if pool == nil || pool.properties == nil {
			continue
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
				return nil, fmt.Errorf(
					"parse %s %q as an AKS subnet resource ID", reference.property, reference.value,
				)
			}
			subnet, err := p.readBYOAKSSubnet(ctx, id, network.subnets, options)
			if err != nil {
				return nil, fmt.Errorf("read AKS subnet %s referenced by %s: %w", id, reference.property, err)
			}
			if !slices.ContainsFunc(sourceSubnets, func(existing byoAKSSubnetRef) bool {
				return strings.EqualFold(existing.id.String(), id.String())
			}) {
				sourceSubnets = append(sourceSubnets, byoAKSSubnetRef{
					id: id, resource: subnet, property: reference.property,
				})
			}
		}
	}
	if err := p.readBYOAKSNetworkDependencies(ctx, network, options); err != nil {
		return nil, err
	}

	privateEndpointConfigured := slices.ContainsFunc(
		storageNetwork.privateEndpointReferences,
		func(reference byoAKSStoragePrivateEndpointReference) bool {
			return strings.EqualFold(reference.status, "Approved")
		},
	)
	publicEnabled := strings.EqualFold(storageNetwork.publicNetworkAccess, "Enabled")
	publicDisabled := strings.EqualFold(storageNetwork.publicNetworkAccess, "Disabled")
	defaultAllow := strings.EqualFold(storageNetwork.defaultAction, "Allow")
	defaultDeny := strings.EqualFold(storageNetwork.defaultAction, "Deny")
	serviceEndpointComplete := defaultDeny &&
		len(byoAKSMissingStorageServiceEndpoints(storageNetwork, sourceSubnets)) == 0
	publicPathBlocked := publicEnabled && (defaultAllow || serviceEndpointComplete) &&
		byoAKSValidateStorageOutboundNSGs(network, sourceSubnets) != nil
	privateEndpointRequired := publicDisabled ||
		(publicEnabled && defaultDeny && !serviceEndpointComplete) ||
		publicPathBlocked
	if privateEndpointRequired && privateEndpointConfigured {
		if err := p.readBYOAKSStoragePrivateEndpoints(ctx, network, options); err != nil {
			return nil, err
		}
		if err := p.readBYOAKSNetworkDependencies(ctx, network, options); err != nil {
			return nil, err
		}
	}
	return network, nil
}

func byoAKSStorageNetworkFromResource(
	resourceID string, resource armresources.GenericResource,
) (byoAKSStorageNetwork, error) {
	var raw struct {
		PublicNetworkAccess string `json:"publicNetworkAccess"`
		PrimaryEndpoints    struct {
			Blob string `json:"blob"`
		} `json:"primaryEndpoints"`
		NetworkACLs struct {
			DefaultAction       string `json:"defaultAction"`
			VirtualNetworkRules []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"virtualNetworkRules"`
		} `json:"networkAcls"`
		PrivateEndpointConnections []struct {
			Properties struct {
				PrivateEndpoint struct {
					ID string `json:"id"`
				} `json:"privateEndpoint"`
				PrivateLinkServiceConnectionState struct {
					Status string `json:"status"`
				} `json:"privateLinkServiceConnectionState"`
			} `json:"properties"`
		} `json:"privateEndpointConnections"`
	}
	encoded, err := json.Marshal(resource.Properties)
	if err != nil {
		return byoAKSStorageNetwork{}, fmt.Errorf("serialize properties: %w", err)
	}
	if err := json.Unmarshal(encoded, &raw); err != nil {
		return byoAKSStorageNetwork{}, fmt.Errorf("decode properties: %w", err)
	}
	result := byoAKSStorageNetwork{
		resourceID:          resourceID,
		publicNetworkAccess: raw.PublicNetworkAccess,
		defaultAction:       raw.NetworkACLs.DefaultAction,
		blobEndpoint:        raw.PrimaryEndpoints.Blob,
	}
	for _, rule := range raw.NetworkACLs.VirtualNetworkRules {
		result.virtualNetworkRules = append(result.virtualNetworkRules, byoAKSStorageVirtualNetworkRule{
			id: rule.ID, state: rule.State,
		})
	}
	for _, connection := range raw.PrivateEndpointConnections {
		result.privateEndpointReferences = append(
			result.privateEndpointReferences,
			byoAKSStoragePrivateEndpointReference{
				id:     connection.Properties.PrivateEndpoint.ID,
				status: connection.Properties.PrivateLinkServiceConnectionState.Status,
			},
		)
	}
	return result, nil
}

func (p *FoundryProvisioningProvider) readBYOAKSSubnet(
	ctx context.Context,
	id *arm.ResourceID,
	cache map[string]armnetwork.Subnet,
	options *arm.ClientOptions,
) (armnetwork.Subnet, error) {
	key := byoAKSNetworkKey(id.String())
	if subnet, exists := cache[key]; exists {
		return subnet, nil
	}
	client, err := armnetwork.NewSubnetsClient(id.SubscriptionID, p.credential, options)
	if err != nil {
		return armnetwork.Subnet{}, fmt.Errorf("create subnet client: %w", err)
	}
	response, err := client.Get(ctx, id.ResourceGroupName, id.Parent.Name, id.Name, nil)
	if err != nil {
		return armnetwork.Subnet{}, err
	}
	cache[key] = response.Subnet
	return response.Subnet, nil
}

func (p *FoundryProvisioningProvider) readBYOAKSStoragePrivateEndpoints(
	ctx context.Context,
	network *byoAKSNetworkSnapshot,
	options *arm.ClientOptions,
) error {
	for _, reference := range network.storage.privateEndpointReferences {
		if !strings.EqualFold(reference.status, "Approved") {
			continue
		}
		id, err := arm.ParseResourceID(reference.id)
		if err != nil || !strings.EqualFold(id.ResourceType.String(), "Microsoft.Network/privateEndpoints") {
			return fmt.Errorf("parse approved storage private endpoint resource ID %q", reference.id)
		}
		client, err := armnetwork.NewPrivateEndpointsClient(id.SubscriptionID, p.credential, options)
		if err != nil {
			return fmt.Errorf("create private endpoints client: %w", err)
		}
		response, err := client.Get(ctx, id.ResourceGroupName, id.Name, nil)
		if err != nil {
			return fmt.Errorf("read storage private endpoint %s: %w", id, err)
		}
		endpoint := &byoAKSPrivateEndpointSnapshot{resource: response.PrivateEndpoint}
		network.privateEndpoints[byoAKSNetworkKey(id.String())] = endpoint
		if response.PrivateEndpoint.Properties == nil {
			continue
		}
		subnetID := ""
		if response.PrivateEndpoint.Properties.Subnet != nil {
			subnetID = byoAKSString(response.PrivateEndpoint.Properties.Subnet.ID)
		}
		if subnetID != "" {
			parsed, parseErr := arm.ParseResourceID(subnetID)
			if parseErr != nil || parsed.Parent == nil ||
				!strings.EqualFold(parsed.ResourceType.String(), "Microsoft.Network/virtualNetworks/subnets") {
				return fmt.Errorf("parse storage private endpoint %s subnet resource ID %q", id, subnetID)
			}
			if _, err := p.readBYOAKSSubnet(ctx, parsed, network.subnets, options); err != nil {
				return fmt.Errorf("read storage private endpoint subnet %s: %w", parsed, err)
			}
		}
		if !byoAKSPrivateEndpointTargetsBlob(response.PrivateEndpoint, network.storage) {
			continue
		}
		zoneClient, err := armnetwork.NewPrivateDNSZoneGroupsClient(id.SubscriptionID, p.credential, options)
		if err != nil {
			return fmt.Errorf("create private DNS zone groups client: %w", err)
		}
		pager := zoneClient.NewListPager(id.Name, id.ResourceGroupName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return fmt.Errorf("list private DNS zone groups for storage private endpoint %s: %w", id, err)
			}
			endpoint.dnsZoneGroups = append(endpoint.dnsZoneGroups, page.Value...)
		}
	}
	return nil
}

func (p *FoundryProvisioningProvider) readBYOAKSNetworkDependencies(
	ctx context.Context,
	network *byoAKSNetworkSnapshot,
	options *arm.ClientOptions,
) error {
	vnetIDs := map[string]*arm.ResourceID{}
	routeTableIDs := map[string]*arm.ResourceID{}
	securityGroupIDs := map[string]*arm.ResourceID{}
	for _, subnet := range network.subnets {
		if subnet.ID == nil {
			return fmt.Errorf("read network dependencies: subnet response is missing id")
		}
		id, err := arm.ParseResourceID(*subnet.ID)
		if err != nil || id.Parent == nil ||
			!strings.EqualFold(id.ResourceType.String(), "Microsoft.Network/virtualNetworks/subnets") {
			return fmt.Errorf("read network dependencies: invalid subnet resource ID %q", *subnet.ID)
		}
		vnetIDs[byoAKSNetworkKey(id.Parent.String())] = id.Parent
		if subnet.Properties == nil {
			continue
		}
		references := []struct {
			raw, resourceType string
			destination       map[string]*arm.ResourceID
		}{
			{
				raw:          byoAKSRouteTableID(subnet.Properties.RouteTable),
				resourceType: "Microsoft.Network/routeTables", destination: routeTableIDs,
			},
			{
				raw:          byoAKSSecurityGroupID(subnet.Properties.NetworkSecurityGroup),
				resourceType: "Microsoft.Network/networkSecurityGroups", destination: securityGroupIDs,
			},
		}
		for _, reference := range references {
			if strings.TrimSpace(reference.raw) == "" {
				continue
			}
			resourceID, err := arm.ParseResourceID(reference.raw)
			if err != nil || !strings.EqualFold(resourceID.ResourceType.String(), reference.resourceType) {
				return fmt.Errorf(
					"read network dependencies: invalid %s resource ID %q",
					reference.resourceType,
					reference.raw,
				)
			}
			reference.destination[byoAKSNetworkKey(resourceID.String())] = resourceID
		}
	}
	for key, id := range vnetIDs {
		if _, exists := network.virtualNetworks[key]; exists {
			continue
		}
		client, err := armnetwork.NewVirtualNetworksClient(id.SubscriptionID, p.credential, options)
		if err != nil {
			return fmt.Errorf("create virtual networks client: %w", err)
		}
		response, err := client.Get(ctx, id.ResourceGroupName, id.Name, nil)
		if err != nil {
			return fmt.Errorf("read virtual network %s: %w", id, err)
		}
		network.virtualNetworks[key] = response.VirtualNetwork
	}
	if len(vnetIDs) > 1 {
		for key, id := range vnetIDs {
			if _, exists := network.peerings[key]; exists {
				continue
			}
			client, err := armnetwork.NewVirtualNetworkPeeringsClient(id.SubscriptionID, p.credential, options)
			if err != nil {
				return fmt.Errorf("create virtual network peerings client: %w", err)
			}
			network.peerings[key] = []*armnetwork.VirtualNetworkPeering{}
			pager := client.NewListPager(id.ResourceGroupName, id.Name, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return fmt.Errorf("list peerings for virtual network %s: %w", id, err)
				}
				network.peerings[key] = append(network.peerings[key], page.Value...)
			}
		}
	}
	for key, id := range routeTableIDs {
		if _, exists := network.routeTables[key]; exists {
			continue
		}
		client, err := armnetwork.NewRouteTablesClient(id.SubscriptionID, p.credential, options)
		if err != nil {
			return fmt.Errorf("create route tables client: %w", err)
		}
		response, err := client.Get(ctx, id.ResourceGroupName, id.Name, nil)
		if err != nil {
			return fmt.Errorf("read route table %s: %w", id, err)
		}
		network.routeTables[key] = response.RouteTable
	}
	for key, id := range securityGroupIDs {
		if _, exists := network.securityGroups[key]; exists {
			continue
		}
		client, err := armnetwork.NewSecurityGroupsClient(id.SubscriptionID, p.credential, options)
		if err != nil {
			return fmt.Errorf("create network security groups client: %w", err)
		}
		response, err := client.Get(ctx, id.ResourceGroupName, id.Name, nil)
		if err != nil {
			return fmt.Errorf("read network security group %s: %w", id, err)
		}
		network.securityGroups[key] = response.SecurityGroup
	}
	zoneIDs := map[string]*arm.ResourceID{}
	for _, endpoint := range network.privateEndpoints {
		for _, group := range endpoint.dnsZoneGroups {
			if group == nil || group.Properties == nil {
				continue
			}
			for _, config := range group.Properties.PrivateDNSZoneConfigs {
				if config == nil || config.Properties == nil {
					continue
				}
				raw := byoAKSString(config.Properties.PrivateDNSZoneID)
				id, err := arm.ParseResourceID(raw)
				if err != nil ||
					!strings.EqualFold(id.ResourceType.String(), "Microsoft.Network/privateDnsZones") {
					return fmt.Errorf("parse private DNS zone resource ID %q", raw)
				}
				zoneIDs[byoAKSNetworkKey(id.String())] = id
			}
		}
	}
	for key, id := range zoneIDs {
		if _, exists := network.privateDNSZoneLinks[key]; exists {
			continue
		}
		links, err := p.readBYOAKSPrivateDNSZoneLinks(ctx, id, options)
		if err != nil {
			return err
		}
		network.privateDNSZoneLinks[key] = links
	}
	return nil
}

func byoAKSRouteTableID(resource *armnetwork.RouteTable) string {
	if resource == nil {
		return ""
	}
	return byoAKSString(resource.ID)
}

func byoAKSSecurityGroupID(resource *armnetwork.SecurityGroup) string {
	if resource == nil {
		return ""
	}
	return byoAKSString(resource.ID)
}

func (p *FoundryProvisioningProvider) readBYOAKSPrivateDNSZoneLinks(
	ctx context.Context,
	zoneID *arm.ResourceID,
	options *arm.ClientOptions,
) ([]byoAKSPrivateDNSZoneLink, error) {
	client, err := armresources.NewClient(zoneID.SubscriptionID, p.credential, options)
	if err != nil {
		return nil, fmt.Errorf("create private DNS zone link resource client: %w", err)
	}
	filter := "resourceType eq 'Microsoft.Network/privateDnsZones/virtualNetworkLinks'"
	pager := client.NewListByResourceGroupPager(
		zoneID.ResourceGroupName,
		&armresources.ClientListByResourceGroupOptions{Filter: &filter},
	)
	var result []byoAKSPrivateDNSZoneLink
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list virtual network links for private DNS zone %s: %w", zoneID, err)
		}
		for _, resource := range page.Value {
			if resource == nil || resource.ID == nil {
				continue
			}
			id, err := arm.ParseResourceID(*resource.ID)
			if err != nil || id.Parent == nil || !strings.EqualFold(id.Parent.String(), zoneID.String()) {
				continue
			}
			link, err := client.GetByID(ctx, id.String(), byoAKSPrivateDNSAPIVersion, nil)
			if err != nil {
				return nil, fmt.Errorf("read private DNS zone link %s: %w", id, err)
			}
			var properties struct {
				VirtualNetwork struct {
					ID string `json:"id"`
				} `json:"virtualNetwork"`
				ProvisioningState       string `json:"provisioningState"`
				VirtualNetworkLinkState string `json:"virtualNetworkLinkState"`
			}
			encoded, err := json.Marshal(link.Properties)
			if err != nil {
				return nil, fmt.Errorf("serialize private DNS zone link %s: %w", id, err)
			}
			if err := json.Unmarshal(encoded, &properties); err != nil {
				return nil, fmt.Errorf("decode private DNS zone link %s: %w", id, err)
			}
			result = append(result, byoAKSPrivateDNSZoneLink{
				id:                id.String(),
				virtualNetworkID:  properties.VirtualNetwork.ID,
				provisioningState: properties.ProvisioningState,
				linkState:         properties.VirtualNetworkLinkState,
			})
		}
	}
	return result, nil
}
