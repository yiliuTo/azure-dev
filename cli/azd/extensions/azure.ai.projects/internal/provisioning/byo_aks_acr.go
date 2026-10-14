// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// cspell:ignore Abac AKSACR BYOAKS BYOAKSACR azurecr kubelet kubeletidentity

package provisioning

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"azure.ai.projects/internal/exterrors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v7"
	"github.com/azure/azure-dev/cli/azd/pkg/grpcbroker"
)

const (
	byoAKSAcrPullRoleID             = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
	byoAKSAcrRepositoryReaderRoleID = "cfdd1b31-da27-4c57-8c4d-79c61a2f2427"
)

type byoAKSACRPlan struct {
	config           *byoAKSConfig
	id               *arm.ResourceID
	client           *armcontainerregistry.RegistriesClient
	endpoint         string
	mode             string
	roleDefinitionID string
	exists           bool
	provided         bool
	role             *byoAKSRole
}

func (p *FoundryProvisioningProvider) planBYOAKSACR(
	ctx context.Context,
	config *byoAKSConfig,
	ids *byoAKSResources,
	state *byoAKSSnapshot,
	options *arm.ClientOptions,
) (*byoAKSACRPlan, error) {
	kubeletID, err := config.kubeletPrincipalID(state.cluster)
	if err != nil {
		return nil, err
	}

	resourceID := ""
	mode := "reuse-connect"
	provided := ids.registry != nil
	if provided {
		resourceID = ids.registry.String()
	}
	if resourceID == "" {
		resourceID, mode, err = p.byoAKSSavedACRState(ctx)
		if err != nil {
			return nil, err
		}
		if resourceID != "" {
			switch strings.ToLower(mode) {
			case "create":
				mode = "create"
			case "", "none", "reuse-connect", "already-connected":
				mode = "reuse-connect"
			default:
				return nil, exterrors.Validation(
					exterrors.CodeInvalidServiceConfig,
					fmt.Sprintf("AZD_FOUNDRY_ACR_MODE has unsupported value %q", mode),
					"clear the stale container registry environment values or set "+
						"agentHosting.containerRegistryResourceId to the registry to reuse",
				)
			}
		}
	}
	if resourceID == "" {
		mode = "create"
		resourceID = fmt.Sprintf(
			"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s",
			p.subID,
			p.rgName,
			p.byoAKSRegistryName(),
		)
	}
	id, err := arm.ParseResourceID(resourceID)
	if err != nil || strings.ContainsAny(resourceID, "?#") ||
		id.SubscriptionID == "" || id.ResourceGroupName == "" || id.Name == "" ||
		!strings.EqualFold(id.ResourceType.String(), "Microsoft.ContainerRegistry/registries") {
		return nil, config.invalid(
			"containerRegistryResourceId",
			"invalid resource ID",
			"Microsoft.ContainerRegistry/registries resource ID",
			"set agentHosting.containerRegistryResourceId to a complete Azure Container Registry ARM resource ID",
		)
	}
	if mode == "create" &&
		(!strings.EqualFold(id.SubscriptionID, p.subID) ||
			!strings.EqualFold(id.ResourceGroupName, p.rgName)) {
		mode = "reuse-connect"
	}
	ids.registry = id

	client, err := armcontainerregistry.NewRegistriesClient(id.SubscriptionID, p.credential, options)
	if err != nil {
		return nil, fmt.Errorf("create Azure Container Registry client: %w", err)
	}
	plan := &byoAKSACRPlan{
		config: config, id: id, client: client, mode: mode, provided: provided,
	}
	registry, err := client.Get(ctx, id.ResourceGroupName, id.Name, nil)
	if err != nil {
		if !isNotFound(err) {
			return nil, fmt.Errorf("read Azure Container Registry %s: %w", id, err)
		}
		canCreate := !provided && strings.EqualFold(mode, "create") &&
			strings.EqualFold(id.SubscriptionID, p.subID) &&
			strings.EqualFold(id.ResourceGroupName, p.rgName)
		if !canCreate {
			return nil, config.invalid(
				"containerRegistryResourceId",
				resourceID,
				"an existing Azure Container Registry",
				"create the registry or correct agentHosting.containerRegistryResourceId",
			)
		}
		plan.roleDefinitionID = byoAKSAcrPullRoleID
	} else {
		plan.exists = true
		plan.endpoint, plan.roleDefinitionID, err = config.validateACR(id, registry.Registry)
		if err != nil {
			return nil, err
		}
	}

	planRole := &byoAKSRole{
		name:         byoAKSACRRoleName(plan.roleDefinitionID),
		definitionID: plan.roleDefinitionID,
		principalID:  kubeletID,
		scope:        id,
		scopeExists:  plan.exists,
	}
	planRole.client, err = armauthorization.NewRoleAssignmentsClient(
		id.SubscriptionID, p.credential, options)
	if err != nil {
		return nil, fmt.Errorf("create Azure Container Registry role assignments client: %w", err)
	}
	plan.role = planRole
	return plan, nil
}

func (c *byoAKSConfig) kubeletPrincipalID(cluster armcontainerservice.ManagedCluster) (string, error) {
	if cluster.Properties == nil {
		return "", c.invalid(
			"clusterResourceId.identityProfile",
			"missing cluster properties",
			"a kubelet identity with objectId",
			"verify the AKS cluster exposes identityProfile.kubeletidentity.objectId",
		)
	}
	for name, identity := range cluster.Properties.IdentityProfile {
		if !strings.EqualFold(name, "kubeletidentity") || identity == nil {
			continue
		}
		objectID := strings.TrimSpace(byoAKSString(identity.ObjectID))
		if objectID != "" {
			return objectID, nil
		}
	}
	return "", c.invalid(
		"clusterResourceId.identityProfile.kubeletidentity.objectId",
		"missing",
		"the kubelet identity principal object ID",
		"configure a kubelet identity on the AKS cluster and verify its objectId is readable",
	)
}

func (c *byoAKSConfig) validateACR(
	id *arm.ResourceID,
	registry armcontainerregistry.Registry,
) (string, string, error) {
	if registry.Properties == nil {
		return "", "", c.invalid(
			"containerRegistryResourceId.properties",
			"missing",
			"Azure Container Registry properties",
			"verify the referenced registry is fully provisioned and readable",
		)
	}
	properties := registry.Properties
	if state := strings.TrimSpace(byoAKSString(properties.ProvisioningState)); state != "" &&
		!strings.EqualFold(state, string(armcontainerregistry.ProvisioningStateSucceeded)) {
		return "", "", c.invalid(
			"containerRegistryResourceId.provisioningState",
			state,
			string(armcontainerregistry.ProvisioningStateSucceeded),
			"wait for the Azure Container Registry provisioning operation to succeed",
		)
	}
	endpoint := strings.TrimSpace(byoAKSString(properties.LoginServer))
	if endpoint == "" {
		return "", "", c.invalid(
			"containerRegistryResourceId.loginServer",
			"missing",
			"the registry login server",
			fmt.Sprintf("verify Azure Container Registry %s is fully provisioned", id),
		)
	}
	mode := armcontainerregistry.RoleAssignmentModeLegacyRegistryPermissions
	if properties.RoleAssignmentMode != nil {
		mode = *properties.RoleAssignmentMode
	}
	switch mode {
	case armcontainerregistry.RoleAssignmentModeLegacyRegistryPermissions:
		return endpoint, byoAKSAcrPullRoleID, nil
	case armcontainerregistry.RoleAssignmentModeAbacRepositoryPermissions:
		return endpoint, byoAKSAcrRepositoryReaderRoleID, nil
	default:
		return "", "", c.invalid(
			"containerRegistryResourceId.roleAssignmentMode",
			string(mode),
			"LegacyRegistryPermissions or AbacRepositoryPermissions",
			"use a registry with a supported Azure Container Registry role assignment mode",
		)
	}
}

func (p *FoundryProvisioningProvider) prepareBYOAKSACR(
	ctx context.Context,
	source *templateSource,
	plan *byoAKSACRPlan,
	progress grpcbroker.ProgressFunc,
) error {
	if !plan.exists {
		progress(fmt.Sprintf("Creating dedicated Azure Container Registry %s...", plan.id))
		mode := armcontainerregistry.RoleAssignmentModeLegacyRegistryPermissions
		poller, err := plan.client.BeginCreate(
			ctx,
			plan.id.ResourceGroupName,
			plan.id.Name,
			armcontainerregistry.Registry{
				Location: new(p.location),
				SKU: &armcontainerregistry.SKU{
					Name: new(armcontainerregistry.SKUNamePremium),
				},
				Identity: &armcontainerregistry.IdentityProperties{
					Type: new(armcontainerregistry.ResourceIdentityTypeSystemAssigned),
				},
				Properties: &armcontainerregistry.RegistryProperties{
					AdminUserEnabled:    new(false),
					PublicNetworkAccess: new(armcontainerregistry.PublicNetworkAccessEnabled),
					ZoneRedundancy:      new(armcontainerregistry.ZoneRedundancyDisabled),
					RoleAssignmentMode:  &mode,
				},
				Tags: map[string]*string{"azd-env-name": new(p.envName)},
			},
			nil,
		)
		if err != nil {
			return fmt.Errorf("create Azure Container Registry %s: %w", plan.id, err)
		}
		response, err := pollWithProgress(ctx, poller, progress, "Azure Container Registry creation in progress")
		if err != nil {
			return fmt.Errorf("complete Azure Container Registry creation %s: %w", plan.id, err)
		}
		plannedDefinitionID := plan.roleDefinitionID
		endpoint, definitionID, err := plan.config.validateACR(plan.id, response.Registry)
		if err != nil {
			return err
		}
		plan.endpoint = endpoint
		plan.roleDefinitionID = definitionID
		plan.exists = true
		plan.role.name = byoAKSACRRoleName(definitionID)
		plan.role.definitionID = definitionID
		plan.role.scopeExists = true
		if !strings.EqualFold(plannedDefinitionID, definitionID) {
			assignments, err := plan.role.list(ctx)
			if err != nil {
				return fmt.Errorf("verify Azure Container Registry role assignments at %s: %w", plan.id, err)
			}
			plan.role.exists = plan.role.matches(assignments)
		}
	} else {
		progress(fmt.Sprintf("Using existing Azure Container Registry %s", plan.id))
	}

	source.parameters["preparedAcrResourceId"] = map[string]any{"value": plan.id.String()}
	source.parameters["preparedAcrRoleDefinitionId"] = map[string]any{
		"value": fmt.Sprintf(
			"/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
			plan.id.SubscriptionID,
			plan.roleDefinitionID,
		),
	}
	source.parameters["acrMode"] = map[string]any{"value": plan.mode}

	persist := p.byoAKSPersistACRState
	if persist == nil {
		persist = p.persistBYOAKSACRState
	}
	if err := persist(ctx, plan); err != nil {
		return err
	}
	return nil
}

func (p *FoundryProvisioningProvider) persistBYOAKSACRState(
	ctx context.Context,
	plan *byoAKSACRPlan,
) error {
	if p.azdClient == nil {
		return nil
	}
	for _, entry := range []struct {
		key, value string
	}{
		{"AZURE_CONTAINER_REGISTRY_RESOURCE_ID", plan.id.String()},
		{"AZURE_CONTAINER_REGISTRY_ENDPOINT", plan.endpoint},
		{"AZD_FOUNDRY_ACR_MODE", plan.mode},
	} {
		if err := p.setEnv(ctx, entry.key, entry.value); err != nil {
			return fmt.Errorf("record prepared Azure Container Registry state %s: %w", entry.key, err)
		}
	}
	return nil
}

func (p *FoundryProvisioningProvider) byoAKSSavedACRState(
	ctx context.Context,
) (string, string, error) {
	if p.azdClient == nil {
		return "", "", nil
	}
	resourceID, err := p.envValue(ctx, "AZURE_CONTAINER_REGISTRY_RESOURCE_ID")
	if err != nil {
		return "", "", fmt.Errorf("read AZURE_CONTAINER_REGISTRY_RESOURCE_ID: %w", err)
	}
	if strings.TrimSpace(resourceID) == "" {
		return "", "", nil
	}
	mode, err := p.envValue(ctx, "AZD_FOUNDRY_ACR_MODE")
	if err != nil {
		return "", "", fmt.Errorf("read AZD_FOUNDRY_ACR_MODE: %w", err)
	}
	return strings.TrimSpace(resourceID), strings.TrimSpace(mode), nil
}

func (p *FoundryProvisioningProvider) byoAKSRegistryName() string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.Join(
		[]string{p.subID, p.rgName, p.location, p.envName},
		"|",
	))))
	return fmt.Sprintf("cr%x", sum[:16])
}

func byoAKSACRRoleName(definitionID string) string {
	if definitionID == byoAKSAcrRepositoryReaderRoleID {
		return "Container Registry Repository Reader"
	}
	return "AcrPull"
}
