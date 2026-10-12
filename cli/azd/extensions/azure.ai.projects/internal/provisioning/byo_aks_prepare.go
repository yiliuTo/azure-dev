// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// cspell:ignore BYOAKS armnetwork roledefinitions

package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"azure.ai.projects/internal/exterrors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/azure/azure-dev/cli/azd/pkg/azdext"
	"github.com/azure/azure-dev/cli/azd/pkg/grpcbroker"
	"github.com/google/uuid"
)

type byoAKSRole struct {
	name, definitionID, principalID string
	scope                           *arm.ResourceID
	exists                          bool
	client                          *armauthorization.RoleAssignmentsClient
}

type byoAKSPlan struct {
	config          *byoAKSConfig
	ids             *byoAKSResources
	state           *byoAKSSnapshot
	needsDelegation bool
	authorization   byoAKSAuthorization
}

func (p *FoundryProvisioningProvider) planBYOAKS(
	ctx context.Context, source *templateSource, progress grpcbroker.ProgressFunc,
) (*byoAKSPlan, error) {
	config, err := byoAKSConfigFromParameters(source.parameters)
	if err != nil {
		return nil, exterrors.Validation(exterrors.CodeBYOAKSPreflightFailed, err.Error(),
			"provide a valid agentHosting object in the Foundry service configuration")
	}
	if source.mode != templateModeEmbedded {
		declared, err := byoAKSConfigFromParameters(p.armParameters())
		if err != nil {
			return nil, exterrors.Validation(exterrors.CodeBYOAKSPreflightFailed, err.Error(),
				"correct the agentHosting configuration")
		}
		if config != nil || declared != nil {
			return nil, exterrors.Validation(exterrors.CodeBYOAKSUnsupported,
				"BYO AKS automatic preparation in this demo only supports the embedded microsoft.foundry template",
				"use a new project without ejected infrastructure; Bicep and Terraform eject are outside this demo")
		}
		return nil, nil
	}
	if config == nil {
		return nil, nil
	}
	if p.brownfieldEndpoint != "" {
		return nil, exterrors.Validation(exterrors.CodeBYOAKSUnsupported,
			"BYO AKS automatic preparation requires a newly created Foundry account",
			"omit endpoint and provision a new Foundry account")
	}
	ids, err := config.resources(p.subID)
	if err != nil {
		return nil, err
	}
	if err := p.ensureCredential(ctx); err != nil {
		return nil, err
	}
	options := arm.ClientOptions{}
	if p.armClientOptions != nil {
		options = *p.armClientOptions
	}
	// A read-only preflight must not implicitly register resource providers.
	options.DisableRPRegistration = true
	progress(fmt.Sprintf("Checking BYO AKS cluster %q using the current azd identity...", ids.cluster))
	state, err := p.readBYOAKS(ctx, ids, &options)
	if err != nil {
		return nil, config.azureError(err, exterrors.OpBYOAKSPreflight)
	}
	validation, err := config.validate(ids, state, p.location)
	if err != nil {
		return nil, err
	}
	if validation.authorization == byoAKSAuthorizationNativeRBAC {
		check := p.byoAKSNativeRBACCheck
		if check == nil {
			check = p.checkBYOAKSNativeRBAC
		}
		if err := check(ctx, ids, *state.management.Properties.PrincipalID, &options); err != nil {
			return nil, config.azureError(err, exterrors.OpBYOAKSPreflight)
		}
	}
	return &byoAKSPlan{
		config: config, ids: ids, state: state,
		needsDelegation: validation.needsDelegation, authorization: validation.authorization,
	}, nil
}

func (p *FoundryProvisioningProvider) applyBYOAKS(
	ctx context.Context, plan *byoAKSPlan, progress grpcbroker.ProgressFunc,
) error {
	if plan == nil {
		return nil
	}
	options := arm.ClientOptions{}
	if p.armClientOptions != nil {
		options = *p.armClientOptions
	}
	options.DisableRPRegistration = true
	roles := byoAKSRoles(plan.ids, plan.state, plan.authorization)
	if err := p.inspectBYOAKSRoles(ctx, roles, &options); err != nil {
		return plan.config.azureError(err, exterrors.OpBYOAKSPreflight)
	}
	progress("BYO AKS runtime preflight passed. Agent-image private trusted roots are validated later, " +
		"when the image digest is known.")
	progress("BYO AKS network preflight validated ARM configuration prerequisites only. Kubernetes API checks " +
		"originate on this machine and do not prove agent-subnet or Storage data-plane traffic.")
	progress("BYO AKS preflight passed. Preparing required Foundry hosting role assignments:")
	for _, role := range roles {
		action := "Assign"
		if role.exists {
			action = "Already assigned"
		}
		progress(fmt.Sprintf("%s %s to principal %s at %s", action, role.name, role.principalID, role.scope))
	}
	if plan.needsDelegation {
		progress(fmt.Sprintf("Add %s delegation to agent subnet %s; preserve its other properties",
			byoAKSDelegation, plan.ids.subnet))
	} else {
		progress(fmt.Sprintf("Agent subnet %s already delegates to %s", plan.ids.subnet, byoAKSDelegation))
	}
	for _, role := range roles {
		if role.exists {
			continue
		}
		if err := role.assign(ctx); err != nil {
			return plan.config.azureError(err, exterrors.OpBYOAKSPrepare)
		}
	}
	if plan.needsDelegation {
		if err := p.delegateBYOAKSSubnet(
			ctx, plan.ids.subnet, plan.state.subnet, &options, progress,
		); err != nil {
			return plan.config.azureError(err, exterrors.OpBYOAKSPrepare)
		}
	}
	progress("BYO AKS preparation complete. New role assignments may still be propagating.")
	return nil
}

func (p *FoundryProvisioningProvider) readBYOAKS(
	ctx context.Context, ids *byoAKSResources, options *arm.ClientOptions,
) (*byoAKSSnapshot, error) {
	clusterClient, err := armcontainerservice.NewManagedClustersClient(ids.cluster.SubscriptionID, p.credential, options)
	if err != nil {
		return nil, fmt.Errorf("create AKS client: %w", err)
	}
	cluster, err := clusterClient.Get(ctx, ids.cluster.ResourceGroupName, ids.cluster.Name, nil)
	if err != nil {
		return nil, fmt.Errorf("read cluster %s: %w", ids.cluster, err)
	}
	poolClient, err := armcontainerservice.NewAgentPoolsClient(ids.cluster.SubscriptionID, p.credential, options)
	if err != nil {
		return nil, fmt.Errorf("create AKS agent pools client: %w", err)
	}
	resourceClient, err := armresources.NewClient(ids.cluster.SubscriptionID, p.credential, options)
	if err != nil {
		return nil, fmt.Errorf("create AKS agent pool resource client: %w", err)
	}
	var pools []*byoAKSAgentPool
	pager := poolClient.NewListPager(ids.cluster.ResourceGroupName, ids.cluster.Name, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list AgentPool child resources for cluster %s: %w", ids.cluster, err)
		}
		for _, pool := range page.Value {
			if pool == nil || pool.Name == nil {
				return nil, fmt.Errorf("list AgentPool child resources for cluster %s: response contains an unnamed pool",
					ids.cluster)
			}
			poolID := ids.cluster.String() + "/agentPools/" + *pool.Name
			raw, err := resourceClient.GetByID(ctx, poolID, byoAKSAgentPoolAPIVersion, nil)
			if err != nil {
				return nil, fmt.Errorf("read AgentPool child resource %s: %w", poolID, err)
			}
			properties, err := byoAKSAgentPoolProperties(raw.Properties)
			if err != nil {
				return nil, fmt.Errorf("read AgentPool child resource %s properties: %w", poolID, err)
			}
			sshAccess, err := byoAKSAgentPoolSSHAccess(raw.Properties)
			if err != nil {
				return nil, fmt.Errorf("read AgentPool child resource %s security profile: %w", poolID, err)
			}
			pools = append(pools, &byoAKSAgentPool{
				name: *pool.Name, properties: properties, sshAccess: sshAccess,
			})
		}
	}
	readIdentity := func(id *arm.ResourceID) (armmsi.Identity, error) {
		client, err := armmsi.NewUserAssignedIdentitiesClient(id.SubscriptionID, p.credential, options)
		if err != nil {
			return armmsi.Identity{}, fmt.Errorf("create identity client: %w", err)
		}
		result, err := client.Get(ctx, id.ResourceGroupName, id.Name, nil)
		if err != nil {
			return armmsi.Identity{}, fmt.Errorf("read identity %s: %w", id, err)
		}
		return result.Identity, nil
	}
	management, err := readIdentity(ids.management)
	if err != nil {
		return nil, err
	}
	workload, err := readIdentity(ids.workload)
	if err != nil {
		return nil, err
	}
	subnetClient, err := armnetwork.NewSubnetsClient(ids.subnet.SubscriptionID, p.credential, options)
	if err != nil {
		return nil, fmt.Errorf("create subnet client: %w", err)
	}
	subnet, err := subnetClient.Get(ctx, ids.subnet.ResourceGroupName, ids.subnet.Parent.Name, ids.subnet.Name, nil)
	if err != nil {
		return nil, fmt.Errorf("read agent subnet %s: %w", ids.subnet, err)
	}
	resourceClient, err = armresources.NewClient(ids.storage.SubscriptionID, p.credential, options)
	if err != nil {
		return nil, fmt.Errorf("create storage resource client: %w", err)
	}
	storage, err := resourceClient.GetByID(ctx, ids.storage.String(), "2023-05-01", nil)
	if err != nil {
		return nil, fmt.Errorf("read storage account %s: %w", ids.storage, err)
	}
	network, err := p.readBYOAKSNetwork(
		ctx, ids, cluster.ManagedCluster, pools, subnet.Subnet, storage.GenericResource, options,
	)
	if err != nil {
		return nil, err
	}
	return &byoAKSSnapshot{
		cluster: cluster.ManagedCluster, agentPools: pools, management: management, workload: workload,
		subnet: subnet.Subnet, storage: storage.GenericResource, network: network,
	}, nil
}

func byoAKSRoles(
	ids *byoAKSResources, state *byoAKSSnapshot, authorization byoAKSAuthorization,
) []*byoAKSRole {
	management := *state.management.Properties.PrincipalID
	workload := *state.workload.Properties.PrincipalID
	roles := []*byoAKSRole{
		{
			name: "Reader", definitionID: "acdd72a7-3385-48ef-bd42-f606fba81ae7",
			principalID: management, scope: ids.cluster,
		},
		{
			name: "Kubernetes Extension Contributor", definitionID: "85cb6faf-e071-4c9b-8136-154b5a04f717",
			principalID: management, scope: ids.cluster,
		},
		{
			name:         "Managed Identity Federated Identity Credential Contributor",
			definitionID: "7e559ce2-48d7-4b27-9128-fa1b247f1308",
			principalID:  management, scope: ids.workload,
		},
		{
			name: "Storage Blob Data Contributor", definitionID: "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
			principalID: workload, scope: ids.storage,
		},
	}
	if authorization == byoAKSAuthorizationAzureRBAC {
		roles = append(roles, &byoAKSRole{
			name: "Azure Kubernetes Service RBAC Cluster Admin", definitionID: byoAKSClusterAdminRoleID,
			principalID: management, scope: ids.cluster,
		})
	}
	return roles
}

func byoAKSAgentPoolSSHAccess(properties any) (string, error) {
	encoded, err := json.Marshal(properties)
	if err != nil {
		return "", err
	}
	var value struct {
		SecurityProfile struct {
			SSHAccess string `json:"sshAccess"`
		} `json:"securityProfile"`
	}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return "", err
	}
	return value.SecurityProfile.SSHAccess, nil
}

func byoAKSAgentPoolProperties(
	properties any,
) (*armcontainerservice.ManagedClusterAgentPoolProfileProperties, error) {
	encoded, err := json.Marshal(properties)
	if err != nil {
		return nil, err
	}
	var value armcontainerservice.ManagedClusterAgentPoolProfileProperties
	if err := json.Unmarshal(encoded, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (p *FoundryProvisioningProvider) inspectBYOAKSRoles(
	ctx context.Context, roles []*byoAKSRole, options *arm.ClientOptions,
) error {
	assignments := map[string][]*armauthorization.RoleAssignment{}
	for _, role := range roles {
		client, err := armauthorization.NewRoleAssignmentsClient(role.scope.SubscriptionID, p.credential, options)
		if err != nil {
			return fmt.Errorf("create role assignments client: %w", err)
		}
		role.client = client
		scope := role.scope.String()
		existing, read := assignments[scope]
		if !read {
			existing, err = role.list(ctx)
			if err != nil {
				return err
			}
			assignments[scope] = existing
		}
		role.exists = role.matches(existing)
	}
	return nil
}

func (role *byoAKSRole) list(ctx context.Context) ([]*armauthorization.RoleAssignment, error) {
	var result []*armauthorization.RoleAssignment
	options := &armauthorization.RoleAssignmentsClientListForScopeOptions{
		Filter: new("atScope()"),
	}
	pager := role.client.NewListForScopePager(role.scope.String(), options)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list role assignments at %s: %w", role.scope, err)
		}
		result = append(result, page.Value...)
	}
	return result, nil
}

func (role *byoAKSRole) matches(assignments []*armauthorization.RoleAssignment) bool {
	for _, assignment := range assignments {
		if assignment == nil || assignment.Properties == nil {
			continue
		}
		properties := assignment.Properties
		definition := strings.ToLower(byoAKSString(properties.RoleDefinitionID))
		if !strings.EqualFold(byoAKSString(properties.PrincipalID), role.principalID) ||
			!strings.HasSuffix(definition, "/roledefinitions/"+role.definitionID) ||
			strings.TrimSpace(byoAKSString(properties.Condition)) != "" {
			continue
		}
		scope := strings.ToLower(strings.TrimSuffix(byoAKSString(properties.Scope), "/"))
		target := strings.ToLower(role.scope.String())
		if scope != "" && (scope == target || strings.HasPrefix(target, scope+"/")) {
			return true
		}
	}
	return false
}

func (role *byoAKSRole) assign(ctx context.Context) error {
	name := uuid.NewSHA1(uuid.NameSpaceURL,
		[]byte(strings.ToLower(role.scope.String()+"|"+role.principalID+"|"+role.definitionID))).String()
	_, err := role.client.Create(ctx, role.scope.String(), name, armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			PrincipalID:   new(role.principalID),
			PrincipalType: new(armauthorization.PrincipalTypeServicePrincipal),
			RoleDefinitionID: new(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
				role.scope.SubscriptionID, role.definitionID)),
		},
	}, nil)
	if err == nil {
		return nil
	}
	if response, ok := errors.AsType[*azcore.ResponseError](err); ok && response.ErrorCode == "RoleAssignmentExists" {
		// Another actor may have assigned this role under a different name after our read.
		assignments, readErr := role.list(ctx)
		if readErr != nil {
			return readErr
		}
		if role.matches(assignments) {
			return nil
		}
	}
	return fmt.Errorf("assign %s to principal %s at %s: %w", role.name, role.principalID, role.scope, err)
}

func (p *FoundryProvisioningProvider) delegateBYOAKSSubnet(
	ctx context.Context, id *arm.ResourceID, subnet armnetwork.Subnet,
	options *arm.ClientOptions, progress grpcbroker.ProgressFunc,
) error {
	client, err := armnetwork.NewSubnetsClient(id.SubscriptionID, p.credential, options)
	if err != nil {
		return fmt.Errorf("create subnet client: %w", err)
	}
	subnet.Properties.Delegations = append(subnet.Properties.Delegations, &armnetwork.Delegation{
		Name:       new("azd-foundry-agent"),
		Properties: &armnetwork.ServiceDelegationPropertiesFormat{ServiceName: new(byoAKSDelegation)},
	})
	poller, err := client.BeginCreateOrUpdate(ctx, id.ResourceGroupName, id.Parent.Name, id.Name, subnet, nil)
	if err != nil {
		return fmt.Errorf("delegate agent subnet %s to %s: %w", id, byoAKSDelegation, err)
	}
	if _, err := pollWithProgress(ctx, poller, progress, "Agent subnet delegation in progress"); err != nil {
		return fmt.Errorf("complete agent subnet delegation %s: %w", id, err)
	}
	return nil
}

func (c *byoAKSConfig) azureError(err error, operation string) error {
	result := exterrors.ServiceFromAzure(err, operation)
	message := fmt.Sprintf("BYO AKS preparation for cluster %q: %s", c.ClusterResourceID, err)
	suggestion := "Verify the configured resources exist and the current azd identity can read the AKS cluster, " +
		"its AgentPool child resources, node and pod subnets, hosting and workload identities, storage account, " +
		"agent subnet, parent VNets, peerings, attached route tables and NSGs, and role assignments at the AKS " +
		"cluster, workload identity, and storage account scopes. Restricted Storage access can additionally require " +
		"read access to private endpoints, private DNS zone groups, zones, and VNet links. Managed Entra clusters " +
		"using native Kubernetes RBAC also require listClusterUserCredential/action and connectivity from this " +
		"machine to read ClusterRoleBindings from the Kubernetes API; that probe does not prove subnet data-plane traffic."
	if operation == exterrors.OpBYOAKSPrepare {
		suggestion = "The current azd identity needs roleAssignments read/write at the AKS cluster, workload identity, " +
			"and storage account scopes, plus write access to the agent subnet. Obtain the required access from an " +
			"administrator, then rerun 'azd provision'. Earlier successful preparation is retained; azd does not " +
			"elevate the caller."
	}
	switch classified := result.(type) {
	case *azdext.ServiceError:
		classified.Message = message
		classified.Suggestion = suggestion
	case *azdext.LocalError:
		if classified.Code != exterrors.CodeCancelled {
			classified.Message = message
			classified.Suggestion = suggestion
		}
	}
	return result
}
