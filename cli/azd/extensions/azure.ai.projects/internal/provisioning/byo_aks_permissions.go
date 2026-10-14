// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// cspell:ignore AKSACR BYOAKS roledefinitions

package provisioning

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"azure.ai.projects/internal/exterrors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

const (
	byoAKSRoleAssignmentsWriteAction = "Microsoft.Authorization/roleAssignments/write"
	byoAKSResourceGroupWriteAction   = "Microsoft.Resources/subscriptions/resourceGroups/write"
	byoAKSRegistryWriteAction        = "Microsoft.ContainerRegistry/registries/write"
)

type byoAKSOperatorPermissionCheck func(
	context.Context,
	*arm.ResourceID,
	[]string,
	*arm.ClientOptions,
) ([]string, error)

type byoAKSPermissionTarget struct {
	scope   *arm.ResourceID
	actions map[string]struct{}
}

func (p *FoundryProvisioningProvider) checkBYOAKSOperatorPermissions(
	ctx context.Context,
	roles []*byoAKSRole,
	acr *byoAKSACRPlan,
	resourceGroupExists bool,
	options *arm.ClientOptions,
) error {
	targets := map[string]*byoAKSPermissionTarget{}
	add := func(scope *arm.ResourceID, actions ...string) {
		key := strings.ToLower(strings.TrimSuffix(scope.String(), "/"))
		target, ok := targets[key]
		if !ok {
			target = &byoAKSPermissionTarget{scope: scope, actions: map[string]struct{}{}}
			targets[key] = target
		}
		for _, action := range actions {
			target.actions[action] = struct{}{}
		}
	}

	var futureACRScope *arm.ResourceID
	for _, role := range roles {
		scope := role.scope
		if !role.scopeExists {
			if futureACRScope == nil {
				var err error
				futureACRScope, err = p.byoAKSFutureResourceParent(acr, resourceGroupExists)
				if err != nil {
					return err
				}
			}
			scope = futureACRScope
		}
		add(scope, byoAKSRoleAssignmentsWriteAction)
	}

	if !resourceGroupExists {
		subscriptionScope, err := arm.ParseResourceID("/subscriptions/" + p.subID)
		if err != nil {
			return fmt.Errorf("construct subscription permission scope: %w", err)
		}
		add(subscriptionScope, byoAKSResourceGroupWriteAction)
	}
	if !acr.exists {
		if futureACRScope == nil {
			var err error
			futureACRScope, err = p.byoAKSFutureResourceParent(acr, resourceGroupExists)
			if err != nil {
				return err
			}
		}
		add(futureACRScope, byoAKSRegistryWriteAction)
	}

	check := p.byoAKSOperatorPermissionCheck
	if check == nil {
		check = p.checkBYOAKSEffectivePermissions
	}
	keys := make([]string, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var denied []string
	for _, key := range keys {
		target := targets[key]
		actions := make([]string, 0, len(target.actions))
		for action := range target.actions {
			actions = append(actions, action)
		}
		sort.Strings(actions)
		missing, err := check(ctx, target.scope, actions, options)
		if err != nil {
			return fmt.Errorf("check current azd identity permissions at %s: %w", target.scope, err)
		}
		for _, action := range missing {
			denied = append(denied, fmt.Sprintf("%s at %s", action, target.scope))
		}
	}
	if len(denied) > 0 {
		return exterrors.Validation(
			exterrors.CodeBYOAKSPreflightFailed,
			fmt.Sprintf("current azd identity is missing required permissions: %s", strings.Join(denied, "; ")),
			"Ask an administrator to grant the listed actions at the listed scopes, then rerun 'azd provision'. "+
				"azd checks roleAssignments/write even when every target assignment already exists.",
		)
	}
	return nil
}

func (p *FoundryProvisioningProvider) byoAKSFutureResourceParent(
	acr *byoAKSACRPlan,
	resourceGroupExists bool,
) (*arm.ResourceID, error) {
	if resourceGroupExists {
		return arm.ParseResourceID(fmt.Sprintf(
			"/subscriptions/%s/resourceGroups/%s",
			acr.id.SubscriptionID,
			acr.id.ResourceGroupName,
		))
	}
	return arm.ParseResourceID("/subscriptions/" + acr.id.SubscriptionID)
}

func (p *FoundryProvisioningProvider) checkBYOAKSEffectivePermissions(
	ctx context.Context,
	scope *arm.ResourceID,
	required []string,
	options *arm.ClientOptions,
) ([]string, error) {
	var permissions []*armauthorization.Permission
	if strings.EqualFold(strings.TrimSuffix(scope.String(), "/"), "/subscriptions/"+scope.SubscriptionID) {
		var err error
		permissions, err = p.byoAKSSubscriptionPermissions(ctx, scope.SubscriptionID, options)
		if err != nil {
			return nil, err
		}
	} else {
		client, err := armauthorization.NewPermissionsClient(scope.SubscriptionID, p.credential, options)
		if err != nil {
			return nil, fmt.Errorf("create effective-permissions client: %w", err)
		}
		if strings.EqualFold(scope.ResourceType.String(), "Microsoft.Resources/resourceGroups") {
			pager := client.NewListForResourceGroupPager(scope.ResourceGroupName, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list effective permissions for resource group %s: %w", scope, err)
				}
				permissions = append(permissions, page.Value...)
			}
		} else {
			parts := strings.Split(scope.ResourceType.String(), "/")
			if len(parts) != 2 {
				return nil, fmt.Errorf("unsupported permission scope resource type %q", scope.ResourceType)
			}
			pager := client.NewListForResourcePager(
				scope.ResourceGroupName,
				parts[0],
				"",
				parts[1],
				scope.Name,
				nil,
			)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list effective permissions for resource %s: %w", scope, err)
				}
				permissions = append(permissions, page.Value...)
			}
		}
	}
	return byoAKSMissingActions(permissions, required), nil
}

// Azure Authorization exposes caller-effective permissions for resource groups
// and resources, but not for a subscription. A missing resource group therefore
// falls back to the repository's role-assignment/definition evaluation pattern
// at the nearest existing parent. Conditional grants are not assumed to apply.
func (p *FoundryProvisioningProvider) byoAKSSubscriptionPermissions(
	ctx context.Context,
	subscriptionID string,
	options *arm.ClientOptions,
) ([]*armauthorization.Permission, error) {
	principalID, err := p.byoAKSCurrentPrincipalID(ctx, options)
	if err != nil {
		return nil, err
	}
	assignmentsClient, err := armauthorization.NewRoleAssignmentsClient(
		subscriptionID, p.credential, options)
	if err != nil {
		return nil, fmt.Errorf("create subscription role assignments client: %w", err)
	}
	definitionsClient, err := armauthorization.NewRoleDefinitionsClient(p.credential, options)
	if err != nil {
		return nil, fmt.Errorf("create role definitions client: %w", err)
	}
	scope := "/subscriptions/" + subscriptionID
	filter := fmt.Sprintf("atScope() and assignedTo('%s')", principalID)
	pager := assignmentsClient.NewListForScopePager(
		scope,
		&armauthorization.RoleAssignmentsClientListForScopeOptions{Filter: &filter},
	)
	definitions := map[string][]*armauthorization.Permission{}
	var permissions []*armauthorization.Permission
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list current identity role assignments at %s: %w", scope, err)
		}
		for _, assignment := range page.Value {
			if assignment == nil || assignment.Properties == nil ||
				strings.TrimSpace(byoAKSString(assignment.Properties.Condition)) != "" {
				continue
			}
			definitionID := byoAKSString(assignment.Properties.RoleDefinitionID)
			if definitionID == "" {
				continue
			}
			rolePermissions, ok := definitions[definitionID]
			if !ok {
				definition, err := definitionsClient.GetByID(ctx, definitionID, nil)
				if err != nil {
					return nil, fmt.Errorf("read role definition %s: %w", definitionID, err)
				}
				if definition.Properties != nil {
					rolePermissions = definition.Properties.Permissions
				}
				definitions[definitionID] = rolePermissions
			}
			permissions = append(permissions, rolePermissions...)
		}
	}
	return permissions, nil
}

func (p *FoundryProvisioningProvider) byoAKSCurrentPrincipalID(
	ctx context.Context,
	options *arm.ClientOptions,
) (string, error) {
	audience := cloud.AzurePublic.Services[cloud.ResourceManager].Audience
	if options != nil {
		if service, ok := options.Cloud.Services[cloud.ResourceManager]; ok &&
			strings.TrimSpace(service.Audience) != "" {
			audience = service.Audience
		}
	}
	token, err := p.credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{strings.TrimSuffix(audience, "/") + "/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("get ARM token to identify the current azd principal: %w", err)
	}
	parts := strings.Split(token.Token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("ARM token does not contain JWT claims for the current azd principal")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode current azd principal claims: %w", err)
	}
	var claims struct {
		ObjectID string `json:"oid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("decode current azd principal claims: %w", err)
	}
	if strings.TrimSpace(claims.ObjectID) == "" {
		return "", fmt.Errorf("ARM token has no oid claim for the current azd principal")
	}
	return claims.ObjectID, nil
}

func byoAKSMissingActions(
	permissions []*armauthorization.Permission,
	required []string,
) []string {
	var missing []string
	for _, action := range required {
		allowed := false
		for _, permission := range permissions {
			if permission == nil {
				continue
			}
			actions := byoAKSStrings(permission.Actions)
			notActions := byoAKSStrings(permission.NotActions)
			if byoAKSActionAllowed(action, actions, notActions) {
				allowed = true
				break
			}
		}
		if !allowed {
			missing = append(missing, action)
		}
	}
	return missing
}

func byoAKSStrings(values []*string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != nil {
			result = append(result, *value)
		}
	}
	return result
}

func byoAKSActionAllowed(required string, actions, notActions []string) bool {
	granted := false
	for _, action := range actions {
		if byoAKSActionMatches(action, required) {
			granted = true
			break
		}
	}
	if !granted {
		return false
	}
	for _, action := range notActions {
		if byoAKSActionMatches(action, required) {
			return false
		}
	}
	return true
}

func byoAKSActionMatches(pattern, target string) bool {
	pattern = strings.ToLower(pattern)
	target = strings.ToLower(target)
	if pattern == target || pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	segments := strings.Split(pattern, "*")
	position := 0
	if segments[0] != "" {
		if !strings.HasPrefix(target, segments[0]) {
			return false
		}
		position = len(segments[0])
	}
	for _, segment := range segments[1 : len(segments)-1] {
		if segment == "" {
			continue
		}
		index := strings.Index(target[position:], segment)
		if index < 0 {
			return false
		}
		position += index + len(segment)
	}
	last := segments[len(segments)-1]
	return last == "" || (strings.HasSuffix(target, last) && len(target)-len(last) >= position)
}
