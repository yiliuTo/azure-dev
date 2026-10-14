// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type byoAKSStaticTokenCredential struct {
	token string
}

func (c byoAKSStaticTokenCredential) GetToken(
	context.Context,
	policy.TokenRequestOptions,
) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: c.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func setBYOAKSTestRegistryConfig(
	t *testing.T,
	provider *FoundryProvisioningProvider,
	resourceID string,
) {
	t.Helper()
	raw, err := json.Marshal(provider.synthResult.Parameters["agentHosting"])
	require.NoError(t, err)
	var hosting map[string]any
	require.NoError(t, json.Unmarshal(raw, &hosting))
	hosting["containerRegistryResourceId"] = resourceID
	provider.synthResult.Parameters["agentHosting"] = hosting
	provider.synthResult.Parameters["includeAcr"] = true
	provider.synthResult.Parameters["preparedAcrResourceId"] = resourceID
	if resourceID == "" {
		provider.synthResult.Parameters["acrMode"] = "create"
	} else {
		provider.synthResult.Parameters["acrMode"] = "reuse-connect"
	}
}

func TestBYOAKSOperatorRoleAssignmentWriteRequiredAtEveryScope(t *testing.T) {
	for _, scope := range []string{
		byoTestCluster,
		byoTestWorkload,
		byoTestStorage,
		byoTestRegistry,
	} {
		t.Run(scope, func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			checked := false
			provider.byoAKSOperatorPermissionCheck = func(
				_ context.Context,
				actual *arm.ResourceID,
				actions []string,
				_ *arm.ClientOptions,
			) ([]string, error) {
				if strings.EqualFold(actual.String(), scope) {
					checked = true
					assert.Contains(t, actions, byoAKSRoleAssignmentsWriteAction)
					return []string{byoAKSRoleAssignmentsWriteAction}, nil
				}
				return nil, nil
			}

			_, err := provider.Deploy(t.Context(), func(string) {})
			require.Error(t, err)
			assert.True(t, checked)
			assert.Contains(t, err.Error(), byoAKSRoleAssignmentsWriteAction)
			assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(scope))
			assert.Empty(t, azure.writes(), "permission failure must occur before every write")
		})
	}
}

func TestBYOAKSOperatorWriteRequiredWhenAssignmentsExist(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	_, err := provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)

	azure.requests = nil
	provider.byoAKSOperatorPermissionCheck = func(
		_ context.Context,
		scope *arm.ResourceID,
		_ []string,
		_ *arm.ClientOptions,
	) ([]string, error) {
		if strings.EqualFold(scope.String(), byoTestCluster) {
			return []string{byoAKSRoleAssignmentsWriteAction}, nil
		}
		return nil, nil
	}

	_, err = provider.Deploy(t.Context(), func(string) {})
	require.ErrorContains(t, err, byoAKSRoleAssignmentsWriteAction)
	assert.Empty(t, azure.writes(),
		"existing target assignments must not bypass the operator permission gate")
}

func TestBYOAKSCreatePermissionsUseNearestExistingParent(t *testing.T) {
	for _, tt := range []struct {
		name                string
		resourceGroupExists bool
		expectedScope       string
		expectedActions     []string
	}{
		{
			name:                "existing resource group",
			resourceGroupExists: true,
			expectedScope:       byoTestFoundryRG,
			expectedActions: []string{
				byoAKSRegistryWriteAction,
				byoAKSRoleAssignmentsWriteAction,
			},
		},
		{
			name:                "missing resource group",
			resourceGroupExists: false,
			expectedScope:       "/subscriptions/" + byoTestSubscription,
			expectedActions: []string{
				byoAKSRegistryWriteAction,
				byoAKSResourceGroupWriteAction,
				byoAKSRoleAssignmentsWriteAction,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			setBYOAKSTestRegistryConfig(t, provider, "")
			azure.registry = armcontainerregistry.Registry{}
			azure.resourceGroupExists = tt.resourceGroupExists
			checked := false
			provider.byoAKSOperatorPermissionCheck = func(
				_ context.Context,
				scope *arm.ResourceID,
				actions []string,
				_ *arm.ClientOptions,
			) ([]string, error) {
				if strings.EqualFold(scope.String(), tt.expectedScope) {
					checked = true
					assert.ElementsMatch(t, tt.expectedActions, actions)
					return []string{tt.expectedActions[0]}, nil
				}
				return nil, nil
			}

			_, err := provider.Deploy(t.Context(), func(string) {})
			require.ErrorContains(t, err, tt.expectedActions[0])
			assert.True(t, checked)
			assert.Empty(t, azure.writes())
		})
	}
}

func TestBYOAKSEffectivePermissionMatching(t *testing.T) {
	permission := func(actions, notActions []string) *armauthorization.Permission {
		result := &armauthorization.Permission{}
		for _, action := range actions {
			result.Actions = append(result.Actions, new(action))
		}
		for _, action := range notActions {
			result.NotActions = append(result.NotActions, new(action))
		}
		return result
	}
	for _, tt := range []struct {
		name        string
		permissions []*armauthorization.Permission
		missing     bool
	}{
		{
			name: "wildcard grants",
			permissions: []*armauthorization.Permission{
				permission([]string{"Microsoft.Authorization/*"}, nil),
			},
		},
		{
			name: "notActions removes wildcard grant",
			permissions: []*armauthorization.Permission{
				permission(
					[]string{"*"},
					[]string{"Microsoft.Authorization/roleAssignments/*"},
				),
			},
			missing: true,
		},
		{
			name: "separate unconditional role restores grant",
			permissions: []*armauthorization.Permission{
				permission(
					[]string{"*"},
					[]string{"Microsoft.Authorization/roleAssignments/*"},
				),
				permission([]string{byoAKSRoleAssignmentsWriteAction}, nil),
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			missing := byoAKSMissingActions(
				tt.permissions,
				[]string{byoAKSRoleAssignmentsWriteAction},
			)
			assert.Equal(t, tt.missing, len(missing) > 0)
		})
	}
}

func TestBYOAKSSubscriptionPermissionUsesCurrentCredentialPrincipal(t *testing.T) {
	const currentPrincipal = "00000000-0000-0000-0000-000000000099"
	claims := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"oid":"` + currentPrincipal + `"}`),
	)
	provider := FoundryProvisioningProvider{
		principalID: "00000000-0000-0000-0000-000000000001",
		credential: byoAKSStaticTokenCredential{
			token: "header." + claims + ".signature",
		},
	}

	actual, err := provider.byoAKSCurrentPrincipalID(t.Context(), &arm.ClientOptions{})
	require.NoError(t, err)
	assert.Equal(t, currentPrincipal, actual)
}

func TestBYOAKSOperatorUsesEffectivePermissionsAPI(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	provider.byoAKSOperatorPermissionCheck = nil

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)

	var scopes []string
	for _, request := range azure.requests {
		suffix := "/providers/Microsoft.Authorization/permissions"
		if strings.HasSuffix(strings.ToLower(request.path), strings.ToLower(suffix)) {
			scopes = append(scopes, request.path[:len(request.path)-len(suffix)])
		}
	}
	for _, scope := range []string{byoTestCluster, byoTestWorkload, byoTestStorage, byoTestRegistry} {
		assert.True(t, slices.ContainsFunc(scopes, func(actual string) bool {
			return strings.EqualFold(actual, scope)
		}), "effective permissions were not requested for %s", scope)
	}
}

func TestBYOAKSACRPermissionModeSelectsOneKubeletRole(t *testing.T) {
	for _, tt := range []struct {
		name     string
		mode     armcontainerregistry.RoleAssignmentMode
		expected string
		unwanted string
	}{
		{
			name:     "legacy",
			mode:     armcontainerregistry.RoleAssignmentModeLegacyRegistryPermissions,
			expected: byoAKSAcrPullRoleID,
			unwanted: byoAKSAcrRepositoryReaderRoleID,
		},
		{
			name:     "ABAC repository permissions",
			mode:     armcontainerregistry.RoleAssignmentModeAbacRepositoryPermissions,
			expected: byoAKSAcrRepositoryReaderRoleID,
			unwanted: byoAKSAcrPullRoleID,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			azure.registry.Properties.RoleAssignmentMode = new(tt.mode)

			_, err := provider.Deploy(t.Context(), func(string) {})
			require.NoError(t, err)

			var registryAssignments []byoAKSTestRequest
			for _, request := range azure.writes() {
				if strings.HasPrefix(strings.ToLower(request.path),
					strings.ToLower(byoTestRegistry+"/providers/Microsoft.Authorization/roleAssignments/")) {
					registryAssignments = append(registryAssignments, request)
				}
			}
			require.Len(t, registryAssignments, 1)
			assert.Contains(t, string(registryAssignments[0].body), tt.expected)
			assert.NotContains(t, string(registryAssignments[0].body), tt.unwanted)
			assert.Contains(t, string(registryAssignments[0].body), byoTestKubeletID)
			for _, request := range azure.writes() {
				assert.False(t,
					request.method == http.MethodPut &&
						strings.EqualFold(request.path, byoTestRegistry),
					"a provided registry must never be created or replaced")
			}
		})
	}
}

func TestBYOAKSKubeletIdentityRequiredBeforeWrites(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	delete(azure.state.cluster.Properties.IdentityProfile, "kubeletidentity")

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.ErrorContains(t, err, "kubeletidentity.objectId")
	assert.Empty(t, azure.writes())
}

func TestBYOAKSACRRoleAssignmentEquivalence(t *testing.T) {
	for _, tt := range []struct {
		name      string
		scope     string
		condition string
		writes    int
	}{
		{
			name:   "unconditional exact role with manual ID is reused",
			scope:  byoTestRegistry,
			writes: 0,
		},
		{
			name:   "unconditional inherited role is reused",
			scope:  "/subscriptions/" + byoTestSubscription,
			writes: 0,
		},
		{
			name:      "conditional exact role is not equivalent",
			scope:     byoTestRegistry,
			condition: "@Resource[Microsoft.ContainerRegistry/registries:name] StringEquals 'other'",
			writes:    1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			azure.assignments[strings.ToLower(byoTestRegistry)] = []*armauthorization.RoleAssignment{{
				ID: new(tt.scope + "/providers/Microsoft.Authorization/roleAssignments/manual"),
				Properties: &armauthorization.RoleAssignmentProperties{
					Scope:       new(tt.scope),
					PrincipalID: new(byoTestKubeletID),
					RoleDefinitionID: new("/subscriptions/" + byoTestSubscription +
						"/providers/Microsoft.Authorization/roleDefinitions/" + byoAKSAcrPullRoleID),
					Condition: new(tt.condition),
				},
			}}

			_, err := provider.Deploy(t.Context(), func(string) {})
			require.NoError(t, err)
			var writes int
			for _, request := range azure.writes() {
				if strings.HasPrefix(strings.ToLower(request.path),
					strings.ToLower(byoTestRegistry+"/providers/Microsoft.Authorization/roleAssignments/")) {
					writes++
				}
			}
			assert.Equal(t, tt.writes, writes)
		})
	}
}

func TestBYOAKSAutoCreatedACRIsOrderedAndIdempotent(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	setBYOAKSTestRegistryConfig(t, provider, "")
	azure.registry = armcontainerregistry.Registry{}
	azure.resourceGroupExists = false

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)

	writes := azure.writes()
	require.GreaterOrEqual(t, len(writes), 9)
	assert.True(t, strings.EqualFold(byoTestFoundryRG, writes[0].path))
	var createdGroup armresources.ResourceGroup
	require.NoError(t, json.Unmarshal(writes[0].body, &createdGroup))
	assert.Equal(t, "eastus2", byoAKSString(createdGroup.Location))
	assert.Equal(t, "test", byoAKSString(createdGroup.Tags["azd-env-name"]))
	assert.Contains(t, strings.ToLower(writes[1].path),
		"/providers/microsoft.containerregistry/registries/")
	registryID := writes[1].path
	var registryRoleIndex, subnetIndex, deploymentIndex = -1, -1, -1
	for i, request := range writes {
		switch {
		case strings.HasPrefix(strings.ToLower(request.path),
			strings.ToLower(registryID+"/providers/Microsoft.Authorization/roleAssignments/")):
			registryRoleIndex = i
		case strings.EqualFold(request.path, byoTestAgentSubnet):
			subnetIndex = i
		case strings.Contains(request.path, "/providers/Microsoft.Resources/deployments/"):
			deploymentIndex = i
		}
	}
	assert.Greater(t, registryRoleIndex, 1)
	assert.Greater(t, subnetIndex, registryRoleIndex)
	assert.Greater(t, deploymentIndex, subnetIndex)
	assert.Equal(t, registryID, azure.acrState["AZURE_CONTAINER_REGISTRY_RESOURCE_ID"])
	assert.NotEmpty(t, azure.acrState["AZURE_CONTAINER_REGISTRY_ENDPOINT"])
	assert.Equal(t, "create", azure.acrState["AZD_FOUNDRY_ACR_MODE"])

	azure.requests = nil
	_, err = provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)
	for _, request := range azure.writes() {
		assert.False(t,
			request.method == http.MethodPut &&
				(strings.EqualFold(request.path, byoTestFoundryRG) ||
					strings.EqualFold(request.path, registryID) ||
					strings.Contains(request.path, "/providers/Microsoft.Authorization/roleAssignments/") ||
					strings.EqualFold(request.path, byoTestAgentSubnet)),
			"second provision must preserve prepared resources and assignments")
	}
}

func TestBYOAKSAutoCreatedACRReusesInheritedRole(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	setBYOAKSTestRegistryConfig(t, provider, "")
	azure.registry = armcontainerregistry.Registry{}
	registryID := fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s",
		byoTestSubscription,
		"foundry",
		provider.byoAKSRegistryName(),
	)
	azure.assignments[strings.ToLower(byoTestFoundryRG)] = []*armauthorization.RoleAssignment{{
		ID: new(byoTestFoundryRG + "/providers/Microsoft.Authorization/roleAssignments/inherited-acr-pull"),
		Properties: &armauthorization.RoleAssignmentProperties{
			Scope:       new(byoTestFoundryRG),
			PrincipalID: new(byoTestKubeletID),
			RoleDefinitionID: new("/subscriptions/" + byoTestSubscription +
				"/providers/Microsoft.Authorization/roleDefinitions/" + byoAKSAcrPullRoleID),
		},
	}}

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)

	for _, request := range azure.writes() {
		assert.False(t,
			strings.HasPrefix(
				strings.ToLower(request.path),
				strings.ToLower(registryID+"/providers/Microsoft.Authorization/roleAssignments/"),
			),
			"the inherited AcrPull assignment must be reused",
		)
	}
}

func TestBYOAKSRegistryRoleFailureStopsSubnetAndFoundry(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	azure.fail = func(request *http.Request) (int, string) {
		if request.Method == http.MethodPut && strings.HasPrefix(
			strings.ToLower(request.URL.Path),
			strings.ToLower(byoTestRegistry+"/providers/Microsoft.Authorization/roleAssignments/"),
		) {
			return http.StatusForbidden, "AuthorizationFailed"
		}
		return 0, ""
	}

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.ErrorContains(t, err, "AuthorizationFailed")
	for _, request := range azure.writes() {
		assert.False(t, strings.EqualFold(request.path, byoTestAgentSubnet),
			"subnet delegation must not run after the registry role fails")
		assert.NotContains(t, request.path, "/providers/Microsoft.Resources/deployments/",
			"Foundry deployment must not run after the registry role fails")
	}
}

func TestBYOAKSResourcePreparationFailuresStopLaterWrites(t *testing.T) {
	for _, tt := range []struct {
		name      string
		failPath  func(*FoundryProvisioningProvider) string
		wantWrite int
	}{
		{
			name:      "resource group creation",
			failPath:  func(*FoundryProvisioningProvider) string { return byoTestFoundryRG },
			wantWrite: 1,
		},
		{
			name: "registry creation",
			failPath: func(provider *FoundryProvisioningProvider) string {
				return fmt.Sprintf(
					"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerRegistry/registries/%s",
					byoTestSubscription,
					"foundry",
					provider.byoAKSRegistryName(),
				)
			},
			wantWrite: 2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			setBYOAKSTestRegistryConfig(t, provider, "")
			azure.registry = armcontainerregistry.Registry{}
			azure.resourceGroupExists = false
			path := tt.failPath(provider)
			azure.fail = func(request *http.Request) (int, string) {
				if request.Method == http.MethodPut && strings.EqualFold(request.URL.Path, path) {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}

			_, err := provider.Deploy(t.Context(), func(string) {})
			require.ErrorContains(t, err, "AuthorizationFailed")
			assert.Len(t, azure.writes(), tt.wantWrite)
			for _, request := range azure.requests {
				assert.NotContains(t, request.path, "/providers/Microsoft.Resources/deployments/")
			}
		})
	}
}

func TestBYOAKSPreflightReadsDoNotRepeatDuringPreparation(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	setBYOAKSTestRegistryConfig(t, provider, "")
	azure.registry = armcontainerregistry.Registry{}

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)

	firstWrite := -1
	for i, request := range azure.requests {
		if request.method != http.MethodGet {
			firstWrite = i
			break
		}
	}
	require.Positive(t, firstWrite)
	for _, request := range azure.requests[firstWrite:] {
		if request.method != http.MethodGet {
			continue
		}
		assert.NotContains(t, request.path, "/roleAssignments",
			"preparation must not re-inspect assignments")
		assert.False(t, strings.EqualFold(request.path, byoTestCluster),
			"preparation must not rerun cluster preflight")
	}
}
