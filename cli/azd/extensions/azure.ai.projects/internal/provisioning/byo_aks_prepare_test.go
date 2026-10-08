// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"azure.ai.projects/internal/exterrors"
	"azure.ai.projects/internal/synthesis"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/azure/azure-dev/cli/azd/pkg/azdext"
	"github.com/azure/azure-dev/cli/azd/test/mocks/mockhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type byoAKSTestRequest struct {
	method, path string
	body         []byte
}

type byoAKSTestAzure struct {
	state         *byoAKSSnapshot
	requests      []byoAKSTestRequest
	assignments   map[string][]*armauthorization.RoleAssignment
	resourceGroup *armresources.ResourceGroup
	fail          func(*http.Request) (int, string)
	transport     *mockhttp.MockHttpClient
}

type byoAKSTestPipelineKey struct{}

type byoAKSTestPipeline struct {
	options *arm.ClientOptions
}

func (p byoAKSTestPipeline) Do(request *policy.Request) (*http.Response, error) {
	transport, ok := p.options.Transport.(*mockhttp.MockHttpClient)
	if !ok || transport == nil {
		return request.Next()
	}
	ctx := context.WithValue(request.Raw().Context(), byoAKSTestPipelineKey{}, true)
	return request.WithContext(ctx).Next()
}

type byoAKSTestCredential struct {
	fake.TokenCredential
}

func (c *byoAKSTestCredential) GetToken(
	ctx context.Context, options policy.TokenRequestOptions,
) (azcore.AccessToken, error) {
	if ctx.Value(byoAKSTestPipelineKey{}) != true {
		return azcore.AccessToken{}, errors.New("test credential refused an unmocked ARM pipeline")
	}
	return c.TokenCredential.GetToken(ctx, options)
}

func byoAKSTestYAML() string {
	return fmt.Sprintf(`name: byo-aks-test
infra:
  provider: microsoft.foundry
services:
  project:
    host: azure.ai.project
    agentHosting:
      hostingType: ManagedCluster
      name: primary
      clusterResourceId: %s
      agentSubnetResourceId: %s
      hostingManagementIdentityResourceId: %s
      workloadIdentityResourceId: %s
      storageAccountResourceId: %s
`, byoTestCluster, byoTestAgentSubnet, byoTestManagement, byoTestWorkload, byoTestStorage)
}

func newBYOAKSTestProvider(t *testing.T) (*FoundryProvisioningProvider, *byoAKSTestAzure) {
	t.Helper()
	azure := &byoAKSTestAzure{
		state: byoAKSTestSnapshot(), assignments: map[string][]*armauthorization.RoleAssignment{},
		transport: mockhttp.NewMockHttpUtil(),
	}
	azure.transport.When(func(*http.Request) bool { return true }).RespondFn(
		func(request *http.Request) (*http.Response, error) {
			assert.Equal(t, "Bearer fake_token", request.Header.Get("Authorization"))
			var body []byte
			if request.Body != nil {
				var err error
				body, err = io.ReadAll(request.Body)
				require.NoError(t, err)
			}
			azure.requests = append(azure.requests, byoAKSTestRequest{request.Method, request.URL.Path, body})
			response := func(status int, value any) (*http.Response, error) {
				raw, err := json.Marshal(value)
				require.NoError(t, err)
				return &http.Response{
					StatusCode: status, Request: request, Body: io.NopCloser(bytes.NewReader(raw)),
					Header: http.Header{"Content-Type": []string{"application/json"}},
				}, nil
			}
			if azure.fail != nil {
				if code, name := azure.fail(request); code != 0 {
					return response(code, map[string]any{
						"error": map[string]string{"code": name, "message": "test service failure"},
					})
				}
			}
			if scope, _, ok := strings.Cut(request.URL.Path, "/providers/Microsoft.Authorization/roleAssignments"); ok {
				key := strings.ToLower(scope)
				if request.Method == http.MethodGet {
					assert.Equal(t, "atScope()", request.URL.Query().Get("$filter"))
					return response(http.StatusOK, armauthorization.RoleAssignmentListResult{Value: azure.assignments[key]})
				}
				require.Equal(t, http.MethodPut, request.Method)
				var parameters armauthorization.RoleAssignmentCreateParameters
				require.NoError(t, json.Unmarshal(body, &parameters))
				require.NotNil(t, parameters.Properties)
				parameters.Properties.Scope = new(scope)
				assignment := &armauthorization.RoleAssignment{ID: new(request.URL.Path), Properties: parameters.Properties}
				azure.assignments[key] = append(azure.assignments[key], assignment)
				return response(http.StatusCreated, assignment)
			}
			if strings.Contains(request.URL.Path, "/providers/Microsoft.Resources/deployments/") {
				if strings.HasSuffix(request.URL.Path, "/whatIf") {
					require.Equal(t, http.MethodPost, request.Method)
					return response(http.StatusOK, map[string]any{
						"status": "Succeeded", "properties": map[string]any{"changes": []any{}},
					})
				}
				require.Equal(t, http.MethodPut, request.Method)
				return response(http.StatusOK, map[string]any{
					"id": request.URL.Path, "properties": map[string]any{
						"provisioningState": "Succeeded", "outputs": map[string]any{},
					},
				})
			}
			if strings.EqualFold(request.URL.Path, byoTestFoundryRG) {
				switch request.Method {
				case http.MethodGet:
					if azure.resourceGroup == nil {
						return response(http.StatusNotFound, map[string]any{
							"error": map[string]string{
								"code": "ResourceGroupNotFound", "message": "test resource group is absent",
							},
						})
					}
				case http.MethodPut:
					var resourceGroup armresources.ResourceGroup
					require.NoError(t, json.Unmarshal(body, &resourceGroup))
					resourceGroup.ID = new(byoTestFoundryRG)
					resourceGroup.Name = new("foundry")
					azure.resourceGroup = &resourceGroup
				default:
					t.Fatalf("unexpected resource group request: %s %s", request.Method, request.URL.Path)
				}
				return response(http.StatusOK, azure.resourceGroup)
			}
			switch strings.ToLower(request.URL.Path) {
			case strings.ToLower(byoTestCluster):
				require.Equal(t, http.MethodGet, request.Method)
				return response(http.StatusOK, azure.state.cluster)
			case strings.ToLower(byoTestManagement):
				require.Equal(t, http.MethodGet, request.Method)
				return response(http.StatusOK, azure.state.management)
			case strings.ToLower(byoTestWorkload):
				require.Equal(t, http.MethodGet, request.Method)
				return response(http.StatusOK, azure.state.workload)
			case strings.ToLower(byoTestStorage):
				require.Equal(t, http.MethodGet, request.Method)
				return response(http.StatusOK, azure.state.storage)
			case strings.ToLower(byoTestAgentSubnet):
				if request.Method == http.MethodPut {
					var subnet armnetwork.Subnet
					require.NoError(t, json.Unmarshal(body, &subnet))
					require.NotNil(t, subnet.Properties)
					subnet.Properties.ProvisioningState = new(armnetwork.ProvisioningStateSucceeded)
					azure.state.subnet = subnet
				} else {
					require.Equal(t, http.MethodGet, request.Method)
				}
				return response(http.StatusOK, azure.state.subnet)
			default:
				t.Fatalf("unexpected ARM request: %s %s", request.Method, request.URL.Path)
				return nil, nil
			}
		})
	result, err := synthesis.Synthesize(synthesis.Input{
		RawAzureYAML: []byte(byoAKSTestYAML()), ServiceName: "project",
	})
	require.NoError(t, err)
	raw, err := synthesis.ARMTemplate()
	require.NoError(t, err)
	var template map[string]any
	require.NoError(t, json.Unmarshal(raw, &template))
	options := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Transport: azure.transport, Retry: policy.RetryOptions{MaxRetries: -1},
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: "https://127.0.0.1:1", Audience: "https://management.azure.com/"},
		}},
	}}
	options.PerCallPolicies = []policy.Policy{byoAKSTestPipeline{options: options}}
	return &FoundryProvisioningProvider{
		projectPath: t.TempDir(), subID: byoTestSubscription, envName: "test", location: "eastus2", rgName: "foundry",
		rgExplicit: true, synthResult: result, armTemplate: template,
		credential: &byoAKSTestCredential{}, armClientOptions: options,
	}, azure
}

func TestBYOAKSTestCredentialBlocksUnmockedRequests(t *testing.T) {
	for _, missing := range []string{"options", "transport"} {
		t.Run(missing, func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			if missing == "options" {
				provider.armClientOptions = nil
			} else {
				provider.armClientOptions.Transport = nil
			}
			_, err := provider.Deploy(t.Context(), func(string) {})
			require.ErrorContains(t, err, "test credential refused an unmocked ARM pipeline")
			assert.Empty(t, azure.requests)
		})
	}
}

func TestBYOAKSDoesNotDiscloseIssuerURLCredentials(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	azure.state.cluster.Properties.OidcIssuerProfile.IssuerURL =
		new("https://sensitive-user:sensitive-password@issuer.example/?sig=sensitive-signature#sensitive-fragment")
	azure.state.cluster.Properties.AgentPoolProfiles[0].NodeLabels = nil
	var messages []string
	_, err := provider.Deploy(t.Context(), func(message string) { messages = append(messages, message) })
	require.Error(t, err)
	output := strings.Join(messages, "\n") + err.Error()
	for _, sensitive := range []string{"sensitive-user", "sensitive-password", "sensitive-signature", "sensitive-fragment"} {
		assert.NotContains(t, output, sensitive)
	}
	assert.Empty(t, azure.writes())
}

func (azure *byoAKSTestAzure) writes() []byoAKSTestRequest {
	var writes []byoAKSTestRequest
	for _, request := range azure.requests {
		if request.method != http.MethodGet && !strings.HasSuffix(request.path, "/whatIf") {
			writes = append(writes, request)
		}
	}
	return writes
}

func TestBYOAKSDeployPreparesBeforeFoundry(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	before, err := json.Marshal(azure.state.subnet.Properties)
	require.NoError(t, err)
	var messages []string
	result, err := provider.Deploy(t.Context(), func(message string) { messages = append(messages, message) })
	require.NoError(t, err)
	require.NotNil(t, result.Deployment)
	writes := azure.writes()
	require.Len(t, writes, 9, "resource group, six roles, subnet update, then the Foundry deployment")
	require.GreaterOrEqual(t, len(azure.requests), 6)
	for _, request := range azure.requests[:5] {
		assert.Equal(t, http.MethodGet, request.method, "all BYO resource validation reads precede the first write")
	}
	assert.Equal(t, strings.ToLower(byoTestFoundryRG), strings.ToLower(writes[0].path))
	var resourceGroup armresources.ResourceGroup
	require.NoError(t, json.Unmarshal(writes[0].body, &resourceGroup))
	assert.Equal(t, "eastus2", byoAKSString(resourceGroup.Location))
	assert.Equal(t, "test", byoAKSString(resourceGroup.Tags["azd-env-name"]))
	expected := []struct{ role, scope, principal string }{
		{"ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8", byoTestCluster, byoTestManagementID},
		{"b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b", byoTestCluster, byoTestManagementID},
		{"85cb6faf-e071-4c9b-8136-154b5a04f717", byoTestCluster, byoTestManagementID},
		{"acdd72a7-3385-48ef-bd42-f606fba81ae7", byoTestFoundryRG, byoTestManagementID},
		{"7e559ce2-48d7-4b27-9128-fa1b247f1308", byoTestWorkload, byoTestManagementID},
		{"ba92f5b4-2d11-453d-a403-e96b0029c9fe", byoTestStorage, byoTestWorkloadID},
	}
	for i, assignment := range expected {
		assert.True(t, strings.HasPrefix(
			writes[i+1].path, assignment.scope+"/providers/Microsoft.Authorization/roleAssignments/",
		))
		var body armauthorization.RoleAssignmentCreateParameters
		require.NoError(t, json.Unmarshal(writes[i+1].body, &body))
		require.NotNil(t, body.Properties)
		assert.Equal(t, assignment.principal, byoAKSString(body.Properties.PrincipalID))
		assert.Equal(t, "ServicePrincipal", byoAKSString(body.Properties.PrincipalType))
		assert.Equal(t, "/subscriptions/"+byoTestSubscription+"/providers/Microsoft.Authorization/roleDefinitions/"+
			assignment.role, byoAKSString(body.Properties.RoleDefinitionID))
	}
	for _, request := range writes {
		if strings.HasPrefix(request.path, byoTestCluster+"/providers/Microsoft.Authorization/roleAssignments/") {
			assert.NotContains(t, string(request.body), "acdd72a7-3385-48ef-bd42-f606fba81ae7",
				"Reader must not be newly assigned on AKS")
		}
	}
	assert.Equal(t, byoTestAgentSubnet, writes[7].path)
	assert.Contains(t, writes[8].path, "/providers/Microsoft.Resources/deployments/")
	var deployment armresources.Deployment
	require.NoError(t, json.Unmarshal(writes[8].body, &deployment))
	require.NotNil(t, deployment.Properties)
	parameters, ok := deployment.Properties.Parameters.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, map[string]any{"value": false}, parameters["createResourceGroup"],
		"the main deployment must not rewrite an existing resource group's tags")
	var original, updated map[string]any
	require.NoError(t, json.Unmarshal(before, &original))
	var subnet struct {
		Properties map[string]any `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(writes[7].body, &subnet))
	updated = subnet.Properties
	require.Contains(t, updated, "delegations")
	delete(updated, "delegations")
	assert.Equal(t, original, updated, "delegation must be the only changed subnet property")
	assert.NotContains(t, updated, "allowMultipleDelegations")
	output := strings.Join(messages, "\n")
	assert.Contains(t, output, "required Foundry hosting role assignments")
	assert.Contains(t, output, byoTestManagementID)
	assert.Contains(t, output, byoTestWorkloadID)
	assert.Contains(t, output, "may still be propagating")

	azure.requests = nil
	_, err = provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)
	writes = azure.writes()
	require.Len(t, writes, 1, "rerunning must not rewrite existing role assignments or subnet delegation")
	assert.Contains(t, writes[0].path, "/providers/Microsoft.Resources/deployments/")
}

func TestBYOAKSExistingFoundryResourceGroupIsNotUpdated(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	azure.resourceGroup = &armresources.ResourceGroup{
		ID:       new(byoTestFoundryRG),
		Name:     new("foundry"),
		Location: new("westus"),
		Tags:     map[string]*string{"existing": new("preserved")},
	}
	before, err := json.Marshal(azure.resourceGroup)
	require.NoError(t, err)

	_, err = provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)

	for _, request := range azure.writes() {
		assert.False(t, request.method == http.MethodPut && strings.EqualFold(request.path, byoTestFoundryRG),
			"an existing Foundry resource group must not be updated")
	}
	after, err := json.Marshal(azure.resourceGroup)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(after))
}

func TestBYOAKSExistingReaderAssignmentsAreReused(t *testing.T) {
	for _, tt := range []struct {
		name, scope string
	}{
		{"exact scope with manual assignment ID", byoTestFoundryRG},
		{"inherited subscription scope", "/subscriptions/" + byoTestSubscription},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			azure.resourceGroup = &armresources.ResourceGroup{
				ID: new(byoTestFoundryRG), Name: new("foundry"), Location: new("eastus2"),
			}
			reader := &armauthorization.RoleAssignment{
				ID: new(tt.scope + "/providers/Microsoft.Authorization/roleAssignments/manual-reader-guid"),
				Properties: &armauthorization.RoleAssignmentProperties{
					RoleDefinitionID: new("/subscriptions/" + byoTestSubscription +
						"/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"),
					PrincipalID: new(byoTestManagementID),
					Scope:       new(tt.scope),
				},
			}
			azure.assignments[strings.ToLower(byoTestFoundryRG)] = []*armauthorization.RoleAssignment{reader}
			oldAKSReader := &armauthorization.RoleAssignment{
				ID: new(byoTestCluster + "/providers/Microsoft.Authorization/roleAssignments/old-aks-reader"),
				Properties: &armauthorization.RoleAssignmentProperties{
					RoleDefinitionID: new("/subscriptions/" + byoTestSubscription +
						"/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"),
					PrincipalID: new(byoTestManagementID),
					Scope:       new(byoTestCluster),
				},
			}
			azure.assignments[strings.ToLower(byoTestCluster)] = []*armauthorization.RoleAssignment{oldAKSReader}

			_, err := provider.Deploy(t.Context(), func(string) {})
			require.NoError(t, err)

			for _, request := range azure.writes() {
				if !strings.Contains(request.path, "/providers/Microsoft.Authorization/roleAssignments/") {
					continue
				}
				assert.NotContains(t, string(request.body), "acdd72a7-3385-48ef-bd42-f606fba81ae7",
					"equivalent Foundry RG Reader must be reused without creating another Reader")
			}
			assert.Contains(t, azure.assignments[strings.ToLower(byoTestCluster)], oldAKSReader,
				"an existing AKS Reader is customer-owned and must not be removed")
		})
	}
}

func TestBYOAKSFreshDefaultResourceGroupOwnershipSurvivesLaterFailure(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	provider.rgExplicit = false
	env := &resolveEnvStubEnvServer{envName: "test", get: map[string]string{}}
	provider.azdClient = newResolveEnvTestClient(t, env, &resolveEnvStubPromptServer{})
	azure.fail = func(request *http.Request) (int, string) {
		if request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/roleAssignments/") {
			return http.StatusForbidden, "AuthorizationFailed"
		}
		return 0, ""
	}

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.Error(t, err)

	assert.Equal(t, "foundry", env.set[envKeyResourceGroup])
	assert.NotContains(t, env.set, envKeyFoundryRG)
	assert.Equal(t, byoTestFoundryRG, env.set[envKeyFoundryRGOwner])
	assert.True(t, provider.rgExplicit)
	assert.Equal(t, byoTestFoundryRG, provider.foundryRGOwnerID)
	assert.NotNil(t, azure.resourceGroup)
	for _, request := range azure.requests {
		assert.NotContains(t, request.path, "/providers/Microsoft.Resources/deployments/")
	}
}

func TestBYOAKSDeployFailureStopsFoundry(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*byoAKSTestAzure)
		writes int
	}{
		{"missing sandbox label", func(a *byoAKSTestAzure) {
			a.state.cluster.Properties.AgentPoolProfiles[0].NodeLabels = nil
		}, 0},
		{"different pool has the label", func(a *byoAKSTestAzure) {
			a.state.cluster.Properties.AgentPoolProfiles[0].NodeLabels = nil
			a.state.cluster.Properties.AgentPoolProfiles = append(a.state.cluster.Properties.AgentPoolProfiles,
				&armcontainerservice.ManagedClusterAgentPoolProfile{
					NodeLabels: map[string]*string{byoAKSSandboxLabel: new("true")}, VnetSubnetID: new(byoTestNodeSubnet),
				})
		}, 0},
		{"native Kubernetes RBAC", func(a *byoAKSTestAzure) { a.state.cluster.Properties.AADProfile = nil }, 0},
		{"role read denied", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/roleAssignments") {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 1},
		{"resource group create denied", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodPut && strings.EqualFold(r.URL.Path, byoTestFoundryRG) {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 1},
		{"no implicit provider registration during preflight", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.URL.Path == byoTestCluster {
					return http.StatusConflict, "MissingSubscriptionRegistration"
				}
				return 0, ""
			}
		}, 0},
		{"role write denied", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/roleAssignments/") {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 2},
		{"Foundry resource group Reader write denied", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodPut &&
					strings.HasPrefix(r.URL.Path, byoTestFoundryRG+"/providers/Microsoft.Authorization/") {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 5},
		{"unverified role exists conflict is not success", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/roleAssignments/") {
					return http.StatusConflict, "RoleAssignmentExists"
				}
				return 0, ""
			}
		}, 2},
		{"subnet write denied", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodPut && r.URL.Path == byoTestAgentSubnet {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 8},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			tt.change(azure)
			_, err := provider.Deploy(t.Context(), func(string) {})
			require.Error(t, err)
			assert.Contains(t, err.Error(), byoTestCluster)
			assert.Len(t, azure.writes(), tt.writes)
			for _, request := range azure.requests {
				assert.NotContains(t, request.path, "/providers/Microsoft.Resources/deployments/")
			}
		})
	}
}

func TestBYOAKSDeployPreservesFoundryServiceError(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	azure.fail = func(r *http.Request) (int, string) {
		if strings.Contains(r.URL.Path, "/providers/Microsoft.Resources/deployments/") {
			return http.StatusBadRequest, "RoleAssignmentNotYetEffective"
		}
		return 0, ""
	}
	_, err := provider.Deploy(t.Context(), func(string) {})
	require.Error(t, err)
	service, ok := errors.AsType[*azdext.ServiceError](err)
	require.True(t, ok)
	assert.Equal(t, exterrors.OpArmDeploymentCreate+".RoleAssignmentNotYetEffective", service.ErrorCode)
	assert.Len(t, azure.writes(), 9)
	azure.requests, azure.fail = nil, nil
	_, err = provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)
	assert.Len(t, azure.writes(), 1, "completed preparation is retained when the Foundry service rejects the first request")
}

func TestBYOAKSPreviewAndInitializeNeverPrepare(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	_, err := provider.Preview(t.Context(), func(string) {})
	require.NoError(t, err)
	assert.Empty(t, azure.writes())
	require.Len(t, azure.requests, 1)
	assert.True(t, strings.HasSuffix(azure.requests[0].path, "/whatIf"))

	projectPath := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(projectPath, "azure.yaml"), []byte(byoAKSTestYAML()), 0o600))
	provider.azdClient = newValidateTestClient(t,
		&validateStubProjectServer{project: &azdext.ProjectConfig{Path: projectPath}},
		&validateStubEnvServer{envName: "test", get: map[string]string{
			envKeySubscriptionID: byoTestSubscription, envKeyLocation: "eastus2", envKeyResourceGroup: "explicit-foundry",
		}},
	)
	azure.requests = nil
	err = provider.Initialize(t.Context(), projectPath, &azdext.ProvisioningOptions{Provider: FoundryProviderName})
	require.NoError(t, err)
	assert.Empty(t, azure.requests)
	assert.Equal(t, "explicit-foundry", provider.rgName)
}

func TestBYOAKSNonBYODeployHasNoExtraRequests(t *testing.T) {
	for _, absent := range []bool{false, true} {
		t.Run(fmt.Sprint("absent=", absent), func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			provider.synthResult.Parameters["agentHosting"] = byoAKSConfig{}
			if absent {
				delete(provider.synthResult.Parameters, "agentHosting")
			}
			_, err := provider.Deploy(t.Context(), func(string) {})
			require.NoError(t, err)
			require.Len(t, azure.requests, 1)
			assert.Contains(t, azure.requests[0].path, "/providers/Microsoft.Resources/deployments/")
		})
	}
}

func TestBYOAKSEjectRejectedBeforeAnyAzureRequest(t *testing.T) {
	for _, mode := range []templateMode{templateModeBicep, templateModeBicepParam} {
		t.Run(mode.String(), func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			provider.onDiskSource = &templateSource{
				mode: mode, armTemplate: map[string]any{}, parameters: map[string]any{},
			}
			_, err := provider.Deploy(t.Context(), func(string) {})
			require.ErrorContains(t, err, "embedded microsoft.foundry")
			assert.Empty(t, azure.requests,
				"even a user template that drops agentHosting must not silently bypass preparation")
		})
	}
}

func TestBYOAKSRoleEquivalence(t *testing.T) {
	config, state := byoAKSTestConfig(), byoAKSTestSnapshot()
	ids, err := config.resources(byoTestSubscription)
	require.NoError(t, err)
	foundryRG, err := arm.ParseResourceID(byoTestFoundryRG)
	require.NoError(t, err)
	role := byoAKSRoles(ids, state, foundryRG)[5]
	for _, tt := range []struct {
		name, scope, principal, condition string
		equivalent                        bool
	}{
		{"exact resource scope", byoTestStorage, byoTestWorkloadID, "", true},
		{"existing inherited role", byoTestScope, byoTestWorkloadID, "", true},
		{
			"container only is insufficient", byoTestStorage + "/blobServices/default/containers/data",
			byoTestWorkloadID, "", false,
		},
		{"wrong principal", byoTestStorage, byoTestManagementID, "", false},
		{"conditional role is insufficient", byoTestStorage, byoTestWorkloadID, "limited", false},
		{"no scope", "", byoTestWorkloadID, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.equivalent, role.matches([]*armauthorization.RoleAssignment{{
				Properties: &armauthorization.RoleAssignmentProperties{
					RoleDefinitionID: new("/providers/Microsoft.Authorization/roleDefinitions/" + role.definitionID),
					PrincipalID:      new(tt.principal), Scope: new(tt.scope), Condition: new(tt.condition),
				},
			}}))
		})
	}
}
