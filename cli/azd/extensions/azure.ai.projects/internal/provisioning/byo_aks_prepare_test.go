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
	state       *byoAKSSnapshot
	requests    []byoAKSTestRequest
	assignments map[string][]*armauthorization.RoleAssignment
	fail        func(*http.Request) (int, string)
	transport   *mockhttp.MockHttpClient
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

func newBYOAKSTestProvider(
	t *testing.T, states ...*byoAKSSnapshot,
) (*FoundryProvisioningProvider, *byoAKSTestAzure) {
	t.Helper()
	state := byoAKSTestSnapshot()
	if len(states) > 0 {
		state = states[0]
	}
	azure := &byoAKSTestAzure{
		state: state, assignments: map[string][]*armauthorization.RoleAssignment{},
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
			poolsPath := byoTestCluster + "/agentPools"
			if strings.EqualFold(request.URL.Path, poolsPath) {
				require.Equal(t, http.MethodGet, request.Method)
				result := armcontainerservice.AgentPoolListResult{}
				for _, pool := range azure.state.agentPools {
					result.Value = append(result.Value, &armcontainerservice.AgentPool{
						Name: new(pool.name), Properties: pool.properties,
					})
				}
				return response(http.StatusOK, result)
			}
			if strings.HasPrefix(strings.ToLower(request.URL.Path), strings.ToLower(poolsPath+"/")) {
				require.Equal(t, http.MethodGet, request.Method)
				name := request.URL.Path[len(poolsPath)+1:]
				for _, pool := range azure.state.agentPools {
					if strings.EqualFold(pool.name, name) {
						properties, err := json.Marshal(pool.properties)
						require.NoError(t, err)
						var rawProperties map[string]any
						require.NoError(t, json.Unmarshal(properties, &rawProperties))
						rawProperties["securityProfile"] = map[string]any{"sshAccess": pool.sshAccess}
						return response(http.StatusOK, armresources.GenericResource{
							ID:         new(request.URL.Path),
							Properties: rawProperties,
						})
					}
				}
				return response(http.StatusNotFound, map[string]any{
					"error": map[string]string{"code": "NotFound", "message": "test pool not found"},
				})
			}
			pathKey := byoAKSNetworkKey(request.URL.Path)
			if subnet, exists := azure.state.network.subnets[pathKey]; exists {
				if request.Method == http.MethodPut {
					require.True(t, strings.EqualFold(request.URL.Path, byoTestAgentSubnet))
					require.NoError(t, json.Unmarshal(body, &subnet))
					require.NotNil(t, subnet.Properties)
					subnet.Properties.ProvisioningState = new(armnetwork.ProvisioningStateSucceeded)
					azure.state.subnet = subnet
					azure.state.network.subnets[pathKey] = subnet
				} else {
					require.Equal(t, http.MethodGet, request.Method)
				}
				return response(http.StatusOK, subnet)
			}
			if vnet, exists := azure.state.network.virtualNetworks[pathKey]; exists {
				require.Equal(t, http.MethodGet, request.Method)
				return response(http.StatusOK, vnet)
			}
			if table, exists := azure.state.network.routeTables[pathKey]; exists {
				require.Equal(t, http.MethodGet, request.Method)
				return response(http.StatusOK, table)
			}
			if group, exists := azure.state.network.securityGroups[pathKey]; exists {
				require.Equal(t, http.MethodGet, request.Method)
				return response(http.StatusOK, group)
			}
			if endpoint, exists := azure.state.network.privateEndpoints[pathKey]; exists {
				require.Equal(t, http.MethodGet, request.Method)
				return response(http.StatusOK, endpoint.resource)
			}
			for vnetID, peerings := range azure.state.network.peerings {
				if strings.EqualFold(request.URL.Path, vnetID+"/virtualNetworkPeerings") {
					require.Equal(t, http.MethodGet, request.Method)
					return response(http.StatusOK, armnetwork.VirtualNetworkPeeringListResult{Value: peerings})
				}
			}
			for endpointID, endpoint := range azure.state.network.privateEndpoints {
				if strings.EqualFold(request.URL.Path, endpointID+"/privateDnsZoneGroups") {
					require.Equal(t, http.MethodGet, request.Method)
					return response(http.StatusOK, armnetwork.PrivateDNSZoneGroupListResult{
						Value: endpoint.dnsZoneGroups,
					})
				}
			}
			for _, links := range azure.state.network.privateDNSZoneLinks {
				for _, link := range links {
					if strings.EqualFold(request.URL.Path, link.id) {
						require.Equal(t, http.MethodGet, request.Method)
						return response(http.StatusOK, armresources.GenericResource{
							ID: new(link.id),
							Properties: map[string]any{
								"virtualNetwork":          map[string]any{"id": link.virtualNetworkID},
								"provisioningState":       link.provisioningState,
								"virtualNetworkLinkState": link.linkState,
							},
						})
					}
				}
			}
			if strings.HasSuffix(strings.ToLower(request.URL.Path), "/resources") &&
				strings.EqualFold(
					request.URL.Query().Get("$filter"),
					"resourceType eq 'Microsoft.Network/privateDnsZones/virtualNetworkLinks'",
				) {
				require.Equal(t, http.MethodGet, request.Method)
				var values []*armresources.GenericResourceExpanded
				for _, links := range azure.state.network.privateDNSZoneLinks {
					for _, link := range links {
						values = append(values, &armresources.GenericResourceExpanded{
							ID: new(link.id),
							Properties: map[string]any{
								"virtualNetwork":          map[string]any{"id": link.virtualNetworkID},
								"provisioningState":       link.provisioningState,
								"virtualNetworkLinkState": link.linkState,
							},
						})
					}
				}
				return response(http.StatusOK, armresources.ResourceListResult{Value: values})
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
	azure.state.agentPools[0].properties.NodeLabels = nil
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
	require.Len(t, writes, 6, "four roles, subnet update, then the Foundry deployment")
	firstWrite := len(azure.requests) - len(writes)
	require.Greater(t, firstWrite, 0)
	for _, request := range azure.requests[:firstWrite] {
		assert.Equal(t, http.MethodGet, request.method, "all prerequisite reads must precede the first write")
	}
	expected := []struct{ role, scope, principal string }{
		{"acdd72a7-3385-48ef-bd42-f606fba81ae7", byoTestCluster, byoTestManagementID},
		{"85cb6faf-e071-4c9b-8136-154b5a04f717", byoTestCluster, byoTestManagementID},
		{"7e559ce2-48d7-4b27-9128-fa1b247f1308", byoTestWorkload, byoTestManagementID},
		{"ba92f5b4-2d11-453d-a403-e96b0029c9fe", byoTestStorage, byoTestWorkloadID},
	}
	for i, assignment := range expected {
		assert.True(t, strings.HasPrefix(
			writes[i].path, assignment.scope+"/providers/Microsoft.Authorization/roleAssignments/",
		))
		var body armauthorization.RoleAssignmentCreateParameters
		require.NoError(t, json.Unmarshal(writes[i].body, &body))
		require.NotNil(t, body.Properties)
		assert.Equal(t, assignment.principal, byoAKSString(body.Properties.PrincipalID))
		assert.Equal(t, "ServicePrincipal", byoAKSString(body.Properties.PrincipalType))
		assert.Equal(t, "/subscriptions/"+byoTestSubscription+"/providers/Microsoft.Authorization/roleDefinitions/"+
			assignment.role, byoAKSString(body.Properties.RoleDefinitionID))
	}
	for _, obsolete := range []string{
		"ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8",
		"b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b",
	} {
		for _, request := range writes {
			assert.NotContains(t, string(request.body), obsolete)
		}
	}
	for _, request := range azure.requests {
		assert.False(t, strings.HasPrefix(
			strings.ToLower(request.path),
			strings.ToLower(byoTestFoundryRG+"/providers/Microsoft.Authorization/roleAssignments"),
		), "Foundry resource-group Reader must not be checked or created")
	}
	for _, request := range azure.requests {
		path := strings.ToLower(request.path)
		assert.NotContains(t, path, "/privateendpoints",
			"public Storage access must not require private endpoint reads")
		assert.NotContains(t, path, "/privatednszonegroups",
			"public Storage access must not require private DNS zone-group reads")
	}
	assert.Equal(t, byoTestAgentSubnet, writes[4].path)
	assert.Contains(t, writes[5].path, "/providers/Microsoft.Resources/deployments/")
	var deployment armresources.Deployment
	require.NoError(t, json.Unmarshal(writes[5].body, &deployment))
	require.NotNil(t, deployment.Properties)
	parameters, ok := deployment.Properties.Parameters.(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, parameters, "createResourceGroup",
		"the main Foundry deployment must retain responsibility for resource-group provisioning")
	var original, updated map[string]any
	require.NoError(t, json.Unmarshal(before, &original))
	var subnet struct {
		Properties map[string]any `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(writes[4].body, &subnet))
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
	assert.Contains(t, output, "private trusted roots are validated later")
	assert.NotContains(t, output, "private trusted roots passed")

	azure.requests = nil
	_, err = provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)
	writes = azure.writes()
	require.Len(t, writes, 1, "rerunning must not rewrite existing role assignments or subnet delegation")
	assert.Contains(t, writes[0].path, "/providers/Microsoft.Resources/deployments/")
}

func TestBYOAKSDeployReadsCrossVNetPrerequisites(t *testing.T) {
	snapshot := byoAKSTestSnapshot()
	aksVNet, _ := configureBYOAKSCrossVNet(snapshot)
	provider, azure := newBYOAKSTestProvider(t, snapshot)

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)

	requests := make([]string, 0, len(azure.requests))
	for _, request := range azure.requests {
		requests = append(requests, strings.ToLower(request.path))
	}
	allRequests := strings.Join(requests, "\n")
	assert.Contains(t, allRequests, strings.ToLower(byoTestVNet+"/virtualNetworkPeerings"))
	assert.Contains(t, allRequests, strings.ToLower(aksVNet+"/virtualNetworkPeerings"))
}

func TestBYOAKSDeployReadsRestrictedStoragePrivateLinkPrerequisites(t *testing.T) {
	snapshot := byoAKSTestSnapshot()
	privateEndpointID, _ := configureBYOAKSStoragePrivateEndpoint(snapshot)
	snapshot.storage.Properties = map[string]any{
		"publicNetworkAccess": "Disabled",
		"networkAcls":         map[string]any{"defaultAction": "Deny"},
		"primaryEndpoints":    map[string]any{"blob": "https://storage.blob.core.windows.net/"},
		"privateEndpointConnections": []any{
			map[string]any{
				"properties": map[string]any{
					"privateEndpoint": map[string]any{"id": privateEndpointID},
					"privateLinkServiceConnectionState": map[string]any{
						"status": "Approved",
					},
					"groupIds": []any{"blob"},
				},
			},
		},
	}
	provider, azure := newBYOAKSTestProvider(t, snapshot)

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)

	requests := make([]string, 0, len(azure.requests))
	for _, request := range azure.requests {
		requests = append(requests, strings.ToLower(request.path))
	}
	allRequests := strings.Join(requests, "\n")
	assert.Contains(t, allRequests, strings.ToLower(privateEndpointID))
	assert.Contains(t, allRequests, strings.ToLower(privateEndpointID+"/privateDnsZoneGroups"))
	assert.Contains(t, allRequests, strings.ToLower(byoTestScope+"/resources"))
}

func TestBYOAKSDeployRestrictedStorageServiceEndpointsSkipPrivateLinkReads(t *testing.T) {
	snapshot := byoAKSTestSnapshot()
	configureBYOAKSStorageServiceEndpoint(snapshot)
	var rules []any
	for _, rule := range snapshot.network.storage.virtualNetworkRules {
		rules = append(rules, map[string]any{"id": rule.id, "state": rule.state})
	}
	snapshot.storage.Properties = map[string]any{
		"publicNetworkAccess": "Enabled",
		"networkAcls": map[string]any{
			"defaultAction":       "Deny",
			"virtualNetworkRules": rules,
		},
		"primaryEndpoints": map[string]any{"blob": "https://storage.blob.core.windows.net/"},
	}
	provider, azure := newBYOAKSTestProvider(t, snapshot)

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)

	for _, request := range azure.requests {
		path := strings.ToLower(request.path)
		assert.NotContains(t, path, "/privateendpoints")
		assert.NotContains(t, path, "/privatednszonegroups")
	}
}

func TestBYOAKSExistingAKSReaderAssignmentsAreReused(t *testing.T) {
	for _, tt := range []struct {
		name, scope string
	}{
		{"exact scope with manual assignment ID", byoTestCluster},
		{"inherited subscription scope", "/subscriptions/" + byoTestSubscription},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			reader := &armauthorization.RoleAssignment{
				ID: new(tt.scope + "/providers/Microsoft.Authorization/roleAssignments/manual-reader-guid"),
				Properties: &armauthorization.RoleAssignmentProperties{
					RoleDefinitionID: new("/subscriptions/" + byoTestSubscription +
						"/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"),
					PrincipalID: new(byoTestManagementID),
					Scope:       new(tt.scope),
				},
			}
			azure.assignments[strings.ToLower(byoTestCluster)] = []*armauthorization.RoleAssignment{reader}

			_, err := provider.Deploy(t.Context(), func(string) {})
			require.NoError(t, err)

			for _, request := range azure.writes() {
				if !strings.Contains(request.path, "/providers/Microsoft.Authorization/roleAssignments/") {
					continue
				}
				assert.NotContains(t, string(request.body), "acdd72a7-3385-48ef-bd42-f606fba81ae7",
					"equivalent AKS Reader must be reused without creating another Reader")
			}
			assert.Contains(t, azure.assignments[strings.ToLower(byoTestCluster)], reader)
		})
	}
}

func TestBYOAKSObsoleteAssignmentsAreNotRemoved(t *testing.T) {
	provider, azure := newBYOAKSTestProvider(t)
	obsolete := []*armauthorization.RoleAssignment{}
	for _, role := range []string{
		"ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8",
		"b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b",
	} {
		obsolete = append(obsolete, &armauthorization.RoleAssignment{
			ID: new(byoTestCluster + "/providers/Microsoft.Authorization/roleAssignments/" + role),
			Properties: &armauthorization.RoleAssignmentProperties{
				RoleDefinitionID: new("/subscriptions/" + byoTestSubscription +
					"/providers/Microsoft.Authorization/roleDefinitions/" + role),
				PrincipalID: new(byoTestManagementID),
				Scope:       new(byoTestCluster),
			},
		})
	}
	foundryReader := &armauthorization.RoleAssignment{
		ID: new(byoTestFoundryRG + "/providers/Microsoft.Authorization/roleAssignments/legacy-reader"),
		Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: new("/subscriptions/" + byoTestSubscription +
				"/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"),
			PrincipalID: new(byoTestManagementID),
			Scope:       new(byoTestFoundryRG),
		},
	}
	azure.assignments[strings.ToLower(byoTestCluster)] = obsolete
	azure.assignments[strings.ToLower(byoTestFoundryRG)] = []*armauthorization.RoleAssignment{foundryReader}

	_, err := provider.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)
	assert.Subset(t, azure.assignments[strings.ToLower(byoTestCluster)], obsolete)
	assert.Equal(t, []*armauthorization.RoleAssignment{foundryReader},
		azure.assignments[strings.ToLower(byoTestFoundryRG)])
}

func TestBYOAKSDeployFailureStopsFoundry(t *testing.T) {
	for _, tt := range []struct {
		name               string
		change             func(*byoAKSTestAzure)
		writes             int
		suggestionContains []string
	}{
		{"missing sandbox label", func(a *byoAKSTestAzure) {
			a.state.agentPools[0].properties.NodeLabels = nil
		}, 0, nil},
		{"different pool has the label", func(a *byoAKSTestAzure) {
			a.state.agentPools[0].properties.NodeLabels = nil
			a.state.agentPools = append(a.state.agentPools, &byoAKSAgentPool{
				name: "wrong", sshAccess: "Disabled",
				properties: &armcontainerservice.ManagedClusterAgentPoolProfileProperties{
					Mode:         new(armcontainerservice.AgentPoolModeUser),
					OSType:       new(armcontainerservice.OSTypeLinux),
					OSSKU:        new(armcontainerservice.OSSKUAzureLinux),
					NodeLabels:   map[string]*string{byoAKSSandboxLabel: new("true")},
					VnetSubnetID: new(byoTestNodeSubnet), Count: new(int32(1)),
					VMSize: new("Standard_D4s_v3"), NodeImageVersion: new(byoAKSMinimumNodeImage),
					ProvisioningState: new("Succeeded"),
				},
			})
		}, 0, nil},
		{"role read denied", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/roleAssignments") {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 0, []string{
			"AKS cluster", "hosting and workload identities", "storage account", "agent subnet",
			"role assignments at the AKS cluster, workload identity, and storage account scopes",
		}},
		{"no implicit provider registration during preflight", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.URL.Path == byoTestCluster {
					return http.StatusConflict, "MissingSubscriptionRegistration"
				}
				return 0, ""
			}
		}, 0, nil},
		{"AgentPool list denied", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if strings.EqualFold(r.URL.Path, byoTestCluster+"/agentPools") {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 0, nil},
		{"AgentPool direct GET failed", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if strings.HasSuffix(strings.ToLower(r.URL.Path), "/agentpools/kata") {
					return http.StatusInternalServerError, "ServiceError"
				}
				return 0, ""
			}
		}, 0, nil},
		{"node subnet direct GET failed", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if strings.EqualFold(r.URL.Path, byoTestNodeSubnet) {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 0, nil},
		{"pod subnet direct GET failed", func(a *byoAKSTestAzure) {
			podSubnetID := byoTestVNet + "/subnets/pods"
			a.state.cluster.Properties.NetworkProfile.NetworkPluginMode = nil
			a.state.agentPools[0].properties.PodSubnetID = new(podSubnetID)
			a.state.network.subnets[byoAKSNetworkKey(podSubnetID)] = armnetwork.Subnet{
				ID: new(podSubnetID), Name: new("pods"),
				Properties: &armnetwork.SubnetPropertiesFormat{AddressPrefix: new("10.20.3.0/24")},
			}
			a.fail = func(r *http.Request) (int, string) {
				if strings.EqualFold(r.URL.Path, podSubnetID) {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 0, nil},
		{"role write denied", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/roleAssignments/") {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 1, []string{
			"roleAssignments read/write at the AKS cluster, workload identity, and storage account scopes",
			"write access to the agent subnet",
		}},
		{"unverified role exists conflict is not success", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/roleAssignments/") {
					return http.StatusConflict, "RoleAssignmentExists"
				}
				return 0, ""
			}
		}, 1, nil},
		{"subnet write denied", func(a *byoAKSTestAzure) {
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodPut && r.URL.Path == byoTestAgentSubnet {
					return http.StatusForbidden, "AuthorizationFailed"
				}
				return 0, ""
			}
		}, 5, []string{
			"roleAssignments read/write at the AKS cluster, workload identity, and storage account scopes",
			"write access to the agent subnet",
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			provider, azure := newBYOAKSTestProvider(t)
			tt.change(azure)
			_, err := provider.Deploy(t.Context(), func(string) {})
			require.Error(t, err)
			assert.Contains(t, err.Error(), byoTestCluster)
			if len(tt.suggestionContains) > 0 {
				service, ok := errors.AsType[*azdext.ServiceError](err)
				require.True(t, ok)
				assert.NotContains(t, service.Suggestion, "Foundry resource group")
				for _, expected := range tt.suggestionContains {
					assert.Contains(t, service.Suggestion, expected)
				}
			}

			assert.Len(t, azure.writes(), tt.writes)
			for _, request := range azure.requests {
				assert.NotContains(t, request.path, "/providers/Microsoft.Resources/deployments/")
			}
		})
	}
}

func TestBYOAKSAuthorizationBranches(t *testing.T) {
	t.Run("managed Entra Azure RBAC plans cluster admin idempotently", func(t *testing.T) {
		provider, azure := newBYOAKSTestProvider(t)
		azure.state.cluster.Properties.AADProfile = &armcontainerservice.ManagedClusterAADProfile{
			Managed: new(true), EnableAzureRBAC: new(true),
		}
		_, err := provider.Deploy(t.Context(), func(string) {})
		require.NoError(t, err)
		var clusterAdminWrites int
		for _, request := range azure.writes() {
			if strings.Contains(string(request.body), byoAKSClusterAdminRoleID) {
				clusterAdminWrites++
			}
		}
		assert.Equal(t, 1, clusterAdminWrites)

		azure.requests = nil
		_, err = provider.Deploy(t.Context(), func(string) {})
		require.NoError(t, err)
		for _, request := range azure.writes() {
			assert.NotContains(t, string(request.body), byoAKSClusterAdminRoleID)
		}
	})

	t.Run("managed Entra native RBAC is checked before writes", func(t *testing.T) {
		provider, azure := newBYOAKSTestProvider(t)
		azure.state.cluster.Properties.AADProfile = &armcontainerservice.ManagedClusterAADProfile{
			Managed: new(true), EnableAzureRBAC: new(false),
		}
		called := false
		provider.byoAKSNativeRBACCheck = func(
			_ context.Context, _ *byoAKSResources, principalID string, _ *arm.ClientOptions,
		) error {
			called = true
			assert.Equal(t, byoTestManagementID, principalID)
			assert.Empty(t, azure.writes())
			return nil
		}
		_, err := provider.Deploy(t.Context(), func(string) {})
		require.NoError(t, err)
		assert.True(t, called)
		for _, request := range azure.writes() {
			assert.NotContains(t, string(request.body), byoAKSClusterAdminRoleID)
		}
	})

	t.Run("native RBAC failure causes zero writes", func(t *testing.T) {
		provider, azure := newBYOAKSTestProvider(t)
		azure.state.cluster.Properties.AADProfile = &armcontainerservice.ManagedClusterAADProfile{
			Managed: new(true), EnableAzureRBAC: new(false),
		}
		provider.byoAKSNativeRBACCheck = func(
			context.Context, *byoAKSResources, string, *arm.ClientOptions,
		) error {
			return errors.New("native Kubernetes RBAC test failure")
		}
		_, err := provider.Deploy(t.Context(), func(string) {})
		require.ErrorContains(t, err, "native Kubernetes RBAC test failure")
		assert.Empty(t, azure.writes())
	})
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
	assert.Len(t, azure.writes(), 6)
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
	role := byoAKSRoles(ids, state, byoAKSAuthorizationNonEntra)[3]
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
