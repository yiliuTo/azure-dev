// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/stretchr/testify/require"
)

func cleanupObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	require.True(t, ok, "expected fixture object, got %T", value)
	return object
}

type cleanupARM struct {
	base             *preparationARM
	options          *arm.ClientOptions
	lifecycle        Lifecycle
	spec             FoundrySpec
	roots            map[string]map[string]any
	result           armresources.DeploymentExtended
	deletes          []string
	rootReadMissing  bool
	deploymentState  string
	afterMaterialize func()
	operationStates  map[string]string
	submissions      int
}

func newCleanupARM(t *testing.T, suppliedStorage, suppliedRegistry bool, suppliedIdentities ...bool) *cleanupARM {
	t.Helper()
	base, facts := preparationContractFixture(t, suppliedStorage, suppliedRegistry, false, suppliedIdentities...)
	data, err := ResolveDeploymentBindings(t.Context(), contractCredential{}, base.options(), base.plan, facts)
	require.NoError(t, err)
	template := map[string]any{
		"$schema":   "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
		"resources": []any{},
	}
	digest, err := TemplateDigest(template)
	require.NoError(t, err)
	account := PlannedFoundryAccount(base.plan)
	f := &cleanupARM{
		base: base, roots: map[string]map[string]any{},
		spec: FoundrySpec{AccountID: account.ID, ProjectID: account.ID + "/projects/project",
			RegistryID: base.plan.Registry.ID, Location: base.plan.Location,
			TemplateHash:   "offline-standard-template-hash",
			TemplateDigest: digest, Deployment: &data},
	}
	baseOptions := base.options()
	f.options = contractARMOptions(func(request *http.Request) (*http.Response, error) {
		path := strings.ToLower(request.URL.Path)
		respond := func(status int, body any) (*http.Response, error) {
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			return contractARMResponse(request, status, string(raw)), nil
		}
		if !strings.Contains(path, "/providers/microsoft.resources/deployments/") {
			return baseOptions.Transport.Do(request)
		}
		require.NotContains(t, path, "/operations", "provisioning does not walk deployment operations")
		require.NotContains(t, path, "/exporttemplate", "retry does not export deployed templates")
		switch request.Method {
		case http.MethodGet:
			if root, exists := f.roots[path]; exists && !f.rootReadMissing {
				return respond(http.StatusOK, root)
			}
			for name, scope := range map[string]string{
				"byo-federation-access": base.plan.Workload.ID, "byo-storage-access": base.plan.Storage.ID,
			} {
				if !strings.HasSuffix(path, "/"+name) {
					continue
				}
				target, err := arm.ParseResourceID(scope)
				require.NoError(t, err)
				principal, role := data.HostingIdentity.PrincipalID, data.FederatedIdentityRoleDefinitionID
				if name == "byo-storage-access" {
					principal = data.WorkloadIdentity.PrincipalID
					role = "/subscriptions/" + target.SubscriptionID +
						"/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe"
				}
				state := "Succeeded"
				for id, status := range f.operationStates {
					if strings.HasPrefix(id, strings.ToLower(scope)+"/providers/microsoft.authorization/roleassignments/") {
						state = status
					}
				}
				return respond(http.StatusOK, map[string]any{"id": request.URL.Path, "properties": map[string]any{
					"provisioningState": state, "parameters": map[string]any{
						"deploymentId":     map[string]any{"value": base.plan.DeploymentID},
						"resourceName":     map[string]any{"value": target.Name},
						"principalId":      map[string]any{"value": principal},
						"roleDefinitionId": map[string]any{"value": role},
					},
				}})
			}
			return respond(http.StatusNotFound, map[string]any{"error": map[string]any{"code": "DeploymentNotFound"}})
		case http.MethodPut:
			state, err := base.journal.Load(request.Context())
			require.NoError(t, err)
			require.NotNil(t, state.Foundry)
			require.Equal(t, request.URL.Path, state.Foundry.Attempts[len(state.Foundry.Attempts)-1].ID,
				"actual deployment ID must be durable before its PUT")
			var body map[string]any
			require.NoError(t, json.NewDecoder(request.Body).Decode(&body))
			body["id"] = request.URL.Path
			properties := cleanupObject(t, body["properties"])
			f.submissions++
			properties["provisioningState"] = "Succeeded"
			properties["correlationId"] = fmt.Sprintf("correlation-%d", f.submissions)
			properties["templateHash"] = "6828760392490666086"
			if f.deploymentState != "" {
				properties["provisioningState"] = f.deploymentState
			}
			if properties["provisioningState"] == "Succeeded" {
				properties["outputs"] = map[string]any{"FOUNDRY_PROJECT_ENDPOINT": map[string]any{
					"type": "String", "value": "https://" + base.plan.Account.Name + ".services.ai.azure.com/api/projects/project",
				}}
			}
			f.roots[path] = body
			base.materializeGraph(f.spec)
			f.operationStates = nil
			base.resources[strings.ToLower(f.spec.AccountID)] = map[string]any{
				"id": f.spec.AccountID, "location": f.spec.Location,
				"properties": map[string]any{"provisioningState": "Succeeded"},
			}
			base.resources[strings.ToLower(f.spec.ProjectID)] = map[string]any{
				"id": f.spec.ProjectID, "location": f.spec.Location,
				"properties": map[string]any{"provisioningState": "Succeeded"},
				"identity": map[string]any{"type": "SystemAssigned", "tenantId": data.TenantID,
					"principalId": "00000000-0000-0000-0000-000000000004"},
			}
			if f.afterMaterialize != nil {
				f.afterMaterialize()
			}
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &f.result))
			return respond(http.StatusOK, body)
		default:
			t.Fatalf("unexpected deployment method: %s", request.Method)
			return nil, nil
		}
	})
	f.lifecycle = NewLifecycle(contractCredential{}, f.options, base.journal)
	report, err := f.lifecycle.Check(t.Context(), base.plan, f.spec)
	require.NoError(t, err)
	require.NoError(t, report.Err())
	return f
}

func (f *cleanupARM) deploy(t *testing.T) {
	t.Helper()
	require.NoError(t, f.submit(t))
	require.NoError(t, f.lifecycle.Observe(t.Context(), f.base.plan, f.result))
}

func (f *cleanupARM) submit(t *testing.T) error {
	t.Helper()
	client, err := armresources.NewDeploymentsClient(f.base.plan.SubscriptionID, contractCredential{}, f.options)
	require.NoError(t, err)
	id := f.base.plan.DeploymentID
	name := id[strings.LastIndex(id, "/")+1:]
	require.NoError(t, f.lifecycle.Start(t.Context(), f.base.plan, f.spec, id))
	poller, err := client.BeginCreateOrUpdateAtSubscriptionScope(t.Context(), name, armresources.Deployment{
		Location: new(f.spec.Location),
		Properties: &armresources.DeploymentProperties{
			Mode: new(armresources.DeploymentModeIncremental), Template: map[string]any{},
			Parameters: map[string]any{
				"byoOnboarding": map[string]any{"value": map[string]any{
					"deploymentId": f.base.plan.DeploymentID, "accountName": PlannedFoundryAccount(f.base.plan).Name,
					"resourceGroupSupplied": f.spec.Deployment.ResourceGroupSupplied,
					"storageName":           f.base.plan.Storage.Name, "storageSupplied": f.spec.Deployment.StorageSupplied,
					"storageSku": f.spec.Deployment.StorageSKU, "registryName": f.base.plan.Registry.Name,
					"registrySupplied": f.spec.Deployment.RegistrySupplied, "registryABAC": f.spec.Deployment.RegistryABAC,
					"kubeletObjectId":                   f.spec.Deployment.KubeletObjectID,
					"federatedIdentityRoleDefinitionId": f.spec.Deployment.FederatedIdentityRoleDefinitionID,
					"kubeletRoleAssignmentId":           f.spec.Deployment.KubeletRoleAssignmentID,
					"clusterResourceId":                 f.base.plan.Cluster.ID,
					"storageAccountResourceId":          f.base.plan.Storage.ID, "registryResourceId": f.base.plan.Registry.ID,
					"hostingIdentityName": f.base.plan.Hosting.Name, "workloadIdentityName": f.base.plan.Workload.Name,
					"hostingIdentityResourceId":  f.base.plan.Hosting.ID,
					"workloadIdentityResourceId": f.base.plan.Workload.ID,
					"hostingIdentitySupplied":    f.base.plan.Hosting.Supplied,
					"workloadIdentitySupplied":   f.base.plan.Workload.Supplied,
					"hostingPrincipalId":         f.spec.Deployment.HostingIdentity.PrincipalID,
					"workloadPrincipalId":        f.spec.Deployment.WorkloadIdentity.PrincipalID,
					"createClusterGrants":        createsGrant(f.base.plan, "G01"),
					"createFederationGrant":      createsGrant(f.base.plan, "G02"),
					"createStorageGrant":         createsGrant(f.base.plan, "G03"),
				}},
				"resourceGroupName":  map[string]any{"value": f.base.plan.ResourceGroup},
				"location":           map[string]any{"value": f.spec.Location},
				"foundryProjectName": map[string]any{"value": "project"},
			},
		},
	}, nil)
	if err != nil {
		return err
	}
	_, err = poller.PollUntilDone(t.Context(), nil)
	return err
}
