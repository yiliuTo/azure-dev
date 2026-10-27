// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStableRootArchivesEachVerifiedGenerationAndRecoversMissingLocalObservation(t *testing.T) {
	f := newCleanupARM(t, false, false)
	f.deploymentState = "Failed"
	f.afterMaterialize = func() { deleteProgressGrant(t, f, f.base.plan.Storage.ID) }
	require.Error(t, f.submit(t))
	require.NoError(t, f.lifecycle.Observe(t.Context(), f.base.plan))
	first, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	require.False(t, first.ResourceProgress["storageAccount"].PreparationComplete)
	original, err := json.Marshal(first.Foundry.Attempts[0].Evidence)
	require.NoError(t, err)

	f.deploymentState, f.afterMaterialize = "Succeeded", nil
	require.NoError(t, f.submit(t))
	pending, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	require.Len(t, pending.Foundry.Attempts, 2)
	assert.True(t, pending.Foundry.Attempts[0].Archived)
	assert.Equal(t, f.base.plan.DeploymentID, pending.Foundry.Attempts[0].ID)
	assert.Equal(t, pending.Foundry.Attempts[0].ID, pending.Foundry.Attempts[1].ID)
	assert.Empty(t, pending.Foundry.Attempts[1].CorrelationID, "cloud completion precedes local observation")
	assert.Len(t, f.roots, 1, "the provider submits the unchanged stable root, not a random attempt name")
	assert.Equal(t, first.ResourceProgress, pending.ResourceProgress, "Start never resets resource preparation wholesale")
	archived, err := json.Marshal(pending.Foundry.Attempts[0].Evidence)
	require.NoError(t, err)
	assert.Equal(t, original, archived)

	require.NoError(t, f.lifecycle.Observe(t.Context(), f.base.plan))
	recovered, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	assert.NotEqual(t, recovered.Foundry.Attempts[0].CorrelationID, recovered.Foundry.Attempts[1].CorrelationID)
	for key, progress := range recovered.ResourceProgress {
		assert.True(t, progress.PreparationComplete, key)
	}
	require.NoError(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, false, nil))
}

func TestStableRootPendingIntentCannotReusePreviousGeneration(t *testing.T) {
	f := newCleanupARM(t, false, false)
	f.deploy(t)
	require.NoError(t, f.lifecycle.Start(t.Context(), f.base.plan, f.spec, f.base.plan.DeploymentID))
	before := append([]byte(nil), f.base.journal.data...)
	require.ErrorContains(t, f.lifecycle.Observe(t.Context(), f.base.plan), "correlation")
	require.Error(t, f.lifecycle.Start(t.Context(), f.base.plan, f.spec, f.base.plan.DeploymentID))
	require.Error(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, false, nil))
	assert.Empty(t, f.deletes)
	state, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	assert.Empty(t, state.Foundry.Attempts[1].CorrelationID)
	assert.NotEmpty(t, before)
}

func TestStableRootRefusesUnverifiedOldAttemptBeforeReplacement(t *testing.T) {
	for _, scenario := range []string{"active", "unknown", "changed template", "changed parameters", "changed correlation"} {
		t.Run(scenario, func(t *testing.T) {
			f := newCleanupARM(t, false, false)
			f.deploy(t)
			root := cleanupObject(t, f.roots[strings.ToLower(f.base.plan.DeploymentID)]["properties"])
			switch scenario {
			case "active":
				root["provisioningState"] = "Running"
			case "unknown":
				f.rootReadMissing = true
			case "changed template":
				root["template"] = map[string]any{"resources": []any{"foreign"}}
			case "changed parameters":
				cleanupObject(t, root["parameters"])["location"] = map[string]any{"value": "elsewhere"}
			case "changed correlation":
				root["correlationId"] = "foreign-generation"
			}
			before := append([]byte(nil), f.base.journal.data...)
			require.Error(t, f.lifecycle.Start(t.Context(), f.base.plan, f.spec, f.base.plan.DeploymentID))
			assert.Equal(t, before, f.base.journal.data)
			assert.Empty(t, f.deletes)
		})
	}
}

func TestArchivedGenerationRequiresIntactExactScopeEvidence(t *testing.T) {
	for _, scenario := range []string{"missing snapshot", "changed digest", "foreign scope", "different environment"} {
		t.Run(scenario, func(t *testing.T) {
			f := newCleanupARM(t, false, false)
			f.deploy(t)
			require.NoError(t, f.submit(t))
			require.NoError(t, f.lifecycle.Observe(t.Context(), f.base.plan))
			state, err := f.base.journal.Load(t.Context())
			require.NoError(t, err)
			attempt := &state.Foundry.Attempts[0]
			switch scenario {
			case "missing snapshot":
				attempt.Evidence = nil
			case "changed digest":
				attempt.Evidence.Digest = "changed"
			case "foreign scope":
				raw, err := json.Marshal(attempt.Evidence.Properties.Parameters)
				require.NoError(t, err)
				var parameters map[string]any
				require.NoError(t, json.Unmarshal(raw, &parameters))
				parameters["resourceGroupName"] = map[string]any{"value": "foreign-rg"}
				attempt.Evidence.Properties.Parameters = parameters
				attempt.Evidence.Digest, err = evidenceDigest(*attempt.Evidence)
				require.NoError(t, err)
			case "different environment":
				state.Environment = "other-environment"
			}
			require.NoError(t, f.base.journal.Save(t.Context(), state))
			require.Error(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, false, nil))
			assert.Empty(t, f.deletes)
		})
	}
}

func TestResourceSourceAndActualBirthAreRequiredBeforeAnyCleanup(t *testing.T) {
	for _, target := range []string{"storage", "registry", "hosting", "workload", "account", "project", "model"} {
		for _, scenario := range []string{"recreated", "missing creation", "missing source", "not initially absent"} {
			t.Run(target+"/"+scenario, func(t *testing.T) {
				f := newCleanupARM(t, false, false)
				f.deploy(t)
				id := map[string]string{
					"storage": f.base.plan.Storage.ID, "registry": f.base.plan.Registry.ID,
					"hosting": f.base.plan.Hosting.ID, "workload": f.base.plan.Workload.ID,
					"account": f.spec.AccountID, "project": f.spec.ProjectID,
					"model": f.spec.AccountID + "/deployments/" + f.spec.ModelNames[0],
				}[target]
				key := strings.ToLower(id)
				actual := f.base.resources[key]
				actual["tags"] = map[string]any{"azd-env-name": f.base.plan.Environment}
				state, err := f.base.journal.Load(t.Context())
				require.NoError(t, err)
				switch scenario {
				case "recreated":
					actual["createdTime"] = "2026-10-27T00:50:00Z"
				case "missing creation":
					delete(actual, "createdTime")
				case "missing source":
					delete(state.Sources, key)
				case "not initially absent":
					source := state.Sources[key]
					source.InitiallyAbsent = false
					state.Sources[key] = source
				}
				require.NoError(t, f.base.journal.Save(t.Context(), state))
				require.Error(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, false, nil))
				assert.Empty(t, f.deletes, "matching environment tags are not creation or ownership evidence")
			})
		}
	}
}

func TestBirthOutsideVerifiedCreateWindowCannotBeAdopted(t *testing.T) {
	f := newCleanupARM(t, false, false)
	require.NoError(t, f.submit(t))
	f.base.resources[strings.ToLower(f.base.plan.Storage.ID)]["createdTime"] = "2025-01-01T00:00:00Z"
	require.ErrorContains(t, f.lifecycle.Observe(t.Context(), f.base.plan), "creation-window")
	require.Error(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, false, nil))
	assert.Empty(t, f.deletes)
}

func TestGrantCreationAndCurrentExactIdentityAreRequiredBeforeAnyDelete(t *testing.T) {
	for _, field := range []string{"createdOn", "principalId", "roleDefinitionId", "scope", "description"} {
		t.Run(field, func(t *testing.T) {
			f := newCleanupARM(t, false, false)
			f.deploy(t)
			state, err := f.base.journal.Load(t.Context())
			require.NoError(t, err)
			var id string
			for _, assignment := range state.Assignments {
				id = assignment.ID
				break
			}
			require.NotEmpty(t, id)
			properties := cleanupObject(t, f.base.resources[strings.ToLower(id)]["properties"])
			properties[field] = "changed"
			if field == "createdOn" {
				properties[field] = "2026-10-27T00:50:00Z"
			}
			require.Error(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, false, nil))
			assert.Empty(t, f.deletes, "all grant sources are validated before cascading resource teardown")
		})
	}
}

func TestCurrentGrantWithoutCreationProofIsNeverClaimed(t *testing.T) {
	f := newCleanupARM(t, false, true)
	require.NoError(t, f.submit(t))
	var customerID string
	for _, id := range f.operationTargets {
		properties := cleanupObject(t, f.base.resources[strings.ToLower(id)]["properties"])
		if properties["principalId"] == f.spec.Deployment.KubeletObjectID {
			customerID = id
			properties["createdOn"] = "2025-01-01T00:00:00Z"
			break
		}
	}
	require.NotEmpty(t, customerID)
	require.ErrorContains(t, f.lifecycle.Observe(t.Context(), f.base.plan), "creation-window")
	state, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	assert.NotContains(t, state.Assignments, strings.ToLower(customerID))
	assert.Empty(t, f.deletes)
}

func TestFoundryChildSystemDataProvesBirthWhenGenericInventoryOmitsIt(t *testing.T) {
	f := newCleanupARM(t, false, false)
	require.NoError(t, f.submit(t))
	project := f.base.resources[strings.ToLower(f.spec.ProjectID)]
	project["systemData"] = map[string]any{"createdAt": "2026-10-26T00:50:00Z"}
	transport := f.options.Transport
	options := contractARMOptions(func(request *http.Request) (*http.Response, error) {
		if strings.HasSuffix(strings.ToLower(request.URL.Path), "/resources") {
			var resources []any
			for id, resource := range f.base.resources {
				if !strings.EqualFold(id, f.spec.ProjectID) {
					resources = append(resources, resource)
				}
			}
			raw, err := json.Marshal(map[string]any{"value": resources})
			require.NoError(t, err)
			return contractARMResponse(request, 200, string(raw)), nil
		}
		return transport.Do(request)
	})
	lifecycle := NewLifecycle(contractCredential{}, options, f.base.journal)
	require.NoError(t, lifecycle.Observe(t.Context(), f.base.plan))
	state, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	assert.False(t, state.Sources[strings.ToLower(f.spec.ProjectID)].CreatedTime.IsZero())
	require.NoError(t, lifecycle.Cleanup(t.Context(), f.base.plan, false, nil))
}

func TestEveryEffectiveGraphParameterMustMatchTheRecordedIntent(t *testing.T) {
	for _, field := range []string{
		"storageName", "registryName", "storageSupplied", "registrySupplied", "resourceGroupSupplied", "storageSku",
		"kubeletObjectId", "federatedIdentityRoleDefinitionId", "kubeletRoleAssignmentId", "createStorageGrant",
		"missing explicit false", "unsupported field",
	} {
		t.Run(field, func(t *testing.T) {
			f := newCleanupARM(t, false, false)
			require.NoError(t, f.submit(t))
			root := cleanupObject(t, f.roots[strings.ToLower(f.base.plan.DeploymentID)]["properties"])
			parameters := cleanupObject(t, root["parameters"])
			binding := cleanupObject(t, cleanupObject(t, parameters["byoOnboarding"])["value"])
			switch field {
			case "missing explicit false":
				delete(binding, "hostingIdentitySupplied")
			case "unsupported field":
				binding["unsupported"] = "value"
			default:
				if value, ok := binding[field].(bool); ok {
					binding[field] = !value
				} else {
					binding[field] = "foreign"
				}
			}
			require.Error(t, f.lifecycle.Observe(t.Context(), f.base.plan))
			require.Error(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, false, nil))
			assert.Empty(t, f.deletes)
		})
	}
}

func TestFreshAbsentResourceGroupCanRecordSourcesWithoutCreatingItSeparately(t *testing.T) {
	f := newCleanupARM(t, false, false)
	group := "/subscriptions/" + f.base.plan.SubscriptionID + "/resourceGroups/" + f.base.plan.ResourceGroup
	delete(f.base.resources, strings.ToLower(group))
	f.base.plan.ResourceGroupSupplied, f.spec.Deployment.ResourceGroupSupplied = false, false
	transport := f.options.Transport
	f.options.Transport = contractARMOptions(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet && f.base.resources[strings.ToLower(group)] == nil &&
			(strings.EqualFold(request.URL.Path, group) ||
				strings.EqualFold(request.URL.Path, group+"/resources") ||
				strings.EqualFold(request.URL.Path, group+"/providers/Microsoft.ManagedIdentity/userAssignedIdentities")) {
			return contractARMResponse(request, 404, `{"error":{"code":"ResourceGroupNotFound"}}`), nil
		}
		return transport.Do(request)
	}).Transport
	f.afterMaterialize = func() {
		f.base.resources[strings.ToLower(group)] = map[string]any{"id": group, "location": f.base.plan.Location}
	}
	f.lifecycle = NewLifecycle(contractCredential{}, f.options, f.base.journal)
	f.deploy(t)
	assert.Empty(t, f.base.writes, "the only creation path is the subscription Incremental graph")
	require.NoError(t, f.lifecycle.Cleanup(t.Context(), f.base.plan, false, nil))
	assert.Contains(t, f.base.resources, strings.ToLower(group), "cleanup never deletes the resource group")
}

func TestPreflightOnlyJournalCleanupDoesNotInferAnAccountOrCallARM(t *testing.T) {
	f, _ := preparationContractFixture(t, false, false, false)
	require.NoError(t, RecordPreflight(t.Context(), f.plan, Report{}, f.journal))
	state, err := f.journal.Load(t.Context())
	require.NoError(t, err)
	plan, err := CleanupPlan(state)
	require.NoError(t, err)
	assert.Empty(t, plan.Account.ID)
	require.NoError(t, NewLifecycle(nil, nil, f.journal).Cleanup(t.Context(), plan, false, nil))
	state, err = f.journal.Load(t.Context())
	require.NoError(t, err)
	assert.True(t, state.CleanupComplete)
}

func TestNestedSourceCannotBorrowAnotherRootGeneration(t *testing.T) {
	const root = "/subscriptions/target/providers/Microsoft.Resources/deployments/root"
	const nested = "/subscriptions/target/resourceGroups/rg/providers/Microsoft.Resources/deployments/nested"
	options := contractARMOptions(func(request *http.Request) (*http.Response, error) {
		require.Equal(t, http.MethodGet, request.Method)
		if strings.EqualFold(request.URL.Path, root+"/operations") {
			raw, err := json.Marshal(map[string]any{"value": []any{map[string]any{
				"id": root + "/operations/nested-create", "properties": map[string]any{
					"provisioningOperation": "Create", "provisioningState": "Succeeded",
					"targetResource": map[string]any{"id": nested, "resourceType": "Microsoft.Resources/deployments"},
				},
			}}})
			require.NoError(t, err)
			return contractARMResponse(request, 200, string(raw)), nil
		}
		require.True(t, strings.EqualFold(request.URL.Path, nested))
		raw, err := json.Marshal(map[string]any{"id": nested, "properties": map[string]any{
			"correlationId": "foreign-root-generation", "templateHash": "some-hash", "provisioningState": "Succeeded",
		}})
		require.NoError(t, err)
		return contractARMResponse(request, 200, string(raw)), nil
	})
	lifecycle := &ownedLifecycle{credential: contractCredential{}, options: options}
	_, err := captureOperationContractAttempt(t, lifecycle, root, "Succeeded", true)
	require.ErrorContains(t, err, "different root correlation")
}
