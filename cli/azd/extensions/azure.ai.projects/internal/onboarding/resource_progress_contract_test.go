// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"encoding/json"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resourceProgressFacts(f *cleanupARM) Facts {
	data := f.spec.Deployment
	return Facts{TenantID: data.TenantID, KubeletObjectID: data.KubeletObjectID, RegistryABAC: data.RegistryABAC,
		HostingIdentity: data.HostingIdentity, WorkloadIdentity: data.WorkloadIdentity}
}

func deleteProgressGrant(t *testing.T, f *cleanupARM, scope string) {
	t.Helper()
	deleted := false
	for id := range f.base.resources {
		if strings.HasPrefix(id, strings.ToLower(scope)+"/providers/microsoft.authorization/roleassignments/") {
			delete(f.base.resources, id)
			if f.deploymentState == "Failed" {
				if f.operationStates == nil {
					f.operationStates = map[string]string{}
				}
				f.operationStates[id] = "Failed"
			}
			deleted = true
		}
	}
	require.True(t, deleted, "the test must remove an actual graph grant")
}

func TestResourceProgressRoundTripKeepsProvenanceAndCurrentPreflight(t *testing.T) {
	f, _ := preparationContractFixture(t, false, false, false)
	report := Report{{ID: "P02", Scope: "/subscriptions/" + f.plan.SubscriptionID, Status: Pass, Mandatory: true}}
	require.NoError(t, RecordPreflight(t.Context(), f.plan, report, f.journal))
	state, err := f.journal.Load(t.Context())
	require.NoError(t, err)
	require.Len(t, state.ResourceProgress, 4)
	for key, entry := range state.ResourceProgress {
		assert.False(t, entry.Supplied, key)
		assert.True(t, entry.PreflightPassed, key)
	}
	assert.Empty(t, state.Resources, "progress is not an owned cleanup ledger")
	report[0].Status = Fail
	require.NoError(t, RecordPreflight(t.Context(), f.plan, report, f.journal))
	state, err = f.journal.Load(t.Context())
	require.NoError(t, err)
	for key, entry := range state.ResourceProgress {
		assert.False(t, entry.PreflightPassed, key)
	}
	state.Resources = map[string]OwnedResource{"R03": {ID: f.plan.Registry.ID, Complete: true}}
	require.NoError(t, f.journal.Save(t.Context(), state))
	reused := f.plan
	reused.Registry.Supplied, reused.RegistryCustomerSupplied = true, true
	reused, err = ResolveRegistrySelection(t.Context(), reused, f.journal)
	require.NoError(t, err)
	require.False(t, reused.RegistryCustomerSupplied)
	require.NoError(t, RecordPreflight(t.Context(), reused, report, f.journal))
	state, err = f.journal.Load(t.Context())
	require.NoError(t, err)
	assert.False(t, state.ResourceProgress["containerRegistry"].Supplied,
		"an owned registry's environment output does not change the original source")
	var legacy PreparationState
	require.NoError(t, json.Unmarshal([]byte(`{"version":2,"owner":"legacy"}`), &legacy))
	assert.False(t, legacy.ResourceProgress["hostingIdentity"].PreflightPassed)
}

func TestResourceProgressRejectsSelectionMigrationWithoutWrites(t *testing.T) {
	f, _ := preparationContractFixture(t, false, false, false)
	require.NoError(t, RecordPreflight(t.Context(), f.plan, nil, f.journal))
	before := append([]byte(nil), f.journal.data...)
	changed := f.plan
	changed.Storage.Supplied = true
	require.ErrorContains(t, RecordPreflight(t.Context(), changed, nil, f.journal), "provenance")
	assert.Equal(t, before, f.journal.data)
}

func TestSuppliedIdentityGrantEvidenceAndDeferredDependencies(t *testing.T) {
	for _, tc := range []struct{ hosting, workload, storage bool }{
		{true, true, true}, {true, false, true}, {false, true, false},
	} {
		f, facts := preparationContractFixture(t, tc.storage, true, false, tc.hosting, tc.workload)
		authorizer := &scopedAuthorizer{credential: contractCredential{}, options: f.options()}
		report := authorizer.suppliedIdentityChecks(t.Context(), f.plan, facts)
		require.NoError(t, report.Err())
		for _, check := range report {
			if check.ID == "G02" && !tc.workload || check.ID == "G03" && !tc.storage {
				assert.Equal(t, NotApplicable, check.Status)
				assert.Contains(t, check.Observed, "same ARM graph")
			} else {
				assert.Equal(t, Pass, check.Status)
			}
		}
	}
	f, facts := preparationContractFixture(t, true, true, false, true, true)
	authorizer := &scopedAuthorizer{credential: contractCredential{}, options: f.options()}
	for _, resource := range f.resources {
		properties, ok := resource["properties"].(map[string]any)
		if ok && properties["scope"] == f.plan.Storage.ID {
			properties["principalId"] = "operator"
		}
	}
	report := authorizer.suppliedIdentityChecks(t.Context(), f.plan, facts)
	require.Error(t, report.Err())
	for _, check := range report {
		if check.ID == "G03" {
			assert.Equal(t, Fail, check.Status, "operator permission is not the workload identity's permission")
		}
	}
}

func TestSuppliedIdentityConditionalAndUnreadableEvidenceIsUnverified(t *testing.T) {
	for _, field := range []string{
		"condition", "conditionVersion", "delegatedManagedIdentityResourceId", "denied definition",
	} {
		t.Run(field, func(t *testing.T) {
			f, facts := preparationContractFixture(t, true, true, false, true, true)
			for _, resource := range f.resources {
				properties, ok := resource["properties"].(map[string]any)
				if ok && properties["scope"] == f.plan.Storage.ID && field != "denied definition" {
					properties[field] = "unsupported"
				}
			}
			options := f.options()
			base := options.Transport
			options.Transport = contractTransport(func(request *http.Request) (*http.Response, error) {
				require.Equal(t, http.MethodGet, request.Method)
				assert.NotContains(t, request.URL.Path, "denyAssignments")
				assert.NotContains(t, request.URL.Host, "graph")
				if field == "denied definition" && strings.HasSuffix(request.URL.Path,
					"/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe") {
					return contractARMResponse(request, 403, `{"error":{"code":"AuthorizationFailed"}}`), nil
				}
				return base.Do(request)
			})
			a := &scopedAuthorizer{credential: contractCredential{}, options: options}
			report := a.suppliedIdentityChecks(t.Context(), f.plan, facts)
			require.Error(t, report.Err())
			for _, check := range report {
				if check.ID == "G03" {
					assert.Equal(t, Unverified, check.Status)
					if field == "denied definition" {
						require.Error(t, check.Cause)
					}
				}
			}
		})
	}
}

func TestIdentityEquivalentPermissionsKeepNotActionsLocal(t *testing.T) {
	for _, tc := range []struct {
		name                string
		available, required []*armauthorization.Permission
		allowed             bool
	}{
		{"inherited contributor covers reader", []*armauthorization.Permission{{
			Actions: []*string{new("*")}, NotActions: []*string{new("Microsoft.Authorization/*/write")},
		}}, []*armauthorization.Permission{{Actions: []*string{new("*/read")}}}, true},
		{"separate permission entry restores allow", []*armauthorization.Permission{
			{Actions: []*string{new("*")}, NotActions: []*string{new("provider/items/write")}},
			{Actions: []*string{new("provider/items/write")}},
		}, []*armauthorization.Permission{{Actions: []*string{new("provider/items/write")}}}, true},
		{"management owner does not grant Blob data", []*armauthorization.Permission{{
			Actions: []*string{new("*")},
		}}, []*armauthorization.Permission{{DataActions: []*string{new("provider/blobs/*")}}}, false},
		{"data-action exclusion matters", []*armauthorization.Permission{{
			DataActions: []*string{new("provider/blobs/*")}, NotDataActions: []*string{new("provider/blobs/delete")},
		}}, []*armauthorization.Permission{{DataActions: []*string{new("provider/blobs/*")}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.allowed, roleCovers(tc.available, tc.required))
		})
	}
}

func TestSuppliedIdentityPermissionsAcceptInheritedEquivalentRoles(t *testing.T) {
	for _, subscription := range []bool{false, true} {
		t.Run(map[bool]string{false: "resource group", true: "subscription"}[subscription], func(t *testing.T) {
			f, facts := preparationContractFixture(t, true, true, false, true, true)
			const role = "/subscriptions/foundry-sub/providers/Microsoft.Authorization/roleDefinitions/equivalent"
			inherited := map[string]map[string]any{}
			for id, resource := range f.resources {
				if !strings.Contains(id, "/providers/microsoft.authorization/roleassignments/") {
					continue
				}
				properties, ok := resource["properties"].(map[string]any)
				require.True(t, ok)
				scope, ok := properties["scope"].(string)
				require.True(t, ok)
				target, err := ParseID(scope, func() string {
					switch scope {
					case f.plan.Cluster.ID:
						return "Microsoft.ContainerService/managedClusters"
					case f.plan.Workload.ID:
						return "Microsoft.ManagedIdentity/userAssignedIdentities"
					default:
						return "Microsoft.Storage/storageAccounts"
					}
				}())
				require.NoError(t, err)
				parent := target.Parent.String()
				if subscription {
					parent = "/subscriptions/" + target.SubscriptionID
				}
				name := id[strings.LastIndex(id, "/")+1:]
				assignmentID := parent + "/providers/Microsoft.Authorization/roleAssignments/" + name
				resource["id"], properties["scope"], properties["roleDefinitionId"] = assignmentID, parent, role
				inherited[strings.ToLower(assignmentID)] = resource
				delete(f.resources, id)
			}
			maps.Copy(f.resources, inherited)
			options := f.options()
			base := options.Transport
			options.Transport = contractTransport(func(request *http.Request) (*http.Response, error) {
				require.Equal(t, http.MethodGet, request.Method)
				if request.URL.Path == role {
					return contractARMResponse(request, 200, `{"properties":{"permissions":[{"actions":["*"],`+
						`"notActions":["Microsoft.Authorization/*/write"],"dataActions":["*"]}]}}`), nil
				}
				return base.Do(request)
			})
			authorizer := &scopedAuthorizer{credential: contractCredential{}, options: options}
			report := authorizer.suppliedIdentityChecks(t.Context(), f.plan, facts)
			require.NoError(t, report.Err())
			require.Len(t, report, 4)
			for _, check := range report {
				assert.Equal(t, Pass, check.Status, check.Scope)
			}
		})
	}
}

func TestProvidedIdentityFutureDependencyGrantRetryIsBounded(t *testing.T) {
	for _, dependency := range []string{"Storage", "workload"} {
		t.Run(dependency, func(t *testing.T) {
			f := newCleanupARM(t, dependency != "Storage", true, true, dependency == "Storage")
			facts := resourceProgressFacts(f)
			scope := f.base.plan.Storage.ID
			checkID := "G03"
			if dependency == "workload" {
				scope, checkID = f.base.plan.Workload.ID, "G02"
			}
			f.deploymentState = "Failed"
			f.afterMaterialize = func() { deleteProgressGrant(t, f, scope) }
			require.Error(t, f.submit(t), "the ARM graph, not a write probe, reports the failed grant")
			require.NoError(t, f.lifecycle.Observe(t.Context(), f.base.plan, f.result))
			before := append([]byte(nil), f.base.journal.data...)
			resolved, err := ResolveRecoveryContext(
				t.Context(), f.base.plan, contractCredential{}, f.options, f.base.journal)
			require.NoError(t, err)
			assert.Equal(t, before, f.base.journal.data, "retry discovery and preview are read-only")
			a := &scopedAuthorizer{credential: contractCredential{}, options: f.options}
			report := a.suppliedIdentityChecks(t.Context(), resolved, facts)
			require.NoError(t, report.Err())
			found := false
			for _, check := range report {
				if check.ID == checkID {
					found = true
					assert.Equal(t, NotApplicable, check.Status)
					assert.Contains(t, check.Observed, "unfinished prior ARM intent")
				}
			}
			require.True(t, found)
			data, err := ResolveDeploymentBindings(t.Context(), contractCredential{}, f.options, resolved, facts)
			require.NoError(t, err)
			if dependency == "Storage" {
				assert.True(t, data.StorageSupplied, "retry references the already-created account")
				assert.False(t, data.StorageCustomerSupplied, "its original source remains azd")
				for _, operation := range resolved.Operations {
					assert.NotEqual(t, "Microsoft.Storage/storageAccounts/write", operation.Action,
						"the replayed graph references Storage rather than PUTting it")
				}
			}

			f.base.plan, f.spec.Deployment = resolved, &data
			f.deploymentState, f.afterMaterialize = "Succeeded", nil
			f.deploy(t)
			state, err := f.base.journal.Load(t.Context())
			require.NoError(t, err)
			assert.Equal(t, "Succeeded", state.Foundry.Attempts[len(state.Foundry.Attempts)-1].ProvisioningState)
			deleteProgressGrant(t, f, scope)
			resolved, err = ResolveRecoveryContext(t.Context(), resolved, contractCredential{}, f.options, f.base.journal)
			require.NoError(t, err)
			report = a.suppliedIdentityChecks(t.Context(), resolved, facts)
			require.Error(t, report.Err(), "completed or revoked grants must not reuse the incomplete-intent exemption")
		})
	}
}

func TestCloudSuccessLocalObservationFailureRecoversAllProgress(t *testing.T) {
	f := newCleanupARM(t, false, true, true, true)
	require.NoError(t, f.submit(t))
	f.base.journal.fail = true
	require.ErrorContains(t, f.lifecycle.Observe(t.Context(), f.base.plan, f.result), "journal unavailable")
	f.base.journal.fail = false
	resolved, err := ResolveRecoveryContext(t.Context(), f.base.plan, contractCredential{}, f.options, f.base.journal)
	require.NoError(t, err)
	a := &scopedAuthorizer{credential: contractCredential{}, options: f.options}
	require.NoError(t, a.suppliedIdentityChecks(t.Context(), resolved, resourceProgressFacts(f)).Err())
	require.NoError(t, f.lifecycle.Observe(t.Context(), resolved, f.result))
	state, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "Succeeded", state.Foundry.Attempts[0].ProvisioningState)
	assert.NotEmpty(t, state.Foundry.ProjectEndpoint)
	assert.NotContains(t, state.Resources, "R04")
	assert.NotContains(t, state.Resources, "R05")
}

func TestPendingAgentStateCleanupPreservesEvidenceBeforeProvisioning(t *testing.T) {
	f := newCleanupARM(t, false, false)
	f.deploy(t)
	state, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	state.CleanupStarted, state.CleanupComplete = true, true
	state.Foundry.ProjectDeleted, state.Foundry.AccountDeleted = true, true
	state.AgentStateCleanupPending = true
	require.NoError(t, f.base.journal.Save(t.Context(), state))
	before := append([]byte(nil), f.base.journal.data...)
	for _, changed := range []bool{false, true} {
		plan, spec := f.base.plan, f.spec
		if changed {
			plan.Account.ID += "-next"
			spec.AccountID = plan.Account.ID
			spec.ProjectID = plan.Account.ID + "/projects/project-next"
		}
		_, err := f.lifecycle.Check(t.Context(), plan, spec)
		require.ErrorContains(t, err, "agent state cleanup is pending")
		require.ErrorContains(t, f.lifecycle.Start(t.Context(), plan, spec, plan.DeploymentID),
			"agent state cleanup is pending")
		_, err = ResolveRecoveryContext(t.Context(), plan, contractCredential{}, f.options, f.base.journal)
		require.ErrorContains(t, err, "agent state cleanup is pending")
		require.ErrorContains(t, RecordPreflight(t.Context(), plan, nil, f.base.journal),
			"agent state cleanup is pending")
		assert.Equal(t, before, f.base.journal.data, "pending Project and endpoint evidence must not be overwritten")
	}
}
func TestRecoveryDiscoveryRejectsActiveAndUnknownAttemptsBeforeIdentityChecks(t *testing.T) {
	for _, state := range []string{"Running", "unknown"} {
		t.Run(state, func(t *testing.T) {
			f := newCleanupARM(t, false, true, true, true)
			require.NoError(t, f.submit(t))
			if state == "unknown" {
				f.rootReadMissing = true
			} else {
				for _, root := range f.roots {
					cleanupObject(t, root["properties"])["provisioningState"] = state
				}
			}
			before := append([]byte(nil), f.base.journal.data...)
			_, err := ResolveRecoveryContext(t.Context(), f.base.plan, contractCredential{}, f.options, f.base.journal)
			require.Error(t, err)
			assert.Equal(t, before, f.base.journal.data)
			assert.Empty(t, f.deletes)
		})
	}
}
