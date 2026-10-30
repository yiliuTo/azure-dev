// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
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
	require.NoError(t, f.lifecycle.Observe(t.Context(), f.base.plan, f.result))
	first, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	require.Equal(t, "Failed", first.Foundry.Attempts[0].ProvisioningState)

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
	assert.Equal(t, first.ResourceProgress, pending.ResourceProgress)
	assert.Equal(t, first.Foundry.Attempts[0].CorrelationID, pending.Foundry.Attempts[0].CorrelationID)

	require.NoError(t, f.lifecycle.Observe(t.Context(), f.base.plan, f.result))
	recovered, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	assert.NotEqual(t, recovered.Foundry.Attempts[0].CorrelationID, recovered.Foundry.Attempts[1].CorrelationID)
	assert.Equal(t, "Succeeded", recovered.Foundry.Attempts[1].ProvisioningState)
	assert.True(t, recovered.Foundry.Attempts[1].Terminal)
}

func TestStableRootPendingIntentCannotReusePreviousGeneration(t *testing.T) {
	f := newCleanupARM(t, false, false)
	f.deploy(t)
	require.NoError(t, f.lifecycle.Start(t.Context(), f.base.plan, f.spec, f.base.plan.DeploymentID))
	before := append([]byte(nil), f.base.journal.data...)
	require.ErrorContains(t, f.lifecycle.Observe(t.Context(), f.base.plan, f.result), "correlation")
	require.Error(t, f.lifecycle.Start(t.Context(), f.base.plan, f.spec, f.base.plan.DeploymentID))
	assert.Empty(t, f.deletes)
	state, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	assert.Empty(t, state.Foundry.Attempts[1].CorrelationID)
	assert.NotEmpty(t, before)
}

func TestStableRootRefusesUnverifiedOldAttemptBeforeReplacement(t *testing.T) {
	for _, scenario := range []string{"active", "unknown", "changed parameters", "changed correlation"} {
		t.Run(scenario, func(t *testing.T) {
			f := newCleanupARM(t, false, false)
			f.deploy(t)
			root := cleanupObject(t, f.roots[strings.ToLower(f.base.plan.DeploymentID)]["properties"])
			switch scenario {
			case "active":
				root["provisioningState"] = "Running"
			case "unknown":
				f.rootReadMissing = true
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
			require.Error(t, f.lifecycle.Start(t.Context(), f.base.plan, f.spec, f.base.plan.DeploymentID))
			assert.Empty(t, f.deletes)
		})
	}
}
