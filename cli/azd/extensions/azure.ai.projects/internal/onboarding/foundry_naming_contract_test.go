// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFoundryResourceNaming(t *testing.T) {
	for _, name := range []string{"cog-official", "ABCDEFGHIJKLMNO", "a", "123456789012345", "cog-é-中"} {
		t.Run(name, func(t *testing.T) {
			in := contractPlanInput()
			in.StorageID, in.RegistryID = "", ""
			in.FoundryAccountID = strings.TrimSuffix(in.FoundryAccountID, "cog-official") + name
			plan, err := BuildPlan(in)
			require.NoError(t, err)
			var part strings.Builder
			for _, ch := range strings.ToLower(name) {
				if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' {
					part.WriteRune(ch)
					if part.Len() == 14 {
						break
					}
				}
			}
			sum := sha256.Sum256([]byte(strings.ToLower(in.FoundryAccountID)))
			assert.Equal(t, part.String()+fmt.Sprintf("%x", sum)[:10], plan.Storage.Name)
			assert.Regexp(t, `^[a-z0-9]{3,24}$`, plan.Storage.Name)
			assert.Equal(t, strings.ToLower(name)+"-hosting-mi", plan.Hosting.Name)
			assert.Equal(t, strings.ToLower(name)+"-workload-mi", plan.Workload.Name)
			assert.Equal(t, in.RegistryName, plan.Registry.Name)
			assert.Equal(t, in.FoundryAccountID, plan.Account.ID)
			assert.Equal(t, in.DeploymentID, plan.DeploymentID)
			in.Environment = "different-environment"
			other, err := BuildPlan(in)
			require.NoError(t, err)
			assert.Equal(t, plan.Storage, other.Storage, "companion names depend only on the exact account")
		})
	}
}

func TestFoundryResourceNamingPreservesSuppliedResources(t *testing.T) {
	in := contractPlanInput()
	in.HostingIdentityID = "/subscriptions/identity-sub/resourceGroups/rg/providers/" +
		"Microsoft.ManagedIdentity/userAssignedIdentities/custom-host"
	in.WorkloadIdentityID = strings.ReplaceAll(in.HostingIdentityID, "custom-host", "custom-work")
	in.RegistryName = ""
	plan, err := BuildPlan(in)
	require.NoError(t, err)
	assert.Equal(t, in.StorageID, plan.Storage.ID)
	assert.Equal(t, in.RegistryID, plan.Registry.ID)
	assert.Equal(t, in.HostingIdentityID, plan.Hosting.ID)
	assert.Equal(t, in.WorkloadIdentityID, plan.Workload.ID)
	in.WorkloadIdentityID = in.HostingIdentityID
	_, err = BuildPlan(in)
	require.ErrorContains(t, err, "distinct")
}

func TestFoundryNamingRequiresOfficialTargets(t *testing.T) {
	for _, change := range []func(*Input){
		func(in *Input) { in.FoundryAccountID = "" },
		func(in *Input) { in.FoundryAccountID = strings.ReplaceAll(in.FoundryAccountID, "foundry-sub", "other") },
		func(in *Input) { in.DeploymentID = "" },
		func(in *Input) { in.RegistryID, in.RegistryName = "", "" },
	} {
		in := contractPlanInput()
		change(&in)
		_, err := BuildPlan(in)
		require.ErrorContains(t, err, "I03")
	}
}

func TestFoundryNamingRetryUsesExactCurrentOwnedResources(t *testing.T) {
	f := newCleanupARM(t, false, false)
	f.deploy(t)
	data, err := ResolveDeploymentBindings(t.Context(), contractCredential{}, f.options, f.base.plan, Facts{
		TenantID: f.spec.Deployment.TenantID, KubeletObjectID: f.spec.Deployment.KubeletObjectID,
	})
	require.NoError(t, err)
	assert.True(t, data.StorageSupplied)
	assert.Equal(t, f.base.plan.Storage.ID, data.StorageID)
	spec := f.spec
	spec.Deployment = &data
	report, err := f.lifecycle.Check(t.Context(), f.base.plan, spec)
	require.NoError(t, err)
	require.NoError(t, report.Err())
}
