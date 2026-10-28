// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type p09GroupCredential struct{}

func (p09GroupCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"oid":"operator","groups":["known-group"]}`))
	return azcore.AccessToken{Token: "header." + claims + ".signature", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func p09BasicPlan(t *testing.T, action string) (Plan, Facts, string) {
	t.Helper()
	input := contractPlanInput()
	input.StorageID, input.AgentSubnetID = "", ""
	if action != roleAssignmentWrite {
		input.RegistryID = ""
	}
	plan, err := BuildPlan(input)
	require.NoError(t, err)
	plan.Operations = nil
	scope := plan.Registry.ID
	if action != roleAssignmentWrite {
		scope = plan.Cluster.Parent
		plan.Operations = []Operation{{CheckID: "P09", Action: action, Scope: scope}}
	}
	return plan, Facts{KubeletObjectID: "kubelet"}, scope
}

func p09BasicAuthorizer(
	t *testing.T, plan Plan, facts Facts, assignments []any, definitions map[string]any, paths *[]string,
) *scopedAuthorizer {
	t.Helper()
	assignments = append(assignments,
		p07Assignment(plan.Cluster.ID, "operator", "baseline"),
		p07Assignment(plan.Workload.Parent, "operator", "baseline"))
	if plan.Registry.Supplied {
		assignments = append(assignments, p07Assignment(plan.Registry.ID, facts.KubeletObjectID, registryRoleID(false)))
	}
	if definitions == nil {
		definitions = map[string]any{}
	}
	definitions["baseline"] = p07Permissions(map[string]any{"actions": []string{roleAssignmentWrite}})
	a := p07Authorizer(t, assignments, definitions, paths, http.StatusOK)
	a.credential = p09GroupCredential{}
	return a
}

func p09CheckAtScope(t *testing.T, report Report, scope, action string) Check {
	t.Helper()
	for _, check := range report {
		if check.ID == "P09" && check.Scope == scope && strings.HasPrefix(check.Expected, action) {
			return check
		}
	}
	t.Fatalf("P09 did not check %s at %s: %+v", action, scope, report)
	return Check{}
}

func TestP09BasicActionWiring(t *testing.T) {
	for _, action := range []string{
		"Microsoft.Resources/deployments/write", "Microsoft.Resources/deployments/read",
		"Microsoft.Resources/deployments/operations/read", roleAssignmentWrite,
	} {
		for _, allowed := range []bool{false, true} {
			status := Fail
			actions := []string{"Microsoft.Resources/unrelated/read"}
			if allowed {
				status, actions = Pass, []string{action}
			}
			t.Run(action+"/"+string(status), func(t *testing.T) {
				plan, facts, scope := p09BasicPlan(t, action)
				assignment := p07Assignment(scope, "operator", "writer")
				properties := cleanupObject(t, assignment["properties"])
				properties["condition"], properties["conditionVersion"] = "unsupported", "2.0"
				var paths []string
				a := p09BasicAuthorizer(t, plan, facts, []any{assignment},
					map[string]any{"writer": p07Permissions(map[string]any{"actions": actions})}, &paths)
				report, err := a.Check(t.Context(), plan, facts)
				check := p09CheckAtScope(t, report, scope, action)
				assert.Equal(t, status, check.Status, check.Observed)
				assert.Equal(t, !allowed, err != nil)
				assert.True(t, check.Mandatory)
				assert.Equal(t, action, check.Expected)
				for _, path := range paths {
					assert.NotContains(t, path, "/denyAssignments")
				}
			})
		}
	}
}
