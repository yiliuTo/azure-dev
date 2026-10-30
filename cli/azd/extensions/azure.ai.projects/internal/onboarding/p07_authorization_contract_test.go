// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const p07AcrPush = "8311e382-0749-4cb8-b61a-304f252e45ec"

func p07Assignment(scope, principal, role string) map[string]any {
	return map[string]any{
		"id": scope + "/providers/Microsoft.Authorization/roleAssignments/existing-" + role,
		"properties": map[string]any{
			"scope": scope, "principalId": principal,
			"roleDefinitionId": "/subscriptions/contract-sub/providers/Microsoft.Authorization/roleDefinitions/" + role,
		},
	}
}

func p07Authorizer(
	t *testing.T, assignments []any, definitions map[string]any, paths *[]string, status int,
) *scopedAuthorizer {
	t.Helper()
	if assignments == nil {
		assignments = []any{}
	}
	var mu sync.Mutex
	options := contractARMOptions(func(request *http.Request) (*http.Response, error) {
		require.Equal(t, http.MethodGet, request.Method)
		mu.Lock()
		*paths = append(*paths, request.URL.Path)
		mu.Unlock()
		if status != http.StatusOK {
			return contractARMResponse(request, status, `{"error":{"code":"AuthorizationFailed"}}`), nil
		}
		var body any
		switch {
		case strings.HasSuffix(request.URL.Path, "/roleAssignments"):
			assert.Equal(t, "atScope()", request.URL.Query().Get("$filter"))
			body = map[string]any{"value": assignments}
		case strings.Contains(request.URL.Path, "/roleDefinitions/"):
			role := request.URL.Path[strings.LastIndex(request.URL.Path, "/")+1:]
			var ok bool
			body, ok = definitions[role]
			require.True(t, ok, "unexpected role definition %s", role)
		default:
			t.Fatalf("unexpected authorization read %s", request.URL.Path)
		}
		data, err := json.Marshal(body)
		require.NoError(t, err)
		return contractARMResponse(request, http.StatusOK, string(data)), nil
	})
	return &scopedAuthorizer{credential: contractCredential{}, options: options}
}

func p07Permissions(entries ...map[string]any) map[string]any {
	return map[string]any{"properties": map[string]any{"permissions": entries}}
}

func TestP07ExistingKubeletAccessNeedsNoOperatorWrite(t *testing.T) {
	for _, tc := range []struct {
		name, role, scope string
		abac              bool
	}{
		{"registry pull", registryRoleID(false), "registry", false},
		{"RG push", p07AcrPush, "rg", false},
		{"subscription pull", registryRoleID(false), "subscription", false},
		{"ABAC repository reader", registryRoleID(true), "rg", true},
		{"custom pull", "custom-pull", "registry", false},
		{"custom repository reader", "custom-repository", "registry", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, facts := preparationContractFixture(t, false, true, tc.abac)
			scope := f.plan.Registry.ID
			if tc.scope == "rg" {
				scope = f.plan.Registry.Parent
			} else if tc.scope == "subscription" {
				registry, err := ParseID(f.plan.Registry.ID, "Microsoft.ContainerRegistry/registries")
				require.NoError(t, err)
				scope = "/subscriptions/" + registry.SubscriptionID
			}
			var paths []string
			a := p07Authorizer(t, []any{p07Assignment(scope, facts.KubeletObjectID, tc.role)},
				map[string]any{
					"custom-pull": p07Permissions(map[string]any{"actions": []string{registryPullAction}}),
					"custom-repository": p07Permissions(map[string]any{
						"dataActions": []string{repositoryReadAction},
					}),
				}, &paths, http.StatusOK)
			check := a.checkP07(t.Context(), f.plan, facts, callerIdentity{}, errors.New("operator unavailable"))
			assert.Equal(t, Pass, check.Status, check.Observed)
			require.NoError(t, Report{check}.Err())
			assert.Contains(t, check.Observed, scope+"/providers/Microsoft.Authorization/roleAssignments/")
			for _, path := range paths {
				assert.NotContains(t, path, "operator")
			}
		})
	}
}

func TestP07OperatorBasicActionAtSelectedScope(t *testing.T) {
	for _, tc := range []struct {
		name        string
		supplied    bool
		parent      string
		permissions []map[string]any
		want        Status
	}{
		{"supplied with write", true, "", []map[string]any{{"actions": []string{roleAssignmentWrite}}}, Pass},
		{"supplied without write", true, "", []map[string]any{{"actions": []string{"*/read"}}}, Fail},
		{"new registry RG", false, "", []map[string]any{{"actions": []string{"*"}}}, Pass},
		{"new registry subscription", false, "/subscriptions/contract-sub",
			[]map[string]any{{"actions": []string{"*"}}}, Pass},
		{"excluded action", true, "", []map[string]any{
			{"actions": []string{"*"}, "notActions": []string{roleAssignmentWrite}},
		}, Fail},
		{"permission entry union", true, "", []map[string]any{
			{"actions": []string{"*"}, "notActions": []string{roleAssignmentWrite}},
			{"actions": []string{roleAssignmentWrite}},
		}, Pass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, facts := preparationContractFixture(t, false, tc.supplied, false)
			if tc.parent != "" {
				f.plan.Registry.Parent = tc.parent
			}
			scope := f.plan.Registry.Parent
			if tc.supplied {
				scope = f.plan.Registry.ID
			}
			var paths []string
			parent := "/subscriptions/" + strings.Split(scope, "/")[2]
			a := p07Authorizer(t, []any{p07Assignment(parent, "operator", "writer")},
				map[string]any{"writer": p07Permissions(tc.permissions...)}, &paths, http.StatusOK)
			check := a.checkP07(t.Context(), f.plan, facts, callerIdentity{objectID: "operator"}, nil)
			assert.Equal(t, tc.want, check.Status, check.Observed)
			assert.Equal(t, scope, check.Scope)
			assert.Equal(t, tc.want != Pass, Report{check}.Err() != nil)
			for _, path := range paths {
				if strings.HasSuffix(path, "/roleAssignments") {
					assert.Equal(t, scope+"/providers/Microsoft.Authorization/roleAssignments", path)
				}
				if !tc.supplied {
					assert.NotContains(t, path, "/registries/")
				}
			}
		})
	}
}

func TestP07RolesCombineWithoutGlobalNotActions(t *testing.T) {
	f, facts := preparationContractFixture(t, false, true, false)
	var paths []string
	a := p07Authorizer(t, []any{
		p07Assignment(f.plan.Registry.Parent, "operator", "excluded"),
		p07Assignment("/subscriptions/"+strings.Split(f.plan.Registry.ID, "/")[2], "operator", "writer"),
	}, map[string]any{
		"excluded": p07Permissions(map[string]any{
			"actions": []string{"*"}, "notActions": []string{roleAssignmentWrite},
		}),
		"writer": p07Permissions(map[string]any{"actions": []string{roleAssignmentWrite}}),
	}, &paths, http.StatusOK)
	assert.Equal(t, Pass, a.checkP07(t.Context(), f.plan, facts, callerIdentity{objectID: "operator"}, nil).Status)
}

func TestP07BasicActionIgnoresConditionMetadata(t *testing.T) {
	f, facts := preparationContractFixture(t, false, true, false)
	assignment := p07Assignment(f.plan.Registry.ID, "operator", "writer")
	properties := cleanupObject(t, assignment["properties"])
	properties["condition"], properties["conditionVersion"] = "unsupported-attribute", "2.0"
	var paths []string
	a := p07Authorizer(t, []any{assignment},
		map[string]any{"writer": p07Permissions(map[string]any{"actions": []string{roleAssignmentWrite}})},
		&paths, http.StatusOK)
	caller := callerIdentity{objectID: "operator"}
	assert.Equal(t, Pass, a.checkP07(t.Context(), f.plan, facts, caller, nil).Status)
}

func TestP07ABACRequiresRepositoryDataPermission(t *testing.T) {
	for _, role := range []string{registryRoleID(false), "arm-reader"} {
		t.Run(role, func(t *testing.T) {
			f, facts := preparationContractFixture(t, false, true, true)
			var paths []string
			a := p07Authorizer(t, []any{p07Assignment(f.plan.Registry.ID, facts.KubeletObjectID, role)},
				map[string]any{role: p07Permissions(map[string]any{"actions": []string{"*/read"}})},
				&paths, http.StatusOK)
			check := a.checkP07(t.Context(), f.plan, facts, callerIdentity{objectID: "operator"}, nil)
			assert.Equal(t, Fail, check.Status, check.Observed)
		})
	}
}

func TestP07ReadErrorsAndIncompleteEvidenceBlock(t *testing.T) {
	for _, supplied := range []bool{true, false} {
		for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
			f, facts := preparationContractFixture(t, false, supplied, false)
			var paths []string
			a := p07Authorizer(t, nil, nil, &paths, status)
			check := a.checkP07(t.Context(), f.plan, facts, callerIdentity{objectID: "operator"}, nil)
			assert.Equal(t, Unverified, check.Status)
			require.Error(t, Report{check}.Err())
			require.ErrorContains(t, check.Cause, "AuthorizationFailed")
		}
	}
	for _, assignment := range []any{
		map[string]any{},
		map[string]any{"properties": map[string]any{"principalId": ""}},
		map[string]any{"properties": map[string]any{"principalId": "kubelet"}},
		map[string]any{"properties": map[string]any{
			"principalId": "kubelet", "scope": "", "roleDefinitionId": "unknown",
		}},
	} {
		f, facts := preparationContractFixture(t, false, true, false)
		facts.KubeletObjectID = "kubelet"
		var paths []string
		a := p07Authorizer(t, []any{assignment}, nil, &paths, http.StatusOK)
		check := a.checkP07(t.Context(), f.plan, facts, callerIdentity{objectID: "operator"}, nil)
		assert.Equal(t, Unverified, check.Status)
		require.Error(t, Report{check}.Err())
	}
	f, facts := preparationContractFixture(t, false, false, false)
	var paths []string
	a := p07Authorizer(t, []any{p07Assignment(f.plan.Registry.Parent, "operator", "unreadable")},
		map[string]any{"unreadable": map[string]any{"properties": map[string]any{}}}, &paths, http.StatusOK)
	check := a.checkP07(t.Context(), f.plan, facts, callerIdentity{objectID: "operator"}, nil)
	assert.Equal(t, Unverified, check.Status)
	require.Error(t, Report{check}.Err())
}

func TestP07OperatorExplicitTokenGroupsAtInheritedScope(t *testing.T) {
	for _, group := range []string{"member-group", "nonmember-group"} {
		t.Run(group, func(t *testing.T) {
			f, facts := preparationContractFixture(t, false, true, false)
			claims := base64.RawURLEncoding.EncodeToString([]byte(`{"oid":"operator","groups":["member-group"]}`))
			caller, err := identityFromToken("header." + claims + ".signature")
			require.NoError(t, err)
			parent := "/subscriptions/" + strings.Split(f.plan.Registry.ID, "/")[2]
			var paths []string
			a := p07Authorizer(t, []any{p07Assignment(parent, group, "writer")},
				map[string]any{"writer": p07Permissions(map[string]any{"actions": []string{roleAssignmentWrite}})},
				&paths, http.StatusOK)
			check := a.checkP07(t.Context(), f.plan, facts, caller, nil)
			if group == "member-group" {
				assert.Equal(t, Pass, check.Status, check.Observed)
			} else {
				assert.Equal(t, Fail, check.Status, check.Observed)
			}
		})
	}
}
