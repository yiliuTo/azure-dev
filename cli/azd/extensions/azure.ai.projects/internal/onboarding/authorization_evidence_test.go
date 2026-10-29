// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type evidenceCredential struct {
	calls atomic.Int32
}

func (c *evidenceCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.calls.Add(1)
	return (removedChecksCredential{}).GetToken(ctx, options)
}

func TestAuthorizationEvidenceDeduplicatesWithinEachPass(t *testing.T) {
	plan := p06Plan(t, false)
	scopes := []string{plan.Cluster.ID, plan.Workload.Parent}
	for i := range 4 {
		scopes = append(scopes, fmt.Sprintf("/subscriptions/foundry-sub/resourceGroups/extra-%d", i))
	}
	for i := range 17 {
		plan.Operations = append(plan.Operations, Operation{
			CheckID: "P02", Scope: scopes[i%len(scopes)], Action: "Microsoft.Resources/deployments/read",
		})
	}
	var lists, definitions atomic.Int32
	allow := true
	options := contractARMOptions(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, http.MethodGet, r.Method)
		var body any
		if strings.HasSuffix(r.URL.Path, "/roleAssignments") {
			lists.Add(1)
			scope := strings.TrimSuffix(r.URL.Path, "/providers/Microsoft.Authorization/roleAssignments")
			body = map[string]any{"value": []any{p07Assignment(scope, "operator", "shared")}}
		} else {
			require.True(t, strings.HasSuffix(r.URL.Path, "/roleDefinitions/shared"))
			definitions.Add(1)
			actions := []string{}
			if allow {
				actions = []string{"*"}
			}
			body = p07Permissions(map[string]any{"actions": actions})
		}
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		return contractARMResponse(r, http.StatusOK, string(raw)), nil
	})
	a := NewAuthorizer(removedChecksCredential{}, options)
	for pass := range 2 {
		report, err := a.Check(t.Context(), plan, Facts{KubeletObjectID: "kubelet"})
		require.Len(t, report, 20)
		if allow {
			require.NoError(t, err)
		} else {
			require.Error(t, err, "a new pass must observe changed permissions")
		}
		for i, op := range plan.Operations {
			check := report[len(report)-len(plan.Operations)+i]
			assert.Equal(t, op.Scope, check.Scope, "completion order must not reorder the report")
			assert.Equal(t, op.Action, check.Expected)
		}
		for _, check := range report {
			if allow {
				assert.Equal(t, Pass, check.Status)
			} else {
				assert.NotEqual(t, Pass, check.Status)
			}
		}
		assert.Equal(t, int32(6*(pass+1)), lists.Load())
		assert.Equal(t, int32(pass+1), definitions.Load())
		allow = false
	}
}

func TestAssignmentEvidenceCoalescesCompletePaginationAndFailures(t *testing.T) {
	const scope = "/subscriptions/evidence-sub/resourceGroups/group"
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var pages atomic.Int32
			options := contractARMOptions(func(r *http.Request) (*http.Response, error) {
				require.Equal(t, http.MethodGet, r.Method)
				pages.Add(1)
				if r.URL.Query().Get("page") == "2" {
					if status != http.StatusOK {
						return contractARMResponse(r, status, `{"error":{"code":"AuthorizationFailed"}}`), nil
					}
					return contractARMResponse(r, status, `{"value":[{"id":"second"}]}`), nil
				}
				next := *r.URL
				query := next.Query()
				query.Set("page", "2")
				next.RawQuery = query.Encode()
				body := fmt.Sprintf(`{"value":[{"id":"first"}],"nextLink":%q}`, next.String())
				return contractARMResponse(r, http.StatusOK, body), nil
			})
			e := newAuthorizationEvidence(contractCredential{}, options)
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					values, err := e.filteredAssignments(t.Context(), scope, "atScope()")
					if status == http.StatusOK {
						assert.NoError(t, err)
						assert.Len(t, values, 2)
					} else {
						assert.Error(t, err)
						assert.Empty(t, values, "a failed later page cannot become partial successful evidence")
					}
				})
			}
			wg.Wait()
			assert.Equal(t, int32(2), pages.Load(), "concurrent misses share the complete enumeration, including errors")
		})
	}
}

func TestAuthorizationEvidenceKeysIncludeFullIDsAndCallerFilter(t *testing.T) {
	var requests atomic.Int32
	options := contractARMOptions(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		if strings.HasSuffix(r.URL.Path, "/roleAssignments") {
			return contractARMResponse(r, http.StatusOK, `{"value":[]}`), nil
		}
		return contractARMResponse(r, http.StatusOK, `{"properties":{"permissions":[]}}`), nil
	})
	credential := &evidenceCredential{}
	e := newAuthorizationEvidence(credential, options)
	for _, scope := range []string{"/subscriptions/first", "/subscriptions/second"} {
		for _, filter := range []string{"atScope()", "assignedTo('first-caller')", "assignedTo('second-caller')"} {
			for range 2 {
				_, err := e.filteredAssignments(t.Context(), scope, filter)
				require.NoError(t, err)
			}
		}
		for range 2 {
			_, err := e.roleDefinition(t.Context(), scope+"/providers/Microsoft.Authorization/roleDefinitions/same-id")
			require.NoError(t, err)
		}
	}
	assert.Equal(t, int32(8), requests.Load(), "filters and full role IDs must not leak evidence across callers or scopes")
	assert.Equal(t, int32(3), credential.calls.Load(),
		"one assignment pipeline per subscription and one definition pipeline retain their token caches")
}

func TestSharedEvidenceDoesNotShareUnconditionalDecision(t *testing.T) {
	const scope = "/subscriptions/contract-sub"
	assignment := p07Assignment(scope, "operator", "conditional")
	properties, ok := assignment["properties"].(map[string]any)
	require.True(t, ok)
	properties["condition"] = "conditional grant"
	var paths []string
	a := p07Authorizer(t, []any{assignment},
		map[string]any{"conditional": p07Permissions(map[string]any{"actions": []string{roleAssignmentWrite}})},
		&paths, http.StatusOK)
	a.reads = newAuthorizationEvidence(a.credential, a.options)
	caller := callerIdentity{objectID: "operator"}
	status, _, err := a.basicAction(t.Context(), scope, caller, roleAssignmentWrite, false)
	require.NoError(t, err)
	assert.Equal(t, Pass, status)
	status, _, err = a.basicAction(t.Context(), scope, caller, roleAssignmentWrite, true)
	require.NoError(t, err)
	assert.NotEqual(t, Pass, status, "P06 still requires unconditional evidence from the same raw assignments")
	assert.Len(t, paths, 2)
}
