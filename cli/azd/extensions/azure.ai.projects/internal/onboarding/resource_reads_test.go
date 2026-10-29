// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourcePassReusesFirstSKUAndRejectsPartialPools(t *testing.T) {
	for _, scenario := range []string{"complete", "SKU forbidden", "partial pools"} {
		t.Run(scenario, func(t *testing.T) {
			f := newStorageNetworkContract(t)
			f.base.plan.Storage.Supplied = false
			f.base.plan.AgentSubnet = Resource{ID: resourceValue(f.base.vnet.ID) + "/subnets/agents", Supplied: true}
			f.bodies[f.base.plan.AgentSubnet.ID] = map[string]any{
				"id": f.base.plan.AgentSubnet.ID, "properties": map[string]any{
					"addressPrefix": "10.0.1.0/27",
					"delegations": []any{map[string]any{
						"properties": map[string]any{"serviceName": "Microsoft.App/environments"},
					}},
				},
			}
			checker := f.checker()
			base := checker.options
			var skuReads, poolPages atomic.Int32
			checker.options = onboardingARMOptions(contractARMOptions(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/skus") {
					skuReads.Add(1)
					if scenario == "SKU forbidden" {
						return contractARMResponse(r, http.StatusForbidden,
							`{"error":{"code":"AuthorizationFailed"}}`), nil
					}
				}
				if strings.HasSuffix(r.URL.Path, "/agentPools") {
					poolPages.Add(1)
					if scenario == "partial pools" {
						if r.URL.Query().Get("page") == "2" {
							return contractARMResponse(r, http.StatusForbidden, `{"error":{"code":"AuthorizationFailed"}}`), nil
						}
						next := *r.URL
						query := next.Query()
						query.Set("page", "2")
						next.RawQuery = query.Encode()
						raw, err := json.Marshal(map[string]any{"value": f.base.fixture.Pools, "nextLink": next.String()})
						require.NoError(t, err)
						return contractARMResponse(r, http.StatusOK, string(raw)), nil
					}
				}
				return base.Transport.Do(r)
			}))
			_, report, err := checker.Check(t.Context(), f.base.plan)
			assert.Equal(t, int32(1), skuReads.Load(), "AKS and network selection must use the same first SKU evidence")
			if scenario == "complete" {
				require.NoError(t, err)
				assert.Equal(t, int32(1), poolPages.Load())
			} else {
				require.Error(t, err)
				id := "A05"
				if scenario == "partial pools" {
					id = "A10"
					assert.Equal(t, int32(2), poolPages.Load())
				}
				var readFailed bool
				for _, check := range report {
					if check.ID == id {
						assert.NotEqual(t, Pass, check.Status)
						readFailed = readFailed || check.Cause != nil
					}
					if check.ID == "N02" && check.Scope == f.base.plan.AgentSubnet.ID {
						assert.NotEqual(t, Pass, check.Status, "incomplete pool/SKU evidence cannot prove subnet safety")
					}
				}
				assert.True(t, readFailed, "the original service failure must be retained")
			}
		})
	}
}

func TestClusterReadsPoolsAndSKUsConcurrently(t *testing.T) {
	f := newNetworkARMContract(t)
	base := f.options()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	started := make(chan string, 2)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	options := contractARMOptions(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/agentPools") || strings.HasSuffix(r.URL.Path, "/skus") {
			started <- r.URL.Path
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return base.Transport.Do(r)
	})
	checker := &sdkResourceChecker{credential: contractCredential{}, options: onboardingARMOptions(options)}
	done := make(chan Report, 1)
	go func() {
		_, _, _, report := checker.readCluster(ctx, f.plan.Cluster)
		done <- report
	}()
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("pool and SKU reads did not overlap")
		}
	}
	unblock()
	select {
	case report := <-done:
		require.NoError(t, report.Err())
	case <-ctx.Done():
		t.Fatal("cluster reads did not join")
	}
}
