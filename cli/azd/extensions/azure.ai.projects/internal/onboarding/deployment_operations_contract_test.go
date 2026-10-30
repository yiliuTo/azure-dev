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

func TestDeploymentOperationsPagerPreservesExactPathAndContinuation(t *testing.T) {
	const deployment = "/subscriptions/target/resourceGroups/target-rg/providers/Microsoft.Resources/deployments/attempt"
	for _, continuation := range []string{
		"https://management.azure.com" + deployment + "/operations?api-version=2021-04-01&$skiptoken=next",
		"https://other.invalid/operations?sig=secret",
		"https://user:password@management.azure.com/operations",
	} {
		t.Run(continuation, func(t *testing.T) {
			reads := 0
			options := contractARMOptions(func(request *http.Request) (*http.Response, error) {
				reads++
				require.Equal(t, http.MethodGet, request.Method)
				require.Equal(t, "management.azure.com", request.URL.Host)
				require.Equal(t, deployment+"/operations", request.URL.Path)
				require.Equal(t, "2021-04-01", request.URL.Query().Get("api-version"))
				body := map[string]any{"value": []any{}}
				if reads == 1 {
					body["nextLink"] = continuation
				} else {
					assert.Equal(t, "next", request.URL.Query().Get("$skiptoken"))
				}
				raw, err := json.Marshal(body)
				require.NoError(t, err)
				return contractARMResponse(request, http.StatusOK, string(raw)), nil
			})
			pager, err := NewDeploymentOperationsPager(deployment, contractCredential{}, options)
			require.NoError(t, err)
			_, err = pager.NextPage(t.Context())
			require.NoError(t, err)
			require.True(t, pager.More())
			_, err = pager.NextPage(t.Context())
			if strings.HasPrefix(continuation, "https://management.azure.com/") {
				require.NoError(t, err)
				assert.Equal(t, 2, reads)
				assert.False(t, pager.More())
			} else {
				require.ErrorContains(t, err, "configured ARM endpoint")
				assert.Equal(t, 1, reads)
				for _, secret := range []string{"secret", "password", "user:"} {
					assert.NotContains(t, err.Error(), secret)
				}
			}
		})
	}
}
