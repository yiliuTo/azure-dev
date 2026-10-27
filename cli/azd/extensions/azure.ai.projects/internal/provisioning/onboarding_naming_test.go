// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/azure/azure-dev/cli/azd/pkg/tools/bicep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func namingCompiledResult(t *testing.T, token string) bicep.BuildResult {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"parametersJson": minimalARMParametersFile(t, map[string]any{"resourceToken": token}),
		"templateJson":   nil,
	})
	require.NoError(t, err)
	return bicep.BuildResult{Compiled: string(raw)}
}

func TestBYOResourceTokenPreservesOfficialInputs(t *testing.T) {
	for _, salt := range []string{"", "dev", "'${notAnExpression}\\\n\t"} {
		t.Run(salt, func(t *testing.T) {
			scope := byoNamingScope{
				SubscriptionID:  "/subscriptions/00000000-1111-2222-3333-444444444444",
				ResourceGroupID: "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/MixedCase",
				Location:        "eastus2", Salt: salt,
			}
			var temporary string
			compiler := &stubCompiler{buildParam: func(
				_ context.Context, path string, env []string,
			) (bicep.BuildResult, error) {
				temporary = filepath.Dir(path)
				// #nosec G304 -- This directory is created by the evaluator for this test.
				raw, err := os.ReadFile(filepath.Join(temporary, "scope.json"))
				require.NoError(t, err)
				var actual byoNamingScope
				require.NoError(t, json.Unmarshal(raw, &actual))
				assert.Equal(t, scope, actual, "the evaluator must not normalize any uniqueString input")
				// #nosec G304 -- This parameter file is created by the evaluator for this test.
				probe, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Contains(t, string(probe), "using none")
				assert.Contains(t, string(probe),
					"? uniqueString(scope.subscriptionId, scope.resourceGroupId, scope.location)")
				assert.Contains(t, string(probe),
					": uniqueString(scope.subscriptionId, scope.resourceGroupId, scope.location, scope.salt)")
				assert.Equal(t, []string{"BICEP_PARAMETERS_OVERRIDES={}"}, env)
				return namingCompiledResult(t, "6ufu4rgx47pmc"), nil
			}}
			token, err := evaluateBYOResourceToken(t.Context(), compiler, scope)
			require.NoError(t, err)
			assert.Equal(t, "6ufu4rgx47pmc", token)
			_, err = os.Stat(temporary)
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestBYONamingDependencyDoesNotAffectEmbeddedNonBYO(t *testing.T) {
	p := byoContractProvider(t)
	p.synthResult.Hosting = nil
	unavailable := errors.New("Bicep must not be required for non-BYO embedded ARM")
	compiler := &stubCompiler{buildErr: unavailable, buildParamErr: unavailable}
	p.bicepCliInstance = compiler
	p.byoNames = func(context.Context, *templateSource) (byoResolvedNames, error) {
		t.Fatal("non-BYO provisioning must not resolve BYO names")
		return byoResolvedNames{}, unavailable
	}
	writes := 0
	p.armClientOptions = &arm.ClientOptions{ClientOptions: policy.ClientOptions{
		Transport: byoHTTPContract(func(request *http.Request) (*http.Response, error) {
			require.Equal(t, http.MethodPut, request.Method)
			writes++
			return contractLifecycleResponse(request, 200,
				`{"properties":{"provisioningState":"Succeeded","outputs":{}}}`), nil
		}),
	}}
	_, err := p.Deploy(t.Context(), func(string) {})
	require.NoError(t, err)
	assert.Equal(t, 1, writes)
	assert.Empty(t, compiler.buildCalls)
	assert.Empty(t, compiler.buildParamCalls)
}

func TestBYOResourceTokenFailsClosed(t *testing.T) {
	failure := errors.New("official evaluator unavailable")
	for _, test := range []struct {
		name   string
		result bicep.BuildResult
		err    error
	}{
		{"compiler failure", bicep.BuildResult{}, failure},
		{"invalid envelope", bicep.BuildResult{Compiled: "invalid"}, nil},
		{"missing parameters", bicep.BuildResult{Compiled: "{}"}, nil},
		{"wrong token length", namingCompiledResult(t, "short"), nil},
		{"wrong token alphabet", namingCompiledResult(t, "AAAAAAAAAAAAA"), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			token, err := evaluateBYOResourceToken(t.Context(),
				&stubCompiler{buildParamResult: test.result, buildParamErr: test.err}, byoNamingScope{})
			require.Error(t, err)
			assert.Empty(t, token, "no approximate naming fallback")
			if test.err != nil {
				assert.ErrorIs(t, err, test.err)
			}
		})
	}
}

func TestBYONamingUsesObservedScopeAndEffectiveSalt(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, salt := range []string{"", "override-salt"} {
			t.Run(salt+map[bool]string{true: "/existing", false: "/new"}[existing], func(t *testing.T) {
				p := byoContractProvider(t)
				p.byoNames = nil
				p.onDiskSource = &templateSource{
					armTemplate: p.armTemplate,
					parameters: map[string]any{
						"resourceTokenSalt": map[string]any{"value": salt},
					},
				}
				source, err := p.resolveTemplate(t.Context(), func(string) {})
				require.NoError(t, err)
				const subscription = "/subscriptions/foundry-sub"
				groupID := subscription + "/resourceGroups/foundry-rg"
				if existing {
					groupID = subscription + "/resourceGroups/Foundry-RG"
				}
				var reads []string
				p.armClientOptions = &arm.ClientOptions{ClientOptions: policy.ClientOptions{
					Transport: byoHTTPContract(func(request *http.Request) (*http.Response, error) {
						require.Equal(t, http.MethodGet, request.Method)
						reads = append(reads, request.URL.Path)
						if strings.EqualFold(request.URL.Path, subscription) {
							return contractLifecycleResponse(request, 200, `{"id":"`+subscription+`"}`), nil
						}
						require.Equal(t, subscription+"/resourcegroups/foundry-rg", strings.ToLower(request.URL.Path))
						if !existing {
							return contractLifecycleResponse(request, 404, `{"error":{"code":"ResourceGroupNotFound"}}`), nil
						}
						return contractLifecycleResponse(request, 200,
							`{"id":"`+groupID+`","name":"Foundry-RG","tags":{"customer":"preserve"}}`), nil
					}),
				}}
				p.bicepCliInstance = &stubCompiler{buildParam: func(
					_ context.Context, path string, _ []string,
				) (bicep.BuildResult, error) {
					raw, err := os.ReadFile(filepath.Join(filepath.Dir(path), "scope.json"))
					require.NoError(t, err)
					var actual byoNamingScope
					require.NoError(t, json.Unmarshal(raw, &actual))
					assert.Equal(t, byoNamingScope{
						SubscriptionID: subscription, ResourceGroupID: groupID, Location: p.location, Salt: salt,
					}, actual)
					return namingCompiledResult(t, "6ufu4rgx47pmc"), nil
				}}
				names, err := p.resolveBYONames(t.Context(), source)
				require.NoError(t, err)
				assert.Equal(t, groupID+"/providers/Microsoft.CognitiveServices/accounts/cog-6ufu4rgx47pmc", names.AccountID)
				assert.Equal(t, byoRegistryName(p.subID, p.rgName, p.envName, p.projectPath), names.RegistryName)
				assert.True(t, names.ParentResolved)
				assert.Equal(t, existing, names.Group != nil)
				assert.Len(t, reads, 2)
			})
		}
	}
}

func TestBYOResourceTokenMatchesOfficialBicep(t *testing.T) {
	executable, err := exec.LookPath("bicep")
	if err != nil {
		t.Skip("Bicep CLI is required for official offline naming evaluation")
	}
	t.Setenv("BICEP_PARAMETERS_OVERRIDES", `{"resourceToken":{"value":"do-not-use"}}`)
	compiler := &stubCompiler{buildParam: func(
		ctx context.Context, path string, env []string,
	) (bicep.BuildResult, error) {
		// #nosec G204 -- Official compiler selected by the test environment; input is test-owned.
		command := exec.CommandContext(ctx, executable, "build-params", path, "--stdout")
		command.Env = append(os.Environ(), env...)
		raw, err := command.CombinedOutput()
		return bicep.BuildResult{Compiled: string(raw)}, err
	}}
	for _, test := range []struct{ salt, token string }{
		{"", "6ufu4rgx47pmc"},
		{"dev", "tj3vrbhuja3fg"},
	} {
		token, err := evaluateBYOResourceToken(t.Context(), compiler, byoNamingScope{
			SubscriptionID: "/subscriptions/00000000-1111-2222-3333-444444444444",
			ResourceGroupID: "/subscriptions/00000000-1111-2222-3333-444444444444" +
				"/resourceGroups/rg-foundry-offline-probe",
			Location: "eastus2", Salt: test.salt,
		})
		require.NoError(t, err)
		assert.Equal(t, test.token, token)
	}
}
