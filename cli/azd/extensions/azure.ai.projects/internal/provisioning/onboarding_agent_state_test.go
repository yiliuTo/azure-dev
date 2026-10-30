// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"azure.ai.projects/internal/onboarding"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/azure/azure-dev/cli/azd/pkg/azdext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercises Destroy -> existing azd namespace dispatch -> production Agents binary.
// Only ARM and environment persistence are fixtures.
func TestBYOProviderAgentStateCleanupRealExtension(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and invokes the azd host and Agents extension")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	core, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	require.NoError(t, err)
	configDir, binDir := t.TempDir(), t.TempDir()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	for _, target := range []struct{ dir, output string }{
		{core, filepath.Join(binDir, "azd"+suffix)},
		{filepath.Join(core, "extensions", "azure.ai.agents"), filepath.Join(configDir, "agents"+suffix)},
	} {
		//nolint:gosec // Builds repository-owned source in a temporary directory.
		command := exec.CommandContext(ctx, "go", "build", "-o", target.output, ".")
		command.Dir = target.dir
		output, err := command.CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	config, err := json.Marshal(map[string]any{
		"extension": map[string]any{"installed": map[string]any{
			"azure.ai.agents": map[string]any{
				"id": "azure.ai.agents", "namespace": "ai.agent", "version": "0.0.0",
				"path": "agents" + suffix, "capabilities": []string{"custom-commands"},
			},
		}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.json"), config, 0o600))
	t.Setenv("AZD_CONFIG_DIR", configDir)
	t.Setenv("AZURE_DEV_COLLECT_TELEMETRY", "no")
	t.Setenv("AZD_DEBUG", "false")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	const subscription = "00000000-0000-0000-0000-000000000001"
	const account = "/subscriptions/" + subscription +
		"/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct"
	state := onboarding.PreparationState{
		Version: 3, SubscriptionID: subscription, ResourceGroup: "rg", Location: "eastus", Environment: "dev",
		DeploymentID: "/subscriptions/" + subscription + "/providers/Microsoft.Resources/deployments/foundry",
		Foundry: &onboarding.FoundryState{
			Spec: onboarding.FoundrySpec{
				AccountID: account, ProjectID: account + "/projects/project", Location: "eastus",
				RegistryID: "/subscriptions/" + subscription +
					"/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/registry",
				Deployment: &onboarding.DeploymentData{},
			},
			ProjectEndpoint: "https://acct.services.ai.azure.com/api/projects/project",
		},
	}
	client := newResolveEnvTestClient(t, &resolveEnvStubEnvServer{}, &resolveEnvStubPromptServer{})
	cloudFailed := true
	p := &FoundryProvisioningProvider{
		azdClient: client, projectPath: t.TempDir(), envName: "dev",
		subID: subscription, rgName: "rg", rgExplicit: true, credential: byoCredentialContract{},
		armClientOptions: &arm.ClientOptions{ClientOptions: policy.ClientOptions{
			Transport: byoHTTPContract(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/accounts") {
					return contractLifecycleResponse(request, http.StatusOK, `{"value":[]}`), nil
				}
				require.Equal(t, http.MethodDelete, request.Method)
				require.Equal(t, "/subscriptions/"+subscription+"/resourcegroups/rg", strings.ToLower(request.URL.Path))
				if cloudFailed {
					return contractLifecycleResponse(request, http.StatusForbidden,
						`{"error":{"code":"AuthorizationFailed","message":"cloud cleanup failed"}}`), nil
				}
				return contractLifecycleResponse(request, http.StatusOK, ""), nil
			}),
		}},
	}
	journal := environmentJournal{p}
	require.NoError(t, journal.Save(ctx, state))

	const base = "acct.services.ai.azure.com/api/projects/project/agents/echo"
	deleted := []string{base, base + "/versions/1/remote", base + "/versions/2/remote"}
	retained := []string{
		base + "/versions/1/local",
		"acct.services.ai.azure.com/api/projects/other/agents/echo/versions/1/remote",
		"localhost:8080/agents/echo",
	}
	original, paths := map[string][]byte{}, map[string]string{}
	cache := filepath.Join(configDir, "state", "extensions", "azure.ai.agents", "agents")
	require.NoError(t, os.MkdirAll(cache, 0o700))
	for _, key := range append(deleted, retained...) {
		data, err := json.Marshal(map[string]any{
			"version": 1, "agentKey": key, "sessionId": "session", "conversationId": "conversation",
		})
		require.NoError(t, err)
		sum := sha256.Sum256([]byte(key))
		path := filepath.Join(cache, hex.EncodeToString(sum[:])+".json")
		require.NoError(t, os.WriteFile(path, data, 0o600))
		original[key], paths[key] = data, path
	}
	options := &azdext.ProvisioningDestroyOptions{Force: true}
	result, err := p.Destroy(ctx, options, func(string) {})
	require.ErrorContains(t, err, "cloud cleanup failed")
	assert.Nil(t, result)
	for key, path := range paths {
		actual, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, original[key], actual)
	}

	cloudFailed = false
	badPath := paths[deleted[1]]
	require.NoError(t, os.WriteFile(badPath, []byte("{"), 0o600))
	result, err = p.Destroy(ctx, options, func(string) {})
	require.ErrorContains(t, err, "local agent state cleanup failed")
	require.ErrorContains(t, err, "inventory", "the real Agents process must reject the corrupt inventory")
	assert.Nil(t, result)
	pending, err := journal.Load(ctx)
	require.NoError(t, err)
	assert.True(t, pending.CleanupComplete)
	assert.True(t, pending.AgentStateCleanupPending)
	assert.Equal(t, state.Foundry.Spec.ProjectID, pending.Foundry.Spec.ProjectID)
	assert.Equal(t, state.Foundry.ProjectEndpoint, pending.Foundry.ProjectEndpoint)
	require.NoError(t, os.WriteFile(badPath, original[deleted[1]], 0o600))

	for range 2 {
		result, err = p.Destroy(ctx, options, func(string) {})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.InvalidatedEnvKeys, envKeyBYOJournal)
		persisted, err := journal.Load(ctx)
		require.NoError(t, err)
		assert.False(t, persisted.AgentStateCleanupPending)
		for _, key := range deleted {
			_, err := os.Stat(paths[key])
			assert.ErrorIs(t, err, os.ErrNotExist, key)
		}
		for _, key := range retained {
			actual, err := os.ReadFile(paths[key])
			require.NoError(t, err, key)
			assert.Equal(t, original[key], actual, key)
		}
	}
}
