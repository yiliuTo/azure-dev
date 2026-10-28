// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func deletedProjectEvidenceForTest() deletedProjectEvidence {
	const subscription = "00000000-0000-0000-0000-000000000001"
	return deletedProjectEvidence{
		Version: 3, Environment: "dev",
		DeploymentID: "/subscriptions/" + subscription + "/providers/Microsoft.Resources/deployments/foundry",
		ProjectID: "/subscriptions/" + subscription +
			"/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/acct/projects/project",
		ProjectEndpoint: "https://acct.services.ai.azure.com/api/projects/project",
		CleanupComplete: true, ProjectDeleted: true, AccountDeleted: true,
	}
}

func TestCleanupProjectStateCommand(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*deletedProjectEvidence)
		fail   bool
	}{
		{"completed", func(*deletedProjectEvidence) {}, false},
		{"cloud-failed", func(e *deletedProjectEvidence) { e.CleanupComplete = false }, true},
		{"project-unconfirmed", func(e *deletedProjectEvidence) { e.ProjectDeleted = false }, true},
		{"account-unconfirmed", func(e *deletedProjectEvidence) { e.AccountDeleted = false }, true},
		{"wrong-project", func(e *deletedProjectEvidence) { e.ProjectEndpoint += "-other" }, true},
		{"unknown-version", func(e *deletedProjectEvidence) { e.Version++ }, true},
		{"foreign-deployment", func(e *deletedProjectEvidence) {
			e.DeploymentID = strings.Replace(e.DeploymentID, "000000000001", "000000000002", 1)
		}, true},
		{"credential-bearing-endpoint", func(e *deletedProjectEvidence) {
			e.ProjectEndpoint = "https://user:private-password@acct.services.ai.azure.com/api/projects/project?sig=private-signature"
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("AZD_CONFIG_DIR", t.TempDir())
			store, err := newAgentStateStore()
			require.NoError(t, err)
			const base = "acct.services.ai.azure.com/api/projects/project/agents/echo"
			owned := []string{
				base, base + "/remote", base + "/versions/1/remote", base + "/versions/2/remote",
				base + "-other/versions/1/remote",
			}
			others := []string{
				base + "/local", base + "/versions/1/local",
				"acct.services.ai.azure.com/api/projects/other/agents/echo/versions/1/remote",
				"localhost:8080/agents/echo",
			}
			for _, key := range append(owned, others...) {
				require.NoError(t, store.mutate(t.Context(), key, func(record *agentStateRecord) {
					record.SessionID, record.ConversationID, record.StateStore = "session", "conversation", "checkpoints"
				}))
			}
			evidence := deletedProjectEvidenceForTest()
			test.mutate(&evidence)
			raw, err := json.Marshal(evidence)
			require.NoError(t, err)
			command := NewRootCommand()
			command.SetIn(bytes.NewReader(raw))
			command.SetArgs([]string{"internal-cleanup-project-state"})
			err = command.ExecuteContext(t.Context())
			if test.fail {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "private-password")
				assert.NotContains(t, err.Error(), "private-signature")
			} else {
				require.NoError(t, err)
			}
			for _, key := range append(owned, others...) {
				record, err := store.get(t.Context(), key)
				require.NoError(t, err)
				if !test.fail && !slices.Contains(others, key) {
					assert.Nil(t, record, key)
				} else {
					require.NotNil(t, record, key)
					assert.Equal(t, "session", record.SessionID)
				}
			}
		})
	}
}

func TestDeleteProjectRemoteVersionsInvalidInventoryCanRetry(t *testing.T) {
	t.Parallel()
	store, err := newAgentStateStoreAt(t.TempDir())
	require.NoError(t, err)
	const base = "acct.services.ai.azure.com/api/projects/project/agents/echo"
	for _, key := range []string{base + "/versions/1/remote", base + "/versions/2/remote"} {
		require.NoError(t, store.mutate(t.Context(), key, func(record *agentStateRecord) {
			record.SessionID = "saved"
		}))
	}
	path := store.statePath(base + "/versions/1/remote")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))
	endpoint := deletedProjectEvidenceForTest().ProjectEndpoint
	require.ErrorContains(t, store.deleteProjectRemoteVersions(t.Context(), endpoint), "inventory")
	record, err := store.get(t.Context(), base+"/versions/2/remote")
	require.NoError(t, err)
	require.NotNil(t, record)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	require.NoError(t, store.deleteProjectRemoteVersions(t.Context(), endpoint))
	require.NoError(t, store.deleteProjectRemoteVersions(t.Context(), endpoint))
	for _, key := range []string{base + "/versions/1/remote", base + "/versions/2/remote"} {
		record, err := store.get(t.Context(), key)
		require.NoError(t, err)
		require.Nil(t, record)
	}
}
