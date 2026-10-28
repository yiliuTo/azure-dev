// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/spf13/cobra"
)

type deletedProjectEvidence struct {
	Version         int    `json:"version"`
	Environment     string `json:"environment"`
	DeploymentID    string `json:"deploymentId"`
	ProjectID       string `json:"projectId"`
	ProjectEndpoint string `json:"projectEndpoint"`
	CleanupComplete bool   `json:"cleanupComplete"`
	ProjectDeleted  bool   `json:"projectDeleted"`
	AccountDeleted  bool   `json:"accountDeleted"`
}

func newCleanupProjectStateCommand() *cobra.Command {
	return &cobra.Command{
		Use: "internal-cleanup-project-state", Hidden: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var evidence deletedProjectEvidence
			decoder := json.NewDecoder(io.LimitReader(cmd.InOrStdin(), 16384))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&evidence); err != nil {
				return fmt.Errorf("invalid Project deletion evidence; saved agent contexts retained")
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				return fmt.Errorf("Project deletion evidence must contain one object")
			}
			endpoint, err := evidence.endpoint()
			if err != nil {
				return err
			}
			store, err := newAgentStateStore()
			if err != nil {
				return err
			}
			return store.deleteProjectRemoteVersions(cmd.Context(), endpoint)
		},
	}
}

func (e deletedProjectEvidence) endpoint() (string, error) {
	if e.Version != 3 || e.Environment == "" || !e.CleanupComplete || !e.ProjectDeleted || !e.AccountDeleted {
		return "", fmt.Errorf("completed owned Project deletion evidence is unverified; saved agent contexts retained")
	}
	id, err := arm.ParseResourceID(e.ProjectID)
	if err != nil || id.ResourceGroupName == "" ||
		!strings.EqualFold(id.ResourceType.String(), "Microsoft.CognitiveServices/accounts/projects") {
		return "", fmt.Errorf("deleted Project identity is invalid; saved agent contexts retained")
	}
	deployment, err := arm.ParseResourceID(e.DeploymentID)
	if err != nil || deployment.ResourceGroupName != "" ||
		!strings.EqualFold(deployment.ResourceType.String(), "Microsoft.Resources/deployments") ||
		!strings.EqualFold(deployment.SubscriptionID, id.SubscriptionID) {
		return "", fmt.Errorf("deleted Project deployment scope is unverified; saved agent contexts retained")
	}
	u, err := url.Parse(e.ProjectEndpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Port() != "" || !isFoundryHost(u.Hostname()) || u.Path != projectEndpointPathPrefix+id.Name {
		return "", fmt.Errorf("deleted Project API endpoint is unverified; saved agent contexts retained")
	}
	u.RawPath = ""
	return u.String(), nil
}

func stateTargetFromDeployedEndpoint(endpoint string) (*stateStoreTarget, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("deployed agent endpoint must be an HTTPS resource URL without credentials")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 5 && (len(parts) != 7 || parts[5] != "versions" || parts[6] == "") {
		return nil, fmt.Errorf("deployed agent endpoint must identify one agent and optional exact version")
	}
	u.Path, u.RawPath = "/"+strings.Join(parts[:5], "/")+"/endpoint/protocols/invocations", ""
	return stateStoreTargetFromEndpoint(u.String())
}

// Project deletion invalidates every cached remote agent version in that
// Project, without relying on currently configured services or environment outputs.
func (s *agentStateStore) deleteProjectRemoteVersions(ctx context.Context, projectEndpoint string) error {
	entries, err := os.ReadDir(s.agentsDir)
	if err != nil {
		return fmt.Errorf("inventory saved agent versions: %w", err)
	}
	keys := map[string]bool{}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("saved agent version inventory contains a non-regular state file")
		}
		raw, err := os.ReadFile(filepath.Join(s.agentsDir, entry.Name()))
		if err != nil {
			return fmt.Errorf("read saved agent version inventory: %w", err)
		}
		var record agentStateRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return fmt.Errorf("decode saved agent version inventory: %w", err)
		}
		target, err := stateTargetFromDeployedEndpoint("https://" + strings.TrimSuffix(record.AgentKey, "/remote"))
		if err != nil || normalizeEndpoint(target.ProjectEndpoint) != normalizeEndpoint(projectEndpoint) ||
			(record.AgentKey != target.agentKey && !strings.HasSuffix(record.AgentKey, "/remote")) {
			continue
		}
		if entry.Name() != agentStateKeyHash(record.AgentKey)+".json" || record.Version != agentStateSchemaVersion {
			return fmt.Errorf("saved agent version identity or schema does not match its file")
		}
		keys[record.AgentKey] = true
		keys[target.agentKey] = true
		keys[target.agentKey+"/remote"] = true
	}
	for key := range keys {
		if err := s.withLock(ctx, key, func(path string) error {
			if _, err := s.load(path, key); err != nil {
				return err
			}
			return s.remove(path, key)
		}); err != nil {
			return fmt.Errorf("remove saved context for the deleted project's agent versions: %w", err)
		}
	}
	return nil
}
