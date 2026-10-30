// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"azure.ai.projects/internal/exterrors"
	"azure.ai.projects/internal/onboarding"

	"github.com/azure/azure-dev/cli/azd/pkg/azdext"
	"github.com/azure/azure-dev/cli/azd/pkg/exec"
)

func (p *FoundryProvisioningProvider) byoJournalValue(ctx context.Context) (string, error) {
	if value, present := p.virtualEnv[envKeyBYOJournal]; present && value != "" {
		return value, nil
	}
	if p.azdClient == nil {
		return "", nil
	}
	response, err := p.azdClient.Environment().GetValues(ctx, &azdext.GetEnvironmentRequest{Name: p.envName})
	if err != nil {
		return "", err
	}
	for _, value := range response.KeyValues {
		if value.Key == envKeyBYOJournal {
			return value.Value, nil
		}
	}
	return "", nil
}

func (p *FoundryProvisioningProvider) byoDestroyState(ctx context.Context) (*onboarding.PreparationState, error) {
	raw, err := p.byoJournalValue(ctx)
	if err != nil {
		return nil, fmt.Errorf("read BYO retry state before resource-group deletion: %w", err)
	}
	if raw == "" {
		return nil, nil
	}
	var state onboarding.PreparationState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("decode BYO retry state before resource-group deletion: %w", err)
	}
	plan, err := onboarding.CleanupPlan(state)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(plan.SubscriptionID, p.subID) || !strings.EqualFold(plan.ResourceGroup, p.rgName) ||
		plan.Environment != p.envName {
		return nil, fmt.Errorf("BYO retry state belongs to another environment or resource group")
	}
	if state.AgentStateCleanupPending && (state.Foundry == nil || state.Foundry.ProjectEndpoint == "") {
		return nil, fmt.Errorf("pending agent state cleanup lacks its persisted Project target")
	}
	return &state, nil
}

func (p *FoundryProvisioningProvider) finishBYODestroy(
	ctx context.Context, state *onboarding.PreparationState,
) (*azdext.ProvisioningDestroyResult, error) {
	if state == nil {
		return p.destroyResult(), nil
	}
	state.CleanupComplete = true
	if state.Foundry != nil {
		state.Foundry.ProjectDeleted, state.Foundry.AccountDeleted = true, true
	}
	journal := environmentJournal{p}
	if err := journal.Save(ctx, *state); err != nil {
		return nil, p.byoLifecycleError(fmt.Errorf(
			"persist resource-group deletion before local agent cleanup; retry azd down: %w", err),
			exterrors.OpBYOOwnedCleanup)
	}
	if state.AgentStateCleanupPending {
		if err := p.cleanupDeletedProjectAgentState(ctx, *state); err != nil {
			return nil, p.byoLifecycleError(fmt.Errorf(
				"resource group was deleted but local agent state cleanup failed; retry azd down: %w", err),
				exterrors.OpBYOOwnedCleanup)
		}
		state.AgentStateCleanupPending = false
		if err := journal.Save(ctx, *state); err != nil {
			return nil, p.byoLifecycleError(fmt.Errorf(
				"persist local agent cleanup completion; retry azd down: %w", err), exterrors.OpBYOOwnedCleanup)
		}
	}
	return p.destroyResult(), nil
}

func (p *FoundryProvisioningProvider) cleanupDeletedProjectAgentState(
	ctx context.Context, state onboarding.PreparationState,
) error {
	evidence := struct {
		Version         int    `json:"version"`
		Environment     string `json:"environment"`
		DeploymentID    string `json:"deploymentId"`
		ProjectID       string `json:"projectId"`
		ProjectEndpoint string `json:"projectEndpoint"`
		CleanupComplete bool   `json:"cleanupComplete"`
		ProjectDeleted  bool   `json:"projectDeleted"`
		AccountDeleted  bool   `json:"accountDeleted"`
	}{
		Version: state.Version, Environment: state.Environment, DeploymentID: state.DeploymentID,
		ProjectID: state.Foundry.Spec.ProjectID, ProjectEndpoint: state.Foundry.ProjectEndpoint,
		CleanupComplete: state.CleanupComplete,
		ProjectDeleted:  state.Foundry.ProjectDeleted, AccountDeleted: state.Foundry.AccountDeleted,
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	// Use the installed namespace dispatcher in a separate host, not a nested
	// workflow that would reuse the provisioning host's active gRPC server.
	result, err := exec.NewCommandRunner(nil).Run(ctx,
		exec.NewRunArgs("azd", "ai", "agent", "internal-cleanup-project-state",
			"--no-prompt", "--output", "json", "--environment", p.envName).
			WithCwd(p.projectPath).WithStdIn(bytes.NewReader(raw)))
	if err != nil {
		return fmt.Errorf("invoke installed azure.ai.agents cleanup (requires the matching Agents release): %w: %s",
			err, strings.TrimSpace(result.Stdout+result.Stderr))
	}
	return nil
}
