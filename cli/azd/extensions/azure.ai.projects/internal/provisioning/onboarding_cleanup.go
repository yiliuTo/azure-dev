// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"azure.ai.projects/internal/exterrors"
	"azure.ai.projects/internal/onboarding"

	"github.com/azure/azure-dev/cli/azd/pkg/azdext"
	"github.com/azure/azure-dev/cli/azd/pkg/exec"
	"github.com/azure/azure-dev/cli/azd/pkg/grpcbroker"
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

func (p *FoundryProvisioningProvider) destroyBYO(
	ctx context.Context, options *azdext.ProvisioningDestroyOptions, progress grpcbroker.ProgressFunc,
) (*azdext.ProvisioningDestroyResult, bool, error) {
	raw, err := p.byoJournalValue(ctx)
	if err != nil {
		return nil, true, p.byoLifecycleError(fmt.Errorf("read ownership journal before destroy: %w", err),
			exterrors.OpBYOOwnedCleanup)
	}
	currentBYO := p.synthResult != nil && p.synthResult.Hosting != nil
	if raw == "" && !currentBYO {
		return nil, false, nil
	}
	fail := func(err error) (*azdext.ProvisioningDestroyResult, bool, error) {
		return nil, true, p.byoLifecycleError(err, exterrors.OpBYOOwnedCleanup)
	}
	if raw == "" {
		return fail(fmt.Errorf("BYO-AKS ownership journal is absent; refusing both dependency and resource-group deletion"))
	}
	var state onboarding.PreparationState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return fail(fmt.Errorf("ownership journal is invalid; retain it for recovery: %w", err))
	}
	if state.AgentStateCleanupPending && state.Foundry == nil {
		return fail(fmt.Errorf("pending agent state cleanup lacks exact Project evidence; retain the ownership journal"))
	}
	plan, err := onboarding.CleanupPlan(state)
	if err != nil {
		return fail(err)
	}
	if !options.GetForce() {
		confirmed, err := p.confirmDestroyTarget(ctx,
			"only journaled owned Foundry resources and grants; resource groups and supplied resources will be retained")
		if err != nil {
			return nil, true, err
		}
		if !confirmed {
			return nil, true, exterrors.Cancelled("owned BYO-AKS cleanup cancelled")
		}
	}
	lifecycle := p.byoLifecycle
	if lifecycle == nil {
		target := *p
		target.subID = plan.SubscriptionID
		if p.azdClient != nil {
			target.credential = nil
		}
		if err := target.ensureCredential(ctx); err != nil {
			return fail(err)
		}
		lifecycle = onboarding.NewLifecycle(target.credential, p.armClientOptions, environmentJournal{p})
	}
	if state.Foundry != nil {
		state.AgentStateCleanupPending = true
		if err := (environmentJournal{p}).Save(ctx, state); err != nil {
			return fail(fmt.Errorf("persist pending agent state cleanup before cloud teardown: %w", err))
		}
	}
	if err := lifecycle.Cleanup(ctx, plan, options.GetPurge(), progress); err != nil {
		return fail(err)
	}
	completed, err := (environmentJournal{p}).Load(ctx)
	if err != nil {
		return fail(fmt.Errorf("read persisted cloud cleanup completion: %w", err))
	}
	if !completed.CleanupComplete || completed.Version != state.Version ||
		completed.DeploymentID != state.DeploymentID || completed.Environment != state.Environment ||
		(completed.Foundry == nil) != (state.Foundry == nil) {
		return fail(fmt.Errorf("cloud cleanup completion is unverified; agent state retained"))
	}
	if completed.Foundry != nil {
		if state.Foundry == nil || !completed.Foundry.ProjectDeleted || !completed.Foundry.AccountDeleted ||
			completed.Foundry.Spec.ProjectID != state.Foundry.Spec.ProjectID {
			return fail(fmt.Errorf("exact Foundry Project deletion is unverified; agent state retained"))
		}
		if err := p.cleanupDeletedProjectAgentState(ctx, completed); err != nil {
			return fail(fmt.Errorf("cloud resources were deleted but local agent state cleanup failed; "+
				"retain the ownership journal and retry azd down: %w", err))
		}
		completed.AgentStateCleanupPending = false
		if err := (environmentJournal{p}).Save(ctx, completed); err != nil {
			return fail(fmt.Errorf("persist agent state cleanup completion; retry azd down: %w", err))
		}
	}
	result := invalidatedEnvKeysResult()
	_, registryOwned := state.Resources["R03"]
	result.InvalidatedEnvKeys = slices.DeleteFunc(result.InvalidatedEnvKeys, func(key string) bool {
		return key == envKeyResourceGroup || key == envKeyFoundryRG || key == envKeyFoundryRGOwner ||
			key == envKeyBYOJournal || (!registryOwned &&
			(key == "AZURE_CONTAINER_REGISTRY_RESOURCE_ID" || key == "AZURE_CONTAINER_REGISTRY_ENDPOINT"))
	})
	return result, true, nil
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
