// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// ResourceSource preserves initial absence and actual ARM birth evidence
// independently of the mutable cleanup ledger and preparation progress.
type ResourceSource struct {
	ID                     string    `json:"id"`
	InitiallyAbsent        bool      `json:"initiallyAbsent"`
	CreatedTime            time.Time `json:"createdTime"`
	AccountSystemCreatedAt time.Time `json:"accountSystemCreatedAt,omitzero"`
	AccountDateCreated     time.Time `json:"accountDateCreated,omitzero"`
}

func sourceResources(plan Plan, spec FoundrySpec) []Resource {
	if data := spec.Deployment; data != nil {
		plan.Storage = Resource{ID: data.StorageID, Supplied: data.StorageCustomerSupplied}
		plan.Registry = Resource{ID: data.RegistryID, Supplied: data.RegistryCustomerSupplied}
		plan.Hosting, plan.Workload = data.Hosting, data.Workload
	}
	if spec.AccountID != "" {
		plan.Account.ID = spec.AccountID
	}
	resources := []Resource{plan.Storage, plan.Registry, plan.Hosting, plan.Workload, plan.Account}
	if spec.ProjectID != "" {
		resources = append(resources, Resource{ID: spec.ProjectID})
	}
	for _, name := range spec.ModelNames {
		resources = append(resources, Resource{ID: spec.AccountID + "/deployments/" + name})
	}
	return resources
}

func (l *ownedLifecycle) recordInitialSources(
	ctx context.Context, plan Plan, state *PreparationState, spec FoundrySpec,
) error {
	actual, err := l.expandedNetworkResources(ctx, plan)
	if err != nil {
		response, ok := errors.AsType[*azcore.ResponseError](err)
		if !ok || response.StatusCode != 404 || !strings.EqualFold(response.ErrorCode, "ResourceGroupNotFound") ||
			plan.ResourceGroupSupplied {
			return err
		}
		actual = map[string]*armresources.GenericResourceExpanded{}
	}
	if state.Sources == nil {
		state.Sources = map[string]ResourceSource{}
	}
	for _, resource := range sourceResources(plan, spec) {
		if resource.Supplied {
			continue
		}
		key := strings.ToLower(resource.ID)
		if old, ok := state.Sources[key]; ok {
			if !old.InitiallyAbsent || !strings.EqualFold(old.ID, resource.ID) {
				return fmt.Errorf("resource source provenance changed for %s", resource.ID)
			}
			continue
		}
		if actual[key] != nil {
			return fmt.Errorf("resource %s lacks initial-absence source evidence; refusing adoption", resource.ID)
		}
		if strings.EqualFold(resource.ID, spec.AccountID) ||
			strings.HasPrefix(key, strings.ToLower(spec.AccountID)+"/deployments/") {
			client, err := armresources.NewClient(plan.SubscriptionID, l.credential, l.options)
			if err != nil {
				return err
			}
			_, err = client.GetByID(ctx, resource.ID, "2025-06-01", nil)
			if !responseNotFound(err) {
				if err != nil {
					return fmt.Errorf("verify initial account absence: %w", err)
				}
				return fmt.Errorf("Foundry resource exists without initial-absence source evidence")
			}
		}
		state.Sources[key] = ResourceSource{ID: resource.ID, InitiallyAbsent: true}
	}
	state.Version, state.DeploymentID, state.Environment = preparationJournalVersion, plan.DeploymentID, plan.Environment
	state.SubscriptionID, state.ResourceGroup, state.Location = plan.SubscriptionID, plan.ResourceGroup, plan.Location
	return nil
}

func attemptBirthInterval(attempt FoundryAttempt) (time.Time, time.Time, error) {
	if err := validateAttemptEvidence(attempt); err != nil {
		return time.Time{}, time.Time{}, err
	}
	p := attempt.Evidence.Properties
	duration := authString(p.Duration)
	if p.Timestamp == nil || !strings.HasPrefix(duration, "PT") {
		return time.Time{}, time.Time{}, fmt.Errorf("resource birth requires a terminal deployment timestamp and duration")
	}
	elapsed, err := time.ParseDuration(strings.NewReplacer("H", "h", "M", "m", "S", "s").Replace(duration[2:]))
	if err != nil || elapsed <= 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("resource birth requires a positive deployment duration")
	}
	return p.Timestamp.Add(-elapsed), *p.Timestamp, nil
}

func (l *ownedLifecycle) verifyResourceSources(ctx context.Context, plan Plan, state *PreparationState) error {
	if state.Foundry == nil {
		return nil
	}
	actual, err := l.expandedNetworkResources(ctx, plan)
	if err != nil {
		return err
	}
	client, err := armresources.NewClient(plan.SubscriptionID, l.credential, l.options)
	if err != nil {
		return err
	}
	for _, resource := range sourceResources(plan, state.Foundry.Spec) {
		if resource.Supplied {
			continue
		}
		key := strings.ToLower(resource.ID)
		source, ok := state.Sources[key]
		if !ok || !source.InitiallyAbsent || !strings.EqualFold(source.ID, resource.ID) {
			return fmt.Errorf("resource %s has missing or changed initial-absence provenance", resource.ID)
		}
		current := actual[key]
		if (current == nil || current.CreatedTime == nil) &&
			(strings.EqualFold(resource.ID, state.Foundry.Spec.AccountID) ||
				strings.HasPrefix(key, strings.ToLower(state.Foundry.Spec.AccountID)+"/")) {
			observed, err := l.foundryBirth(ctx, resource.ID)
			if err != nil && !responseNotFound(err) {
				return err
			}
			if err == nil && observed.CreatedTime != nil {
				current = observed
			}
		}
		if current == nil {
			version := "2025-06-01"
			switch {
			case strings.Contains(key, "/microsoft.storage/"):
				version = "2024-01-01"
			case strings.Contains(key, "/microsoft.containerregistry/"):
				version = "2025-05-01-preview"
			case strings.Contains(key, "/microsoft.managedidentity/"):
				version = "2023-01-31"
			}
			_, err := client.GetByID(ctx, resource.ID, version, nil)
			if responseNotFound(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("verify resource omitted from creation inventory: %w", err)
			}
			return fmt.Errorf("resource %s exists but has no actual ARM creation inventory evidence", resource.ID)
		}
		for _, record := range state.Resources {
			if record.Deleted && strings.EqualFold(record.ID, resource.ID) {
				return fmt.Errorf("a deleted resource %s was recreated", resource.ID)
			}
		}
		if state.Foundry.AccountDeleted && strings.EqualFold(resource.ID, state.Foundry.Spec.AccountID) ||
			state.Foundry.ProjectDeleted && strings.EqualFold(resource.ID, state.Foundry.Spec.ProjectID) {
			return fmt.Errorf("a deleted Foundry resource %s was recreated", resource.ID)
		}
		if strings.HasPrefix(key, strings.ToLower(state.Foundry.Spec.AccountID)+"/deployments/") &&
			state.Foundry.ModelsDeleted[key[strings.LastIndex(key, "/")+1:]] {
			return fmt.Errorf("a deleted Foundry model deployment %s was recreated", resource.ID)
		}
		if current.CreatedTime == nil || current.CreatedTime.IsZero() {
			return fmt.Errorf("resource %s has no actual ARM creation evidence", resource.ID)
		}
		if !source.CreatedTime.IsZero() && !source.CreatedTime.Equal(*current.CreatedTime) {
			return fmt.Errorf("resource %s was replaced or recreated; refusing adoption or deletion", resource.ID)
		}
		proven := false
		for _, attempt := range state.Foundry.Attempts {
			created := map[string]bool{}
			single := *state.Foundry
			single.Attempts = []FoundryAttempt{attempt}
			if _, err := l.deploymentGrantTargets(ctx, plan, &single, nil, created); err != nil {
				return err
			}
			if !created[key] {
				continue
			}
			start, end, err := attemptBirthInterval(attempt)
			if err != nil {
				return err
			}
			output := false
			for _, target := range attempt.Evidence.Properties.OutputResources {
				if target != nil && strings.EqualFold(authString(target.ID), resource.ID) {
					output = true
				}
			}
			if !output {
				window, ok := partialResourceCreate(attempt, resource.ID, false)
				output = ok && window.contains(*current.CreatedTime)
			}
			if output && !current.CreatedTime.Before(start) && !current.CreatedTime.After(end) {
				proven = true
				break
			}
		}
		if !proven {
			return fmt.Errorf(
				"resource %s has no exact Create/output-resource binding/creation-window provenance", resource.ID)
		}
		source.CreatedTime = *current.CreatedTime
		state.Sources[key] = source
	}
	return nil
}

func (l *ownedLifecycle) foundryBirth(
	ctx context.Context, resourceID string,
) (*armresources.GenericResourceExpanded, error) {
	id, err := ParseID(resourceID, "Microsoft.CognitiveServices/accounts")
	project := false
	model := false
	if err != nil {
		id, err = ParseID(resourceID, "Microsoft.CognitiveServices/accounts/projects")
		project = true
	}
	if err != nil {
		id, err = ParseID(resourceID, "Microsoft.CognitiveServices/accounts/deployments")
		project, model = false, true
	}
	if err != nil {
		return nil, err
	}
	var actualID *string
	var system *armcognitiveservices.SystemData
	if project {
		client, err := armcognitiveservices.NewProjectsClient(id.SubscriptionID, l.credential, l.options)
		if err != nil {
			return nil, err
		}
		actual, err := client.Get(ctx, id.ResourceGroupName, id.Parent.Name, id.Name, nil)
		if err != nil {
			return nil, fmt.Errorf("read current Foundry project creation evidence: %w", err)
		}
		actualID, system = actual.ID, actual.SystemData
	} else if model {
		client, err := armcognitiveservices.NewDeploymentsClient(id.SubscriptionID, l.credential, l.options)
		if err != nil {
			return nil, err
		}
		actual, err := client.Get(ctx, id.ResourceGroupName, id.Parent.Name, id.Name, nil)
		if err != nil {
			return nil, fmt.Errorf("read current Foundry model creation evidence: %w", err)
		}
		actualID, system = actual.ID, actual.SystemData
	} else {
		client, err := armcognitiveservices.NewAccountsClient(id.SubscriptionID, l.credential, l.options)
		if err != nil {
			return nil, err
		}
		actual, err := client.Get(ctx, id.ResourceGroupName, id.Name, nil)
		if err != nil {
			return nil, fmt.Errorf("read current Foundry account creation evidence: %w", err)
		}
		actualID, system = actual.ID, actual.SystemData
	}
	if !strings.EqualFold(authString(actualID), resourceID) {
		return nil, fmt.Errorf("current Foundry creation-evidence resource ID changed")
	}
	result := &armresources.GenericResourceExpanded{ID: actualID}
	if system != nil {
		result.CreatedTime = system.CreatedAt
	}
	return result, nil
}
