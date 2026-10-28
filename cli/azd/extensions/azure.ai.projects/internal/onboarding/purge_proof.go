// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices/v2"
)

func deletedAccountResourceID(accountID, location string) (string, error) {
	account, err := ParseID(accountID, "Microsoft.CognitiveServices/accounts")
	if err != nil {
		return "", err
	}
	return "/subscriptions/" + account.SubscriptionID + "/providers/Microsoft.CognitiveServices/locations/" +
		location + "/resourceGroups/" + account.ResourceGroupName + "/deletedAccounts/" + account.Name, nil
}

// ARM createdTime and the RP's two creation timestamps are different clocks.
// Bind all three to the same exact successful Account Create, not a tolerance.
// Once RP birth has been recorded, its two timestamps must remain identical.
func (l *ownedLifecycle) accountPurgeSource(
	ctx context.Context, plan Plan, state *PreparationState, account armcognitiveservices.Account,
) (ResourceSource, error) {
	id := state.Foundry.Spec.AccountID
	source, exists := state.Sources[strings.ToLower(id)]
	if !exists || !source.InitiallyAbsent || !strings.EqualFold(source.ID, id) || source.CreatedTime.IsZero() ||
		account.SystemData == nil || account.SystemData.CreatedAt == nil || account.SystemData.CreatedAt.IsZero() ||
		account.Properties == nil || account.Properties.DateCreated == nil {
		return source, fmt.Errorf("owned account purge requires exact initial-absence and actual RP birth evidence")
	}
	dateCreated, err := time.Parse(time.RFC3339Nano, *account.Properties.DateCreated)
	if err != nil || dateCreated.IsZero() {
		return source, fmt.Errorf("owned account purge requires a valid RP dateCreated")
	}
	systemCreated := *account.SystemData.CreatedAt
	if !source.AccountSystemCreatedAt.IsZero() || !source.AccountDateCreated.IsZero() {
		if !source.AccountSystemCreatedAt.Equal(systemCreated) || !source.AccountDateCreated.Equal(dateCreated) {
			return source, fmt.Errorf("owned account RP birth identity changed; refusing irreversible purge")
		}
	}
	for _, attempt := range state.Foundry.Attempts {
		created := map[string]bool{}
		createdOperations := map[string]bool{}
		single := *state.Foundry
		single.Attempts = []FoundryAttempt{attempt}
		if _, err := l.deploymentGrantTargets(ctx, plan, &single, nil, created, nil, createdOperations); err != nil {
			return source, err
		}
		if !created[strings.ToLower(id)] {
			continue
		}
		start, end, err := attemptBirthInterval(attempt)
		if err != nil {
			return source, err
		}
		for deploymentID, operations := range attempt.Evidence.Operations {
			for _, operation := range operations {
				if operation == nil || !createdOperations[strings.ToLower(authString(operation.ID))] ||
					!succeededCreateOperation(operation, deploymentID) || operation.Properties.TargetResource == nil ||
					!strings.EqualFold(authString(operation.Properties.TargetResource.ID), id) ||
					!strings.EqualFold(authString(operation.Properties.TargetResource.ResourceType),
						"Microsoft.CognitiveServices/accounts") {
					continue
				}
				p := operation.Properties
				duration := authString(p.Duration)
				if p.Timestamp == nil || !strings.HasPrefix(duration, "PT") {
					continue
				}
				elapsed, err := time.ParseDuration(strings.NewReplacer("H", "h", "M", "m", "S", "s").Replace(duration[2:]))
				if err != nil || elapsed <= 0 {
					continue
				}
				window := partialCreateWindow{start: *p.Timestamp, end: p.Timestamp.Add(elapsed)}
				if window.start.Before(start) || window.end.After(end) || !window.contains(source.CreatedTime) ||
					!window.contains(systemCreated) || !window.contains(dateCreated) {
					continue
				}
				source.AccountSystemCreatedAt, source.AccountDateCreated = systemCreated, dateCreated
				return source, nil
			}
		}
	}
	return source, fmt.Errorf("owned account birth lacks the same exact verified successful Account Create; refusing purge")
}

func (l *ownedLifecycle) verifyDeletedAccount(
	ctx context.Context, plan Plan, state *PreparationState, account armcognitiveservices.Account,
) (ResourceSource, error) {
	spec := state.Foundry.Spec
	id, err := ParseID(spec.AccountID, "Microsoft.CognitiveServices/accounts")
	if err != nil {
		return ResourceSource{}, err
	}
	deletedID, err := deletedAccountResourceID(spec.AccountID, spec.Location)
	if err != nil {
		return ResourceSource{}, err
	}
	if !state.CleanupStarted || !state.Foundry.AccountDeleted ||
		!strings.EqualFold(authString(account.ID), deletedID) ||
		!strings.EqualFold(authString(account.Name), id.Name) ||
		!strings.EqualFold(authString(account.Type), "Microsoft.CognitiveServices/deletedAccounts") ||
		!strings.EqualFold(authString(account.Location), spec.Location) ||
		account.Properties == nil || account.Properties.ProvisioningState == nil ||
		*account.Properties.ProvisioningState != armcognitiveservices.ProvisioningStateSucceeded ||
		account.Properties.DeletionDate == nil {
		return ResourceSource{}, fmt.Errorf("soft-deleted account ownership/location changed; refusing irreversible purge")
	}
	source, err := l.accountPurgeSource(ctx, plan, state, account)
	if err != nil {
		return source, err
	}
	deletedAt, err := time.Parse(time.RFC3339Nano, *account.Properties.DeletionDate)
	if err != nil || deletedAt.Before(source.CreatedTime) || deletedAt.Before(source.AccountSystemCreatedAt) ||
		deletedAt.Before(source.AccountDateCreated) {
		return source, fmt.Errorf("soft-deleted account deletion date is unverified; refusing irreversible purge")
	}
	return source, nil
}
