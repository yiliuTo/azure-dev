// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

func (l *ownedLifecycle) verifyGrantBirth(
	ctx context.Context, state PreparationState, id string, created time.Time,
) error {
	plan := Plan{SubscriptionID: state.SubscriptionID, ResourceGroup: state.ResourceGroup}
	for _, attempt := range state.Foundry.Attempts {
		single := *state.Foundry
		single.Attempts = []FoundryAttempt{attempt}
		targets, err := l.deploymentGrantTargets(ctx, plan, &single)
		if err != nil {
			return err
		}
		if !targets[strings.ToLower(id)] {
			continue
		}
		start, end, err := attemptBirthInterval(attempt)
		if err != nil {
			return err
		}
		if !created.Before(start) && !created.After(end) {
			return nil
		}
	}
	return fmt.Errorf("grant %s has no exact operation and current creation-window provenance", id)
}

func (l *ownedLifecycle) verifyAssignmentInventory(ctx context.Context, state PreparationState) error {
	for _, record := range state.Assignments {
		id, err := ParseID(record.ID, "Microsoft.Authorization/roleAssignments")
		if err != nil {
			return err
		}
		client, err := armauthorization.NewRoleAssignmentsClient(id.SubscriptionID, l.credential, l.options)
		if err != nil {
			return err
		}
		actual, err := client.GetByID(ctx, record.ID, nil)
		if responseNotFound(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("validate exact grant inventory before cleanup: %w", err)
		}
		if record.Deleted || !strings.EqualFold(authString(actual.ID), record.ID) ||
			!compatibleGrant(actual.RoleAssignment, grantRequest{scope: record.Scope,
				principalID: record.PrincipalID, roleID: record.RoleID}) ||
			!strings.EqualFold(authString(actual.Properties.Description), state.DeploymentID) ||
			actual.Properties.CreatedOn == nil || record.CreatedOn.IsZero() ||
			!record.CreatedOn.Equal(*actual.Properties.CreatedOn) {
			return fmt.Errorf("owned assignment %s actual identity or creation evidence changed", record.ID)
		}
		if err := l.verifyGrantBirth(ctx, state, record.ID, record.CreatedOn); err != nil {
			return err
		}
	}
	return nil
}
