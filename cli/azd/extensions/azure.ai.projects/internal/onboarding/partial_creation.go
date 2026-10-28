// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"strings"
	"time"
)

type partialCreateWindow struct {
	start, end time.Time
	failed     bool
}

func (w partialCreateWindow) contains(birth time.Time) bool {
	return !birth.Before(w.start) && !birth.After(w.end)
}

// Failed ARM deployments omit outputResources. An exact timed resource Create
// in their verified operation graph can bind birth instead. Failed Creates are
// considered only for private endpoints, never companion resources or grants.
func partialResourceCreate(
	attempt FoundryAttempt, resourceID string, allowFailedEndpoint bool,
) (partialCreateWindow, bool) {
	if !attempt.Terminal || attempt.ProvisioningState != "Failed" || attempt.Evidence == nil {
		return partialCreateWindow{}, false
	}
	start, end, err := attemptBirthInterval(attempt)
	if err != nil {
		return partialCreateWindow{}, false
	}
	for deploymentID, operations := range attempt.Evidence.Operations {
		for _, operation := range operations {
			if !exactCreateOperation(operation, deploymentID) || operation.Properties.TargetResource == nil ||
				!strings.EqualFold(authString(operation.Properties.TargetResource.ID), resourceID) {
				continue
			}
			p := operation.Properties
			failed := authString(p.ProvisioningState) == "Failed"
			if authString(p.ProvisioningState) != "Succeeded" &&
				!(allowFailedEndpoint && failed &&
					strings.EqualFold(authString(p.TargetResource.ResourceType), privateEndpointType)) {
				continue
			}
			duration := authString(p.Duration)
			if p.Timestamp == nil || !strings.HasPrefix(duration, "PT") {
				continue
			}
			elapsed, err := time.ParseDuration(strings.NewReplacer("H", "h", "M", "m", "S", "s").Replace(duration[2:]))
			if err != nil || elapsed <= 0 {
				continue
			}
			// Unlike terminal deployment timestamps, operation timestamps mark the operation's start.
			window := partialCreateWindow{*p.Timestamp, p.Timestamp.Add(elapsed), failed}
			if !window.start.Before(start) && !window.end.After(end) {
				return window, true
			}
		}
	}
	return partialCreateWindow{}, false
}

func failedEndpointBirth(state *PreparationState, resourceID string, birth time.Time) bool {
	for _, attempt := range state.Foundry.Attempts {
		if window, ok := partialResourceCreate(attempt, resourceID, true); ok && window.failed && window.contains(birth) {
			return true
		}
	}
	return false
}

func recordedFailedEndpoint(state *PreparationState, resourceID string) bool {
	if state.Foundry.Network == nil {
		return false
	}
	record, ok := state.Foundry.Network.Resources[strings.ToLower(resourceID)]
	return ok && !record.Deleted && !record.CreatedTime.IsZero() &&
		failedEndpointBirth(state, resourceID, record.CreatedTime)
}
