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
)

const preparationJournalVersion = 3

// Journal atomically stores deployment intents and observed ownership. Load returns a zero state when absent.
// Callers must serialize deployment for an environment; this interface is not a distributed lock.
type Journal interface {
	Load(context.Context) (PreparationState, error)
	Save(context.Context, PreparationState) error
}

// PreparationState associates exact deployment provenance and cleanup progress with an environment.
type PreparationState struct {
	Version          int                         `json:"version"`
	SubscriptionID   string                      `json:"subscriptionId"`
	ResourceGroup    string                      `json:"resourceGroup"`
	Location         string                      `json:"location"`
	Environment      string                      `json:"environment"`
	DeploymentID     string                      `json:"deploymentId"`
	Network          *SubnetPreparation          `json:"network,omitempty"`
	Resources        map[string]OwnedResource    `json:"resources"`
	Assignments      map[string]OwnedAssignment  `json:"assignments"`
	Foundry          *FoundryState               `json:"foundry,omitempty"`
	Registry         *RegistryBinding            `json:"registry,omitempty"`
	ResourceProgress map[string]ResourceProgress `json:"resourceProgress,omitempty"`
	Sources          map[string]ResourceSource   `json:"sources,omitempty"`
	CleanupStarted   bool                        `json:"cleanupStarted,omitempty"`
	CleanupComplete  bool                        `json:"cleanupComplete,omitempty"`

	AgentStateCleanupPending bool `json:"agentStateCleanupPending,omitempty"`
}

// ResourceProgress records preparation evidence, independently of the owned cleanup ledger.
type ResourceProgress struct {
	ResourceID          string `json:"resourceId"`
	Supplied            bool   `json:"supplied"`
	PreflightPassed     bool   `json:"preflightPassed"`
	PreparationComplete bool   `json:"preparationComplete"`
}

func validateHistoricalNetwork(state PreparationState) error {
	if state.CleanupComplete {
		return nil
	}
	if _, recorded := state.Resources["R06Subnet"]; state.Network != nil || recorded {
		return fmt.Errorf("I03: an older automatic hosting-subnet lifecycle remains; retain its journal and " +
			"complete owned cleanup before selecting the current network behavior")
	}
	return nil
}

// RegistryBinding retains the selected registry without claiming ownership.
type RegistryBinding struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint,omitempty"`
	ABAC     bool   `json:"abac"`
	Verified bool   `json:"verified"`
}

// OwnedResource records an exact intended ID and its observed creation result.
type OwnedResource struct {
	ID       string   `json:"id"`
	Complete bool     `json:"complete"`
	Deleted  bool     `json:"deleted,omitempty"`
	Identity Identity `json:"identity,omitzero"`
}

// OwnedAssignment records an observed exact owned grant; reused customer grants are never added.
type OwnedAssignment struct {
	ID          string    `json:"id"`
	Scope       string    `json:"scope"`
	PrincipalID string    `json:"principalId"`
	RoleID      string    `json:"roleId"`
	Complete    bool      `json:"complete"`
	Deleted     bool      `json:"deleted,omitempty"`
	CreatedOn   time.Time `json:"createdOn"`
}

func confirmOwned(state PreparationState, step, id string, _ map[string]*string) error {
	record, ok := state.Resources[step]
	if !ok || !strings.EqualFold(record.ID, id) || state.DeploymentID == "" {
		return fmt.Errorf("%s: existing resource is not the exact journaled resource; refusing adoption", step)
	}
	return nil
}

func responseNotFound(err error) bool {
	response, ok := errors.AsType[*azcore.ResponseError](err)
	return ok && response.StatusCode == 404
}
