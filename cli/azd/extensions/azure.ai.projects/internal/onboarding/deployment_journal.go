// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
)

const preparationJournalVersion = 3

// Journal atomically stores deployment intents and retry progress. Load returns a zero state when absent.
// Callers must serialize deployment for an environment; this interface is not a distributed lock.
type Journal interface {
	Load(context.Context) (PreparationState, error)
	Save(context.Context, PreparationState) error
}

// PreparationState binds deployment selections, attempts and local cleanup progress to an environment.
type PreparationState struct {
	Version          int                         `json:"version"`
	SubscriptionID   string                      `json:"subscriptionId"`
	ResourceGroup    string                      `json:"resourceGroup"`
	Location         string                      `json:"location"`
	Environment      string                      `json:"environment"`
	DeploymentID     string                      `json:"deploymentId"`
	Network          *SubnetPreparation          `json:"network,omitempty"`
	Resources        map[string]OwnedResource    `json:"resources"`
	Foundry          *FoundryState               `json:"foundry,omitempty"`
	Registry         *RegistryBinding            `json:"registry,omitempty"`
	ResourceProgress map[string]ResourceProgress `json:"resourceProgress,omitempty"`
	CleanupStarted   bool                        `json:"cleanupStarted,omitempty"`
	CleanupComplete  bool                        `json:"cleanupComplete,omitempty"`

	AgentStateCleanupPending bool `json:"agentStateCleanupPending,omitempty"`
}

// ResourceProgress records current preflight results for the selected dependencies.
type ResourceProgress struct {
	ResourceID      string `json:"resourceId"`
	Supplied        bool   `json:"supplied"`
	PreflightPassed bool   `json:"preflightPassed"`
}

func validateHistoricalNetwork(state PreparationState) error {
	if state.CleanupComplete {
		return nil
	}
	if _, recorded := state.Resources["R06Subnet"]; state.Network != nil || recorded {
		return fmt.Errorf("I03: an older automatic hosting-subnet lifecycle remains; retain its journal and " +
			"complete azd down before selecting the current network behavior")
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

// OwnedResource binds a planned creation target and optional identity metadata for retry.
type OwnedResource struct {
	ID       string   `json:"id"`
	Complete bool     `json:"complete"`
	Deleted  bool     `json:"deleted,omitempty"`
	Identity Identity `json:"identity,omitzero"`
}

func confirmOwned(state PreparationState, step, id string, _ map[string]*string) error {
	record, ok := state.Resources[step]
	if !ok || !strings.EqualFold(record.ID, id) || state.DeploymentID == "" {
		return fmt.Errorf("%s: existing resource is not the exact journaled resource; refusing adoption", step)
	}
	return nil
}

func verifyOwnedIdentity(state PreparationState, step string, identity armmsi.Identity) error {
	if err := confirmOwned(state, step, authString(identity.ID), identity.Tags); err != nil {
		return err
	}
	record := state.Resources[step].Identity
	if record.PrincipalID != "" && (identity.Properties == nil ||
		!strings.EqualFold(authString(identity.Properties.PrincipalID), record.PrincipalID) ||
		!strings.EqualFold(authString(identity.Properties.ClientID), record.ClientID) ||
		!strings.EqualFold(authString(identity.Properties.TenantID), record.TenantID)) {
		return fmt.Errorf("recorded identity principal/client/tenant changed; refusing reuse")
	}
	return nil
}

func responseNotFound(err error) bool {
	response, ok := errors.AsType[*azcore.ResponseError](err)
	return ok && response.StatusCode == 404
}
