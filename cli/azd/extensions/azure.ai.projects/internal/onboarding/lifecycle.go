// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// FoundrySpec retains the effective resource selections for another deployment attempt.
type FoundrySpec struct {
	AccountID      string          `json:"accountId"`
	ProjectID      string          `json:"projectId"`
	RegistryID     string          `json:"registryId"`
	RegistryABAC   bool            `json:"registryABAC"`
	Location       string          `json:"location"`
	TemplateHash   string          `json:"templateHash,omitempty"`
	TemplateDigest string          `json:"templateDigest,omitempty"`
	Deployment     *DeploymentData `json:"deployment,omitempty"`
}

// FoundryAttempt is persisted before submitting one generation of the stable ARM deployment.
type FoundryAttempt struct {
	ID                string `json:"id"`
	CorrelationID     string `json:"correlationId,omitempty"`
	Terminal          bool   `json:"terminal"`
	TemplateHash      string `json:"templateHash,omitempty"`
	TemplateDigest    string `json:"templateDigest,omitempty"`
	ARMTemplateHash   string `json:"armTemplateHash,omitempty"`
	ProvisioningState string `json:"provisioningState,omitempty"`
	Archived          bool   `json:"archived,omitempty"`
}

// FoundryState preserves deployment bindings and local cleanup progress across interruptions.
type FoundryState struct {
	Spec            FoundrySpec      `json:"spec"`
	Attempts        []FoundryAttempt `json:"attempts"`
	ProjectEndpoint string           `json:"projectEndpoint,omitempty"`
	ProjectDeleted  bool             `json:"projectDeleted,omitempty"`
	AccountDeleted  bool             `json:"accountDeleted"`
	Purged          bool             `json:"purged"`
}

// Lifecycle retains deployment intent and ARM results for interrupted provisioning.
type Lifecycle interface {
	Check(context.Context, Plan, FoundrySpec) (Report, error)
	Start(context.Context, Plan, FoundrySpec, string) error
	Observe(context.Context, Plan, armresources.DeploymentExtended) error
}

type ownedLifecycle struct {
	credential azcore.TokenCredential
	options    *arm.ClientOptions
	journal    Journal
}

// NewLifecycle binds deployment attempts to the environment's persisted resource selections.
func NewLifecycle(credential azcore.TokenCredential, options *arm.ClientOptions, journal Journal) Lifecycle {
	return &ownedLifecycle{credential: credential, options: onboardingARMOptions(options), journal: journal}
}

// PlannedFoundryAccount returns the actual BYO account target bound into the standard template.
func PlannedFoundryAccount(plan Plan) Resource {
	return plan.Account
}

// CleanupPlan resolves only persisted target scope, independent of the current YAML or environment defaults.
func CleanupPlan(state PreparationState) (Plan, error) {
	if state.Version != preparationJournalVersion || state.DeploymentID == "" || state.Environment == "" ||
		state.SubscriptionID == "" || state.ResourceGroup == "" || state.Location == "" {
		return Plan{}, fmt.Errorf("legacy/unknown ownership journal lacks an authoritative cleanup target")
	}
	plan := Plan{
		DeploymentID: state.DeploymentID, Environment: state.Environment,
		SubscriptionID: state.SubscriptionID, ResourceGroup: state.ResourceGroup, Location: state.Location,
	}
	if _, err := subscriptionDeploymentID(plan.DeploymentID, plan.SubscriptionID); err != nil {
		return Plan{}, fmt.Errorf("persisted cleanup deployment scope is invalid: %w", err)
	}
	if state.Foundry != nil {
		account, err := ParseID(state.Foundry.Spec.AccountID, "Microsoft.CognitiveServices/accounts")
		if err != nil || !strings.EqualFold(account.SubscriptionID, plan.SubscriptionID) ||
			!strings.EqualFold(account.ResourceGroupName, plan.ResourceGroup) {
			return Plan{}, fmt.Errorf("persisted account target does not belong to the resource group")
		}
		project, err := ParseID(state.Foundry.Spec.ProjectID, "Microsoft.CognitiveServices/accounts/projects")
		if err != nil || !strings.EqualFold(project.Parent.String(), account.String()) {
			return Plan{}, fmt.Errorf("persisted Project target does not belong to the account")
		}
		if state.Foundry.ProjectEndpoint != "" {
			if err := recordProjectEndpoint(&state, state.Foundry.ProjectEndpoint); err != nil {
				return Plan{}, err
			}
		}
		plan.Account = Resource{ID: state.Foundry.Spec.AccountID, Name: account.Name, Parent: account.Parent.String()}
	}
	if _, err := ParseID("/subscriptions/"+plan.SubscriptionID+"/resourceGroups/"+plan.ResourceGroup,
		"Microsoft.Resources/resourceGroups"); err != nil {
		return Plan{}, fmt.Errorf("persisted cleanup target is invalid: %w", err)
	}
	return plan, nil
}

func (l *ownedLifecycle) load(ctx context.Context, plan Plan) (PreparationState, error) {
	if l.journal == nil || plan.DeploymentID == "" || plan.Environment == "" {
		return PreparationState{}, fmt.Errorf("owned lifecycle requires a durable journal, environment and deployment scope")
	}
	state, err := l.journal.Load(ctx)
	if err != nil {
		return state, fmt.Errorf("read owned lifecycle journal: %w", err)
	}
	if state.Version != 0 && state.Version != preparationJournalVersion {
		return state, fmt.Errorf("legacy/unknown journal cannot prove whether Foundry was deployed; resolve its lifecycle first")
	}
	if state.DeploymentID != "" && (!strings.EqualFold(state.DeploymentID, plan.DeploymentID) ||
		state.Environment != plan.Environment) {
		return state, fmt.Errorf("owned lifecycle journal belongs to another environment")
	}
	if state.DeploymentID != "" && (!strings.EqualFold(state.SubscriptionID, plan.SubscriptionID) ||
		!strings.EqualFold(state.ResourceGroup, plan.ResourceGroup) ||
		!strings.EqualFold(state.Location, plan.Location) || state.Location == "") {
		return state, fmt.Errorf("journaled target scope/location is missing or differs from the environment")
	}
	if state.DeploymentID == "" && (state.Foundry != nil || len(state.Resources) > 0 ||
		len(state.ResourceProgress) > 0) {
		return state, fmt.Errorf("owned lifecycle journal has entries without an owner")
	}
	return state, nil
}

func validateFoundrySpec(plan Plan, spec FoundrySpec) error {
	if spec.Deployment == nil {
		return fmt.Errorf("Foundry lifecycle requires exact effective deployment graph bindings")
	}
	account, err := ParseID(spec.AccountID, "Microsoft.CognitiveServices/accounts")
	if err != nil || !strings.EqualFold(spec.AccountID, PlannedFoundryAccount(plan).ID) {
		return fmt.Errorf("Foundry account does not match the internally planned target")
	}
	project, err := ParseID(spec.ProjectID, "Microsoft.CognitiveServices/accounts/projects")
	if err != nil || !strings.EqualFold(project.Parent.String(), account.String()) || spec.Location == "" ||
		!strings.EqualFold(spec.Location, plan.Location) {
		return fmt.Errorf("Foundry project/location does not match the exact account target")
	}
	if _, err := ParseID(spec.RegistryID, "Microsoft.ContainerRegistry/registries"); err != nil {
		return fmt.Errorf("Foundry lifecycle registry is invalid: %w", err)
	}
	return nil
}

func sameFoundrySpec(a, b FoundrySpec) bool {
	same := strings.EqualFold(a.AccountID, b.AccountID) && strings.EqualFold(a.ProjectID, b.ProjectID) &&
		strings.EqualFold(a.Location, b.Location) && strings.EqualFold(a.RegistryID, b.RegistryID) &&
		a.RegistryABAC == b.RegistryABAC
	if !same || a.Deployment == nil || b.Deployment == nil {
		return same && a.Deployment == nil && b.Deployment == nil
	}
	x, y := a.Deployment, b.Deployment
	return strings.EqualFold(x.ClusterID, y.ClusterID) && strings.EqualFold(x.StorageID, y.StorageID) &&
		strings.EqualFold(x.Hosting.ID, y.Hosting.ID) && strings.EqualFold(x.Workload.ID, y.Workload.ID) &&
		strings.EqualFold(x.KubeletObjectID, y.KubeletObjectID) && strings.EqualFold(x.TenantID, y.TenantID) &&
		strings.EqualFold(x.FederatedIdentityRoleDefinitionID, y.FederatedIdentityRoleDefinitionID) &&
		x.Hosting.Supplied == y.Hosting.Supplied && x.Workload.Supplied == y.Workload.Supplied &&
		x.StorageCustomerSupplied == y.StorageCustomerSupplied && x.RegistryCustomerSupplied == y.RegistryCustomerSupplied &&
		x.HostingIdentity == y.HostingIdentity && x.WorkloadIdentity == y.WorkloadIdentity
}

func (l *ownedLifecycle) Check(ctx context.Context, plan Plan, spec FoundrySpec) (Report, error) {
	check := resourceCheck("I03", spec.AccountID, "exact Foundry creation/reuse and deployment ownership")
	check.Status = Fail
	fail := func(err error) (Report, error) {
		check.Observed = RedactDiagnostic(err.Error())
		check.Missing = "unambiguous persisted lifecycle ownership; retain the journal and resolve the reported state"
		return Report{check}, err
	}
	if err := validateFoundrySpec(plan, spec); err != nil {
		return fail(err)
	}
	state, err := l.load(ctx, plan)
	if err != nil {
		return fail(err)
	}
	if err := validateProgressSelection(plan, state); err != nil {
		return fail(err)
	}
	if err := validateDeploymentData(plan, spec, state); err != nil {
		return fail(err)
	}
	if err := validateHistoricalNetwork(state); err != nil {
		return fail(err)
	}
	if !state.CleanupComplete && state.DeploymentID != "" && state.Foundry == nil &&
		len(state.Resources) > 0 {
		return fail(fmt.Errorf("legacy dependency ownership remains; retain the journal and complete azd down before deployment"))
	}
	if state.CleanupStarted && !state.CleanupComplete {
		return fail(fmt.Errorf("owned cleanup is incomplete; resume azd down before provisioning"))
	}
	if !state.CleanupComplete && state.Registry != nil &&
		(!strings.EqualFold(state.Registry.ID, spec.RegistryID) ||
			state.Registry.Verified && state.Registry.ABAC != spec.RegistryABAC) {
		return fail(fmt.Errorf("registry differs from the recorded deployment binding"))
	}
	if state.Foundry != nil {
		if !state.CleanupComplete && state.Foundry.Spec.Deployment == nil && spec.Deployment != nil {
			return fail(fmt.Errorf("legacy deployment ownership remains; complete exact owned cleanup before the new ARM graph"))
		}
		if !state.CleanupComplete && !sameFoundrySpec(state.Foundry.Spec, spec) {
			return fail(fmt.Errorf("Foundry selections differ from the active ownership journal"))
		}
		if err := l.verifyAttempts(ctx, plan, state.Foundry); err != nil {
			return fail(err)
		}
	}
	if err := l.checkDeploymentResources(ctx, plan, state); err != nil {
		return fail(err)
	}
	account, err := ParseID(spec.AccountID, "Microsoft.CognitiveServices/accounts")
	if err != nil {
		return fail(err)
	}
	client, err := armcognitiveservices.NewAccountsClient(account.SubscriptionID, l.credential, l.options)
	if err != nil {
		return fail(err)
	}
	found, err := client.Get(ctx, account.ResourceGroupName, account.Name, nil)
	if err == nil {
		if state.Foundry == nil || state.Foundry.AccountDeleted ||
			!strings.EqualFold(authString(found.ID), spec.AccountID) ||
			!strings.EqualFold(authString(found.Location), spec.Location) {
			return fail(fmt.Errorf("Foundry account is not the exact journaled account; refusing adoption"))
		}
	} else if !responseNotFound(err) {
		return fail(fmt.Errorf("read Foundry creation target: %w", err))
	} else if state.Foundry != nil && state.Foundry.AccountDeleted && !state.Foundry.Purged {
		deleted, err := armcognitiveservices.NewDeletedAccountsClient(account.SubscriptionID, l.credential, l.options)
		if err != nil {
			return fail(err)
		}
		if _, err := deleted.Get(ctx, spec.Location, account.ResourceGroupName, account.Name, nil); err == nil {
			return fail(fmt.Errorf("Foundry account remains soft-deleted; explicitly use azd down --purge or await retention"))
		} else if !responseNotFound(err) {
			return fail(fmt.Errorf("verify soft-deleted Foundry name reservation: %w", err))
		}
	}
	check.Status, check.Observed = Pass, "exact account is absent or has matching durable ownership; no active ARM attempt"
	return Report{check}, nil
}

func (l *ownedLifecycle) Start(ctx context.Context, plan Plan, spec FoundrySpec, deploymentID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateFoundrySpec(plan, spec); err != nil {
		return err
	}
	if spec.TemplateHash == "" {
		return fmt.Errorf("deployment intent requires the generated template version before submission")
	}
	if spec.TemplateDigest == "" {
		return fmt.Errorf("deployment intent requires the actual template content digest before submission")
	}
	_, err := subscriptionDeploymentID(deploymentID, plan.SubscriptionID)
	if err != nil || !strings.EqualFold(deploymentID, plan.DeploymentID) {
		return fmt.Errorf("Foundry attempt requires an exact subscription deployment ID")
	}
	state, err := l.load(ctx, plan)
	if err != nil {
		return err
	}
	if err := validateProgressSelection(plan, state); err != nil {
		return err
	}
	if state.CleanupStarted && !state.CleanupComplete {
		return fmt.Errorf("Foundry attempt requires no pending cleanup")
	}
	if state.DeploymentID != "" && state.Foundry == nil && !state.CleanupComplete &&
		len(state.Resources) > 0 {
		return fmt.Errorf("legacy dependency ownership remains; complete owned cleanup before starting a new deployment")
	}
	if !state.CleanupComplete && state.Foundry != nil &&
		state.Foundry.Spec.Deployment == nil && spec.Deployment != nil {
		return fmt.Errorf("legacy deployment ownership remains; complete exact owned cleanup before the new ARM graph")
	}
	if err := validateHistoricalNetwork(state); err != nil {
		return err
	}
	if !state.CleanupComplete && state.Registry != nil &&
		(!strings.EqualFold(state.Registry.ID, spec.RegistryID) ||
			state.Registry.Verified && state.Registry.ABAC != spec.RegistryABAC) {
		return fmt.Errorf("Foundry attempt registry does not match the recorded binding")
	}
	if err := l.checkDeploymentResources(ctx, plan, state); err != nil {
		return err
	}
	if err := validateDeploymentData(plan, spec, state); err != nil {
		return err
	}
	if state.CleanupComplete {
		state.Resources = map[string]OwnedResource{}
		state.Network = nil
	}
	state.Version = preparationJournalVersion
	state.DeploymentID, state.Environment, state.SubscriptionID = plan.DeploymentID, plan.Environment, plan.SubscriptionID
	state.ResourceGroup, state.Location = plan.ResourceGroup, plan.Location
	if err := validateProgressSelection(plan, state); err != nil {
		return err
	}
	if state.ResourceProgress == nil {
		state.ResourceProgress = selectedProgress(plan)
	}
	if state.Resources == nil {
		state.Resources = map[string]OwnedResource{}
	}
	for step, resource := range deploymentResources(plan) {
		if resource.Supplied {
			continue
		}
		if previous, exists := state.Resources[step]; exists {
			if !strings.EqualFold(previous.ID, resource.ID) || previous.Deleted {
				return fmt.Errorf("%s: planned resource differs from active ownership", step)
			}
		} else {
			state.Resources[step] = OwnedResource{ID: resource.ID}
		}
	}
	state.Registry = &RegistryBinding{ID: spec.RegistryID, ABAC: spec.RegistryABAC}
	if state.Foundry == nil || state.CleanupComplete {
		state.Foundry = &FoundryState{Spec: spec}
	} else if state.Foundry.AccountDeleted {
		state.Foundry = &FoundryState{Spec: spec, Attempts: slices.Clone(state.Foundry.Attempts)}
	}
	if !sameFoundrySpec(state.Foundry.Spec, spec) {
		return fmt.Errorf("Foundry attempt does not match the journaled selections")
	}
	if len(state.Foundry.Attempts) > 0 {
		if err := l.verifyAttempts(ctx, plan, state.Foundry); err != nil {
			return err
		}
		for index := range state.Foundry.Attempts {
			attempt := &state.Foundry.Attempts[index]
			attempt.Archived = true
		}
	}
	for _, attempt := range state.Foundry.Attempts {
		if !attempt.Terminal {
			return fmt.Errorf("previous ARM attempt is unresolved")
		}
	}
	state.Foundry.Spec.TemplateHash = spec.TemplateHash
	state.Foundry.Spec.TemplateDigest = spec.TemplateDigest
	state.Foundry.Spec.Deployment = spec.Deployment
	state.Foundry.Attempts = append(state.Foundry.Attempts, FoundryAttempt{
		ID: deploymentID, TemplateHash: spec.TemplateHash, TemplateDigest: spec.TemplateDigest,
	})
	state.Foundry.AccountDeleted, state.Foundry.Purged = false, false
	state.CleanupStarted, state.CleanupComplete = false, false
	return l.journal.Save(ctx, state)
}

func (l *ownedLifecycle) verifyAttempts(ctx context.Context, plan Plan, foundry *FoundryState) error {
	if len(foundry.Attempts) == 0 {
		return fmt.Errorf("Foundry lifecycle has no exact ARM attempt evidence")
	}
	seen := map[string]bool{}
	for index := range foundry.Attempts {
		attempt := &foundry.Attempts[index]
		id, err := subscriptionDeploymentID(attempt.ID, plan.SubscriptionID)
		if err != nil || !strings.EqualFold(attempt.ID, plan.DeploymentID) {
			return fmt.Errorf("invalid or duplicate recorded Foundry deployment ID")
		}
		if attempt.TemplateHash == "" || attempt.TemplateDigest == "" {
			return fmt.Errorf("recorded deployment's actual template binding is unverified")
		}
		if attempt.Archived {
			if attempt.CorrelationID != "" && seen[attempt.CorrelationID] {
				return fmt.Errorf("duplicate archived deployment generation")
			}
			if attempt.CorrelationID != "" {
				seen[attempt.CorrelationID] = true
			}
			continue
		}
		client, err := armresources.NewDeploymentsClient(id.SubscriptionID, l.credential, l.options)
		if err != nil {
			return err
		}
		observed, err := client.GetAtSubscriptionScope(ctx, id.Name, nil)
		if err != nil {
			return fmt.Errorf("read previous ARM deployment before retry: %w", err)
		}
		properties := observed.Properties
		if !strings.EqualFold(authString(observed.ID), attempt.ID) || properties == nil {
			return fmt.Errorf("recorded deployment ownership changed or is unverified")
		}
		if properties.Mode == nil || *properties.Mode != armresources.DeploymentModeIncremental {
			return fmt.Errorf("recorded deployment is not the selected single Incremental graph")
		}
		actualHash := authString(properties.TemplateHash)
		if actualHash == "" || attempt.ARMTemplateHash != "" && actualHash != attempt.ARMTemplateHash {
			return fmt.Errorf("recorded deployment's actual template binding is unverified or changed")
		}
		var parameters map[string]struct {
			Value string `json:"value"`
		}
		raw, err := json.Marshal(properties.Parameters)
		if err != nil {
			return err
		}
		// Only decode the ownership bindings; ordinary parameters include non-string values.
		var values map[string]json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return fmt.Errorf("deployment ownership parameters are unavailable: %w", err)
		}
		for _, key := range []string{"resourceGroupName", "location", "foundryProjectName"} {
			var value struct {
				Value string `json:"value"`
			}
			if err := json.Unmarshal(values[key], &value); err != nil {
				return fmt.Errorf("deployment ownership parameter %s is unavailable: %w", key, err)
			}
			if parameters == nil {
				parameters = map[string]struct {
					Value string `json:"value"`
				}{}
			}
			parameters[key] = value
		}
		if !strings.EqualFold(parameters["resourceGroupName"].Value, plan.ResourceGroup) ||
			!strings.EqualFold(parameters["location"].Value, plan.Location) {
			return fmt.Errorf("recorded deployment target/ownership parameters changed")
		}
		project, err := ParseID(foundry.Spec.ProjectID, "Microsoft.CognitiveServices/accounts/projects")
		if err != nil || !strings.EqualFold(parameters["foundryProjectName"].Value, project.Name) {
			return fmt.Errorf("recorded deployment project target changed")
		}
		if err := verifyEffectiveGraph(plan, foundry.Spec, properties.Parameters); err != nil {
			return err
		}
		correlation := authString(properties.CorrelationID)
		if correlation == "" || seen[correlation] ||
			(attempt.CorrelationID != "" && attempt.CorrelationID != correlation) {
			return fmt.Errorf("recorded deployment correlation is missing or changed")
		}
		if properties.ProvisioningState == nil {
			return fmt.Errorf("recorded deployment state is unknown")
		}
		switch string(*properties.ProvisioningState) {
		case "Succeeded", "Failed", "Canceled":
			attempt.Terminal, attempt.CorrelationID = true, correlation
			attempt.ProvisioningState = string(*properties.ProvisioningState)
			attempt.ARMTemplateHash = actualHash
		default:
			return fmt.Errorf("recorded deployment is still active; wait for it to terminate before proceeding")
		}
		seen[correlation] = true
	}
	return nil
}

func subscriptionDeploymentID(value, subscription string) (*arm.ResourceID, error) {
	if !validResourceIDSyntax(value) {
		return nil, fmt.Errorf("invalid subscription deployment ID syntax")
	}
	id, err := arm.ParseResourceID(value)
	if err != nil || id.ResourceGroupName != "" || !strings.EqualFold(id.SubscriptionID, subscription) ||
		!strings.EqualFold(id.ResourceType.String(), "Microsoft.Resources/deployments") || id.Name == "" ||
		!strings.EqualFold(value, "/subscriptions/"+subscription+"/providers/Microsoft.Resources/deployments/"+id.Name) {
		return nil, fmt.Errorf("invalid subscription deployment target")
	}
	return id, nil
}

func (l *ownedLifecycle) Observe(ctx context.Context, plan Plan, result armresources.DeploymentExtended) error {
	state, err := l.load(ctx, plan)
	if err != nil {
		return err
	}
	if state.Foundry == nil {
		return fmt.Errorf("Foundry lifecycle intent is missing")
	}
	if len(state.Foundry.Attempts) == 0 || result.Properties == nil || result.Properties.ProvisioningState == nil {
		return fmt.Errorf("ARM deployment result is missing its attempt or state")
	}
	attempt := &state.Foundry.Attempts[len(state.Foundry.Attempts)-1]
	if !strings.EqualFold(attempt.ID, plan.DeploymentID) ||
		result.ID != nil && !strings.EqualFold(*result.ID, attempt.ID) {
		return fmt.Errorf("ARM deployment result differs from the submitted target")
	}
	if attempt.TemplateHash == "" || attempt.TemplateDigest == "" {
		return fmt.Errorf("submitted deployment template binding is missing")
	}
	correlation := authString(result.Properties.CorrelationID)
	if correlation == "" || attempt.CorrelationID != "" && attempt.CorrelationID != correlation {
		return fmt.Errorf("ARM deployment result correlation is missing or changed")
	}
	for _, previous := range state.Foundry.Attempts[:len(state.Foundry.Attempts)-1] {
		if previous.CorrelationID == correlation {
			return fmt.Errorf("ARM deployment result correlation belongs to an earlier attempt")
		}
	}
	status := string(*result.Properties.ProvisioningState)
	switch status {
	case "Succeeded", "Failed", "Canceled":
		attempt.Terminal = true
	default:
		return fmt.Errorf("ARM deployment result is not terminal: %s", status)
	}
	attempt.CorrelationID = correlation
	attempt.ProvisioningState = status
	attempt.ARMTemplateHash = authString(result.Properties.TemplateHash)
	if status == "Succeeded" {
		raw, err := json.Marshal(result.Properties.Outputs)
		if err != nil {
			return fmt.Errorf("encode deployment outputs for retry state: %w", err)
		}
		var outputs struct {
			ProjectEndpoint struct {
				Value string `json:"value"`
			} `json:"FOUNDRY_PROJECT_ENDPOINT"`
		}
		if err := json.Unmarshal(raw, &outputs); err != nil {
			return fmt.Errorf("decode Project endpoint from deployment outputs: %w", err)
		}
		if err := recordProjectEndpoint(&state, outputs.ProjectEndpoint.Value); err != nil {
			return err
		}
	}
	return l.journal.Save(ctx, state)
}
