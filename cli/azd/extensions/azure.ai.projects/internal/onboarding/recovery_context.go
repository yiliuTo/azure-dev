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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// ResolveRecoveryContext validates old attempts before supplied-identity permission checks.
// It is read-only, including in preview, and retains the original resource selections.
func ResolveRecoveryContext(
	ctx context.Context, plan Plan, credential azcore.TokenCredential, options *arm.ClientOptions, journal Journal,
) (Plan, error) {
	plan.Recovery = RecoveryContext{}
	lifecycle := &ownedLifecycle{credential: credential, options: onboardingARMOptions(options), journal: journal}
	state, err := lifecycle.load(ctx, plan)
	if err != nil {
		return plan, err
	}
	if err := validateProgressSelection(plan, state); err != nil {
		return plan, err
	}
	if state.CleanupComplete {
		return plan, nil
	}
	if state.CleanupStarted {
		return plan, fmt.Errorf("owned cleanup is incomplete; resume azd down before provisioning")
	}
	if err := validateHistoricalNetwork(state); err != nil {
		return plan, err
	}
	if state.Foundry == nil {
		return plan, nil
	}
	data := state.Foundry.Spec.Deployment
	if data == nil || !strings.EqualFold(data.ClusterID, plan.Cluster.ID) ||
		!strings.EqualFold(data.Hosting.ID, plan.Hosting.ID) || data.Hosting.Supplied != plan.Hosting.Supplied ||
		!strings.EqualFold(data.Workload.ID, plan.Workload.ID) || data.Workload.Supplied != plan.Workload.Supplied ||
		!strings.EqualFold(data.StorageID, plan.Storage.ID) || !strings.EqualFold(data.RegistryID, plan.Registry.ID) {
		return plan, fmt.Errorf("resource selections differ from the exact active ARM preparation intent")
	}
	_, ownedStorage := state.Resources["R02"]
	storageCustomerSupplied := data.StorageSupplied && !ownedStorage
	if storageCustomerSupplied != plan.Storage.Supplied {
		return plan, fmt.Errorf("Storage source differs from the exact active ARM preparation intent")
	}
	if err := lifecycle.verifyAttempts(ctx, plan, state.Foundry); err != nil {
		return plan, err
	}
	everSucceeded := false
	for _, attempt := range state.Foundry.Attempts {
		everSucceeded = everSucceeded || attempt.ProvisioningState == "Succeeded"
	}
	if !plan.Workload.Supplied {
		exists, err := lifecycle.existingWorkload(ctx, plan, state)
		if err != nil {
			return plan, err
		}
		plan.Recovery.ExistingWorkload = exists
		if plan.Hosting.Supplied && exists && !everSucceeded {
			plan.Recovery.FederationPending, err = lifecycle.pendingDependencyGrant(
				ctx, plan, plan.Workload.ID, "byo-federation-access",
				data.HostingIdentity.PrincipalID, data.FederatedIdentityRoleDefinitionID)
			if err != nil {
				return plan, err
			}
		}
	}
	if !plan.Storage.Supplied {
		client, err := armresources.NewClient(plan.SubscriptionID, credential, lifecycle.options)
		if err != nil {
			return plan, err
		}
		found, err := client.GetByID(ctx, plan.Storage.ID, "2024-01-01", nil)
		if err != nil && !responseNotFound(err) {
			return plan, fmt.Errorf("read exact intended Storage dependency: %w", err)
		}
		if err == nil {
			if err := confirmOwned(state, "R02", authString(found.ID), found.Tags); err != nil {
				return plan, err
			}
			plan.Recovery.ExistingStorage = true
			plan.Operations = slices.DeleteFunc(slices.Clone(plan.Operations), func(operation Operation) bool {
				return operation.CheckID == "P04" && operation.Action == "Microsoft.Storage/storageAccounts/write"
			})
			if plan.Workload.Supplied && !everSucceeded {
				plan.Recovery.StorageGrantPending, err = lifecycle.pendingDependencyGrant(
					ctx, plan, plan.Storage.ID, "byo-storage-access", data.WorkloadIdentity.PrincipalID,
					"/subscriptions/"+plan.SubscriptionID+"/providers/Microsoft.Authorization/roleDefinitions/"+
						"ba92f5b4-2d11-453d-a403-e96b0029c9fe")
				if err != nil {
					return plan, err
				}
			}
		}
	}
	return plan, nil
}

// Only an unfinished dependency grant needs a targeted read on partial retry.
// Successful graphs and completed grants cannot defer a newly missing permission.
func (l *ownedLifecycle) pendingDependencyGrant(
	ctx context.Context, plan Plan, scope, name, principalID, roleID string,
) (bool, error) {
	target, err := arm.ParseResourceID(scope)
	if err != nil {
		return false, err
	}
	client, err := armresources.NewDeploymentsClient(target.SubscriptionID, l.credential, l.options)
	if err != nil {
		return false, err
	}
	found, err := client.Get(ctx, target.ResourceGroupName, name, nil)
	if deploymentRecordNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read unfinished dependency grant deployment: %w", err)
	}
	expectedID := "/subscriptions/" + target.SubscriptionID + "/resourceGroups/" + target.ResourceGroupName +
		"/providers/Microsoft.Resources/deployments/" + name
	if !strings.EqualFold(authString(found.ID), expectedID) || found.Properties == nil {
		return false, fmt.Errorf("dependency grant deployment target is unverified")
	}
	raw, err := json.Marshal(found.Properties.Parameters)
	if err != nil {
		return false, err
	}
	var parameters map[string]struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &parameters); err != nil {
		return false, fmt.Errorf("decode dependency grant deployment parameters: %w", err)
	}
	for key, value := range map[string]string{
		"deploymentId": plan.DeploymentID, "resourceName": target.Name,
		"principalId": principalID, "roleDefinitionId": roleID,
	} {
		if value == "" || !strings.EqualFold(parameters[key].Value, value) {
			return false, fmt.Errorf("dependency grant deployment parameter %s differs from the retry intent", key)
		}
	}
	switch resourceValue(found.Properties.ProvisioningState) {
	case "Succeeded":
		return false, nil
	case "Failed", "Canceled":
		return true, nil
	default:
		return false, fmt.Errorf("dependency grant deployment is active or its state is unknown")
	}
}

func (l *ownedLifecycle) existingWorkload(ctx context.Context, plan Plan, state PreparationState) (bool, error) {
	client, err := armmsi.NewUserAssignedIdentitiesClient(plan.SubscriptionID, l.credential, l.options)
	if err != nil {
		return false, err
	}
	pager := client.NewListByResourceGroupPager(plan.ResourceGroup, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if responseNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("read existing intended workload dependency: %w", err)
		}
		for _, identity := range page.Value {
			if identity == nil {
				return false, fmt.Errorf("intended workload dependency listing is incomplete")
			}
			if !strings.EqualFold(authString(identity.ID), plan.Workload.ID) {
				continue
			}
			if err := confirmOwned(state, "R05", authString(identity.ID), identity.Tags); err != nil {
				return false, err
			}
			if err := verifyOwnedIdentity(state, "R05", *identity); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}
