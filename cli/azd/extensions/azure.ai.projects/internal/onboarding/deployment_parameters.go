// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"encoding/json"
	"fmt"

	"azure.ai.projects/internal/synthesis"
)

func verifyEffectiveGraph(plan Plan, spec FoundrySpec, parameters any) error {
	data := spec.Deployment
	if data == nil {
		return fmt.Errorf("recorded deployment has no exact effective graph intent")
	}
	account, err := ParseID(spec.AccountID, "Microsoft.CognitiveServices/accounts")
	if err != nil {
		return err
	}
	storage, err := ParseID(data.StorageID, "Microsoft.Storage/storageAccounts")
	if err != nil {
		return err
	}
	registry, err := ParseID(data.RegistryID, "Microsoft.ContainerRegistry/registries")
	if err != nil {
		return err
	}
	expected := synthesis.BYOOnboardingParameters{
		DeploymentID: plan.DeploymentID, AccountName: account.Name,
		ResourceGroupSupplied: data.ResourceGroupSupplied, ClusterResourceID: data.ClusterID,
		StorageAccountResourceID: data.StorageID, StorageName: storage.Name, StorageSupplied: data.StorageSupplied,
		StorageSKU: data.StorageSKU, HostingIdentityName: data.Hosting.Name, WorkloadIdentityName: data.Workload.Name,
		RegistryResourceID: data.RegistryID, RegistryName: registry.Name,
		RegistrySupplied: data.RegistrySupplied, RegistryABAC: data.RegistryABAC, KubeletObjectID: data.KubeletObjectID,
		FederatedIdentityRoleDefinitionID: data.FederatedIdentityRoleDefinitionID,
		KubeletRoleAssignmentID:           data.KubeletRoleAssignmentID,
		HostingIdentityResourceID:         data.Hosting.ID, WorkloadIdentityResourceID: data.Workload.ID,
		HostingIdentitySupplied: data.Hosting.Supplied, WorkloadIdentitySupplied: data.Workload.Supplied,
		HostingPrincipalID: data.HostingIdentity.PrincipalID, WorkloadPrincipalID: data.WorkloadIdentity.PrincipalID,
		CreateClusterGrants:   !data.Hosting.Supplied,
		CreateFederationGrant: !data.Hosting.Supplied || !data.Workload.Supplied,
		CreateStorageGrant:    !data.Workload.Supplied || !data.StorageCustomerSupplied,
	}
	raw, err := json.Marshal(parameters)
	if err != nil {
		return err
	}
	var actual struct {
		Binding struct {
			Value map[string]json.RawMessage `json:"value"`
		} `json:"byoOnboarding"`
	}
	if err := json.Unmarshal(raw, &actual); err != nil {
		return fmt.Errorf("decode exact effective graph parameters: %w", err)
	}
	rawExpected, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawExpected, &fields); err != nil {
		return err
	}
	if len(fields) != len(actual.Binding.Value) {
		return fmt.Errorf("recorded deployment effective graph parameters are missing or contain unsupported fields")
	}
	for name, value := range fields {
		if string(actual.Binding.Value[name]) != string(value) {
			return fmt.Errorf("recorded deployment effective graph parameter %s changed or is unavailable", name)
		}
	}
	return nil
}
