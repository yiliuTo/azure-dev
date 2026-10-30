// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

func deploymentResources(plan Plan) map[string]Resource {
	return map[string]Resource{
		"R01": {ID: "/subscriptions/" + plan.SubscriptionID + "/resourceGroups/" + plan.ResourceGroup,
			Supplied: plan.ResourceGroupSupplied},
		"R02": plan.Storage, "R03": plan.Registry, "R04": plan.Hosting, "R05": plan.Workload,
	}
}

func validateDeploymentData(plan Plan, spec FoundrySpec, state PreparationState) error {
	data := spec.Deployment
	if data == nil {
		return nil
	}
	role, err := arm.ParseResourceID(data.FederatedIdentityRoleDefinitionID)
	if err != nil || !validResourceIDSyntax(data.FederatedIdentityRoleDefinitionID) ||
		!strings.EqualFold(role.ResourceType.String(), "Microsoft.Authorization/roleDefinitions") || data.TenantID == "" {
		return fmt.Errorf("deployment requires the verified tenant and full G02 role-definition ID")
	}
	if data.KubeletRoleAssignmentID != "" {
		if !reusedKubeletGrantScope(data.KubeletRoleAssignmentID, data.RegistryID) {
			return fmt.Errorf("reused kubelet role assignment must apply to the registry or its RG/subscription")
		}
	}
	expected, err := PlannedDeployment(plan, Facts{
		TenantID: data.TenantID, KubeletObjectID: data.KubeletObjectID, RegistryABAC: spec.RegistryABAC,
		HostingIdentity: data.HostingIdentity, WorkloadIdentity: data.WorkloadIdentity,
	})
	if err != nil {
		return err
	}
	if !plan.Storage.Supplied && data.StorageSupplied {
		record, tracked := state.Resources["R02"]
		if !tracked || record.Deleted || state.CleanupComplete || !strings.EqualFold(record.ID, data.StorageID) {
			return fmt.Errorf("R02: owned Storage reference requires the exact active journaled resource")
		}
		expected.StorageSupplied = true
	}
	if !strings.EqualFold(data.ClusterID, expected.ClusterID) || !strings.EqualFold(data.Hosting.ID, expected.Hosting.ID) ||
		!strings.EqualFold(data.Workload.ID, expected.Workload.ID) ||
		!strings.EqualFold(data.StorageID, expected.StorageID) || !strings.EqualFold(data.RegistryID, expected.RegistryID) ||
		data.StorageSupplied != expected.StorageSupplied || data.RegistrySupplied != expected.RegistrySupplied ||
		data.ResourceGroupSupplied != expected.ResourceGroupSupplied || data.StorageSKU != expected.StorageSKU ||
		data.Hosting.Supplied != expected.Hosting.Supplied || data.Workload.Supplied != expected.Workload.Supplied ||
		data.RegistryABAC != spec.RegistryABAC || data.FederatedIdentityRoleDefinitionID == "" {
		return fmt.Errorf("deployment bindings differ from the internally planned resource graph")
	}
	if data.StorageCustomerSupplied != expected.StorageCustomerSupplied ||
		data.RegistryCustomerSupplied != expected.RegistryCustomerSupplied {
		return fmt.Errorf("deployment resource source differs from the original explicit selection")
	}
	return nil
}

func (l *ownedLifecycle) checkDeploymentResources(ctx context.Context, plan Plan, state PreparationState) error {
	check := func(step, id string, tags map[string]*string) error {
		if state.CleanupComplete {
			return fmt.Errorf("%s: resource exists after completed cleanup; refusing adoption", step)
		}
		return confirmOwned(state, step, id, tags)
	}
	if !plan.ResourceGroupSupplied {
		groups, err := armresources.NewResourceGroupsClient(plan.SubscriptionID, l.credential, l.options)
		if err != nil {
			return err
		}
		found, err := groups.Get(ctx, plan.ResourceGroup, nil)
		if err == nil {
			if err := check("R01", authString(found.ID), found.Tags); err != nil {
				return err
			}
		} else if !responseNotFound(err) {
			return fmt.Errorf("read planned resource-group creation target: %w", err)
		}
	}
	// List only existing identities at the target RG. No GET of a future identity is a preflight prerequisite.
	seenIdentities := map[string]bool{}
	if !plan.Hosting.Supplied || !plan.Workload.Supplied {
		identities, err := armmsi.NewUserAssignedIdentitiesClient(plan.SubscriptionID, l.credential, l.options)
		if err != nil {
			return err
		}
		pager := identities.NewListByResourceGroupPager(plan.ResourceGroup, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if responseNotFound(err) {
				break
			}
			if err != nil {
				return fmt.Errorf("read existing target identities for collision protection: %w", err)
			}
			for _, identity := range page.Value {
				if identity == nil {
					return fmt.Errorf("target identity listing is incomplete")
				}
				for step, resource := range map[string]Resource{"R04": plan.Hosting, "R05": plan.Workload} {
					if resource.Supplied {
						continue
					}
					if strings.EqualFold(authString(identity.ID), resource.ID) {
						seenIdentities[step] = true
						if err := check(step, authString(identity.ID), identity.Tags); err != nil {
							return err
						}
						if err := verifyOwnedIdentity(state, step, *identity); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	for _, step := range []string{"R04", "R05"} {
		if record, tracked := state.Resources[step]; tracked && record.Complete && !record.Deleted &&
			!state.CleanupComplete && !seenIdentities[step] {
			return fmt.Errorf("%s: a previously confirmed identity disappeared; refusing silent replacement", step)
		}
	}
	client, err := armresources.NewClient(plan.SubscriptionID, l.credential, l.options)
	if err != nil {
		return err
	}
	for step, resource := range map[string]Resource{"R02": plan.Storage, "R03": plan.Registry} {
		if resource.Supplied {
			record, tracked := state.Resources[step]
			if !tracked || state.CleanupComplete {
				continue
			}
			if !strings.EqualFold(record.ID, resource.ID) {
				return fmt.Errorf("%s: supplied selection differs from the active owned resource", step)
			}
		}
		version := "2024-01-01"
		if step == "R03" {
			version = "2025-05-01-preview"
		}
		found, err := client.GetByID(ctx, resource.ID, version, nil)
		if responseNotFound(err) {
			if record, tracked := state.Resources[step]; tracked && record.Complete &&
				!record.Deleted && !state.CleanupComplete {
				return fmt.Errorf("%s: a previously confirmed resource disappeared; refusing silent replacement", step)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: read creation target: %w", step, err)
		}
		if err := check(step, authString(found.ID), found.Tags); err != nil {
			return err
		}
	}
	return nil
}

func deploymentRecordNotFound(err error) bool {
	response, ok := errors.AsType[*azcore.ResponseError](err)
	return ok && response.StatusCode == 404 &&
		(response.ErrorCode == "DeploymentNotFound" || response.ErrorCode == "ResourceNotFound")
}
