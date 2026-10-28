// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// AttemptEvidence is an immutable terminal-generation snapshot. Stable ARM
// deployment records (including nested deployments) can be replaced on retry.
type AttemptEvidence struct {
	Properties     *armresources.DeploymentPropertiesExtended            `json:"properties"`
	Operations     map[string][]*armresources.DeploymentOperation        `json:"operations"`
	Deployments    map[string]*armresources.DeploymentPropertiesExtended `json:"deployments"`
	TemplateDigest string                                                `json:"templateDigest"`
	Digest         string                                                `json:"digest"`
}

func evidenceDigest(e AttemptEvidence) (string, error) {
	raw, err := json.Marshal(struct {
		Properties     *armresources.DeploymentPropertiesExtended            `json:"properties"`
		Operations     map[string][]*armresources.DeploymentOperation        `json:"operations"`
		Deployments    map[string]*armresources.DeploymentPropertiesExtended `json:"deployments"`
		TemplateDigest string                                                `json:"templateDigest"`
	}{e.Properties, e.Operations, e.Deployments, e.TemplateDigest})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func validateAttemptEvidence(attempt FoundryAttempt) error {
	e := attempt.Evidence
	if !attempt.Terminal || attempt.CorrelationID == "" || attempt.TemplateDigest == "" ||
		attempt.ARMTemplateHash == "" || e == nil || e.Properties == nil ||
		e.TemplateDigest != attempt.TemplateDigest ||
		authString(e.Properties.CorrelationID) != attempt.CorrelationID ||
		authString(e.Properties.TemplateHash) != attempt.ARMTemplateHash ||
		e.Properties.ProvisioningState == nil ||
		string(*e.Properties.ProvisioningState) != attempt.ProvisioningState {
		return fmt.Errorf("archived deployment provenance is missing or changed")
	}
	digest, err := evidenceDigest(*e)
	if err != nil || digest != e.Digest {
		return fmt.Errorf("archived deployment provenance content changed")
	}
	if _, ok := e.Operations[strings.ToLower(attempt.ID)]; !ok {
		return fmt.Errorf("archived deployment root operations are missing")
	}
	if e.Deployments == nil {
		return fmt.Errorf("archived nested deployment generation evidence is missing")
	}
	for id, operations := range e.Operations {
		if !strings.EqualFold(id, attempt.ID) {
			if _, exists := e.Deployments[id]; !exists {
				return fmt.Errorf("archived operation source has no exact nested generation evidence")
			}
		}
		children, err := nestedCreateOperations(operations, id)
		if err != nil {
			return err
		}
		for _, operation := range children {
			properties, ok := e.Deployments[strings.ToLower(authString(operation.Properties.TargetResource.ID))]
			if !ok || properties != nil && (properties.ProvisioningState == nil ||
				string(*properties.ProvisioningState) != authString(operation.Properties.ProvisioningState)) {
				return fmt.Errorf("nested deployment generation differs from its exact parent Create result")
			}
		}
	}
	for id, properties := range e.Deployments {
		if properties == nil {
			proven := false
			for parent, operations := range e.Operations {
				for _, operation := range operations {
					if nestedValidationRejected(operation, parent) && operation.Properties.TargetResource != nil &&
						strings.EqualFold(authString(operation.Properties.TargetResource.ID), id) &&
						attempt.ProvisioningState == "Failed" {
						proven = true
					}
				}
			}
			if !proven {
				return fmt.Errorf("archived absent nested deployment has no exact validation rejection evidence")
			}
		} else if err := verifyNestedGeneration(properties, attempt.CorrelationID); err != nil {
			return err
		}
	}
	return nil
}

func (l *ownedLifecycle) captureAttemptEvidence(
	ctx context.Context, attempt *FoundryAttempt, properties *armresources.DeploymentPropertiesExtended,
) error {
	if attempt.Evidence != nil {
		if err := validateAttemptEvidence(*attempt); err != nil {
			return err
		}
		rawOld, _ := json.Marshal(attempt.Evidence.Properties)
		rawNew, _ := json.Marshal(properties)
		if string(rawOld) != string(rawNew) {
			return fmt.Errorf("terminal deployment generation changed after provenance capture")
		}
	}
	e := &AttemptEvidence{Properties: properties, Operations: map[string][]*armresources.DeploymentOperation{},
		Deployments:    map[string]*armresources.DeploymentPropertiesExtended{},
		TemplateDigest: attempt.TemplateDigest}
	var read func(string, bool) error
	read = func(deploymentID string, rejected bool) error {
		key := strings.ToLower(deploymentID)
		if _, ok := e.Operations[key]; ok {
			return nil
		}

		if len(e.Operations) >= 256 {
			return fmt.Errorf("deployment operation graph exceeds the supported observation bound")
		}
		id, err := arm.ParseResourceID(deploymentID)
		if err != nil || !validResourceIDSyntax(deploymentID) ||
			!strings.EqualFold(id.ResourceType.String(), "Microsoft.Resources/deployments") {
			return fmt.Errorf("invalid exact nested deployment source")
		}
		e.Operations[key] = []*armresources.DeploymentOperation{}
		var before *armresources.DeploymentPropertiesExtended
		absentNested := false
		if !strings.EqualFold(deploymentID, attempt.ID) {
			observed, err := l.readNestedGeneration(ctx, deploymentID, attempt.CorrelationID)
			if deploymentRecordNotFound(err) && rejected {
				absentNested = true
				e.Deployments[key] = nil
			} else if err != nil {
				return err
			} else {
				before = observed
				e.Deployments[key] = observed
			}
		}
		pager, err := NewDeploymentOperationsPager(deploymentID, l.credential, l.options)
		if err != nil {
			return err
		}
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if deploymentRecordNotFound(err) && rejected {
				return l.confirmRejectedDeploymentAbsent(ctx, deploymentID)
			}
			if err != nil {
				return fmt.Errorf("retain exact terminal deployment operations before replacement: %w", err)
			}
			if absentNested {
				return fmt.Errorf("rejected nested deployment absence conflicts with existing operation evidence")
			}
			e.Operations[key] = append(e.Operations[key], page.Value...)
		}
		children, err := nestedCreateOperations(e.Operations[key], deploymentID)
		if err != nil {
			return err
		}
		for _, operation := range children {
			target := authString(operation.Properties.TargetResource.ID)
			if err := read(target, attempt.ProvisioningState == "Failed" &&
				nestedValidationRejected(operation, deploymentID)); err != nil {
				return err
			}
			if properties := e.Deployments[strings.ToLower(target)]; properties != nil &&
				(properties.ProvisioningState == nil ||
					string(*properties.ProvisioningState) != authString(operation.Properties.ProvisioningState)) {
				return fmt.Errorf("nested deployment generation differs from its exact parent Create result")
			}
		}
		if before != nil {
			after, err := l.readNestedGeneration(ctx, deploymentID, attempt.CorrelationID)
			if err != nil {
				return err
			}
			old, _ := json.Marshal(before)
			actual, _ := json.Marshal(after)
			if string(old) != string(actual) {
				return fmt.Errorf("nested deployment generation changed during provenance capture")
			}
		}
		return nil
	}
	if err := read(attempt.ID, false); err != nil {
		return err
	}
	digest, err := evidenceDigest(*e)
	if err != nil {
		return err
	}
	e.Digest = digest
	if attempt.Evidence != nil && attempt.Evidence.Digest != digest {
		return fmt.Errorf("terminal deployment operation source changed after provenance capture")
	}
	attempt.Evidence = e
	return nil
}

func verifyNestedGeneration(properties *armresources.DeploymentPropertiesExtended, correlation string) error {
	if properties == nil || authString(properties.CorrelationID) != correlation ||
		authString(properties.TemplateHash) == "" || properties.ProvisioningState == nil {
		return fmt.Errorf("nested deployment generation is unknown or belongs to a different root correlation")
	}
	switch string(*properties.ProvisioningState) {
	case "Succeeded", "Failed", "Canceled":
		return nil
	default:
		return fmt.Errorf("nested deployment is still active; refusing root replacement or cleanup")
	}
}

func (l *ownedLifecycle) readNestedGeneration(
	ctx context.Context, deploymentID, correlation string,
) (*armresources.DeploymentPropertiesExtended, error) {
	id, err := arm.ParseResourceID(deploymentID)
	if err != nil {
		return nil, err
	}
	client, err := armresources.NewDeploymentsClient(id.SubscriptionID, l.credential, l.options)
	if err != nil {
		return nil, err
	}
	var actualID *string
	var properties *armresources.DeploymentPropertiesExtended
	if id.ResourceGroupName == "" {
		actual, err := client.GetAtSubscriptionScope(ctx, id.Name, nil)
		if err != nil {
			return nil, fmt.Errorf("read exact nested deployment generation: %w", err)
		}
		actualID, properties = actual.ID, actual.Properties
	} else {
		actual, err := client.Get(ctx, id.ResourceGroupName, id.Name, nil)
		if err != nil {
			return nil, fmt.Errorf("read exact nested deployment generation: %w", err)
		}
		actualID, properties = actual.ID, actual.Properties
	}
	if !strings.EqualFold(authString(actualID), deploymentID) {
		return nil, fmt.Errorf("nested deployment exact resource identity changed")
	}
	if err := verifyNestedGeneration(properties, correlation); err != nil {
		return nil, err
	}
	return properties, nil
}

func validateArchivedTarget(plan Plan, spec FoundrySpec, attempt FoundryAttempt) error {
	raw, err := json.Marshal(attempt.Evidence.Properties.Parameters)
	if err != nil {
		return err
	}
	var parameters map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &parameters); err != nil {
		return fmt.Errorf("archived effective parameters are invalid: %w", err)
	}
	for name, expected := range map[string]string{
		"resourceGroupName": plan.ResourceGroup, "location": plan.Location,
	} {
		var actual string
		if err := json.Unmarshal(parameters[name].Value, &actual); err != nil || !strings.EqualFold(actual, expected) {
			return fmt.Errorf("archived deployment effective target parameter %s changed", name)
		}
	}
	var binding struct {
		DeploymentID string `json:"deploymentId"`
		AccountName  string `json:"accountName"`
		ClusterID    string `json:"clusterResourceId"`
		StorageID    string `json:"storageAccountResourceId"`
		RegistryID   string `json:"registryResourceId"`
		HostingID    string `json:"hostingIdentityResourceId"`
		WorkloadID   string `json:"workloadIdentityResourceId"`
	}
	if err := json.Unmarshal(parameters["byoOnboarding"].Value, &binding); err != nil {
		return fmt.Errorf("archived deployment effective graph binding is invalid: %w", err)
	}
	account, err := ParseID(spec.AccountID, "Microsoft.CognitiveServices/accounts")
	if err != nil || !strings.EqualFold(binding.DeploymentID, plan.DeploymentID) ||
		!strings.EqualFold(binding.AccountName, account.Name) || spec.Deployment == nil {
		return fmt.Errorf("archived deployment belongs to a different account or deployment scope")
	}
	for _, pair := range [][2]string{
		{binding.ClusterID, spec.Deployment.ClusterID}, {binding.StorageID, spec.Deployment.StorageID},
		{binding.RegistryID, spec.Deployment.RegistryID}, {binding.HostingID, spec.Deployment.Hosting.ID},
		{binding.WorkloadID, spec.Deployment.Workload.ID},
	} {
		if !strings.EqualFold(pair[0], pair[1]) {
			return fmt.Errorf("archived deployment dependency resource target changed")
		}
	}
	return nil
}
