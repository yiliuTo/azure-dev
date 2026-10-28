// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// Failed modules can contain successful resource Creates. Only their exact
// terminal Create edges, never output Reads, establish deployment ancestry.
func nestedCreateOperations(
	operations []*armresources.DeploymentOperation, deploymentID string,
) ([]*armresources.DeploymentOperation, error) {
	var creates, reads []*armresources.DeploymentOperation
	targets := map[string]bool{}
	for _, operation := range operations {
		if operation == nil || operation.Properties == nil || operation.Properties.TargetResource == nil {
			continue
		}
		if !strings.EqualFold(
			authString(operation.Properties.TargetResource.ResourceType), "Microsoft.Resources/deployments",
		) {
			continue
		}
		target := authString(operation.Properties.TargetResource.ID)
		id, err := arm.ParseResourceID(target)
		if err != nil || !validResourceIDSyntax(target) ||
			!strings.EqualFold(id.ResourceType.String(), "Microsoft.Resources/deployments") {
			return nil, fmt.Errorf("nested deployment target identity is invalid")
		}
		switch {
		case exactCreateOperation(operation, deploymentID):
			switch authString(operation.Properties.ProvisioningState) {
			case "Succeeded", "Failed", "Canceled":
			default:
				return nil, fmt.Errorf("nested deployment parent Create operation is not terminal")
			}
			key := strings.ToLower(target)
			if targets[key] {
				return nil, fmt.Errorf("nested deployment has ambiguous parent Create operations")
			}
			targets[key] = true
			creates = append(creates, operation)
		case exactDeploymentOperation(operation, deploymentID, armresources.ProvisioningOperationRead) &&
			authString(operation.Properties.ProvisioningState) == "Succeeded":
			reads = append(reads, operation)
		default:
			return nil, fmt.Errorf("nested deployment source lacks an exact parent Create operation")
		}
	}
	for _, read := range reads {
		if !targets[strings.ToLower(authString(read.Properties.TargetResource.ID))] {
			return nil, fmt.Errorf("nested deployment output Read lacks its exact parent Create operation")
		}
	}
	return creates, nil
}
