// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"azure.ai.projects/internal/exterrors"
	"azure.ai.projects/internal/onboarding"
	"azure.ai.projects/internal/synthesis"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/azure/azure-dev/cli/azd/pkg/azdext"
	"github.com/azure/azure-dev/cli/azd/pkg/grpcbroker"
)

func (p *FoundryProvisioningProvider) ownedBYOLifecycle() onboarding.Lifecycle {
	if p.byoLifecycle != nil {
		return p.byoLifecycle
	}
	return onboarding.NewLifecycle(p.credential, p.armClientOptions, environmentJournal{p})
}

func byoFoundrySpec(plan onboarding.Plan, source *templateSource, abac bool) (onboarding.FoundrySpec, error) {
	hash, err := standardBYOTemplateHash(source.armTemplate)
	if err != nil {
		return onboarding.FoundrySpec{}, err
	}
	digest, err := onboarding.TemplateDigest(source.armTemplate)
	if err != nil {
		return onboarding.FoundrySpec{}, err
	}
	account := onboarding.PlannedFoundryAccount(plan)
	project, ok := byoParameterValue(source, "foundryProjectName").(string)
	if !ok || project == "" {
		return onboarding.FoundrySpec{}, fmt.Errorf("effective Foundry project name is required for lifecycle ownership")
	}
	spec := onboarding.FoundrySpec{
		AccountID: account.ID, ProjectID: account.ID + "/projects/" + project,
		RegistryID: plan.Registry.ID, RegistryABAC: abac, Location: plan.Location,
		TemplateHash: hash, TemplateDigest: digest,
	}
	return spec, nil
}

func standardBYOTemplateHash(template map[string]any) (string, error) {
	raw, err := synthesis.ARMTemplate()
	if err != nil {
		return "", err
	}
	var standard map[string]any
	if err := json.Unmarshal(raw, &standard); err != nil {
		return "", err
	}
	actual, err := onboarding.TemplateDigest(template)
	if err != nil {
		return "", err
	}
	expected, err := onboarding.TemplateDigest(standard)
	if err != nil {
		return "", err
	}
	if actual != expected {
		return "", fmt.Errorf("BYO-AKS requires the standard ownership-bound template; " +
			"restore/regenerate the Bicep files and express supported selections through configuration/parameters")
	}
	metadata, ok := template["metadata"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("BYO-AKS template lacks generated template-hash evidence")
	}
	generator, ok := metadata["_generator"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("BYO-AKS template lacks generator template-hash evidence")
	}
	hash, ok := generator["templateHash"].(string)
	if !ok || hash == "" {
		return "", fmt.Errorf("BYO-AKS template hash is unavailable")
	}
	return hash, nil
}

func (p *FoundryProvisioningProvider) byoARMOptions() *arm.ClientOptions {
	options := arm.ClientOptions{DisableRPRegistration: true}
	if p.armClientOptions != nil {
		options = *p.armClientOptions
		options.DisableRPRegistration = true
	}
	return &options
}

func (p *FoundryProvisioningProvider) deployBYO(
	ctx context.Context, progress grpcbroker.ProgressFunc, source *templateSource, deployment armresources.Deployment,
) (*azdext.ProvisioningDeployResult, error) {
	lifecycle := p.ownedBYOLifecycle()
	plan := *p.byoPlan
	client, err := armresources.NewDeploymentsClient(p.subID, p.credential, p.byoARMOptions())
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, p.byoLifecycleError(err, exterrors.OpArmDeploymentCreate)
	}
	target, err := arm.ParseResourceID(plan.DeploymentID)
	if err != nil || target.SubscriptionID != p.subID || target.ResourceGroupName != "" ||
		!strings.EqualFold(target.ResourceType.String(), "Microsoft.Resources/deployments") {
		return nil, fmt.Errorf("BYO-AKS requires its exact subscription deployment target")
	}
	name, id := target.Name, plan.DeploymentID
	if err := lifecycle.Start(ctx, plan, p.byoSpec, id); err != nil {
		return nil, p.byoLifecycleError(err, exterrors.OpArmDeploymentCreate)
	}
	p.byoDeploymentID = id
	progress(fmt.Sprintf("Starting owned Foundry ARM deployment %q...", name))
	poller, err := client.BeginCreateOrUpdateAtSubscriptionScope(ctx, name, deployment, nil)
	if err != nil {
		return nil, p.deploymentFailure(ctx, err)
	}
	response, err := pollWithProgress(ctx, poller, progress, "Foundry deployment in progress")
	if err != nil {
		return nil, p.deploymentFailure(ctx, err)
	}
	if err := lifecycle.Observe(ctx, plan, response.DeploymentExtended); err != nil {
		return nil, p.byoLifecycleError(err, exterrors.OpArmDeploymentCreate)
	}
	outputs := deploymentOutputs(response.Properties)
	if err := validateBYODeploymentOutputs(plan, p.byoSpec, outputs); err != nil {
		return nil, p.byoLifecycleError(err, exterrors.OpArmDeploymentCreate)
	}
	progress("Foundry deployment complete")
	return &azdext.ProvisioningDeployResult{
		Deployment: &azdext.ProvisioningDeployment{
			Parameters: armInputsToProto(source.parameters),
			Outputs:    p.normalizeOutputs(p.withTenantOutput(armOutputsToProto(outputs))),
		},
	}, nil
}

func validateBYODeploymentOutputs(plan onboarding.Plan, spec onboarding.FoundrySpec, raw any) error {
	project, err := arm.ParseResourceID(spec.ProjectID)
	if err != nil {
		return fmt.Errorf("invalid planned Foundry project target: %w", err)
	}
	expected := map[string]string{
		"AZURE_AI_ACCOUNT_NAME":                onboarding.PlannedFoundryAccount(plan).Name,
		"AZURE_AI_PROJECT_NAME":                project.Name,
		"AZURE_AI_PROJECT_ID":                  spec.ProjectID,
		"AZURE_CONTAINER_REGISTRY_RESOURCE_ID": plan.Registry.ID,
	}
	outputs, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("BYO-AKS deployment lacks outputs required to verify its exact targets")
	}
	seen := map[string]bool{}
	for name, value := range outputs {
		key := canonicalizeOutputName(name)
		want, required := expected[key]
		if !required {
			continue
		}
		if seen[key] {
			return fmt.Errorf("BYO-AKS deployment returned ambiguous %s outputs", key)
		}
		seen[key] = true
		entry, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("BYO-AKS deployment returned invalid %s output", key)
		}
		actual, isString := entry["value"].(string)
		kind, _ := entry["type"].(string)
		matches := actual == want
		if strings.HasSuffix(key, "_ID") {
			matches = strings.EqualFold(actual, want)
		}
		if !isString || !strings.EqualFold(kind, "String") || want == "" || !matches {
			return fmt.Errorf("BYO-AKS deployment %s does not match the exact planned target", key)
		}
	}
	for key := range expected {
		if !seen[key] {
			return fmt.Errorf("BYO-AKS deployment is missing required %s output", key)
		}
	}
	return nil
}

func (p *FoundryProvisioningProvider) byoLifecycleError(cause error, operation string) error {
	message := onboarding.RedactDiagnostic(cause.Error())
	var classified error
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		classified = exterrors.Cancelled("BYO-AKS deployment interrupted; retain its ownership record and resume the operation")
	} else if _, ok := errors.AsType[*azcore.ResponseError](cause); ok {
		classified = exterrors.ServiceFromAzure(cause, operation)
		if service, ok := errors.AsType[*azdext.ServiceError](classified); ok {
			copy := *service
			copy.Message = message
			copy.Suggestion = "Retain the deployment ownership record, resolve the reported permission/service failure, and retry."
			classified = &copy
		}
	} else {
		classified = exterrors.Validation(
			exterrors.CodeInvalidServiceConfig, message,
			"retain the deployment ownership record; resolve the ownership/deployment state before retrying",
		)
	}
	return &byoDeploymentFailure{classified: classified, cause: cause}
}
