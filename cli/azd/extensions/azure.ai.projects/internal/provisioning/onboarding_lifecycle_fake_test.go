// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"context"

	"azure.ai.projects/internal/onboarding"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// Gate contracts isolate deployment ownership; SDK lifecycle contracts inject NewLifecycle instead.
type byoLifecycleContract struct{}

func (byoLifecycleContract) Check(
	context.Context, onboarding.Plan, onboarding.FoundrySpec,
) (onboarding.Report, error) {
	return nil, nil
}

func (byoLifecycleContract) Start(context.Context, onboarding.Plan, onboarding.FoundrySpec, string) error {
	return nil
}

func (byoLifecycleContract) Observe(context.Context, onboarding.Plan, armresources.DeploymentExtended) error {
	return nil
}
