// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

type scopedAuthorizer struct {
	credential azcore.TokenCredential
	options    *arm.ClientOptions
	reads      *authorizationEvidence
}

type operation struct {
	checkID, action, scope string
}

// NewAuthorizer checks basic scoped ARM action allow without trial writes, deny reads or Graph calls.
func NewAuthorizer(credential azcore.TokenCredential, options *arm.ClientOptions) Authorizer {
	return &scopedAuthorizer{credential: credential, options: onboardingARMOptions(options)}
}

func supportingOperations(plan Plan, facts Facts) ([]operation, error) {
	var operations []operation
	add := func(id, action, scope string) {
		op := operation{id, action, scope}
		if !slices.ContainsFunc(operations, func(existing operation) bool {
			return existing.checkID == id && strings.EqualFold(existing.action, action) &&
				strings.EqualFold(existing.scope, scope)
		}) {
			operations = append(operations, op)
		}
	}
	for _, identity := range []Resource{plan.Hosting, plan.Workload} {
		actions := []string{"write", "read", "assign/action"}
		if identity.Supplied {
			actions = []string{"read", "assign/action"}
		}
		for _, action := range actions {
			add("P02", "Microsoft.ManagedIdentity/userAssignedIdentities/"+action, facts.scope(identity))
		}
	}
	if !plan.Storage.Supplied {
		add("P04", "Microsoft.Storage/storageAccounts/write", facts.scope(plan.Storage))
	}
	target := "/subscriptions/" + plan.SubscriptionID + "/resourceGroups/" + plan.ResourceGroup
	for _, item := range []struct {
		resource Resource
		checkID  string
	}{
		{plan.Cluster, "G01"}, {plan.Workload, "G02"}, {plan.Storage, "G03"},
	} {
		if !createsGrant(plan, item.checkID) {
			continue
		}
		id, err := arm.ParseResourceID(item.resource.ID)
		if err != nil {
			return nil, fmt.Errorf("resolve cross-resource-group deployment scope: %w", err)
		}
		scope := id.Parent.String()
		if strings.EqualFold(scope, target) {
			continue
		}
		for _, action := range []string{"write", "read", "operations/read"} {
			add("P09", "Microsoft.Resources/deployments/"+action, scope)
		}
	}
	return operations, nil
}

func (a *scopedAuthorizer) Check(ctx context.Context, p Plan, f Facts) (Report, error) {
	local := *a
	local.reads = newAuthorizationEvidence(a.credential, a.options)
	a = &local
	report := a.suppliedIdentityChecks(ctx, p, f)
	audience := "https://management.azure.com/"
	if a.options != nil {
		if service, ok := a.options.Cloud.Services[cloud.ResourceManager]; ok && service.Audience != "" {
			audience = service.Audience
		}
	}
	token, tokenErr := a.credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{strings.TrimRight(audience, "/") + "/.default"},
	})
	caller, identityErr := identityFromToken(token.Token)
	basicIdentityErr := identityErr
	if tokenErr != nil {
		basicIdentityErr = tokenErr
	}
	report = append(report, a.checkP06(ctx, p, f, caller, basicIdentityErr)...)
	operations, err := supportingOperations(p, f)
	if err != nil {
		return report, err
	}
	checks := make(Report, len(operations))
	tasks := make([]func(), 0, len(operations))
	for i, op := range operations {
		tasks = append(tasks, func() {
			check := Check{
				ID: op.checkID, Scope: op.scope, Status: Unverified, Mandatory: true,
				Expected: op.action, Missing: op.action,
				Remediation: "Ask the scope administrator to provide readable operator role assignments " +
					"and definitions permitting " + op.action + " at this scope or an applicable ancestor.",
			}
			switch {
			case tokenErr != nil:
				check.Observed, check.Cause = "operator token evidence unavailable", tokenErr
			case identityErr != nil:
				check.Observed, check.Cause = identityErr.Error(), identityErr
			default:
				check.Status, check.Observed, check.Cause = a.basicAction(ctx, op.scope, caller, op.action, false)
				if check.Status == Pass {
					check.Observed += "; ARM authorizes the actual operation"
					check.Missing, check.Remediation = "", ""
				}
			}
			checks[i] = check
		})
	}
	parallelReads(tasks...)
	report = append(report, checks...)
	return report, report.Err()
}

func (e *authorizationEvidence) resolveGrantRole(
	ctx context.Context, subscription string, grant grantRequest,
) (string, error) {
	if scope, err := arm.ParseResourceID(grant.scope); err == nil && scope.SubscriptionID != "" {
		subscription = scope.SubscriptionID
	}
	if grant.roleID != "" {
		return "/subscriptions/" + subscription + "/providers/Microsoft.Authorization/roleDefinitions/" + grant.roleID, nil
	}
	return e.roleNames.get(strings.ToLower(subscription)+"|"+grant.roleName, func() (string, error) {
		client, err := e.definitionClient()
		if err != nil {
			return "", err
		}
		pager := client.NewListPager("/subscriptions/"+subscription,
			&armauthorization.RoleDefinitionsClientListOptions{Filter: new("roleName eq '" + grant.roleName + "'")})
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return "", err
			}
			for _, role := range page.Value {
				if role != nil && role.ID != nil && role.Properties != nil &&
					authString(role.Properties.RoleName) == grant.roleName &&
					strings.EqualFold(authString(role.Properties.RoleType), "BuiltInRole") {
					return *role.ID, nil
				}
			}
		}
		return "", fmt.Errorf("required built-in role %q is unavailable", grant.roleName)
	})
}
