// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

type sdkResourceChecker struct {
	credential azcore.TokenCredential
	options    *arm.ClientOptions
	identities *passReads[*armmsi.UserAssignedIdentitiesClient]
}

// NewResourceChecker constructs read-only ARM adapters using an already resolved user-access-tenant credential.
func NewResourceChecker(credential azcore.TokenCredential, options *arm.ClientOptions) ResourceChecker {
	return &sdkResourceChecker{credential: credential, options: onboardingARMOptions(options)}
}

func onboardingARMOptions(options *arm.ClientOptions) *arm.ClientOptions {
	var local arm.ClientOptions
	if options != nil {
		local = *options
	}
	local.DisableRPRegistration = true
	return &local
}

func readFailure(id, scope, action string, err error) Check {
	c := resourceCheck(id, scope, action)
	c.Cause = err
	c.Missing = action + " at " + scope
	c.Observed = "resource could not be read; inspect the original service error"
	c.Remediation = "allow the stated read operation and retry; do not replace an unreadable resource"
	if response, ok := errors.AsType[*azcore.ResponseError](err); ok {
		if response.StatusCode == http.StatusNotFound {
			c.Status, c.Observed = Fail, "referenced resource does not exist (HTTP 404)"
		} else {
			c.Observed = fmt.Sprintf("resource read failed (HTTP %d; code %s)", response.StatusCode, response.ErrorCode)
		}
	}
	return c
}

func responseNotFound(err error) bool {
	response, ok := errors.AsType[*azcore.ResponseError](err)
	return ok && response.StatusCode == http.StatusNotFound
}

func resourceReadiness(scope, returnedID, state, action string) Check {
	c := resourceCheck("I02", scope, "referenced resource ID matches and provisioningState=Succeeded")
	if returnedID == "" || state == "" {
		return c
	}
	return resourceKnown(c, true, strings.EqualFold(scope, returnedID) && state == "Succeeded",
		"resource ID matches="+fmt.Sprint(strings.EqualFold(scope, returnedID))+"; provisioningState="+state+"; "+action)
}

func (c *sdkResourceChecker) subscriptionTenants(ctx context.Context, plan Plan) (string, Report) {
	report := Report{}
	subscriptions := map[string]bool{}
	if plan.SubscriptionID != "" && !strings.ContainsAny(plan.SubscriptionID, "/\\?#% ") {
		subscriptions[strings.ToLower(plan.SubscriptionID)] = true
	} else {
		report = append(report, resourceResult(resourceCheck("I02", plan.SubscriptionID,
			"valid target subscription ID"), Fail, "target subscription is absent or malformed"))
	}
	for _, item := range []struct {
		resource Resource
		kind     string
	}{
		{plan.Cluster, "Microsoft.ContainerService/managedClusters"},
		{plan.Storage, "Microsoft.Storage/storageAccounts"},
		{plan.Hosting, "Microsoft.ManagedIdentity/userAssignedIdentities"},
		{plan.Workload, "Microsoft.ManagedIdentity/userAssignedIdentities"},
	} {
		if !item.resource.Supplied && item.kind != "Microsoft.ContainerService/managedClusters" {
			continue
		}
		id, err := ParseID(item.resource.ID, item.kind)
		if err != nil {
			check := resourceResult(resourceCheck("I02", item.resource.ID, item.kind), Fail,
				"malformed supplied resource ID")
			check.Cause = err
			report = append(report, check)
			continue
		}
		subscriptions[strings.ToLower(id.SubscriptionID)] = true
	}
	client, err := arm.NewClient("azure.ai.projects.onboarding", "v1.0.0", c.credential, c.options)
	if err != nil {
		return "", append(report, readFailure("I02", plan.SubscriptionID, "subscriptions/read", err))
	}
	keys := slices.Sorted(maps.Keys(subscriptions))
	checks := make(Report, len(keys))
	tenants := make([]string, len(keys))
	tasks := make([]func(), 0, len(keys))
	for i, subscription := range keys {
		tasks = append(tasks, func() {
			tenants[i], checks[i] = readSubscriptionTenant(ctx, client, subscription)
		})
	}
	parallelReads(tasks...)
	var tenant string
	for i, check := range checks {
		if tenants[i] != "" {
			if tenant == "" {
				tenant = tenants[i]
			}
			check = resourceKnown(check, true, strings.EqualFold(tenant, tenants[i]),
				"subscription owning tenantId="+tenants[i])
		}
		report = append(report, check)
	}
	if report.Err() != nil {
		tenant = ""
	}
	return tenant, report
}

func readSubscriptionTenant(ctx context.Context, client *arm.Client, subscription string) (string, Check) {
	scope := "/subscriptions/" + subscription
	request, err := runtime.NewRequest(ctx, http.MethodGet,
		strings.TrimRight(client.Endpoint(), "/")+scope+"?api-version=2022-12-01")
	if err != nil {
		return "", readFailure("I02", scope, "Microsoft.Resources/subscriptions/read", err)
	}
	response, err := client.Pipeline().Do(request)
	if err == nil && !runtime.HasStatusCode(response, http.StatusOK) {
		err = runtime.NewResponseError(response)
	}
	if err != nil {
		return "", readFailure("I02", scope, "Microsoft.Resources/subscriptions/read", err)
	}
	var result struct {
		TenantID string `json:"tenantId"`
	}
	err = runtime.UnmarshalAsJSON(response, &result)
	if err != nil {
		return "", readFailure("I02", scope, "top-level subscription tenantId", err)
	}
	check := resourceCheck("I02", scope, "all referenced and target subscriptions have the same top-level tenantId")
	if result.TenantID == "" {
		check.Observed = "subscription response has no top-level tenantId; managedByTenants is not ownership"
	}
	return result.TenantID, check
}

func (c *sdkResourceChecker) Check(ctx context.Context, plan Plan) (Facts, Report, error) {
	local := *c
	local.identities = &passReads[*armmsi.UserAssignedIdentitiesClient]{}
	c = &local
	tenant, report := c.subscriptionTenants(ctx, plan)
	facts := Facts{TenantID: tenant, Exists: map[string]bool{}}
	var identities [2]Identity
	var existence [3]*bool
	var identityReports [2]Check
	var storage *armstorage.Account
	var storageReport Report
	tasks := []func(){func() {
		storage, existence[2], storageReport = c.readStorage(ctx, plan.Storage)
	}}
	for i, resource := range []Resource{plan.Hosting, plan.Workload} {
		tasks = append(tasks, func() {
			identities[i], existence[i], identityReports[i] = c.readIdentity(ctx, resource, tenant)
		})
	}
	parallelReads(tasks...)
	facts.HostingIdentity, facts.WorkloadIdentity = identities[0], identities[1]
	for i, resource := range []Resource{plan.Hosting, plan.Workload, plan.Storage} {
		if existence[i] != nil {
			facts.Exists[strings.ToLower(resource.ID)] = *existence[i]
		}
	}
	report = append(report, identityReports[:]...)
	report = append(report, storageReport...)
	if plan.Storage.Supplied {
		if storage != nil {
			report = append(report, storageResourceChecks(*storage)...)
		} else {
			for _, id := range []string{"S01", "S02"} {
				report = append(report, resourceCheck(id, plan.Storage.ID, "readable supplied Storage account"))
			}
		}
	} else {
		for _, id := range []string{"S01", "S02"} {
			report = append(report, resourceResult(resourceCheck(id, plan.Storage.Parent, "supplied Storage"),
				NotApplicable, "Storage uses the default ARM creation/update path"))
		}
	}
	report = append(report, storageNetworkChecks(plan, storage)...)
	if err := ctx.Err(); err != nil {
		return facts, report, err
	}
	return facts, report, report.Err()
}

func (c *sdkResourceChecker) readStorage(
	ctx context.Context, resource Resource,
) (*armstorage.Account, *bool, Report) {
	id, err := ParseID(resource.ID, "Microsoft.Storage/storageAccounts")
	if err != nil {
		return nil, nil, Report{readFailure("I02", resource.ID, "valid Storage resource ID", err)}
	}
	client, err := armstorage.NewAccountsClient(id.SubscriptionID, c.credential, c.options)
	if err != nil {
		return nil, nil, Report{readFailure("I02", resource.ID, "Microsoft.Storage/storageAccounts/read", err)}
	}
	response, err := client.GetProperties(ctx, id.ResourceGroupName, id.Name, nil)
	if responseNotFound(err) && !resource.Supplied {
		return nil, new(false), Report{resourceResult(resourceCheck("I03", resource.ID, "current default Storage existence"),
			Pass, "default Storage does not exist; ARM will create it")}
	}
	if err != nil {
		return nil, nil, Report{readFailure("I02", resource.ID, "Microsoft.Storage/storageAccounts/read", err)}
	}
	if !resource.Supplied {
		check := resourceKnown(resourceCheck("I03", resource.ID, "exact default Storage target"),
			response.ID != nil, strings.EqualFold(resourceValue(response.ID), resource.ID),
			"default Storage exists; its ordinary ARM creation/update path is retained")
		return &response.Account, new(true), Report{check}
	}
	state := ""
	if response.Properties != nil {
		state = resourceValue(response.Properties.ProvisioningState)
	}
	return &response.Account, new(true), Report{
		resourceReadiness(resource.ID, resourceValue(response.ID), state, "storageAccounts/read"),
	}
}

func (c *sdkResourceChecker) readIdentity(
	ctx context.Context, resource Resource, tenant string,
) (Identity, *bool, Check) {
	check := resourceCheck("I02", resource.ID,
		"existing user-assigned identity with matching ID, principal, client and tenant")
	id, err := ParseID(resource.ID, "Microsoft.ManagedIdentity/userAssignedIdentities")
	if err != nil {
		check.Status, check.Observed, check.Cause = Fail, "invalid identity resource ID", err
		return Identity{}, nil, check
	}
	client, err := c.identities.get(strings.ToLower(id.SubscriptionID),
		func() (*armmsi.UserAssignedIdentitiesClient, error) {
			return armmsi.NewUserAssignedIdentitiesClient(id.SubscriptionID, c.credential, c.options)
		})
	if err != nil {
		check.Cause = err
		return Identity{}, nil, check
	}
	response, err := client.Get(ctx, id.ResourceGroupName, id.Name, nil)
	if responseNotFound(err) && !resource.Supplied {
		return Identity{}, new(false), resourceResult(check, Pass, "default identity does not exist; ARM will create it")
	}
	if err != nil {
		return Identity{}, nil, readFailure("I02", resource.ID, "Microsoft.ManagedIdentity/userAssignedIdentities/read", err)
	}
	if !resource.Supplied {
		return Identity{}, new(true), resourceKnown(check, response.ID != nil,
			strings.EqualFold(authString(response.ID), resource.ID),
			"default identity exists; its ordinary ARM creation/update path is retained")
	}
	properties := response.Properties
	if response.ID == nil || properties == nil || authString(properties.PrincipalID) == "" ||
		authString(properties.ClientID) == "" || authString(properties.TenantID) == "" || tenant == "" {
		check.Observed = "supplied identity ID, principal, client or owning tenant evidence is missing"
		return Identity{}, new(true), check
	}
	identity := Identity{
		ID: *response.ID, PrincipalID: *properties.PrincipalID,
		ClientID: *properties.ClientID, TenantID: *properties.TenantID,
	}
	if !strings.EqualFold(resource.ID, identity.ID) || !strings.EqualFold(tenant, identity.TenantID) {
		return Identity{}, new(true), resourceResult(check, Fail, "supplied identity ID or owning tenant does not match")
	}
	return identity, new(true), resourceResult(check, Pass,
		"existing identity metadata matches; no identity PUT or owner tag is planned")
}

func safeResourceEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}
