// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

func resourceCheck(id, scope, expected string) Check {
	return Check{
		ID: id, Scope: scope, Status: Unverified, Mandatory: true, Expected: expected,
		Observed: "required ARM evidence is unavailable", Missing: "readable, explicit resource properties",
		Remediation: "provide the stated evidence or ask the resource administrator to correct the configuration",
	}
}

func resourceResult(c Check, status Status, observed string) Check {
	c.Status, c.Observed = status, observed
	if status == Pass || status == NotApplicable {
		c.Missing, c.Remediation = "", ""
	}
	return c
}

func resourceValue[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

func resourceBool(p *bool) bool {
	return p != nil && *p
}

func resourceKnown(c Check, known, valid bool, observed string) Check {
	if !known {
		return resourceResult(c, Unverified, observed)
	}
	if !valid {
		return resourceResult(c, Fail, observed)
	}
	return resourceResult(c, Pass, observed)
}

func storageResourceChecks(account armstorage.Account) Report {
	scope := resourceValue(account.ID)
	typeCheck := resourceCheck("S01", scope, "StorageV2; Hot tier; HNS explicitly disabled")
	security := resourceCheck("S02", scope, "HTTPS only; TLS >= 1.2; Shared Key disabled; anonymous Blob disabled")
	p := account.Properties
	if p == nil {
		return Report{typeCheck, security}
	}
	known := account.Kind != nil && p.AccessTier != nil && p.IsHnsEnabled != nil
	valid := resourceValue(account.Kind) == "StorageV2" && resourceValue(p.AccessTier) == "Hot" &&
		p.IsHnsEnabled != nil && !*p.IsHnsEnabled
	typeCheck = resourceKnown(typeCheck, known, valid,
		"kind="+resourceValue(account.Kind)+"; tier="+resourceValue(p.AccessTier)+"; HNS evidence")
	if account.Kind != nil && resourceValue(account.Kind) != "StorageV2" ||
		p.AccessTier != nil && resourceValue(p.AccessTier) != "Hot" || resourceBool(p.IsHnsEnabled) {
		typeCheck = resourceResult(typeCheck, Fail, "incompatible Storage kind, tier or HNS configuration")
	}
	sku := ""
	if account.SKU != nil {
		sku = resourceValue(account.SKU.Name)
	}
	typeCheck.Observed += "; SKU=" + sku
	switch strings.ToUpper(strings.TrimSpace(sku)) {
	case "STANDARD_ZRS", "STANDARD_GZRS", "STANDARD_RAGZRS", "PREMIUM_ZRS":
	case "STANDARD_LRS", "STANDARD_GRS", "STANDARD_RAGRS", "PREMIUM_LRS":
		typeCheck.Warning = fmt.Sprintf(
			"Supplied Storage account uses %s without zone redundancy. "+
				"Zone redundancy is recommended; this recommendation does not block provisioning or change the account.",
			sku)
	default:
		typeCheck.Warning = "The supplied Storage account SKU does not establish zone redundancy. " +
			"Zone redundancy is recommended; confirm the account's redundancy setting. " +
			"This recommendation does not block provisioning or change the account."
	}
	// Accounts.GetProperties uses API 2024-01-01. Its documented defaults are:
	// HTTPS=true (since 2019-04-01), minimum TLS=1.0, Shared Key=true, anonymous Blob=false.
	https := p.EnableHTTPSTrafficOnly == nil || *p.EnableHTTPSTrafficOnly
	anonymous := resourceBool(p.AllowBlobPublicAccess)
	shared := p.AllowSharedKeyAccess == nil || *p.AllowSharedKeyAccess
	tls := resourceValue(p.MinimumTLSVersion)
	tlsKnown := tls == "" || tls == "TLS1_0" || tls == "TLS1_1" || tls == "TLS1_2" || tls == "TLS1_3"
	tlsValid := tls == "TLS1_2" || tls == "TLS1_3"
	security = resourceKnown(security, tlsKnown, https && !anonymous && !shared && tlsValid,
		fmt.Sprintf("HTTPS=%t; minimum TLS=%s; Shared Key=%t; anonymous Blob=%t", https, tls, shared, anonymous))
	if !https || anonymous || shared || tlsKnown && !tlsValid {
		security = resourceResult(security, Fail, security.Observed)
	}
	return Report{typeCheck, security}
}

func storageNetworkChecks(plan Plan, storage *armstorage.Account) Report {
	check := resourceCheck("S03", plan.Storage.ID, "supplied Storage matches the public static network baseline")
	if !plan.Storage.Supplied {
		return Report{resourceResult(check, NotApplicable,
			"S03 applies only to supplied Storage; new Storage checks are skipped before and after deployment")}
	}
	if storage == nil || storage.Properties == nil || storage.Properties.PrimaryEndpoints == nil {
		return Report{check}
	}
	p := storage.Properties
	endpoint := safeResourceEndpoint(resourceValue(p.PrimaryEndpoints.Blob))
	access := resourceValue(p.PublicNetworkAccess)
	action := ""
	if p.NetworkRuleSet != nil {
		action = resourceValue(p.NetworkRuleSet.DefaultAction)
	}
	check.Observed = "Blob endpoint=" + endpoint + "; publicNetworkAccess=" + access + "; defaultAction=" + action
	if endpoint == "" || access != "Enabled" && access != "Disabled" || action != "Allow" && action != "Deny" {
		check.Missing = "valid HTTPS Blob endpoint and explicit public/firewall access settings"
		return Report{check}
	}
	if access == "Enabled" && action == "Allow" {
		return Report{resourceResult(check, Pass, check.Observed+"; public static baseline, not actual connectivity")}
	}
	check = resourceResult(check, NotApplicable, check.Observed+"; restricted/private network path verification skipped")
	check.Mandatory = false
	check.Warning = "Restricted/private Storage network connectivity was not verified; " +
		"S03 is skipped and does not block provisioning."
	return Report{check}
}
