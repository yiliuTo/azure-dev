// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

var operatorObjectIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

func (e *authorizationEvidence) filteredAssignments(
	ctx context.Context, scope, filter string,
) ([]*armauthorization.RoleAssignment, error) {
	return e.assignments.get(strings.ToLower(scope)+"|"+filter, func() ([]*armauthorization.RoleAssignment, error) {
		return e.readAssignments(ctx, scope, filter)
	})
}

func (e *authorizationEvidence) readAssignments(
	ctx context.Context, scope, filter string,
) ([]*armauthorization.RoleAssignment, error) {
	id, err := arm.ParseResourceID(scope)
	if err != nil || id.SubscriptionID == "" {
		return nil, fmt.Errorf("authorization requires a complete subscription scope: %s", scope)
	}
	client, err := e.assignmentClients.get(strings.ToLower(id.SubscriptionID),
		func() (*armauthorization.RoleAssignmentsClient, error) {
			return armauthorization.NewRoleAssignmentsClient(id.SubscriptionID, e.credential, e.options)
		})
	if err != nil {
		return nil, err
	}
	pager := client.NewListForScopePager(scope,
		&armauthorization.RoleAssignmentsClientListForScopeOptions{Filter: new(filter)})
	var assignments []*armauthorization.RoleAssignment
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("read applicable role assignments at %s: %w", scope, err)
		}
		assignments = append(assignments, page.Value...)
	}
	return assignments, nil
}

// operatorAssignmentApplies consumes only assignments returned by the target's ARM scope query.
// ARM establishes management-group ancestry; its resource IDs are not subscription path prefixes.
func operatorAssignmentApplies(assignment *armauthorization.RoleAssignment, scope string) bool {
	p := assignment.Properties
	if scopeContains(authString(p.Scope), scope) {
		return true
	}
	parent := authString(p.Scope)
	parts := strings.Split(parent, "/")
	if len(parts) != 5 || parts[0] != "" || !strings.EqualFold(parts[1], "providers") ||
		!strings.EqualFold(parts[2], "Microsoft.Management") || !strings.EqualFold(parts[3], "managementGroups") ||
		parts[4] == "" || strings.ContainsAny(parts[4], "?#%\\@:\x00 \t\r\n") {
		return false
	}
	id, err := arm.ParseResourceID(authString(assignment.ID))
	return err == nil && id.Name != "" && strings.EqualFold(id.ResourceType.String(),
		"Microsoft.Authorization/roleAssignments") && strings.EqualFold(id.Parent.String(), parent)
}

func (a *scopedAuthorizer) basicAction(
	ctx context.Context, scope string, caller callerIdentity, action string, unconditionalOnly bool,
) (Status, string, error) {
	reads := a.evidence()
	assignments, err := reads.filteredAssignments(ctx, scope, "atScope()")
	if err != nil {
		return Unverified, "operator role assignments could not be read", err
	}
	provenAssignments := map[*armauthorization.RoleAssignment]bool{}
	if caller.groupOverage {
		if !operatorObjectIDPattern.MatchString(caller.objectID) {
			return Unverified, "operator object ID is invalid for ARM group-assignment evidence", nil
		}
		proven, err := reads.filteredAssignments(ctx, scope,
			"assignedTo('"+caller.objectID+"')")
		if err != nil {
			return Unverified, "ARM operator group-assignment evidence could not be read", err
		}
		for _, assignment := range proven {
			provenAssignments[assignment] = true
		}
		assignments = append(slices.Clone(assignments), proven...)
	}
	operator := "operator"
	if unconditionalOnly {
		operator = "unconditional operator"
	}
	for _, assignment := range assignments {
		if assignment == nil || assignment.Properties == nil {
			return Unverified, "operator role assignment evidence is incomplete", nil
		}
		p := assignment.Properties
		if unconditionalOnly && (authString(p.Condition) != "" || authString(p.ConditionVersion) != "" ||
			authString(p.DelegatedManagedIdentityResourceID) != "") {
			continue
		}
		if authString(p.PrincipalID) == "" {
			return Unverified, "operator role assignment evidence is incomplete", nil
		}
		if !caller.includes(*p.PrincipalID) && !provenAssignments[assignment] {
			continue
		}
		if authString(p.Scope) == "" || authString(p.RoleDefinitionID) == "" {
			return Unverified, "operator assignment scope or role definition is unavailable", nil
		}
		if !operatorAssignmentApplies(assignment, scope) {
			continue
		}
		role, err := reads.roleDefinition(ctx, *p.RoleDefinitionID)
		if err != nil {
			return Unverified, "operator role definition could not be read", err
		}
		if role.Properties == nil || role.Properties.Permissions == nil {
			return Unverified, "operator role definition permissions are unavailable", nil
		}
		if permissionAllows(role.Properties.Permissions, action) {
			return Pass, operator + " Actions/NotActions allow " + action, nil
		}
	}
	return Fail, "no applicable " + operator + " role permits " + action, nil
}

func (a *scopedAuthorizer) checkP06(
	ctx context.Context, plan Plan, facts Facts, caller callerIdentity, identityErr error,
) Report {
	var report Report
	scopes := []string{}
	if createsGrant(plan, "G01") {
		scopes = append(scopes, plan.Cluster.ID)
	}
	if createsGrant(plan, "G02") {
		scopes = append(scopes, facts.scope(plan.Workload))
	}
	if createsGrant(plan, "G03") {
		scopes = append(scopes, facts.scope(plan.Storage))
	}
	seen := map[string]bool{}
	for _, scope := range scopes {
		key := strings.ToLower(scope)
		if seen[key] {
			continue
		}
		seen[key] = true
		check := resourceCheck("P06", scope, "unconditional operator "+roleAssignmentWrite+" for G01-G03")
		check.Missing = "readable unconditional operator " + roleAssignmentWrite
		check.Remediation = "Ask the scope administrator to provide a readable, unconditional role assignment " +
			"permitting " + roleAssignmentWrite + " at this scope or an applicable ancestor."
		if identityErr != nil || caller.objectID == "" {
			check.Observed, check.Cause = "operator object ID is unavailable", identityErr
			check.Missing = "operator object ID"
		} else {
			check.Status, check.Observed, check.Cause = a.basicAction(ctx, scope, caller, roleAssignmentWrite, true)
			if check.Status == Pass {
				check.Observed += "; ARM authorizes the actual assignment"
				check.Missing, check.Remediation = "", ""
			}
		}
		report = append(report, check)
	}
	return report
}
