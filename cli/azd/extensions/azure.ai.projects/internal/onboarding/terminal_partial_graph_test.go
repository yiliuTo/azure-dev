// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type terminalPartialGraph struct {
	*cleanupARM
	operations  map[string][]any
	deployments map[string]map[string]any
	nested      string
	prereqs     string
}

// Mirrors the sealed native graph: twelve deployments, Failed root/module/PE,
// successful descendants, and module output Reads preceding their paired Creates.
func terminalPartialFixture(t *testing.T, f *cleanupARM, network *networkCleanupARM) *terminalPartialGraph {
	t.Helper()
	g := &terminalPartialGraph{cleanupARM: f, operations: map[string][]any{},
		deployments: map[string]map[string]any{}}
	root := f.base.plan.DeploymentID
	group := "/subscriptions/" + f.base.plan.SubscriptionID + "/resourceGroups/" + f.base.plan.ResourceGroup
	module := func(name string) string { return group + "/providers/Microsoft.Resources/deployments/" + name }
	g.nested, g.prereqs = module("foundry-resources"), module("byo-prerequisites")
	properties := cleanupObject(t, f.roots[strings.ToLower(root)]["properties"])
	properties["provisioningState"], properties["outputResources"] = "Failed", nil
	for name, status := range map[string]string{
		"foundry-resources": "Failed", "byo-prerequisites": "Succeeded", "acr": "Succeeded",
		"foundry-private-endpoint-dns": "Failed", "foundry-network": "Succeeded",
		"byo-storage-access": "Succeeded", "byo-kubelet-registry-access": "Succeeded",
		"byo-federation-access": "Succeeded", "byo-cluster-one": "Succeeded",
		"byo-cluster-two": "Succeeded", "prepared-registry-project-access": "Succeeded",
	} {
		id := module(name)
		g.deployments[strings.ToLower(id)] = map[string]any{"id": id, "properties": map[string]any{
			"correlationId": properties["correlationId"], "templateHash": "verified-nested-hash",
			"provisioningState": status,
		}}
		g.operations[strings.ToLower(id)] = []any{}
	}
	add := func(parent, target, verb, status string) {
		id, err := arm.ParseResourceID(target)
		require.NoError(t, err)
		g.operations[strings.ToLower(parent)] = append(g.operations[strings.ToLower(parent)], map[string]any{
			"id": parent + "/operations/" + verb + "-" + id.Name,
			"properties": map[string]any{
				"provisioningOperation": verb, "provisioningState": status,
				"timestamp": "2026-10-26T00:49:00Z", "duration": "PT2M",
				"targetResource": map[string]any{"id": target, "resourceType": id.ResourceType.String()},
			},
		})
	}
	add(root, g.nested, "Create", "Failed")
	add(root, g.prereqs, "Create", "Succeeded")
	for _, name := range []string{"acr", "foundry-private-endpoint-dns", "foundry-network"} {
		status := "Succeeded"
		if name == "foundry-private-endpoint-dns" {
			status = "Failed"
		}
		add(g.nested, module(name), "Create", status)
	}
	for _, id := range []string{f.spec.AccountID, f.spec.ProjectID} {
		add(g.nested, id, "Create", "Succeeded")
	}
	for _, name := range f.spec.ModelNames {
		add(g.nested, f.spec.AccountID+"/deployments/"+name, "Create", "Succeeded")
	}
	for _, resource := range []Resource{
		f.base.plan.Storage, f.base.plan.Registry, f.base.plan.Hosting, f.base.plan.Workload,
	} {
		if !resource.Supplied {
			add(g.prereqs, resource.ID, "Create", "Succeeded")
		}
	}
	grantModules := []string{"byo-storage-access", "byo-kubelet-registry-access", "byo-federation-access",
		"byo-cluster-one", "byo-cluster-two", "prepared-registry-project-access"}
	require.Len(t, f.operationTargets, len(grantModules))
	for index, name := range grantModules {
		parent := g.prereqs
		if name == "prepared-registry-project-access" {
			parent = module("acr")
		}
		add(parent, module(name), "Read", "Succeeded")
		add(parent, module(name), "Create", "Succeeded")
		add(module(name), f.operationTargets[index], "Create", "Succeeded")
	}
	add(module("acr"), f.spec.ProjectID+"/connections/"+f.base.plan.Registry.Name+"-conn", "Create", "Succeeded")
	if network != nil {
		for _, id := range append(append([]string{}, network.zones...), network.links...) {
			add(module("foundry-private-endpoint-dns"), id, "Create", "Succeeded")
		}
		add(module("foundry-private-endpoint-dns"), network.pe, "Create", "Failed")
		delete(f.base.resources, strings.ToLower(network.group))
		for key, records := range network.records {
			network.records[key] = records[:1]
		}
		cleanupObject(t, f.base.resources[strings.ToLower(network.pe)]["properties"])["provisioningState"] = "Failed"
	}
	transport := f.options.Transport
	active := true
	f.options.Transport = contractARMOptions(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPut {
			active = false
		}
		if active && request.Method == http.MethodGet {
			path := strings.ToLower(request.URL.Path)
			var body any
			if id, operations := strings.CutSuffix(path, "/operations"); operations {
				if value, ok := g.operations[id]; ok {
					body = map[string]any{"value": value}
				}
			} else if value, ok := g.deployments[path]; ok {
				body = value
			}
			if body != nil {
				raw, err := json.Marshal(body)
				require.NoError(t, err)
				return contractARMResponse(request, 200, string(raw)), nil
			}
		}
		return transport.Do(request)
	}).Transport
	f.lifecycle = NewLifecycle(contractCredential{}, f.options, f.base.journal)
	return g
}

func newTerminalPartialFixture(t *testing.T) *terminalPartialGraph {
	t.Helper()
	f := newCleanupARM(t, false, false)
	f.deploymentState = "Failed"
	require.Error(t, f.submit(t))
	return terminalPartialFixture(t, f, nil)
}

func (g *terminalPartialGraph) operation(t *testing.T, parent, target, verb string) map[string]any {
	t.Helper()
	for _, raw := range g.operations[strings.ToLower(parent)] {
		operation := cleanupObject(t, raw)
		p := cleanupObject(t, operation["properties"])
		id, ok := cleanupObject(t, p["targetResource"])["id"].(string)
		require.True(t, ok)
		if p["provisioningOperation"] == verb && strings.EqualFold(
			id, target) {
			return operation
		}
	}
	t.Fatalf("missing fixture %s operation on %s", verb, target)
	return nil
}

func TestTerminalPartialGraphRecoversAndArchivesBeforeSameIDRetry(t *testing.T) {
	g := newTerminalPartialFixture(t)
	state, err := g.base.journal.Load(t.Context())
	require.NoError(t, err)
	require.False(t, state.Foundry.Attempts[0].Terminal, "cloud terminal success/failure was not saved locally")
	lifecycle, ok := g.lifecycle.(*ownedLifecycle)
	require.True(t, ok)
	require.NoError(t, lifecycle.verifyAttempts(t.Context(), g.base.plan, state.Foundry))
	created := map[string]bool{}
	_, err = lifecycle.deploymentGrantTargets(t.Context(), g.base.plan, state.Foundry, nil, created)
	require.NoError(t, err)
	for id := range state.Sources {
		require.True(t, created[id], "successful resource Create remains bound across Failed modules: %s", id)
		_, bound := partialResourceCreate(state.Foundry.Attempts[0], id, false)
		require.True(t, bound, "exact successful operation has a bounded birth window: %s", id)
	}
	require.NoError(t, g.lifecycle.Observe(t.Context(), g.base.plan))
	state, err = g.base.journal.Load(t.Context())
	require.NoError(t, err)
	require.Equal(t, "Failed", state.Foundry.Attempts[0].ProvisioningState)
	require.Len(t, state.Foundry.Attempts[0].Evidence.Deployments, 11)
	require.Len(t, state.Assignments, 6)
	for id, source := range state.Sources {
		require.False(t, source.CreatedTime.IsZero(), id)
	}
	require.Empty(t, state.Foundry.Attempts[0].Evidence.Properties.OutputResources)
	original, err := json.Marshal(state.Foundry.Attempts[0].Evidence)
	require.NoError(t, err)
	report, err := g.lifecycle.Check(t.Context(), g.base.plan, g.spec)
	require.NoError(t, err)
	require.NoError(t, report.Err())
	g.deploymentState = "Succeeded"
	require.NoError(t, g.submit(t))
	require.NoError(t, g.lifecycle.Observe(t.Context(), g.base.plan))
	state, err = g.base.journal.Load(t.Context())
	require.NoError(t, err)
	require.Len(t, state.Foundry.Attempts, 2)
	assert.True(t, state.Foundry.Attempts[0].Archived)
	assert.Equal(t, state.Foundry.Attempts[0].ID, state.Foundry.Attempts[1].ID)
	snapshot, err := json.Marshal(state.Foundry.Attempts[0].Evidence)
	require.NoError(t, err)
	assert.Equal(t, original, snapshot)
	require.NoError(t, g.lifecycle.Cleanup(t.Context(), g.base.plan, false, nil))
}

func TestTerminalPartialGraphRejectsUnboundOrChangedNestedSources(t *testing.T) {
	for _, scenario := range []string{"unpaired Read", "foreign Read parent", "foreign Create parent",
		"unrelated Read", "active Create", "mismatched result", "foreign correlation"} {
		t.Run(scenario, func(t *testing.T) {
			g := newTerminalPartialFixture(t)
			leaf := strings.Replace(g.prereqs, "byo-prerequisites", "byo-storage-access", 1)
			read := g.operation(t, g.prereqs, leaf, "Read")
			create := g.operation(t, g.prereqs, leaf, "Create")
			switch scenario {
			case "unpaired Read":
				cleanupObject(t, create["properties"])["targetResource"] = map[string]any{
					"id": leaf + "-other", "resourceType": "Microsoft.Resources/deployments",
				}
			case "foreign Read parent":
				read["id"] = g.nested + "/operations/foreign"
			case "foreign Create parent":
				create["id"] = g.nested + "/operations/foreign"
			case "unrelated Read":
				cleanupObject(t, read["properties"])["targetResource"] = map[string]any{
					"id": leaf + "-other", "resourceType": "Microsoft.Resources/deployments",
				}
			case "active Create":
				cleanupObject(t, create["properties"])["provisioningState"] = "Running"
			case "mismatched result":
				cleanupObject(t, g.deployments[strings.ToLower(g.nested)]["properties"])["provisioningState"] = "Succeeded"
			case "foreign correlation":
				cleanupObject(t, g.deployments[strings.ToLower(g.nested)]["properties"])["correlationId"] = "foreign"
			}
			require.Error(t, g.lifecycle.Observe(t.Context(), g.base.plan))
			require.Error(t, g.lifecycle.Start(t.Context(), g.base.plan, g.spec, g.base.plan.DeploymentID))
			require.Error(t, g.lifecycle.Cleanup(t.Context(), g.base.plan, false, nil))
			assert.Empty(t, g.deletes)
		})
	}
}

func TestTerminalPartialResourceBirthStillRequiresExactSuccessfulTimedCreate(t *testing.T) {
	for _, scenario := range []string{"failed resource Create", "foreign operation", "missing operation time",
		"missing operation duration", "outside operation window", "operation outside root", "foreign module scope",
		"missing birth", "missing initial absence", "replaced resource"} {
		t.Run(scenario, func(t *testing.T) {
			g := newTerminalPartialFixture(t)
			create := g.operation(t, g.nested, g.spec.AccountID, "Create")
			p := cleanupObject(t, create["properties"])
			switch scenario {
			case "failed resource Create":
				p["provisioningState"] = "Failed"
			case "foreign operation":
				create["id"] = g.prereqs + "/operations/foreign"
			case "missing operation time":
				delete(p, "timestamp")
			case "missing operation duration":
				delete(p, "duration")
			case "outside operation window":
				p["timestamp"] = "2026-10-26T00:51:01Z"
			case "operation outside root":
				p["timestamp"] = "2026-10-25T00:49:00Z"
			case "foreign module scope":
				foreign := strings.Replace(g.nested, "/resourceGroups/"+g.base.plan.ResourceGroup+"/",
					"/resourceGroups/foreign/", 1)
				edge := cleanupObject(t, g.operation(t, g.base.plan.DeploymentID, g.nested, "Create")["properties"])
				cleanupObject(t, edge["targetResource"])["id"] = foreign
				properties := g.deployments[strings.ToLower(g.nested)]
				properties["id"] = foreign
				g.deployments[strings.ToLower(foreign)] = properties
				g.operations[strings.ToLower(foreign)] = g.operations[strings.ToLower(g.nested)]
				for _, raw := range g.operations[strings.ToLower(foreign)] {
					op := cleanupObject(t, raw)
					id, ok := op["id"].(string)
					require.True(t, ok)
					op["id"] = strings.Replace(id, g.nested, foreign, 1)
				}
			case "missing birth":
				delete(g.base.resources[strings.ToLower(g.spec.AccountID)], "createdTime")
				delete(g.base.resources[strings.ToLower(g.spec.AccountID)], "systemData")
			case "missing initial absence", "replaced resource":
				state, err := g.base.journal.Load(t.Context())
				require.NoError(t, err)
				source := state.Sources[strings.ToLower(g.spec.AccountID)]
				if scenario == "missing initial absence" {
					source.InitiallyAbsent = false
				} else {
					source.CreatedTime = time.Date(2026, 10, 26, 0, 49, 30, 0, time.UTC)
				}
				state.Sources[strings.ToLower(g.spec.AccountID)] = source
				require.NoError(t, g.base.journal.Save(t.Context(), state))
			}
			require.Error(t, g.lifecycle.Observe(t.Context(), g.base.plan))
			require.Error(t, g.lifecycle.Cleanup(t.Context(), g.base.plan, false, nil))
			assert.Empty(t, g.deletes)
		})
	}
}

func terminalPartialNetworkFixture(t *testing.T) (*terminalPartialGraph, *networkCleanupARM) {
	t.Helper()
	n := newNetworkCleanupARM(t)
	state, err := n.base.journal.Load(t.Context())
	require.NoError(t, err)
	attempt := &state.Foundry.Attempts[0]
	attempt.Terminal, attempt.OwnershipObserved = false, false
	attempt.ProvisioningState, attempt.CorrelationID, attempt.ARMTemplateHash, attempt.Evidence = "", "", "", nil
	state.Assignments = map[string]OwnedAssignment{}
	require.NoError(t, n.base.journal.Save(t.Context(), state))
	return terminalPartialFixture(t, n.cleanupARM, n), n
}

func TestTerminalFailedPrivateEndpointCleanupUsesExactBirthAndTopology(t *testing.T) {
	g, n := terminalPartialNetworkFixture(t)
	require.NoError(t, g.lifecycle.Cleanup(t.Context(), g.base.plan, false, nil))
	state, err := g.base.journal.Load(t.Context())
	require.NoError(t, err)
	require.True(t, state.CleanupComplete)
	record := state.Foundry.Network.Resources[strings.ToLower(n.pe)]
	assert.True(t, record.Deleted)
	assert.False(t, record.CreatedTime.IsZero())
	assert.NotContains(t, g.deletes, strings.ToLower(n.nic), "the RP deletes its NIC; no direct NIC delete")
	assert.NotContains(t, g.deletes, n.vnet)
	assert.NotContains(t, g.deletes, n.subnet)
}

func TestTerminalFailedPrivateEndpointDoesNotWeakenNetworkOwnership(t *testing.T) {
	for _, scenario := range []string{"missing operation", "missing birth", "foreign birth", "foreign service",
		"foreign NIC", "active endpoint", "failed zone", "recreated endpoint", "recreated NIC"} {
		t.Run(scenario, func(t *testing.T) {
			g, n := terminalPartialNetworkFixture(t)
			switch scenario {
			case "missing operation":
				parent := strings.Replace(g.nested, "foundry-resources", "foundry-private-endpoint-dns", 1)
				p := cleanupObject(t, g.operation(t, parent, n.pe, "Create")["properties"])
				p["provisioningOperation"] = "Read"
			case "missing birth":
				delete(n.births, strings.ToLower(n.pe))
			case "foreign birth":
				n.births[strings.ToLower(n.pe)] = "2026-10-25T00:50:00Z"
			case "foreign service":
				p := cleanupObject(t, g.base.resources[strings.ToLower(n.pe)]["properties"])
				p["privateLinkServiceConnections"] = []any{map[string]any{"properties": map[string]any{
					"privateLinkServiceId": g.spec.AccountID + "-other", "groupIds": []any{"account"},
				}}}
			case "foreign NIC":
				g.base.resources[strings.ToLower(n.nic)]["managedBy"] = "/foreign"
			case "active endpoint":
				cleanupObject(t, g.base.resources[strings.ToLower(n.pe)]["properties"])["provisioningState"] = "Updating"
			case "failed zone":
				cleanupObject(t, g.base.resources[strings.ToLower(n.zones[0])]["properties"])["provisioningState"] = "Failed"
			case "recreated endpoint", "recreated NIC":
				lifecycle, ok := g.lifecycle.(*ownedLifecycle)
				require.True(t, ok)
				state, err := g.base.journal.Load(t.Context())
				require.NoError(t, err)
				require.NoError(t, lifecycle.verifyAttempts(t.Context(), g.base.plan, state.Foundry))
				require.NoError(t, lifecycle.inventoryFoundryNetwork(t.Context(), g.base.plan, &state))
				id := n.pe
				if scenario == "recreated NIC" {
					id = n.nic
				}
				n.births[strings.ToLower(id)] = "2026-10-26T00:50:30Z"
			}
			require.Error(t, g.lifecycle.Cleanup(t.Context(), g.base.plan, false, nil))
			assert.Empty(t, g.deletes)
		})
	}
}
