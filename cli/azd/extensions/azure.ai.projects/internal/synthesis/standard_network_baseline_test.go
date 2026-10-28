// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package synthesis

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandardNetworkARMContract(t *testing.T) {
	raw, err := ARMTemplate()
	require.NoError(t, err)
	var arm map[string]any
	require.NoError(t, json.Unmarshal(raw, &arm))
	object := func(value any) map[string]any {
		t.Helper()
		result, ok := value.(map[string]any)
		require.True(t, ok)
		return result
	}
	rootResources := object(arm["resources"])
	resourceModule := object(rootResources["resources"])
	moduleProperties := object(resourceModule["properties"])
	module := object(moduleProperties["template"])
	for _, name := range []string{
		"enableNetworkIsolation", "useManagedEgress", "vnetId", "agentSubnetName", "agentSubnetPrefix",
		"createAgentSubnet", "peSubnetName", "peSubnetPrefix", "createPESubnet", "managedIsolationMode",
		"dnsZonesResourceGroup", "dnsZonesSubscription",
	} {
		assert.Contains(t, object(arm["parameters"]), name)
		assert.Equal(t, map[string]any{"value": "[parameters('" + name + "')]"},
			object(moduleProperties["parameters"])[name], name)
	}
	variables := object(module["variables"])
	assert.Equal(t, "[parameters('enableNetworkIsolation')]", variables["disablePublicDataPlaneAccess"])
	resources := object(module["resources"])
	account, ok := object(resources["foundryAccount"])["properties"].(string)
	require.True(t, ok)
	assert.Contains(t, account, "'networkInjections', variables('agentNetworkInjections')")
	assert.Contains(t, account,
		"'publicNetworkAccess', if(variables('disablePublicDataPlaneAccess'), 'Disabled', 'Enabled')")
	assert.Contains(t, account, "'networkAcls', createObject("+
		"'defaultAction', if(variables('disablePublicDataPlaneAccess'), 'Deny', 'Allow'), "+
		"'bypass', if(variables('disablePublicDataPlaneAccess'), 'AzureServices', null()), "+
		"'virtualNetworkRules', createArray(), 'ipRules', createArray())")
	for _, name := range []string{"network", "privateEndpointDns"} {
		assert.Equal(t, "[parameters('enableNetworkIsolation')]", object(resources[name])["condition"], name)
	}
	assert.Equal(t, "[and(variables('useManagedNetwork'), not(empty(parameters('managedIsolationMode'))))]",
		object(resources["foundryManagedNetwork"])["condition"])
	pe := object(object(resources["privateEndpointDns"])["properties"])
	assert.Equal(t, map[string]any{"value": "[reference('network').outputs.peSubnetId.value]"},
		object(pe["parameters"])["peSubnetId"])
	for _, name := range []string{"AZURE_FOUNDRY_NETWORK_MODE", "AZURE_FOUNDRY_MANAGED_ISOLATION_MODE"} {
		assert.Equal(t, "[reference('resources').outputs."+name+".value]", object(object(arm["outputs"])[name])["value"])
	}
}

func TestStandardNetworkSelectionUnaffectedByOnboarding(t *testing.T) {
	const vnet = "/subscriptions/network-sub/resourceGroups/network-rg/providers/Microsoft.Network/virtualNetworks/network"
	for _, choice := range []string{"none", "managed", "existing customer subnet", "create customer and PE subnets"} {
		t.Run(choice, func(t *testing.T) {
			network := ""
			expected := map[string]any{
				"enableNetworkIsolation": false, "useManagedEgress": false, "vnetId": "",
				"agentSubnetName": "agent-subnet", "agentSubnetPrefix": "", "createAgentSubnet": false,
				"peSubnetName": "pe-subnet", "peSubnetPrefix": "", "createPESubnet": false,
				"managedIsolationMode": "", "dnsZonesResourceGroup": "", "dnsZonesSubscription": "",
			}
			if choice != "none" {
				network = "    network:\n      peSubnet: {vnet: " + vnet + ", name: pe}\n"
				expected["enableNetworkIsolation"], expected["useManagedEgress"] = true, true
				expected["vnetId"], expected["peSubnetName"] = vnet, "pe"
			}
			if strings.Contains(choice, "customer") {
				network += "      agentSubnet: {vnet: " + vnet + ", name: agents}\n"
				expected["useManagedEgress"], expected["agentSubnetName"] = false, "agents"
			}
			if strings.HasPrefix(choice, "create") {
				network = strings.Replace(network, "name: agents}", "name: agents, prefix: 10.0.1.0/24}", 1)
				network = strings.Replace(network, "name: pe}", "name: pe, prefix: 10.0.2.0/24}", 1)
				expected["createAgentSubnet"], expected["agentSubnetPrefix"] = true, "10.0.1.0/24"
				expected["createPESubnet"], expected["peSubnetPrefix"] = true, "10.0.2.0/24"
			}
			standard, err := Synthesize(Input{
				RawAzureYAML: []byte("services:\n  project:\n    host: azure.ai.project\n" + network),
				ServiceName:  "project",
			})
			require.NoError(t, err)
			byoInput := hostingContractInput("")
			byoInput.RawAzureYAML = append(byoInput.RawAzureYAML, []byte(network)...)
			byo, err := Synthesize(byoInput)
			require.NoError(t, err)
			for _, result := range []*Result{standard, byo} {
				for key, value := range expected {
					assert.Equal(t, value, result.Parameters[key], key)
				}
				assert.Equal(t, standard.NetworkMode, result.NetworkMode)
			}
			require.NoError(t, ApplyBYOOnboarding(byo, onboardingContractPlan()))
			for key, value := range expected {
				assert.Equal(t, value, byo.Parameters[key], "binding the graph must preserve "+key)
			}
		})
	}
}
