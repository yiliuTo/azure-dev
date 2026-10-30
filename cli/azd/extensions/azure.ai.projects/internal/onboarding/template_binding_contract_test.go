// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"encoding/json"

	"strings"
	"testing"

	"azure.ai.projects/internal/synthesis"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateDigestRetainsResourceMetadata(t *testing.T) {
	template := map[string]any{
		"$schema":  "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		"metadata": map[string]any{"_generator": map[string]any{"templateHash": "compiler"}},
		"resources": map[string]any{
			"connection": map[string]any{
				"properties": map[string]any{"metadata": map[string]any{"ResourceId": "actual-registry"}},
			},
		},
	}
	before, err := TemplateDigest(template)
	require.NoError(t, err)
	delete(template, "metadata")
	after, err := TemplateDigest(template)
	require.NoError(t, err)
	assert.Equal(t, before, after, "only template-level non-executable metadata is excluded")
	connection := cleanupObject(t, cleanupObject(t, template["resources"])["connection"])
	cleanupObject(t, cleanupObject(t, connection["properties"])["metadata"])["ResourceId"] = "changed-registry"
	after, err = TemplateDigest(template)
	require.NoError(t, err)
	assert.NotEqual(t, before, after, "resource metadata is part of the actual request and must stay bound")
}

func TestTemplateDigestCanonicalizesOnlyARMDeclarationTypes(t *testing.T) {
	const source = `{
		"$schema":"https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
		"contentVersion":"1.0.0.0","languageVersion":"2.0",
		"metadata":{"_generator":{"templateHash":"9622934973028600007"}},
		"definitions":{"hosting":{"type":"object","properties":{"enabled":{"type":"bool"}}}},
		"parameters":{"mode":{"type":"string","defaultValue":"String"}},
		"outputs":{"id":{"type":"string","value":"[parameters('mode')]"}},
		"variables":{"authored":{"type":"string","metadata":{"owner":"unchanged"}}},
		"resources":{"nested":{"type":"Microsoft.Resources/deployments","properties":{"template":{
			"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
			"metadata":{"_generator":{"templateHash":"3250899696596760951"}},
			"parameters":{"name":{"type":"string"}},"resources":{}
		}}}}
	}`
	// Actual export shape: symbolic resources, no root metadata, capitalized root declaration types,
	// while nested templates retain their own generator metadata.
	const exported = `{
		"$schema":"https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
		"contentVersion":"1.0.0.0","languageVersion":"2.0",
		"definitions":{"hosting":{"type":"Object","properties":{"enabled":{"type":"Bool"}}}},
		"parameters":{"mode":{"type":"String","defaultValue":"String"}},
		"outputs":{"id":{"type":"String","value":"[parameters('mode')]"}},
		"variables":{"authored":{"type":"string","metadata":{"owner":"unchanged"}}},
		"resources":{"nested":{"type":"Microsoft.Resources/deployments","properties":{"template":{
			"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
			"metadata":{"_generator":{"templateHash":"3250899696596760951"}},
			"parameters":{"name":{"type":"string"}},"resources":{}
		}}}}
	}`
	var template, actual map[string]any
	require.NoError(t, json.Unmarshal([]byte(source), &template))
	require.NoError(t, json.Unmarshal([]byte(exported), &actual))
	expected, err := TemplateDigest(template)
	require.NoError(t, err)
	digest, err := TemplateDigest(actual)
	require.NoError(t, err)
	assert.Equal(t, expected, digest)
	for _, replacement := range []string{
		strings.Replace(exported, `"defaultValue":"String"`, `"defaultValue":"string"`, 1),
		strings.Replace(exported, `"type":"Microsoft.Resources/deployments"`, `"type":"changed"`, 1),
		strings.Replace(exported, `"authored":{"type":"string"`, `"authored":{"type":"String"`, 1),
		strings.Replace(exported, `"owner":"unchanged"`, `"owner":"changed"`, 1),
		strings.Replace(exported, `"resources":{}`, `"resources":[]`, 1),
	} {
		var changed map[string]any
		require.NoError(t, json.Unmarshal([]byte(replacement), &changed))
		digest, err := TemplateDigest(changed)
		require.NoError(t, err)
		assert.NotEqual(t, expected, digest, "normalization must not erase authored content changes")
	}
}

func TestMissingContentDigestCannotRecoverOwnership(t *testing.T) {
	f := newCleanupARM(t, false, false)
	f.deploy(t)
	state, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	raw, err := synthesis.ARMTemplate()
	require.NoError(t, err)
	var template map[string]any
	require.NoError(t, json.Unmarshal(raw, &template))
	generator := cleanupObject(t, cleanupObject(t, template["metadata"])["_generator"])
	hash, ok := generator["templateHash"].(string)
	require.True(t, ok)
	state.Foundry.Spec.TemplateHash, state.Foundry.Spec.TemplateDigest = hash, ""
	for index := range state.Foundry.Attempts {
		state.Foundry.Attempts[index].TemplateHash = hash
		state.Foundry.Attempts[index].TemplateDigest = ""
		state.Foundry.Attempts[index].ARMTemplateHash = ""
		root := f.roots[strings.ToLower(state.Foundry.Attempts[index].ID)]
		properties := cleanupObject(t, root["properties"])
		properties["templateHash"] = "6828760392490666086"
		properties["template"] = template
	}
	require.NoError(t, f.base.journal.Save(t.Context(), state))
	before, err := json.Marshal(state)
	require.NoError(t, err)
	_, err = ResolveRecoveryContext(t.Context(), f.base.plan, contractCredential{}, f.options, f.base.journal)
	require.Error(t, err)
	after, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	encoded, err := json.Marshal(after)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(encoded), "read-only recovery must not rewrite the old hash or progress")
	require.Error(t, f.lifecycle.Observe(t.Context(), f.base.plan, f.result))
	confirmed, err := f.base.journal.Load(t.Context())
	require.NoError(t, err)
	assert.Equal(t, hash, confirmed.Foundry.Attempts[0].TemplateHash, "preserve the old generator-version binding")
	assert.Empty(t, confirmed.Foundry.Attempts[0].ARMTemplateHash,
		"missing source evidence cannot be repaired by accepting a new ARM generation")
}
