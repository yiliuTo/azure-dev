// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"azure.ai.projects/internal/onboarding"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func contractBYOOutputs(t *testing.T, p *FoundryProvisioningProvider) map[string]any {
	t.Helper()
	project, err := arm.ParseResourceID(p.byoSpec.ProjectID)
	require.NoError(t, err)
	outputs := map[string]any{}
	for name, value := range map[string]string{
		"AZURE_AI_ACCOUNT_NAME":                p.byoPlan.Account.Name,
		"AZURE_AI_PROJECT_NAME":                project.Name,
		"AZURE_AI_PROJECT_ID":                  p.byoSpec.ProjectID,
		"AZURE_CONTAINER_REGISTRY_RESOURCE_ID": p.byoPlan.Registry.ID,
	} {
		outputs[name] = map[string]any{"type": "String", "value": value}
	}
	outputs["AZD_BYO_AKS_OWNERSHIP"] = map[string]any{
		"type": "Object", "value": map[string]any{
			"deploymentId": p.byoPlan.DeploymentID, "roleAssignments": []any{},
		},
	}
	return outputs
}

func contractBYOSuccessBody(t *testing.T, p *FoundryProvisioningProvider, id string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"id": id, "properties": map[string]any{
			"provisioningState": "Succeeded", "outputs": contractBYOOutputs(t, p),
		},
	})
	require.NoError(t, err)
	return string(raw)
}

func TestBYODeploymentOutputsMatchExactPlan(t *testing.T) {
	p := byoContractProvider(t)
	var events []string
	p.byoPipeline = byoContractPipeline(&events, onboarding.Pass)
	require.NoError(t, p.planBYO(t.Context(), func(string) {}, false))
	require.NoError(t, validateBYODeploymentOutputs(*p.byoPlan, p.byoSpec, contractBYOOutputs(t, p)))
	for _, key := range []string{
		"AZURE_AI_ACCOUNT_NAME", "AZURE_AI_PROJECT_NAME", "AZURE_AI_PROJECT_ID", "AZURE_CONTAINER_REGISTRY_RESOURCE_ID",
	} {
		t.Run(key, func(t *testing.T) {
			for _, value := range []any{"different-target", 42, nil} {
				outputs := contractBYOOutputs(t, p)
				outputs[key] = map[string]any{"type": "String", "value": value}
				require.ErrorContains(t, validateBYODeploymentOutputs(*p.byoPlan, p.byoSpec, outputs), key)
			}
			outputs := contractBYOOutputs(t, p)
			delete(outputs, key)
			require.ErrorContains(t, validateBYODeploymentOutputs(*p.byoPlan, p.byoSpec, outputs), key)
			outputs = contractBYOOutputs(t, p)
			outputs[strings.ToLower(key)] = outputs[key]
			require.ErrorContains(t, validateBYODeploymentOutputs(*p.byoPlan, p.byoSpec, outputs), "ambiguous")
			delete(outputs, key)
			require.NoError(t, validateBYODeploymentOutputs(*p.byoPlan, p.byoSpec, outputs))
		})
	}
	require.Error(t, validateBYODeploymentOutputs(*p.byoPlan, p.byoSpec, nil))
}

func contractLifecycleResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: request,
	}
}

func lifecycleObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	require.True(t, ok, "expected an object, got %T", value)
	return object
}

func TestBYOSelectedOperationsFollowEffectiveOnDiskInputs(t *testing.T) {
	p := byoContractProvider(t)
	const principal = "00000000-0000-0000-0000-000000000044"
	p.onDiskSource = &templateSource{
		mode: templateModeBicep, armTemplate: p.armTemplate, sourcePath: "offline-main.bicep",
		parameters: map[string]any{
			"principalId":   map[string]any{"value": principal},
			"principalType": map[string]any{"value": "ServicePrincipal"},
			"deployments":   map[string]any{"value": []any{map[string]any{"name": "selected-model"}}},
		},
	}
	var checked bool
	p.byoPipeline = &onboarding.Pipeline{
		Resources: byoResourceContract(func(context.Context, onboarding.Plan) (onboarding.Facts, onboarding.Report, error) {
			return onboarding.Facts{KubeletObjectID: principal}, nil, nil
		}),
		Access: byoAccessContract(func(_ context.Context, plan onboarding.Plan, _ onboarding.Facts) (onboarding.Report, error) {
			checked = true
			var models, connections, developer bool
			for _, op := range plan.Operations {
				models = models || op.Action == "Microsoft.CognitiveServices/accounts/deployments/write"
				connections = connections || op.Action == "Microsoft.CognitiveServices/accounts/projects/connections/write"
				developer = developer || op.RoleID == "a97b65f3-24c7-4388-baec-2e87135dc908"
			}
			assert.False(t, models, "ordinary model deployment is not a BYO permission precheck")
			assert.False(t, connections, "ordinary ACR connection is not a BYO permission precheck")
			assert.False(t, developer, "developer grant remains in the separate predeploy lifecycle")
			return nil, nil
		}),
	}
	require.NoError(t, p.planBYO(t.Context(), func(string) {}, false))
	assert.True(t, checked)
	assert.Equal(t, []string{"selected-model"}, p.byoSpec.ModelNames,
		"removing model permission inference does not remove the actual deployment")
}

func TestBYOPlannedGroupTagsPreserveObservedAndExplicitChoices(t *testing.T) {
	for _, test := range []struct {
		name     string
		observed map[string]string
		explicit map[string]string
		want     map[string]string
	}{
		{
			name: "explicit case-insensitive customer change",
			observed: map[string]string{
				"customer-billing": "old", "untouched": "preserve",
			},
			explicit: map[string]string{"Customer-Billing": "new"},
			want: map[string]string{
				"Customer-Billing": "new", "untouched": "preserve",
			},
		},
		{
			name:     "explicit case-insensitive alias",
			observed: map[string]string{"customer": "original"},
			explicit: map[string]string{"CUSTOMER": "updated"},
			want:     map[string]string{"CUSTOMER": "updated"},
		},
		{
			name: "empty explicit value", observed: map[string]string{"customer": "original"},
			explicit: map[string]string{"customer": ""}, want: map[string]string{"customer": ""},
		},
		{
			name: "new explicit tag", observed: map[string]string{"customer": "preserve"},
			explicit: map[string]string{"billing": "new"},
			want:     map[string]string{"customer": "preserve", "billing": "new"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := byoContractProvider(t)
			p.synthResult.Parameters["tags"] = test.observed
			parameters := map[string]any{"tags": map[string]any{"value": test.explicit}}
			err := p.bindPlannedGroupTags(parameters)
			require.NoError(t, err)
			assert.Equal(t, test.want, parameters["tags"].(map[string]any)["value"])
		})
	}
}
