// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

type byoResolvedNames struct {
	AccountID      string
	RegistryName   string
	DeploymentID   string
	Group          *armresources.ResourceGroup
	ParentResolved bool
}

type byoNamingScope struct {
	SubscriptionID  string `json:"subscriptionId"`
	ResourceGroupID string `json:"resourceGroupId"`
	Location        string `json:"location"`
	Salt            string `json:"salt"`
}

var officialResourceToken = regexp.MustCompile(`^[a-z2-7]{13}$`)

func (p *FoundryProvisioningProvider) resolveBYONames(
	ctx context.Context, source *templateSource,
) (byoResolvedNames, error) {
	var result byoResolvedNames
	values := map[string]string{}
	for _, key := range []string{"resourceGroupName", "location", "resourceTokenSalt", "foundryProjectName"} {
		value, ok := byoParameterValue(source, key).(string)
		if !ok || key != "resourceTokenSalt" && value == "" {
			return result, fmt.Errorf("I03: effective %s must be a literal string, nonempty except resourceTokenSalt", key)
		}
		values[key] = value
	}
	if p.byoNames != nil {
		return p.byoNames(ctx, source)
	}
	if err := p.ensureCredential(ctx); err != nil {
		return result, err
	}
	subscriptions, err := armsubscriptions.NewClient(p.credential, p.byoARMOptions())
	if err != nil {
		return result, err
	}
	subscription, err := subscriptions.Get(ctx, p.subID, nil)
	if err != nil {
		return result, fmt.Errorf("read exact subscription scope for official Foundry naming: %w", err)
	}
	subscriptionID := ""
	if subscription.ID != nil {
		subscriptionID = *subscription.ID
	}
	if !strings.EqualFold(subscriptionID, "/subscriptions/"+p.subID) {
		return result, fmt.Errorf("official Foundry naming requires the actual selected subscription ARM ID")
	}
	groupID := subscriptionID + "/resourceGroups/" + values["resourceGroupName"]
	groups, err := armresources.NewResourceGroupsClient(p.subID, p.credential, p.byoARMOptions())
	if err != nil {
		return result, err
	}
	group, err := groups.Get(ctx, values["resourceGroupName"], nil)
	if err == nil {
		if group.ID == nil || !strings.EqualFold(*group.ID, groupID) {
			return result, fmt.Errorf("official Foundry naming requires the exact selected resource-group ARM ID")
		}
		groupID = *group.ID
		result.Group = &group.ResourceGroup
	} else if !isNotFound(err) {
		return result, fmt.Errorf("read exact resource-group scope for official Foundry naming: %w", err)
	}
	token, err := evaluateBYOResourceToken(ctx, p.bicepCli(), byoNamingScope{
		SubscriptionID: subscriptionID, ResourceGroupID: groupID,
		Location: values["location"], Salt: values["resourceTokenSalt"],
	})
	if err != nil {
		return result, err
	}
	result.AccountID = groupID + "/providers/Microsoft.CognitiveServices/accounts/cog-" + token
	result.RegistryName = byoRegistryName(p.subID, p.rgName, p.envName, p.projectPath)
	result.DeploymentID = "/subscriptions/" + p.subID + "/providers/Microsoft.Resources/deployments/" + p.deploymentName()
	result.ParentResolved = true
	return result, nil
}

func byoRegistryName(subscription, group, environment, projectPath string) string {
	parent := "/subscriptions/" + subscription + "/resourceGroups/" + group
	hash := sha256.Sum256([]byte(strings.ToLower(parent) + "|" + environment + "|" + projectPath))
	return fmt.Sprintf("azd%x", hash[:8])
}

func evaluateBYOResourceToken(
	ctx context.Context, compiler bicepCompiler, scope byoNamingScope,
) (token string, err error) {
	dir, err := os.MkdirTemp("", "azd-foundry-naming-")
	if err != nil {
		return "", fmt.Errorf("create official Foundry naming evaluation directory: %w", err)
	}
	defer func() {
		err = errors.Join(err, os.RemoveAll(dir))
	}()
	raw, err := json.Marshal(scope)
	if err != nil {
		return "", fmt.Errorf("encode official Foundry naming scope: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scope.json"), raw, 0o600); err != nil {
		return "", fmt.Errorf("write official Foundry naming scope: %w", err)
	}
	const probe = "using none\n" +
		"var scope = loadJsonContent('./scope.json')\n" +
		"param resourceToken = empty(scope.salt)\n" +
		"  ? uniqueString(scope.subscriptionId, scope.resourceGroupId, scope.location)\n" +
		"  : uniqueString(scope.subscriptionId, scope.resourceGroupId, scope.location, scope.salt)\n"
	path := filepath.Join(dir, "naming.bicepparam")
	if err := os.WriteFile(path, []byte(probe), 0o600); err != nil {
		return "", fmt.Errorf("write official Foundry naming expression: %w", err)
	}
	compiled, err := compiler.BuildBicepParam(ctx, path, []string{"BICEP_PARAMETERS_OVERRIDES={}"})
	if err != nil {
		return "", fmt.Errorf("evaluate official Foundry naming with azd-managed Bicep: %w", err)
	}
	var envelope struct {
		ParametersJSON string `json:"parametersJson"`
	}
	if err := json.Unmarshal([]byte(compiled.Compiled), &envelope); err != nil {
		return "", fmt.Errorf("decode official Foundry naming evaluation: %w", err)
	}
	var parameters struct {
		Parameters map[string]struct {
			Value string `json:"value"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal([]byte(envelope.ParametersJSON), &parameters); err != nil {
		return "", fmt.Errorf("decode official Foundry naming parameters: %w", err)
	}
	token = parameters.Parameters["resourceToken"].Value
	if !officialResourceToken.MatchString(token) {
		return "", fmt.Errorf("official Bicep returned an invalid Foundry resource token")
	}
	return token, nil
}
