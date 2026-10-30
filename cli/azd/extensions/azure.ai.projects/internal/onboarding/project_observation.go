// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"fmt"
	"net/url"
	"strings"
)

func recordProjectEndpoint(state *PreparationState, endpoint string) error {
	if endpoint == "" {
		return fmt.Errorf("deployment output does not contain the Project API endpoint")
	}
	id, err := ParseID(state.Foundry.Spec.ProjectID, "Microsoft.CognitiveServices/accounts/projects")
	if err != nil {
		return err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		!strings.EqualFold(parsed.Path, "/api/projects/"+id.Name) {
		return fmt.Errorf("owned Foundry project's actual API endpoint is unverified")
	}
	endpoint = strings.TrimRight(endpoint, "/")
	if state.Foundry.ProjectEndpoint != "" && !strings.EqualFold(state.Foundry.ProjectEndpoint, endpoint) {
		return fmt.Errorf("owned Foundry project's recorded API endpoint changed")
	}
	state.Foundry.ProjectEndpoint = endpoint
	return nil
}
