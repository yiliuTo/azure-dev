// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package synthesis

import (
	"path/filepath"
	"testing"

	"github.com/azure/azure-dev/cli/azd/pkg/tools/bicep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBicepToolVersionRequirement(t *testing.T) {
	newer := bicep.Version
	newer.Patch++
	for _, tc := range []struct {
		name, output, wantError string
	}{
		{"SDK minimum", "Bicep CLI version " + bicep.Version.String() + " (hash)", ""},
		{"newer", "Bicep CLI version " + newer.String() + " (hash)", ""},
		{"old compiler", "Bicep CLI version 0.38.33 (hash)", "below azd SDK minimum " + bicep.Version.String()},
		{"invalid output", "unrecognized compiler", "unrecognized Bicep version"},
		{"other tool", "other CLI version 99.0.0", "unrecognized Bicep version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBicepVersion(tc.output)
			if tc.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantError)
			}
		})
	}
}

func TestBicepToolExplicitOverrideDoesNotFallBack(t *testing.T) {
	override := filepath.Join(t.TempDir(), "missing-bicep")
	path, err := findBicep(t.Context(), override)
	require.ErrorContains(t, err, override)
	assert.ErrorContains(t, err, "read Bicep version")
	assert.Empty(t, path)
}
