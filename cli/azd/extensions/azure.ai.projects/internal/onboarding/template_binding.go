// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package onboarding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// TemplateDigest identifies template content independently of Bicep generator metadata.
func TemplateDigest(template any) (string, error) {
	object, ok := template.(map[string]any)
	if !ok || len(object) == 0 {
		return "", fmt.Errorf("deployment template content is unavailable")
	}
	raw, err := json.Marshal(templateBindingContent(object))
	if err != nil {
		return "", fmt.Errorf("encode deployment template binding: %w", err)
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

func templateBindingContent(value any) any {
	switch value := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(value))
		schema, _ := value["$schema"].(string)
		isTemplate := strings.HasSuffix(strings.ToLower(schema), "deploymenttemplate.json#")
		for key, item := range value {
			if key != "metadata" || !isTemplate {
				if isTemplate && (key == "parameters" || key == "outputs" || key == "definitions") {
					result[key] = templateDeclarationMap(item)
				} else {
					result[key] = templateBindingContent(item)
				}
			}
		}
		return result
	case []any:
		result := make([]any, len(value))
		for index, item := range value {
			result[index] = templateBindingContent(item)
		}
		return result
	default:
		return value
	}
}

func templateDeclarationMap(value any) any {
	definitions, ok := value.(map[string]any)
	if !ok {
		return value
	}
	result := make(map[string]any, len(definitions))
	for key, definition := range definitions {
		result[key] = templateDeclaration(definition)
	}
	return result
}

func templateDeclaration(value any) any {
	definition, ok := value.(map[string]any)
	if !ok {
		return value
	}
	result := make(map[string]any, len(definition))
	for key, item := range definition {
		switch key {
		case "type":
			if kind, ok := item.(string); ok {
				switch lower := strings.ToLower(kind); lower {
				case "string", "securestring", "int", "bool", "object", "secureobject", "array":
					item = lower
				}
			}
			result[key] = item
		case "properties":
			result[key] = templateDeclarationMap(item)
		case "items", "additionalProperties":
			result[key] = templateDeclaration(item)
		default:
			result[key] = templateBindingContent(item)
		}
	}
	return result
}
