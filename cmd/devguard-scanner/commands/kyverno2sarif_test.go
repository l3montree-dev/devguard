package commands

import (
	"testing"

	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractKyvernoJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:     "valid JSON array with text before and after",
			input:    "Some text\n[{\"key\":\"value\"}]\nMore text",
			expected: "[{\"key\":\"value\"}]",
		},
		{
			name:     "JSON array only",
			input:    "[{\"ID\":1,\"POLICY\":\"test\"}]",
			expected: "[{\"ID\":1,\"POLICY\":\"test\"}]",
		},
		{
			name:        "no JSON array",
			input:       "No JSON here",
			expectError: true,
		},
		{
			name:        "malformed JSON - missing closing bracket",
			input:       "[{\"key\":\"value\"",
			expectError: true,
		},
		{
			name:     "nested arrays",
			input:    "prefix [1,[2,3]] suffix",
			expected: "[1,[2,3]]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractKyvernoJSON(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestConvertKyvernoToSARIF(t *testing.T) {
	t.Run("converts basic kyverno results", func(t *testing.T) {
		input := []kyvernoTestResult{
			{
				ID:       1,
				Policy:   "require-run-as-nonroot",
				Rule:     "check-runAsNonRoot",
				Resource: "Pod/nginx",
				Result:   "fail",
				Reason:   "validation error: Running as root is not allowed",
			},
		}

		result := convertKyvernoToSARIF(input)

		assert.Equal(t, sarif.SarifSchema210JsonVersionA210, result.Version)
		assert.Len(t, result.Runs, 1)
		assert.Equal(t, "Kyverno", result.Runs[0].Tool.Driver.Name)
		assert.Len(t, result.Runs[0].Results, 1)
		assert.Equal(t, "require-run-as-nonroot/check-runAsNonRoot", *result.Runs[0].Results[0].RuleID)
	})

	t.Run("groups multiple results by rule", func(t *testing.T) {
		input := []kyvernoTestResult{
			{ID: 1, Policy: "policy1", Rule: "rule1", Resource: "Pod/a", Result: "fail"},
			{ID: 2, Policy: "policy1", Rule: "rule1", Resource: "Pod/b", Result: "fail"},
			{ID: 3, Policy: "policy2", Rule: "rule2", Resource: "Pod/c", Result: "pass"},
		}

		result := convertKyvernoToSARIF(input)

		assert.Len(t, result.Runs[0].Tool.Driver.Rules, 2)
		assert.Len(t, result.Runs[0].Results, 3)
	})

	t.Run("extracts resource name for locations", func(t *testing.T) {
		input := []kyvernoTestResult{
			{
				ID:       1,
				Policy:   "test-policy",
				Rule:     "test-rule",
				Resource: "Namespace/default/Pod/nginx",
				Result:   "fail",
			},
		}

		result := convertKyvernoToSARIF(input)

		require.Len(t, result.Runs[0].Results[0].Locations, 1)
		require.Len(t, result.Runs[0].Results[0].Locations[0].LogicalLocations, 1)
		assert.Equal(t, "nginx", *result.Runs[0].Results[0].Locations[0].LogicalLocations[0].Name)
		assert.Equal(t, "resource", *result.Runs[0].Results[0].Locations[0].LogicalLocations[0].Kind)
	})
}
