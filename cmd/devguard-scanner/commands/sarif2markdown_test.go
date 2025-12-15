package commands

import (
	"testing"

	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/stretchr/testify/assert"
)

func TestExtractResourceName(t *testing.T) {
	tests := []struct {
		name     string
		result   sarif.Result
		expected string
	}{
		{
			name: "from properties",
			result: sarif.Result{
				Properties: &sarif.PropertyBag{
					AdditionalProperties: map[string]interface{}{
						"resource": "Pod/nginx",
					},
				},
			},
			expected: "Pod/nginx",
		},
		{
			name: "from logical location",
			result: sarif.Result{
				Locations: []sarif.Location{
					{
						LogicalLocations: []sarif.LogicalLocation{
							{Name: ptr("test-pod")},
						},
					},
				},
			},
			expected: "test-pod",
		},
		{
			name:     "no resource info",
			result:   sarif.Result{},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractResourceName(tt.result)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractPolicyAndRuleFromRuleID(t *testing.T) {
	tests := []struct {
		ruleID         string
		expectedPolicy string
		expectedRule   string
	}{
		{
			ruleID:         "require-labels/check-labels",
			expectedPolicy: "require-labels",
			expectedRule:   "check-labels",
		},
		{
			ruleID:         "single-part",
			expectedPolicy: "single-part",
			expectedRule:   "single-part",
		},
		{
			ruleID:         "policy/rule/extra",
			expectedPolicy: "policy",
			expectedRule:   "rule", // Only returns parts[1], not all remaining parts
		},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			policy := extractPolicyFromRuleID(tt.ruleID)
			rule := extractRuleFromRuleID(tt.ruleID)
			assert.Equal(t, tt.expectedPolicy, policy)
			assert.Equal(t, tt.expectedRule, rule)
		})
	}
}

func TestGetResultStatus(t *testing.T) {
	tests := []struct {
		message  string
		expected string
	}{
		{"Got fail on resource", "❌"},
		{"Got skip for this check", "⏭️"},
		{"Got pass on all checks", "✅"},
		{"Check passed successfully", "✅"},
		{"Unknown message format", "❓"},
	}

	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			result := getResultStatus(tt.message)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSeverityBadge(t *testing.T) {
	tests := []struct {
		level    string
		expected string
	}{
		{"critical", "🔴 Critical"},
		{"CRITICAL", "🔴 Critical"},
		{"high", "🟠 High"},
		{"medium", "🟡 Medium"},
		{"low", "🔵 Low"},
		{"note", "⚪ Note"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			result := getSeverityBadge(tt.level)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCleanMessage(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "validation error (Resource: Pod/nginx)",
			expected: "validation error",
		},
		{
			input:    "simple message",
			expected: "simple message",
		},
		{
			input:    "error message (Resource: test) with more",
			expected: "error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := cleanMessage(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEscapeMarkdown(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple text", "simple text"},
		{"text|with|pipes", "text\\|with\\|pipes"},
		{"no|pipes|here", "no\\|pipes\\|here"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := escapeMarkdown(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAggregateResults(t *testing.T) {
	t.Run("aggregates results by rule ID", func(t *testing.T) {
		results := []sarif.Result{
			{
				RuleID: ptr("policy1/rule1"),
				Level:  "high",
				Message: sarif.Message{
					Text: "Got fail on resource1",
				},
				Properties: &sarif.PropertyBag{
					AdditionalProperties: map[string]interface{}{
						"policy":   "policy1",
						"resource": "Pod/test1",
					},
				},
			},
			{
				RuleID: ptr("policy1/rule1"),
				Level:  "high",
				Message: sarif.Message{
					Text: "Got pass on resource2",
				},
				Properties: &sarif.PropertyBag{
					AdditionalProperties: map[string]interface{}{
						"policy":   "policy1",
						"resource": "Pod/test2",
					},
				},
			},
		}

		summaries := aggregateResults(results)

		assert.Len(t, summaries, 1)
		assert.Equal(t, "policy1/rule1", summaries[0].RuleID)
		assert.Equal(t, 1, summaries[0].FailCount)
		assert.Equal(t, 1, summaries[0].PassCount)
		assert.Len(t, summaries[0].Resources, 2)
	})

	t.Run("sorts by severity", func(t *testing.T) {
		results := []sarif.Result{
			{
				RuleID:  ptr("policy1/rule1"),
				Level:   "low",
				Message: sarif.Message{Text: "test"},
				Properties: &sarif.PropertyBag{
					AdditionalProperties: map[string]interface{}{
						"policy":   "policy1",
						"resource": "resource1",
					},
				},
			},
			{
				RuleID:  ptr("policy2/rule2"),
				Level:   "critical",
				Message: sarif.Message{Text: "test"},
				Properties: &sarif.PropertyBag{
					AdditionalProperties: map[string]interface{}{
						"policy":   "policy2",
						"resource": "resource2",
					},
				},
			},
			{
				RuleID:  ptr("policy3/rule3"),
				Level:   "medium",
				Message: sarif.Message{Text: "test"},
				Properties: &sarif.PropertyBag{
					AdditionalProperties: map[string]interface{}{
						"policy":   "policy3",
						"resource": "resource3",
					},
				},
			},
		}

		summaries := aggregateResults(results)

		assert.Equal(t, "critical", summaries[0].Level)
		assert.Equal(t, "medium", summaries[1].Level)
		assert.Equal(t, "low", summaries[2].Level)
	})
}

func TestGetStatusIndicator(t *testing.T) {
	tests := []struct {
		name     string
		pass     int
		fail     int
		skip     int
		expected string
	}{
		{"only fails", 0, 5, 0, "❌ 5 fail"},
		{"only passes", 10, 0, 0, "✅ 10 pass"},
		{"only skips", 0, 0, 3, "⏭️ 3 skip"},
		{"fails take precedence", 5, 2, 1, "❌ 2 fail"},
		{"skips over passes", 5, 0, 2, "⏭️ 2 skip"},
		{"no results", 0, 0, 0, "—"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStatusIndicator(tt.pass, tt.fail, tt.skip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateSummaryMarkdown(t *testing.T) {
	doc := &sarif.SarifSchema210Json{
		Runs: []sarif.Run{
			{
				Tool: sarif.Tool{
					Driver: sarif.ToolComponent{
						Name: "TestTool",
					},
				},
				Results: []sarif.Result{
					{
						RuleID: ptr("policy1/rule1"),
						Level:  "high",
						Message: sarif.Message{
							Text: "Got fail on check",
						},
						Properties: &sarif.PropertyBag{
							AdditionalProperties: map[string]interface{}{
								"policy":   "policy1",
								"resource": "Pod/test",
							},
						},
					},
				},
			},
		},
	}

	markdown := generateSummaryMarkdown(doc)

	assert.Contains(t, markdown, "# TestTool Security Scan Results")
	assert.Contains(t, markdown, "## Summary by Policy Rule")
	assert.Contains(t, markdown, "policy1")
	assert.Contains(t, markdown, "rule1")
	assert.Contains(t, markdown, "## Overall Statistics")
	assert.Contains(t, markdown, "❌ Failed: 1")
}

func ptr[T any](v T) *T {
	return &v
}
