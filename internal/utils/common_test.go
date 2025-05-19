package utils

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddToWhitespaceSeparatedStringList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		item     string
		expected string
	}{
		{
			name:     "Add item to empty list",
			input:    "",
			item:     "item1",
			expected: "item1",
		},
		{
			name:     "Add item to non-empty list",
			input:    "item1 item2",
			item:     "item3",
			expected: "item1 item2 item3",
		},
		{
			name:     "Add duplicate item",
			input:    "item1 item2",
			item:     "item1",
			expected: "item1 item2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AddToWhitespaceSeparatedStringList(tt.input, tt.item)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestRemoveFromWhitespaceSeparatedStringList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		item     string
		expected string
	}{
		{
			name:     "Remove item from list",
			input:    "item1 item2 item3",
			item:     "item2",
			expected: "item1 item3",
		},
		{
			name:     "Remove non-existent item",
			input:    "item1 item2 item3",
			item:     "item4",
			expected: "item1 item2 item3",
		},
		{
			name:     "Remove item from single-item list",
			input:    "item1",
			item:     "item1",
			expected: "",
		},
		{
			name:     "Remove item from empty list",
			input:    "",
			item:     "item1",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveFromWhitespaceSeparatedStringList(tt.input, tt.item)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: 0.,
		},
		{
			name:     "Single character string",
			input:    "a",
			expected: 0.,
		},
		{
			name:     "String with all unique characters",
			input:    "abcdef",
			expected: 2.584963,
		},
		{
			name:     "String with repeated characters",
			input:    "aabbcc",
			expected: 1.584963,
		},
		{
			name:     "String with highly repetitive characters",
			input:    "aaaaaa",
			expected: 0.,
		},
		{
			name:     "String with mixed characters",
			input:    "abcabcabc",
			expected: 1.584963,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShannonEntropy(tt.input)
			if math.Abs(result-tt.expected) > 0.000001 {
				t.Errorf("expected %f, got %f", tt.expected, result)
			}
		})
	}
}

func TestBeautifyPURL(t *testing.T) {
	t.Run("empty String should also return an empty string back", func(t *testing.T) {
		inputString := ""
		result, _ := BeautifyPURL(inputString)
		assert.Equal(t, "", result)
	})
	t.Run("invalid purl format should also be returned unchanged", func(t *testing.T) {
		inputString := "this is definitely not a valid purl"
		result, _ := BeautifyPURL(inputString)
		assert.Equal(t, inputString, result)
	})
	t.Run("should return only the namespace and the name of a valid purl and cut the rest", func(t *testing.T) {
		inputString := "pkg:npm/@ory/integrations@v0.0.1"
		result, _ := BeautifyPURL(inputString)
		assert.Equal(t, "@ory/integrations", result)
	})
	t.Run("should return no leading slash if the namespace is empty", func(t *testing.T) {
		inputString := "pkg:npm/integrations@v0.0.1"
		result, _ := BeautifyPURL(inputString)
		assert.Equal(t, "integrations", result)
	})
}
