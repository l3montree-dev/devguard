package utils

import (
	"testing"
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
