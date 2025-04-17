package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeApiUrl(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/", "https://example.com"},
		{"http://example.com/", "http://example.com"},
		{"example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
	}

	for _, test := range tests {
		result := sanitizeApiUrl(test.input)
		assert.Equal(t, test.expected, result)
	}
}
