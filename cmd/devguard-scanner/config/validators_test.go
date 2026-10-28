package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeAPIURL(t *testing.T) {
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
		result := sanitizeAPIURL(test.input)
		assert.Equal(t, test.expected, result)
	}
}

func TestIsValidPathList(t *testing.T) {
	t.Run("should accept a single existing path", func(t *testing.T) {
		assert.NoError(t, isValidPathList("validators.go"))
	})

	t.Run("should accept a comma separated list of existing paths", func(t *testing.T) {
		assert.NoError(t, isValidPathList("validators.go, config.go,"))
	})

	t.Run("should reject the list if one path does not exist", func(t *testing.T) {
		assert.Error(t, isValidPathList("validators.go,does-not-exist.go"))
	})
}
