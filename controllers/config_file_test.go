package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateConfigFile(t *testing.T) {
	testCases := []struct {
		name      string
		configID  string
		content   string
		expectErr bool
	}{
		{name: "unknown config id is not validated", configID: "other", content: `{not json`, expectErr: false},
		{name: "empty content is skipped", configID: dependencyProxyConfigFileID, content: "", expectErr: false},
		{name: "valid config", configID: dependencyProxyConfigFileID, content: `{"rules":"pkg:npm/foo","minReleaseAge":72}`, expectErr: false},
		{name: "zero disables cooldown", configID: dependencyProxyConfigFileID, content: `{"minReleaseAge":0}`, expectErr: false},
		{name: "at upper bound", configID: dependencyProxyConfigFileID, content: `{"minReleaseAge":87600}`, expectErr: false},
		{name: "negative rejected", configID: dependencyProxyConfigFileID, content: `{"minReleaseAge":-1}`, expectErr: true},
		{name: "above upper bound rejected", configID: dependencyProxyConfigFileID, content: `{"minReleaseAge":87601}`, expectErr: true},
		{name: "malformed json rejected", configID: dependencyProxyConfigFileID, content: `{not json`, expectErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfigFile(tc.configID, []byte(tc.content))
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
