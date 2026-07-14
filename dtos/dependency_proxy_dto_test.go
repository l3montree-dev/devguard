// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dtos_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/dtos"
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
		{name: "empty content is skipped", configID: dtos.DependencyProxyConfigFileID, content: "", expectErr: false},
		{name: "valid config", configID: dtos.DependencyProxyConfigFileID, content: `{"rules":"pkg:npm/foo","minReleaseAge":72}`, expectErr: false},
		{name: "zero disables cooldown", configID: dtos.DependencyProxyConfigFileID, content: `{"minReleaseAge":0}`, expectErr: false},
		{name: "at upper bound", configID: dtos.DependencyProxyConfigFileID, content: `{"minReleaseAge":87600}`, expectErr: false},
		{name: "negative rejected", configID: dtos.DependencyProxyConfigFileID, content: `{"minReleaseAge":-1}`, expectErr: true},
		{name: "above upper bound rejected", configID: dtos.DependencyProxyConfigFileID, content: `{"minReleaseAge":87601}`, expectErr: true},
		{name: "malformed json rejected", configID: dtos.DependencyProxyConfigFileID, content: `{not json`, expectErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := dtos.ValidateConfigFile([]byte(tc.content))
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
