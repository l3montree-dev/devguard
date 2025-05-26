// Copyright (C) 2025 l3montree UG (haftungsbeschraenkt)
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

package config

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestParseBaseConfig(t *testing.T) {
	t.Run("should use the provided config values if passed directly", func(t *testing.T) {
		viper.Set("apiUrl", "http://example.com")
		viper.Set("path", ".")
		viper.Set("ref", "myref")
		viper.Set("defaultRef", "mydefaultref")

		ParseBaseConfig()
		assert.Equal(t, "http://example.com", RuntimeBaseConfig.ApiUrl)
		assert.Equal(t, ".", RuntimeBaseConfig.Path)
		assert.Equal(t, "myref", RuntimeBaseConfig.Ref)
		assert.Equal(t, "mydefaultref", RuntimeBaseConfig.DefaultRef)
	})

	t.Run("should panic if the path is invalid", func(t *testing.T) {
		assert.Panics(t, func() {
			viper.Set("path", "/invalid/path")
			ParseBaseConfig()
		}, "Expected panic due to invalid path")
	})

	t.Run("should sanitize the provided apiUrl like adding the protocol", func(t *testing.T) {
		viper.Set("apiUrl", "example.com/api")
		viper.Set("path", ".")
		ParseBaseConfig()
		assert.Equal(t, "https://example.com/api", RuntimeBaseConfig.ApiUrl)
	})

	t.Run("should remove a trailing slash from the apiUrl", func(t *testing.T) {
		viper.Set("apiUrl", "https://example.com/api/")
		viper.Set("path", ".")
		ParseBaseConfig()
		assert.Equal(t, "https://example.com/api", RuntimeBaseConfig.ApiUrl)
	})

	t.Run("should use the git version info if ref is NOT set", func(t *testing.T) {
		// not setting ref
		viper.Set("ref", "")
		viper.Set("defaultRef", "main")
		viper.Set("path", ".")
		viper.Set("apiUrl", "https://example.com/api")

		m := mocks.NewGitLister(t)
		m.On("GetTags", ".").Return([]string{"v1.0.0", "v1.0.5", "v2.0.9"}, nil)
		m.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		m.On("GetBranchName", ".").Return("", nil)
		m.On("GetDefaultBranchName", ".").Return("other-than-main", nil)

		utils.GitLister = m

		ParseBaseConfig()

		assert.Equal(t, "https://example.com/api", RuntimeBaseConfig.ApiUrl)
		assert.Equal(t, ".", RuntimeBaseConfig.Path)
		assert.Equal(t, "2.0.9", RuntimeBaseConfig.Ref)
		assert.Equal(t, "main", RuntimeBaseConfig.DefaultRef)
	})

	t.Run("should use the git version info if defaultRef is NOT set", func(t *testing.T) {
		// not setting defaultRef
		viper.Set("ref", "v1.0.0")
		viper.Set("defaultRef", "")
		viper.Set("path", ".")
		viper.Set("apiUrl", "https://example.com/api")

		m := mocks.NewGitLister(t)
		m.On("GetTags", ".").Return([]string{"v1.0.0", "v1.0.5", "v2.0.9"}, nil)
		m.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		m.On("GetBranchName", ".").Return("", nil)
		m.On("GetDefaultBranchName", ".").Return("main", nil)

		utils.GitLister = m

		ParseBaseConfig()

		assert.Equal(t, "https://example.com/api", RuntimeBaseConfig.ApiUrl)
		assert.Equal(t, ".", RuntimeBaseConfig.Path)
		assert.Equal(t, "v1.0.0", RuntimeBaseConfig.Ref)
		assert.Equal(t, "main", RuntimeBaseConfig.DefaultRef)
	})
}
