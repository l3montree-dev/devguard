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
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setEmptyEnvVars(t *testing.T) {
	// Clear the environment variables to avoid conflicts
	t.Setenv("CI_COMMIT_REF_NAME", "")
	t.Setenv("CI_DEFAULT_BRANCH", "")
	t.Setenv("CI_COMMIT_TAG", "")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_BASE_REF", "")
}

func TestParseBaseConfig(t *testing.T) {
	setEmptyEnvVars(t)
	t.Run("should use the provided config values if passed directly", func(t *testing.T) {
		viper.Set("apiURL", "http://example.com")
		viper.Set("path", ".")
		viper.Set("ref", "myref")
		viper.Set("defaultRef", "mydefaultref")

		ParseBaseConfig()
		assert.Equal(t, "http://example.com", RuntimeBaseConfig.APIURL)
		assert.Equal(t, ".", RuntimeBaseConfig.Path)
		assert.Equal(t, "myref", RuntimeBaseConfig.Ref)
		assert.Equal(t, "mydefaultref", RuntimeBaseConfig.DefaultBranch)
	})

	t.Run("should panic if the path is invalid", func(t *testing.T) {
		assert.Panics(t, func() {
			viper.Set("path", "/invalid/path")
			ParseBaseConfig()
		}, "Expected panic due to invalid path")
	})

	t.Run("should sanitize the provided apiURL like adding the protocol", func(t *testing.T) {
		viper.Set("apiURL", "example.com/api")
		viper.Set("path", ".")
		ParseBaseConfig()
		assert.Equal(t, "https://example.com/api", RuntimeBaseConfig.APIURL)
	})

	t.Run("should remove a trailing slash from the apiURL", func(t *testing.T) {
		viper.Set("apiURL", "https://example.com/api/")
		viper.Set("path", ".")
		ParseBaseConfig()
		assert.Equal(t, "https://example.com/api", RuntimeBaseConfig.APIURL)
	})

	t.Run("should use the git version info if ref is NOT set", func(t *testing.T) {
		// not setting ref
		viper.Set("ref", "")
		viper.Set("defaultRef", "main")
		viper.Set("path", ".")
		viper.Set("apiURL", "https://example.com/api")

		m := mocks.NewGitLister(t)
		m.On("GetTags", ".").Return([]string{"v1.0.0", "v1.0.5", "v2.0.9"}, nil)
		m.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		m.On("GetBranchName", ".").Return("", nil)
		m.On("GetDefaultBranchName", ".").Return("other-than-main", nil)

		utils.GitLister = m

		ParseBaseConfig()

		assert.Equal(t, "https://example.com/api", RuntimeBaseConfig.APIURL)
		assert.Equal(t, ".", RuntimeBaseConfig.Path)
		assert.Equal(t, "2.0.9", RuntimeBaseConfig.Ref)
		assert.Equal(t, "main", RuntimeBaseConfig.DefaultBranch)
	})

	t.Run("should use the git version info if defaultRef is NOT set", func(t *testing.T) {
		// not setting defaultRef
		viper.Set("ref", "v1.0.0")
		viper.Set("defaultRef", "")
		viper.Set("path", ".")
		viper.Set("apiURL", "https://example.com/api")

		m := mocks.NewGitLister(t)
		m.On("GetTags", ".").Return([]string{"v1.0.0", "v1.0.5", "v2.0.9"}, nil)
		m.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		m.On("GetBranchName", ".").Return("", nil)
		m.On("GetDefaultBranchName", ".").Return("main", nil)

		utils.GitLister = m

		ParseBaseConfig()

		assert.Equal(t, "https://example.com/api", RuntimeBaseConfig.APIURL)
		assert.Equal(t, ".", RuntimeBaseConfig.Path)
		assert.Equal(t, "v1.0.0", RuntimeBaseConfig.Ref)
		assert.Equal(t, "main", RuntimeBaseConfig.DefaultBranch)
	})
}

func TestSetXAssetHeaders(t *testing.T) {
	t.Run("should set the X-Asset headers based on the RuntimeBaseConfig", func(t *testing.T) {
		RuntimeBaseConfig.AssetName = "my-asset"
		RuntimeBaseConfig.Ref = "1.0.0"
		RuntimeBaseConfig.DefaultBranch = "main"

		req := httptest.NewRequest("GET", "http://example.com", nil)

		SetXAssetHeaders(req)

		assert.Equal(t, "my-asset", req.Header.Get("X-Asset-Name"))
		assert.Equal(t, "1.0.0", req.Header.Get("X-Asset-Ref"))
		assert.Equal(t, "main", req.Header.Get("X-Asset-Default-Branch"))
	})

	t.Run("should not set the X-Asset-Default-Branch header if DefaultBranch is nil", func(t *testing.T) {
		RuntimeBaseConfig.AssetName = "my-asset"
		RuntimeBaseConfig.Ref = "1.0.0"
		RuntimeBaseConfig.DefaultBranch = ""

		req := httptest.NewRequest("GET", "http://example.com", nil)

		SetXAssetHeaders(req)

		assert.Equal(t, "my-asset", req.Header.Get("X-Asset-Name"))
		assert.Equal(t, "1.0.0", req.Header.Get("X-Asset-Ref"))
		assert.Empty(t, req.Header.Get("X-Asset-Default-Branch"))
	})

	t.Run("should set the X-Tag header to 1 if IsTag is true", func(t *testing.T) {
		RuntimeBaseConfig.AssetName = "my-asset"
		RuntimeBaseConfig.Ref = "1.0.0"
		RuntimeBaseConfig.DefaultBranch = "main"
		RuntimeBaseConfig.IsTag = true

		req := httptest.NewRequest("GET", "http://example.com", nil)

		SetXAssetHeaders(req)

		assert.Equal(t, "my-asset", req.Header.Get("X-Asset-Name"))
		assert.Equal(t, "1.0.0", req.Header.Get("X-Asset-Ref"))
		assert.Equal(t, "main", req.Header.Get("X-Asset-Default-Branch"))
		assert.Equal(t, "1", req.Header.Get("X-Tag"))
	})
	t.Run("should set the X-Tag header to 0 if IsTag is false", func(t *testing.T) {
		RuntimeBaseConfig.AssetName = "my-asset"
		RuntimeBaseConfig.Ref = "1.0.0"
		RuntimeBaseConfig.DefaultBranch = "main"
		RuntimeBaseConfig.IsTag = false

		req := httptest.NewRequest("GET", "http://example.com", nil)

		SetXAssetHeaders(req)

		assert.Equal(t, "my-asset", req.Header.Get("X-Asset-Name"))
		assert.Equal(t, "1.0.0", req.Header.Get("X-Asset-Ref"))
		assert.Equal(t, "main", req.Header.Get("X-Asset-Default-Branch"))
		assert.Equal(t, "0", req.Header.Get("X-Tag"))
	})
}
