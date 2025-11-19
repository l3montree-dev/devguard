package config

import (
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestArtifactNameGeneration(t *testing.T) {
	// keep tests deterministic by setting required viper keys
	cases := []struct {
		name           string
		runningCMD     string
		assetName      string
		ref            string
		defaultRef     string
		presetArtifact string
		want           string
	}{
		{
			name:           "container-scanning",
			runningCMD:     "container-scanning",
			assetName:      "org/projects/foo/assets/bar",
			ref:            "main",
			defaultRef:     "main",
			presetArtifact: "",
			want:           "pkg:oci/org/foo/bar",
		},
		{
			name:           "default-command",
			runningCMD:     "other",
			assetName:      "org/projects/foo/assets/bar",
			ref:            "main",
			defaultRef:     "main",
			presetArtifact: "",
			want:           "pkg:devguard/org/foo/bar",
		},
		{
			name:           "default-command",
			runningCMD:     "other",
			assetName:      "org/projects/foo/assets/bar",
			ref:            "1.0.0",
			defaultRef:     "main",
			presetArtifact: "",
			want:           "pkg:devguard/org/foo/bar",
		},
		{
			name:           "preset-artifact-unchanged",
			runningCMD:     "container-scanning",
			assetName:      "/projects/aa/assets/bb",
			ref:            "feature/x",
			defaultRef:     "feature/x",
			presetArtifact: "custom-artifact",
			want:           "custom-artifact",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// set viper keys used by ParseBaseConfig (mapstructure tags)
			viper.Set("assetName", tc.assetName)
			viper.Set("ref", tc.ref)
			viper.Set("defaultRef", tc.defaultRef)
			viper.Set("artifactName", tc.presetArtifact)

			// run the parser
			ParseBaseConfig(tc.runningCMD)

			if RuntimeBaseConfig.ArtifactName != tc.want {
				t.Fatalf("unexpected artifact name for %s: got %q want %q", tc.name, RuntimeBaseConfig.ArtifactName, tc.want)
			}
		})
	}
}

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
		viper.Set("apiUrl", "http://example.com")
		viper.Set("path", ".")
		viper.Set("ref", "myref")
		viper.Set("defaultRef", "mydefaultref")

		ParseBaseConfig("")
		assert.Equal(t, "http://example.com", RuntimeBaseConfig.APIURL)
		assert.Equal(t, ".", RuntimeBaseConfig.Path)
		assert.Equal(t, "myref", RuntimeBaseConfig.Ref)
		assert.Equal(t, "mydefaultref", RuntimeBaseConfig.DefaultBranch)
	})

	t.Run("should panic if the path is invalid", func(t *testing.T) {
		assert.Panics(t, func() {
			viper.Set("path", "/invalid/path")
			ParseBaseConfig("")
		}, "Expected panic due to invalid path")
	})

	t.Run("should sanitize the provided apiURL like adding the protocol", func(t *testing.T) {
		viper.Set("apiUrl", "example.com/api")
		viper.Set("path", ".")
		ParseBaseConfig("")
		assert.Equal(t, "https://example.com/api", RuntimeBaseConfig.APIURL)
	})

	t.Run("should remove a trailing slash from the apiURL", func(t *testing.T) {
		viper.Set("apiUrl", "https://example.com/api/")
		viper.Set("path", ".")
		ParseBaseConfig("")
		assert.Equal(t, "https://example.com/api", RuntimeBaseConfig.APIURL)
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

		ParseBaseConfig("")

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
		viper.Set("apiUrl", "https://example.com/api")

		m := mocks.NewGitLister(t)
		m.On("GetTags", ".").Return([]string{"v1.0.0", "v1.0.5", "v2.0.9"}, nil)
		m.On("GitCommitCount", ".", mock.Anything).Return(0, nil)
		m.On("GetBranchName", ".").Return("", nil)
		m.On("GetDefaultBranchName", ".").Return("main", nil)

		utils.GitLister = m

		ParseBaseConfig("")

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
