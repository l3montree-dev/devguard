package commands

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateTag(t *testing.T) {
	tests := []struct {
		name                 string
		upstreamVersion      string
		architecture         string
		imagePath            string
		imageVariant         string
		imageSuffix          string
		refFlag              string
		wantErr              bool
		expectedImageTagName string
		expectedArtifactName string
	}{
		{
			name:                 "development tag with correct version prefix",
			upstreamVersion:      "10.11.14",
			architecture:         "amd64",
			imagePath:            "registry.opencode.de/open-code/oci/mariadb",
			imageVariant:         "minimal",
			refFlag:              "main",
			expectedImageTagName: "registry.opencode.de/open-code/oci/mariadb:10.11.14-main-minimal-amd64",
			expectedArtifactName: "pkg:oci/mariadb?repository_url=registry.opencode.de/open-code/oci/mariadb&arch=amd64&tag=10.11.14-main-minimal-amd64",
			wantErr:              false,
		},
		{
			name:                 "production tag without ref flag",
			upstreamVersion:      "1.2.3",
			architecture:         "arm64",
			imagePath:            "docker.io/library/nginx",
			imageVariant:         "full",
			refFlag:              "",
			expectedImageTagName: "docker.io/library/nginx:1.2.3-full-arm64",
			expectedArtifactName: "pkg:oci/nginx?repository_url=docker.io/library/nginx&arch=arm64&tag=1.2.3-full-arm64",
			wantErr:              false,
		},
		{
			name:                 "tag with image suffix",
			upstreamVersion:      "2.0.0",
			architecture:         "amd64",
			imagePath:            "ghcr.io/org/app",
			imageVariant:         "alpine",
			imageSuffix:          "debug",
			refFlag:              "develop",
			expectedImageTagName: "ghcr.io/org/app/debug:2.0.0-develop-alpine-amd64",
			expectedArtifactName: "pkg:oci/debug?repository_url=ghcr.io/org/app/debug&arch=amd64&tag=2.0.0-develop-alpine-amd64",
			wantErr:              false,
		},
		{
			name:                 "semver with patch version",
			upstreamVersion:      "3.14.159",
			architecture:         "arm64",
			imagePath:            "gcr.io/project/service",
			imageVariant:         "standard",
			refFlag:              "release",
			expectedImageTagName: "gcr.io/project/service:3.14.159-release-standard-arm64",
			expectedArtifactName: "pkg:oci/service?repository_url=gcr.io/project/service&arch=arm64&tag=3.14.159-release-standard-arm64",
			wantErr:              false,
		},
		{
			name:                 "localhost registry",
			upstreamVersion:      "0.1.0",
			architecture:         "amd64",
			imagePath:            "localhost:5000/myapp",
			imageVariant:         "dev",
			refFlag:              "feature-123",
			expectedImageTagName: "localhost:5000/myapp:0.1.0-feature-123-dev-amd64",
			expectedArtifactName: "pkg:oci/myapp?repository_url=localhost:5000/myapp&arch=amd64&tag=0.1.0-feature-123-dev-amd64",
			wantErr:              false,
		},
		{
			name:                 "complex version with rc tag",
			upstreamVersion:      "4.0.0-rc.1",
			architecture:         "amd64",
			imagePath:            "registry.io/namespace/image",
			imageVariant:         "slim",
			refFlag:              "staging",
			expectedImageTagName: "registry.io/namespace/image:4.0.0-rc.1-staging-slim-amd64",
			expectedArtifactName: "pkg:oci/image?repository_url=registry.io/namespace/image&arch=amd64&tag=4.0.0-rc.1-staging-slim-amd64",
			wantErr:              false,
		},
		{
			name:                 "empty image type",
			upstreamVersion:      "1.0.0",
			architecture:         "arm64",
			imagePath:            "registry.com/app",
			imageVariant:         "",
			refFlag:              "main",
			expectedImageTagName: "registry.com/app:1.0.0-main-arm64",
			expectedArtifactName: "pkg:oci/app?repository_url=registry.com/app&arch=arm64&tag=1.0.0-main-arm64",
			wantErr:              false,
		},
		{
			name:                 "multiple namespace levels",
			upstreamVersion:      "5.6.7",
			architecture:         "amd64",
			imagePath:            "registry.example.com/org/team/project/service",
			imageVariant:         "production",
			refFlag:              "v1",
			expectedImageTagName: "registry.example.com/org/team/project/service:5.6.7-v1-production-amd64",
			expectedArtifactName: "pkg:oci/service?repository_url=registry.example.com/org/team/project/service&arch=amd64&tag=5.6.7-v1-production-amd64",
			wantErr:              false,
		},
		{
			name:                 "version with build metadata",
			upstreamVersion:      "1.0.0+build.123",
			architecture:         "arm64",
			imagePath:            "docker.io/myorg/myimage",
			imageVariant:         "test",
			refFlag:              "ci",
			expectedImageTagName: "docker.io/myorg/myimage:1.0.0+build.123-ci-test-arm64",
			expectedArtifactName: "pkg:oci/myimage?repository_url=docker.io/myorg/myimage&arch=arm64&tag=1.0.0+build.123-ci-test-arm64",
			wantErr:              false,
		},
		{
			name:                 "all optional parameters empty",
			upstreamVersion:      "2.3.4",
			architecture:         "amd64",
			imagePath:            "example.com/image",
			imageVariant:         "",
			imageSuffix:          "",
			refFlag:              "",
			expectedImageTagName: "example.com/image:2.3.4-amd64",
			expectedArtifactName: "pkg:oci/image?repository_url=example.com/image&arch=amd64&tag=2.3.4-amd64",
			wantErr:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, output, err := generateTag(tt.upstreamVersion, tt.architecture, tt.imagePath, tt.refFlag, tt.imageVariant, tt.imageSuffix)

			if (err != nil) != tt.wantErr {
				t.Errorf("generateTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.expectedImageTagName, output.ImageTag)
			assert.Equal(t, tt.expectedArtifactName, output.ArtifactName)
			assert.Equal(t, url.PathEscape(tt.expectedArtifactName), output.ArtifactURLEncoded)
		})
	}
}

func TestGenerateArtifactName(t *testing.T) {
	tests := []struct {
		name                   string
		imageTag               string
		arch                   string
		wantArtifactName       string
		wantArtifactURLEncoded string
		wantErr                bool
	}{
		{
			name:                   "simple registry with namespace and name",
			imageTag:               "registry.example.com/namespace/image:1.0.0",
			arch:                   "amd64",
			wantArtifactName:       "pkg:oci/image?repository_url=registry.example.com/namespace/image&arch=amd64&tag=1.0.0",
			wantArtifactURLEncoded: "pkg:oci%2Fimage%3Frepository_url=registry.example.com%2Fnamespace%2Fimage&arch=amd64&tag=1.0.0",
			wantErr:                false,
		},
		{
			name:                   "docker hub with namespace",
			imageTag:               "docker.io/library/nginx:latest",
			arch:                   "arm64",
			wantArtifactName:       "pkg:oci/nginx?repository_url=docker.io/library/nginx&arch=arm64&tag=latest",
			wantArtifactURLEncoded: "pkg:oci%2Fnginx%3Frepository_url=docker.io%2Flibrary%2Fnginx&arch=arm64&tag=latest",
			wantErr:                false,
		},
		{
			name:                   "ghcr with multiple path segments",
			imageTag:               "ghcr.io/owner/repo/image:v1.2.3",
			arch:                   "amd64",
			wantArtifactName:       "pkg:oci/image?repository_url=ghcr.io/owner/repo/image&arch=amd64&tag=v1.2.3",
			wantArtifactURLEncoded: "pkg:oci%2Fimage%3Frepository_url=ghcr.io%2Fowner%2Frepo%2Fimage&arch=amd64&tag=v1.2.3",
			wantErr:                false,
		},
		{
			name:                   "localhost registry",
			imageTag:               "localhost:5000/myapp:dev",
			arch:                   "amd64",
			wantArtifactName:       "pkg:oci/myapp?repository_url=localhost:5000/myapp&arch=amd64&tag=dev",
			wantArtifactURLEncoded: "pkg:oci%2Fmyapp%3Frepository_url=localhost:5000%2Fmyapp&arch=amd64&tag=dev",
			wantErr:                false,
		},
		{
			name:                   "gcr registry",
			imageTag:               "gcr.io/project-id/image-name:1.0.0-amd64",
			arch:                   "amd64",
			wantArtifactName:       "pkg:oci/image-name?repository_url=gcr.io/project-id/image-name&arch=amd64&tag=1.0.0-amd64",
			wantArtifactURLEncoded: "pkg:oci%2Fimage-name%3Frepository_url=gcr.io%2Fproject-id%2Fimage-name&arch=amd64&tag=1.0.0-amd64",
			wantErr:                false,
		},
		{
			name:     "missing colon separator",
			imageTag: "registry.example.com/namespace/image",
			arch:     "amd64",
			wantErr:  true,
		},
		{
			name:     "missing slash after registry",
			imageTag: "registry.example.com:latest",
			arch:     "amd64",
			wantErr:  true,
		},
		{
			name:     "empty image tag",
			imageTag: "",
			arch:     "amd64",
			wantErr:  true,
		},
		{
			name:                   "tag with special characters",
			imageTag:               "registry.io/my-namespace/my-image:v1.0.0-rc.1-build.123",
			arch:                   "arm64",
			wantArtifactName:       "pkg:oci/my-image?repository_url=registry.io/my-namespace/my-image&arch=arm64&tag=v1.0.0-rc.1-build.123",
			wantArtifactURLEncoded: "pkg:oci%2Fmy-image%3Frepository_url=registry.io%2Fmy-namespace%2Fmy-image&arch=arm64&tag=v1.0.0-rc.1-build.123",
			wantErr:                false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactName, artifactURLEncoded, err := generateArtifactName(tt.imageTag, tt.arch)

			if (err != nil) != tt.wantErr {
				t.Errorf("generateArtifactName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && artifactName != tt.wantArtifactName {
				t.Errorf("generateArtifactName() artifactName = %v, want %v", artifactName, tt.wantArtifactName)
			}

			if !tt.wantErr && artifactURLEncoded != tt.wantArtifactURLEncoded {
				t.Errorf("generateArtifactName() artifactURLEncoded = %v, want %v", artifactURLEncoded, tt.wantArtifactURLEncoded)
			}
		})
	}
}
