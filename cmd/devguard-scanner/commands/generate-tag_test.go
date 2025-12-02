package commands

import (
	"strings"
	"testing"
)

func TestGenerateTag(t *testing.T) {
	tests := []struct {
		name            string
		upstreamVersion string
		architecture    string
		imagePath       string
		refFlag         string
		wantErr         bool
		validateOutput  func(t *testing.T, output string)
	}{

		{
			name:            "development tag with correct version prefix",
			upstreamVersion: "10.11.14",
			architecture:    "amd64",
			imagePath:       "registry.opencode.de/open-code/oci/mariadb",
			refFlag:         "main",
			wantErr:         false,
			validateOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "IMAGE_TAG=registry.opencode.de/open-code/oci/mariadb:10.11.14+main-amd64") {
					t.Errorf("expected IMAGE_TAG to contain 'registry.opencode.de/open-code/oci/mariadb:10.11.14+main-amd64', got: %s", output)
				}
				if !strings.Contains(output, "ARTIFACT_NAME=pkg:oci/mariadb?repository_url=registry.opencode.de/open-code/oci/mariadb&arch=amd64&tag=10.11.14+main-amd64") {
					t.Errorf("expected ARTIFACT_NAME to contain full purl, got: %s", output)
				}
				if !strings.Contains(output, "ARTIFACT_URL_ENCODED=pkg:oci%2Fmariadb%3Frepository_url=registry.opencode.de%2Fopen-code%2Foci%2Fmariadb&arch=amd64&tag=10.11.14+main-amd64") {
					t.Errorf("expected ARTIFACT_URL_ENCODED to be present with correct encoding, got: %s", output)
				}
			},
		},
		{
			name:            "tag with version and ref",
			upstreamVersion: "10.11.14",
			architecture:    "amd64",
			imagePath:       "registry.opencode.de/open-code/oci/mariadb",
			refFlag:         "main",
			wantErr:         false,
			validateOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "IMAGE_TAG=registry.opencode.de/open-code/oci/mariadb:10.11.14+main-amd64") {
					t.Errorf("expected IMAGE_TAG to contain 'registry.opencode.de/open-code/oci/mariadb:10.11.14+main-amd64', got: %s", output)
				}
				if !strings.Contains(output, "ARTIFACT_NAME=pkg:oci/mariadb?repository_url=registry.opencode.de/open-code/oci/mariadb&arch=amd64&tag=10.11.14+main-amd64") {
					t.Errorf("expected ARTIFACT_NAME to contain full purl, got: %s", output)
				}
				if !strings.Contains(output, "ARTIFACT_URL_ENCODED=pkg:oci%2Fmariadb%3Frepository_url=registry.opencode.de%2Fopen-code%2Foci%2Fmariadb&arch=amd64&tag=10.11.14+main-amd64") {
					t.Errorf("expected ARTIFACT_URL_ENCODED to be present with correct encoding, got: %s", output)
				}
			},
		},
		{
			name:            "tag with version 0 and ref",
			upstreamVersion: "0",
			architecture:    "amd64",
			imagePath:       "example/image",
			refFlag:         "main",
			wantErr:         false,
			validateOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "IMAGE_TAG=example/image:main+amd64") {
					t.Errorf("expected IMAGE_TAG to contain 'example/image:main+amd64', got: %s", output)
				}
				if !strings.Contains(output, "ARTIFACT_NAME=pkg:oci/image?repository_url=example/image&arch=amd64&tag=main+amd64") {
					t.Errorf("expected ARTIFACT_NAME to contain full purl, got: %s", output)
				}
				if !strings.Contains(output, "ARTIFACT_URL_ENCODED=pkg:oci%2Fimage%3Frepository_url=example%2Fimage&arch=amd64&tag=main+amd64") {
					t.Errorf("expected ARTIFACT_URL_ENCODED to be present with correct encoding, got: %s", output)
				}
			},
		},
		{
			name:            "single architecture",
			upstreamVersion: "1.0.0",
			architecture:    "amd64",
			imagePath:       "example/image",
			refFlag:         "main",
			wantErr:         false,
			validateOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "IMAGE_TAG=example/image:1.0.0+main-amd64") {
					t.Errorf("expected IMAGE_TAG to contain 'example/image:1.0.0+main-amd64', got: %s", output)
				}
				if !strings.Contains(output, "ARTIFACT_NAME=pkg:oci/image?repository_url=example/image&arch=amd64&tag=1.0.0+main-amd64") {
					t.Errorf("expected ARTIFACT_NAME to contain full purl, got: %s", output)
				}
				if !strings.Contains(output, "ARTIFACT_URL_ENCODED=pkg:oci%2Fimage%3Frepository_url=example%2Fimage&arch=amd64&tag=1.0.0+main-amd64") {
					t.Errorf("expected ARTIFACT_URL_ENCODED to be present with correct encoding, got: %s", output)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := generateTag(tt.upstreamVersion, tt.architecture, tt.imagePath, tt.refFlag, "")

			if (err != nil) != tt.wantErr {
				t.Errorf("generateTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validateOutput != nil {
				tt.validateOutput(t, output)
			}
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
			imageTag:               "registry.io/my-namespace/my-image:v1.0.0-rc.1+build.123",
			arch:                   "arm64",
			wantArtifactName:       "pkg:oci/my-image?repository_url=registry.io/my-namespace/my-image&arch=arm64&tag=v1.0.0-rc.1+build.123",
			wantArtifactURLEncoded: "pkg:oci%2Fmy-image%3Frepository_url=registry.io%2Fmy-namespace%2Fmy-image&arch=arm64&tag=v1.0.0-rc.1+build.123",
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
