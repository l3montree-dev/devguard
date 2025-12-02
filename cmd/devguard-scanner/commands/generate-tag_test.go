package commands

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateTag(t *testing.T) {
	tests := []struct {
		name            string
		upstreamVersion string
		architecture    []string
		imageType       string
		imagePath       string
		isTag           bool
		refFlag         string
		wantErr         bool
		validateOutput  func(t *testing.T, output string)
	}{
		{
			name:            "development tag without version prefix",
			upstreamVersion: "",
			architecture:    []string{"amd64"},
			imageType:       "runtime",
			imagePath:       "example/image",
			isTag:           false,
			refFlag:         "main",
			wantErr:         false,
			validateOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "TAGS=example/image:main-amd64") {
					t.Errorf("expected TAGS to contain 'example/image:main-amd64', got: %s", output)
				}
				if !strings.Contains(output, "IMAGE_TAG=example/image:main-amd64") {
					t.Errorf("expected IMAGE_TAG to contain 'example/image:main-amd64', got: %s", output)
				}
			},
		},
		{
			name:            "development tag single architecture",
			upstreamVersion: "1.0.0",
			architecture:    []string{"amd64"},
			imageType:       "runtime",
			imagePath:       "example/image",
			isTag:           false,
			refFlag:         "main",
			wantErr:         false,
			validateOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "TAGS=example/image:main-1.0.0-amd64") {
					t.Errorf("expected TAGS to contain 'example/image:main-1.0.0-amd64', got: %s", output)
				}
				if !strings.Contains(output, "IMAGE_TAG=example/image:main-1.0.0-amd64") {
					t.Errorf("expected IMAGE_TAG to contain 'example/image:main-1.0.0-amd64', got: %s", output)
				}
			},
		},
		{
			name:            "development tag multiple architectures",
			upstreamVersion: "2.1.3",
			architecture:    []string{"amd64", "arm64"},
			imageType:       "runtime",
			imagePath:       "example/image",
			isTag:           false,
			refFlag:         "feature/test-branch",
			wantErr:         false,
			validateOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "TAGS=example/image:feature-test-branch-2.1.3-amd64,example/image:feature-test-branch-2.1.3-arm64") {
					t.Errorf("expected TAGS to contain both architectures, got: %s", output)
				}
				if !strings.Contains(output, "IMAGE_TAG=example/image:feature-test-branch-2.1.3-amd64") {
					t.Errorf("expected IMAGE_TAG to be first architecture, got: %s", output)
				}
			},
		},
		{
			name:            "runtime tag single architecture",
			upstreamVersion: "3.2.1",
			architecture:    []string{"amd64"},
			imageType:       "runtime",
			imagePath:       "example/image",
			isTag:           true,
			refFlag:         "",
			wantErr:         false,
			validateOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "TAGS=example/image:3.2.1-amd64+oc-") {
					t.Errorf("expected TAGS to contain 'example/image:3.2.1-amd64+oc-', got: %s", output)
				}
				if !strings.Contains(output, "IMAGE_TAG=example/image:3.2.1-amd64+oc-") {
					t.Errorf("expected IMAGE_TAG to contain 'example/image:3.2.1-amd64+oc-', got: %s", output)
				}
			},
		},
		{
			name:            "composed tag single architecture",
			upstreamVersion: "1.2.3",
			architecture:    []string{"arm64"},
			imageType:       "composed",
			imagePath:       "example/image",
			isTag:           true,
			refFlag:         "",
			wantErr:         false,
			validateOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "TAGS=example/image:1.2.3-arm64") {
					t.Errorf("expected TAGS to contain 'example/image:1.2.3-arm64', got: %s", output)
				}
				if !strings.Contains(output, "IMAGE_TAG=example/image:1.2.3-arm64") {
					t.Errorf("expected IMAGE_TAG to contain 'example/image:1.2.3-arm64', got: %s", output)
				}
			},
		},
		{
			name:            "composed tag invalid semver",
			upstreamVersion: "invalid-version",
			architecture:    []string{"amd64"},
			imageType:       "composed",
			imagePath:       "example/image",
			isTag:           true,
			refFlag:         "",
			wantErr:         true,
		},
		{
			name:            "unknown image type",
			upstreamVersion: "1.0.0",
			architecture:    []string{"amd64"},
			imageType:       "unknown",
			imagePath:       "example/image",
			isTag:           true,
			refFlag:         "",
			wantErr:         true,
		},
		{
			name:            "multiple architectures runtime tags",
			upstreamVersion: "4.5.6",
			architecture:    []string{"amd64", "arm64", "s390x"},
			imageType:       "runtime",
			imagePath:       "example/image",
			isTag:           true,
			refFlag:         "",
			wantErr:         false,
			validateOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "TAGS=example/image:4.5.6-amd64+oc-") {
					t.Errorf("expected TAGS to contain 'example/image:4.5.6-amd64+oc-', got: %s", output)
				}
				if !strings.Contains(output, "example/image:4.5.6-arm64+oc-") {
					t.Errorf("expected tags to contain 'example/image:4.5.6-arm64+oc-', got: %s", output)
				}
				if !strings.Contains(output, "example/image:4.5.6-s390x+oc-") {
					t.Errorf("expected tags to contain 'example/image:4.5.6-s390x+oc-', got: %s", output)
				}

				if !strings.Contains(output, "IMAGE_TAG=example/image:4.5.6-amd64+oc-") {
					t.Errorf("expected IMAGE_TAG to be first architecture, got: %s", output)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := generateTag(tt.upstreamVersion, tt.architecture, tt.imageType, tt.imagePath, tt.isTag, tt.refFlag)

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

func TestGenerateDevelopmentTag(t *testing.T) {
	tests := []struct {
		name            string
		branchName      string
		upstreamVersion string
		architecture    string
		expectedTag     string
	}{
		{
			name:            "simple branch name",
			branchName:      "main",
			upstreamVersion: "1.0.0",
			architecture:    "amd64",
			expectedTag:     "main-1.0.0-amd64",
		},
		{
			name:            "branch with slashes",
			branchName:      "feature/new-feature",
			upstreamVersion: "2.1.0",
			architecture:    "arm64",
			expectedTag:     "feature-new-feature-2.1.0-arm64",
		},
		{
			name:            "branch with multiple slashes",
			branchName:      "bugfix/user/issue-123",
			upstreamVersion: "3.0.0",
			architecture:    "s390x",
			expectedTag:     "bugfix-user-issue-123-3.0.0-s390x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateDevelopmentTag(tt.branchName, tt.upstreamVersion, tt.architecture)
			if got != tt.expectedTag {
				t.Errorf("generateDevelopmentTag() = %v, want %v", got, tt.expectedTag)
			}
		})
	}
}

func TestSanitizeBranchName(t *testing.T) {
	tests := []struct {
		name       string
		branchName string
		want       string
	}{
		{
			name:       "no slashes",
			branchName: "main",
			want:       "main",
		},
		{
			name:       "single slash",
			branchName: "feature/test",
			want:       "feature-test",
		},
		{
			name:       "multiple slashes",
			branchName: "feature/user/test",
			want:       "feature-user-test",
		},
		{
			name:       "trailing slash",
			branchName: "feature/",
			want:       "feature-",
		},
		{
			name:       "leading slash",
			branchName: "/feature",
			want:       "-feature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeBranchName(tt.branchName)
			if got != tt.want {
				t.Errorf("sanitizeBranchName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateRuntimeTag(t *testing.T) {
	tests := []struct {
		name            string
		upstreamVersion string
		architecture    string
		wantErr         bool
		validateTag     func(t *testing.T, tag string)
	}{
		{
			name:            "valid runtime tag",
			upstreamVersion: "1.2.3",
			architecture:    "amd64",
			wantErr:         false,
			validateTag: func(t *testing.T, tag string) {
				if !strings.HasPrefix(tag, "1.2.3-amd64+oc-") {
					t.Errorf("expected tag to start with '1.2.3-amd64+oc-', got: %s", tag)
				}
				// Verify timestamp format (should end with Z)
				if !strings.HasSuffix(tag, "Z") {
					t.Errorf("expected tag to end with 'Z' (UTC timestamp), got: %s", tag)
				}
			},
		},
		{
			name:            "empty upstream version",
			upstreamVersion: "",
			architecture:    "arm64",
			wantErr:         true,
		},
		{
			name:            "different architecture",
			upstreamVersion: "2.0.0",
			architecture:    "s390x",
			wantErr:         false,
			validateTag: func(t *testing.T, tag string) {
				if !strings.HasPrefix(tag, "2.0.0-s390x+oc-") {
					t.Errorf("expected tag to start with '2.0.0-s390x+oc-', got: %s", tag)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateRuntimeTag(tt.upstreamVersion, tt.architecture)

			if (err != nil) != tt.wantErr {
				t.Errorf("generateRuntimeTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.validateTag != nil {
				tt.validateTag(t, got)
			}
		})
	}
}

func TestGenerateRuntimeTagTimestamp(t *testing.T) {
	// Test that two calls within the same second produce different timestamps
	tag1, err := generateRuntimeTag("1.0.0", "amd64")
	if err != nil {
		t.Fatalf("generateRuntimeTag() error = %v", err)
	}

	time.Sleep(1 * time.Second)

	tag2, err := generateRuntimeTag("1.0.0", "amd64")
	if err != nil {
		t.Fatalf("generateRuntimeTag() error = %v", err)
	}

	if tag1 == tag2 {
		t.Errorf("expected different timestamps, got identical tags: %s", tag1)
	}
}

func TestGenerateComposedTags(t *testing.T) {
	tests := []struct {
		name    string
		version string
		arch    string
		wantTag string
		wantErr bool
	}{
		{
			name:    "valid semver",
			version: "1.2.3",
			arch:    "amd64",
			wantTag: "1.2.3-amd64",
			wantErr: false,
		},
		{
			name:    "valid semver with zeros",
			version: "0.0.0",
			arch:    "arm64",
			wantTag: "0.0.0-arm64",
			wantErr: false,
		},
		{
			name:    "valid semver large numbers",
			version: "10.20.30",
			arch:    "s390x",
			wantTag: "10.20.30-s390x",
			wantErr: false,
		},
		{
			name:    "invalid semver - no patch",
			version: "1.2",
			arch:    "amd64",
			wantErr: true,
		},
		{
			name:    "invalid semver - text",
			version: "v1.2.3",
			arch:    "amd64",
			wantErr: true,
		},
		{
			name:    "invalid semver - prerelease",
			version: "1.2.3-alpha",
			arch:    "amd64",
			wantErr: true,
		},
		{
			name:    "invalid semver - build metadata",
			version: "1.2.3+build",
			arch:    "amd64",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateComposedTags(tt.version, tt.arch)

			if (err != nil) != tt.wantErr {
				t.Errorf("generateComposedTags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got != tt.wantTag {
				t.Errorf("generateComposedTags() = %v, want %v", got, tt.wantTag)
			}
		})
	}
}

func TestCheckSemverFormat(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{
			name:    "valid semver",
			version: "1.2.3",
			want:    true,
		},
		{
			name:    "valid with zeros",
			version: "0.0.0",
			want:    true,
		},
		{
			name:    "large numbers",
			version: "100.200.300",
			want:    true,
		},
		{
			name:    "missing patch",
			version: "1.2",
			want:    false,
		},
		{
			name:    "missing minor and patch",
			version: "1",
			want:    false,
		},
		{
			name:    "with v prefix",
			version: "v1.2.3",
			want:    false,
		},
		{
			name:    "with prerelease",
			version: "1.2.3-alpha",
			want:    false,
		},
		{
			name:    "with build metadata",
			version: "1.2.3+build.1",
			want:    false,
		},
		{
			name:    "non-numeric",
			version: "a.b.c",
			want:    false,
		},
		{
			name:    "extra dots",
			version: "1.2.3.4",
			want:    false,
		},
		{
			name:    "empty string",
			version: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkSemverFormat(tt.version)
			if got != tt.want {
				t.Errorf("checkSemverFormat(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestGenerateArtifactPURL(t *testing.T) {
	tests := []struct {
		name     string
		imageTag string
		wantPURL string
		wantErr  bool
	}{
		{
			name:     "simple registry with namespace and name",
			imageTag: "registry.example.com/namespace/image:1.0.0",
			wantPURL: "pkg:oci/image?repository_url=registry.example.com%2Fnamespace%2Fimage",
			wantErr:  false,
		},
		{
			name:     "docker hub with namespace",
			imageTag: "docker.io/library/nginx:latest",
			wantPURL: "pkg:oci/nginx?repository_url=docker.io%2Flibrary%2Fnginx",
			wantErr:  false,
		},
		{
			name:     "ghcr with multiple path segments",
			imageTag: "ghcr.io/owner/repo/image:v1.2.3",
			wantPURL: "pkg:oci/image?repository_url=ghcr.io%2Fowner%2Frepo%2Fimage",
			wantErr:  false,
		},
		{
			name:     "localhost registry",
			imageTag: "localhost:5000/myapp:dev",
			wantPURL: "pkg:oci/myapp?repository_url=localhost%3A5000%2Fmyapp",
			wantErr:  false,
		},
		{
			name:     "registry with port and nested namespace",
			imageTag: "registry.example.com:443/org/team/project/image:sha256-abcdef",
			wantPURL: "pkg:oci/image?repository_url=registry.example.com%3A443%2Forg%2Fteam%2Fproject%2Fimage",
			wantErr:  false,
		},
		{
			name:     "gcr registry",
			imageTag: "gcr.io/project-id/image-name:1.0.0-amd64",
			wantPURL: "pkg:oci/image-name?repository_url=gcr.io%2Fproject-id%2Fimage-name",
			wantErr:  false,
		},
		{
			name:     "missing colon separator",
			imageTag: "registry.example.com/namespace/image",
			wantPURL: "",
			wantErr:  true,
		},
		{
			name:     "missing slash after registry",
			imageTag: "registry.example.com:latest",
			wantPURL: "",
			wantErr:  true,
		},
		{
			name:     "empty image tag",
			imageTag: "",
			wantPURL: "",
			wantErr:  true,
		},
		{
			name:     "only registry name",
			imageTag: "registry.example.com:",
			wantPURL: "",
			wantErr:  true,
		},
		{
			name:     "tag with special characters",
			imageTag: "registry.io/my-namespace/my-image:v1.0.0-rc.1+build.123",
			wantPURL: "pkg:oci/my-image?repository_url=registry.io%2Fmy-namespace%2Fmy-image",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateArtifactPURL(tt.imageTag)

			if (err != nil) != tt.wantErr {
				t.Errorf("generateArtifactPURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got != tt.wantPURL {
				t.Errorf("generateArtifactPURL() = %v, want %v", got, tt.wantPURL)
			}
		})
	}
}
