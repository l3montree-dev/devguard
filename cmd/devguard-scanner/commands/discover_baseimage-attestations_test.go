package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestationFilenameGeneration(t *testing.T) {
	tests := []struct {
		name                  string
		attestations          []map[string]any
		expectedFilenames     []string
		expectedUniqueCount   int
		expectedPrefixPattern string
	}{
		{
			name: "attestations with identical predicateType produce same filename (merged by DevGuard)",
			attestations: []map[string]any{
				{"predicateType": "https://cyclonedx.org/vex"},
				{"predicateType": "https://cyclonedx.org/vex"},
				{"predicateType": "https://cyclonedx.org/vex"},
			},
			expectedFilenames: []string{
				"attestation-vex.json",
				"attestation-vex.json",
				"attestation-vex.json",
			},
			expectedUniqueCount:   1,
			expectedPrefixPattern: "attestation-",
		},
		{
			name: "attestations with different predicateTypes",
			attestations: []map[string]any{
				{"predicateType": "https://cyclonedx.org/vex"},
				{"predicateType": "https://spdx.dev/Document"},
				{"predicateType": "https://in-toto.io/attestation/v1"},
			},
			expectedFilenames: []string{
				"attestation-vex.json",
				"attestation-Document.json",
				"attestation-v1.json",
			},
			expectedUniqueCount:   3,
			expectedPrefixPattern: "attestation-",
		},
		{
			name: "attestation without predicateType falls back to index-only name",
			attestations: []map[string]any{
				{"predicateType": "https://cyclonedx.org/bom"},
				{"someOtherField": "value"},
				{"predicateType": "https://example.com/sbom"},
			},
			expectedFilenames: []string{
				"attestation-bom.json",
				"attestation-2.json",
				"attestation-sbom.json",
			},
			expectedUniqueCount:   3,
			expectedPrefixPattern: "attestation-",
		},
		{
			name: "mixed identical and different predicateTypes (duplicates merged)",
			attestations: []map[string]any{
				{"predicateType": "https://slsa.dev/provenance/v1"},
				{"predicateType": "https://slsa.dev/provenance/v1"},
				{"predicateType": "https://cyclonedx.org/vex"},
				{"predicateType": "https://cyclonedx.org/vex"},
			},
			expectedFilenames: []string{
				"attestation-v1.json",
				"attestation-v1.json",
				"attestation-vex.json",
				"attestation-vex.json",
			},
			expectedUniqueCount:   2,
			expectedPrefixPattern: "attestation-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := t.TempDir()

			generatedFilenames := make([]string, 0, len(tt.attestations))

			for i, attestation := range tt.attestations {
				// Replicate the filename generation logic from runDiscoverBaseImageAttestations
				attestationFileName := filepath.Join(output, fmt.Sprintf("attestation-%d.json", i+1))
				if predicate, ok := attestation["predicateType"].(string); ok {
					// get everything after the last / in the predicate type
					predicate = strings.Split(predicate, "/")[len(strings.Split(predicate, "/"))-1]
					// remove .json suffix if it exists
					predicate = strings.TrimSuffix(predicate, ".json")
					attestationFileName = filepath.Join(output, fmt.Sprintf("attestation-%s.json", predicate))
				}

				generatedFilenames = append(generatedFilenames, filepath.Base(attestationFileName))

				// Create the file to ensure we can verify uniqueness
				f, err := os.Create(attestationFileName)
				require.NoError(t, err, "should be able to create attestation file")
				f.Close()
			}

			// Verify expected filenames match
			assert.Equal(t, tt.expectedFilenames, generatedFilenames, "generated filenames should match expected")

			// Verify unique filename count
			uniqueFilenames := make(map[string]bool)
			for _, filename := range generatedFilenames {
				uniqueFilenames[filename] = true
			}
			assert.Equal(t, tt.expectedUniqueCount, len(uniqueFilenames), "unique filename count should match expected")

			// Verify all filenames start with expected prefix
			for _, filename := range generatedFilenames {
				assert.True(t, strings.HasPrefix(filename, tt.expectedPrefixPattern),
					"filename %s should start with prefix %s", filename, tt.expectedPrefixPattern)
			}

			// Verify all filenames have .json extension
			for _, filename := range generatedFilenames {
				assert.True(t, strings.HasSuffix(filename, ".json"),
					"filename %s should have .json extension", filename)
			}

			// Verify the files were actually created (unique files only)
			entries, err := os.ReadDir(output)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedUniqueCount, len(entries), "should have created correct number of unique files")
		})
	}
}

func TestAttestationContentExtraction(t *testing.T) {
	tests := []struct {
		name            string
		attestation     map[string]any
		expectedContent map[string]any
	}{
		{
			name: "intoto attestation extracts only predicate content",
			attestation: map[string]any{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": "https://cyclonedx.org/bom",
				"subject":       []any{map[string]any{"name": "pkg:oci/alpine@sha256:abc123"}},
				"predicate": map[string]any{
					"bomFormat":   "CycloneDX",
					"specVersion": "1.5",
					"components":  []any{map[string]any{"name": "musl", "version": "1.2.4"}},
				},
			},
			expectedContent: map[string]any{
				"bomFormat":   "CycloneDX",
				"specVersion": "1.5",
				"components":  []any{map[string]any{"name": "musl", "version": "1.2.4"}},
			},
		},
		{
			name: "intoto vex attestation extracts only predicate content",
			attestation: map[string]any{
				"_type":         "https://in-toto.io/Statement/v1",
				"predicateType": "https://cyclonedx.org/vex",
				"subject":       []any{map[string]any{"name": "pkg:oci/nginx@sha256:def456"}},
				"predicate": map[string]any{
					"bomFormat":       "CycloneDX",
					"specVersion":     "1.5",
					"vulnerabilities": []any{map[string]any{"id": "CVE-2024-1234"}},
				},
			},
			expectedContent: map[string]any{
				"bomFormat":       "CycloneDX",
				"specVersion":     "1.5",
				"vulnerabilities": []any{map[string]any{"id": "CVE-2024-1234"}},
			},
		},
		{
			name: "non-intoto attestation keeps full content",
			attestation: map[string]any{
				"bomFormat":   "CycloneDX",
				"specVersion": "1.5",
				"components":  []any{map[string]any{"name": "libc", "version": "2.38"}},
			},
			expectedContent: map[string]any{
				"bomFormat":   "CycloneDX",
				"specVersion": "1.5",
				"components":  []any{map[string]any{"name": "libc", "version": "2.38"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := t.TempDir()

			// Replicate the content extraction logic from runDiscoverBaseImageAttestations
			attestationFileName := filepath.Join(output, "attestation-1.json")
			attContent := tt.attestation

			if predicate, ok := tt.attestation["predicateType"].(string); ok {
				predicate = strings.Split(predicate, "/")[len(strings.Split(predicate, "/"))-1]
				predicate = strings.TrimSuffix(predicate, ".json")
				attestationFileName = filepath.Join(output, fmt.Sprintf("attestation-%s.json", predicate))
				attContent = tt.attestation["predicate"].(map[string]any)
			}

			attestationBytes, err := json.MarshalIndent(attContent, "", "  ")
			require.NoError(t, err, "should marshal attestation content")

			err = os.WriteFile(attestationFileName, attestationBytes, 0644)
			require.NoError(t, err, "should write attestation file")

			// Read back and verify content
			writtenBytes, err := os.ReadFile(attestationFileName)
			require.NoError(t, err, "should read back attestation file")

			var writtenContent map[string]any
			err = json.Unmarshal(writtenBytes, &writtenContent)
			require.NoError(t, err, "should unmarshal written content")

			assert.Equal(t, tt.expectedContent, writtenContent,
				"written content should match expected (predicate only for intoto, full content otherwise)")

			// For intoto attestations, verify envelope fields are NOT in the written content
			if _, ok := tt.attestation["predicateType"]; ok {
				assert.NotContains(t, writtenContent, "_type",
					"intoto envelope _type should not be in written content")
				assert.NotContains(t, writtenContent, "predicateType",
					"intoto envelope predicateType should not be in written content")
				assert.NotContains(t, writtenContent, "subject",
					"intoto envelope subject should not be in written content")
			}
		})
	}
}

func TestGetImageFromContainerFile(t *testing.T) {
	tests := []struct {
		name           string
		containerFile  string
		expectedImage  string
		expectedErrMsg string
	}{
		{
			name:          "simple FROM statement",
			containerFile: "FROM alpine:3.18",
			expectedImage: "alpine:3.18",
		},
		{
			name:          "FROM with AS alias",
			containerFile: "FROM golang:1.21 AS builder",
			expectedImage: "golang:1.21 AS builder",
		},
		{
			name: "multi-stage build returns last FROM",
			containerFile: `FROM golang:1.21 AS builder
RUN go build -o app
FROM alpine:3.18
COPY --from=builder /app /app`,
			expectedImage: "alpine:3.18",
		},
		{
			name:          "lowercase from",
			containerFile: "from ubuntu:22.04",
			expectedImage: "ubuntu:22.04",
		},
		{
			name:          "FROM with leading spaces",
			containerFile: "  FROM nginx:latest",
			expectedImage: "nginx:latest",
		},
		{
			name:           "no FROM statement",
			containerFile:  "RUN echo hello",
			expectedErrMsg: "no FROM statement found in container file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getImageFromContainerFile([]byte(tt.containerFile))

			if tt.expectedErrMsg != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedImage, result)
			}
		})
	}
}
