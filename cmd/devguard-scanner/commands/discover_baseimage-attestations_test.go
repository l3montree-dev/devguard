package commands

import (
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
		attestations          []map[string]interface{}
		expectedFilenames     []string
		expectedUniqueCount   int
		expectedPrefixPattern string
	}{
		{
			name: "attestations with identical predicateType produce same filename (merged by DevGuard)",
			attestations: []map[string]interface{}{
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
			attestations: []map[string]interface{}{
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
			attestations: []map[string]interface{}{
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
			attestations: []map[string]interface{}{
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
