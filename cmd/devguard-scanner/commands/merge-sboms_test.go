package commands

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeSBOMs(t *testing.T) {
	tests := []struct {
		name               string
		purl               string
		sboms              []cyclonedx.BOM
		expectedComponents int
		expectedDeps       int
		wantErr            bool
	}{
		{
			name: "merge sboms with nil components",
			purl: "pkg:test/app@1.0.0",
			sboms: []cyclonedx.BOM{
				{
					SpecVersion: cyclonedx.SpecVersion1_6,
					Metadata: &cyclonedx.Metadata{
						Component: &cyclonedx.Component{
							BOMRef:     "pkg:test/lib1@1.0.0",
							PackageURL: "pkg:test/lib1@1.0.0",
						},
					},
					Components:   nil, // nil components
					Dependencies: &[]cyclonedx.Dependency{},
				},
			},
			expectedComponents: 0,
			expectedDeps:       1, // root dependency only
			wantErr:            false,
		},
		{
			name: "merge sboms with nil dependencies",
			purl: "pkg:test/app@1.0.0",
			sboms: []cyclonedx.BOM{
				{
					SpecVersion: cyclonedx.SpecVersion1_6,
					Metadata: &cyclonedx.Metadata{
						Component: &cyclonedx.Component{
							BOMRef:     "pkg:test/lib1@1.0.0",
							PackageURL: "pkg:test/lib1@1.0.0",
						},
					},
					Components: &[]cyclonedx.Component{
						{
							BOMRef:     "pkg:test/comp1@1.0.0",
							PackageURL: "pkg:test/comp1@1.0.0",
							Name:       "comp1",
						},
					},
					Dependencies: nil, // nil dependencies
				},
			},
			expectedComponents: 1,
			expectedDeps:       1, // root dependency only
			wantErr:            false,
		},
		{
			name: "merge sboms with both nil components and dependencies",
			purl: "pkg:test/app@1.0.0",
			sboms: []cyclonedx.BOM{
				{
					SpecVersion: cyclonedx.SpecVersion1_6,
					Metadata: &cyclonedx.Metadata{
						Component: &cyclonedx.Component{
							BOMRef:     "pkg:test/lib1@1.0.0",
							PackageURL: "pkg:test/lib1@1.0.0",
						},
					},
					Components:   nil, // nil components
					Dependencies: nil, // nil dependencies
				},
			},
			expectedComponents: 0,
			expectedDeps:       1, // root dependency only
			wantErr:            false,
		},
		{
			name: "merge multiple sboms with valid components and dependencies",
			purl: "pkg:test/app@1.0.0",
			sboms: []cyclonedx.BOM{
				{
					SpecVersion: cyclonedx.SpecVersion1_6,
					Metadata: &cyclonedx.Metadata{
						Component: &cyclonedx.Component{
							BOMRef:     "pkg:test/lib1@1.0.0",
							PackageURL: "pkg:test/lib1@1.0.0",
						},
					},
					Components: &[]cyclonedx.Component{
						{
							BOMRef:     "pkg:test/comp1@1.0.0",
							PackageURL: "pkg:test/comp1@1.0.0",
							Name:       "comp1",
						},
					},
					Dependencies: &[]cyclonedx.Dependency{
						{
							Ref:          "pkg:test/lib1@1.0.0",
							Dependencies: &[]string{"pkg:test/comp1@1.0.0"},
						},
					},
				},
				{
					SpecVersion: cyclonedx.SpecVersion1_6,
					Metadata: &cyclonedx.Metadata{
						Component: &cyclonedx.Component{
							BOMRef:     "pkg:test/lib2@1.0.0",
							PackageURL: "pkg:test/lib2@1.0.0",
						},
					},
					Components: &[]cyclonedx.Component{
						{
							BOMRef:     "pkg:test/comp2@1.0.0",
							PackageURL: "pkg:test/comp2@1.0.0",
							Name:       "comp2",
						},
					},
					Dependencies: &[]cyclonedx.Dependency{
						{
							Ref:          "pkg:test/lib2@1.0.0",
							Dependencies: &[]string{"pkg:test/comp2@1.0.0"},
						},
					},
				},
			},
			expectedComponents: 2,
			expectedDeps:       3, // 2 from sboms + 1 root
			wantErr:            false,
		},
		{
			name: "merge sboms with empty BOMRef",
			purl: "pkg:test/app@1.0.0",
			sboms: []cyclonedx.BOM{
				{
					SpecVersion: cyclonedx.SpecVersion1_6,
					Metadata: &cyclonedx.Metadata{
						Component: &cyclonedx.Component{
							BOMRef:     "", // empty BOMRef
							PackageURL: "pkg:test/lib1@1.0.0",
						},
					},
					Components:   &[]cyclonedx.Component{},
					Dependencies: &[]cyclonedx.Dependency{},
				},
			},
			expectedComponents: 0,
			expectedDeps:       1, // root dependency only (empty BOMRef not added)
			wantErr:            false,
		},
		{
			name: "skip sbom with nil metadata",
			purl: "pkg:test/app@1.0.0",
			sboms: []cyclonedx.BOM{
				{
					SpecVersion:  cyclonedx.SpecVersion1_6,
					Metadata:     nil, // nil metadata
					Components:   &[]cyclonedx.Component{},
					Dependencies: &[]cyclonedx.Dependency{},
				},
			},
			expectedComponents: 0,
			expectedDeps:       1, // root dependency only
			wantErr:            false,
		},
		{
			name: "skip sbom with nil component in metadata",
			purl: "pkg:test/app@1.0.0",
			sboms: []cyclonedx.BOM{
				{
					SpecVersion: cyclonedx.SpecVersion1_6,
					Metadata: &cyclonedx.Metadata{
						Component: nil, // nil component
					},
					Components:   &[]cyclonedx.Component{},
					Dependencies: &[]cyclonedx.Dependency{},
				},
			},
			expectedComponents: 0,
			expectedDeps:       1, // root dependency only
			wantErr:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test files
			tmpDir := t.TempDir()

			// Write test SBOMs to temporary files
			sbomPaths := make([]string, len(tt.sboms))
			for i, sbom := range tt.sboms {
				sbomPath := filepath.Join(tmpDir, "sbom_"+string(rune('0'+i))+".json")
				f, err := os.Create(sbomPath)
				require.NoError(t, err)

				encoder := cyclonedx.NewBOMEncoder(f, cyclonedx.BOMFileFormatJSON)
				err = encoder.Encode(&sbom)
				require.NoError(t, err)
				f.Close()

				sbomPaths[i] = sbomPath
			}

			// Redirect stdout to capture output
			oldStdout := os.Stdout
			tmpFile, err := os.CreateTemp(tmpDir, "output")
			require.NoError(t, err)
			os.Stdout = tmpFile
			defer func() {
				os.Stdout = oldStdout
				tmpFile.Close()
			}()

			// Run the merge
			err = mergeSBOMs(context.Background(), tt.purl, sbomPaths)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Read and parse the output
			var result cyclonedx.BOM
			_, err = tmpFile.Seek(0, 0)
			require.NoError(t, err)
			err = json.NewDecoder(tmpFile).Decode(&result)
			require.NoError(t, err)

			// Verify the result
			assert.NotNil(t, result.Metadata)
			assert.NotNil(t, result.Metadata.Component)
			assert.Equal(t, tt.purl, result.Metadata.Component.BOMRef)
			assert.Equal(t, tt.purl, result.Metadata.Component.PackageURL)

			if result.Components != nil {
				assert.Equal(t, tt.expectedComponents, len(*result.Components), "component count mismatch")
			} else {
				assert.Equal(t, 0, tt.expectedComponents, "expected no components but result has nil Components")
			}

			if result.Dependencies != nil {
				assert.Equal(t, tt.expectedDeps, len(*result.Dependencies), "dependency count mismatch")
			} else {
				assert.Equal(t, 0, tt.expectedDeps, "expected no dependencies but result has nil Dependencies")
			}
		})
	}
}

func TestRunMergeSBOMs(t *testing.T) {
	t.Run("config file not found", func(t *testing.T) {
		tmpDir := t.TempDir()
		cmd := NewMergeSBOMSCommand()

		err := runMergeSBOMs(cmd, []string{filepath.Join(tmpDir, "nonexistent.json")})
		assert.Error(t, err)
	})

	t.Run("valid config file", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a test SBOM
		sbom := cyclonedx.BOM{
			SpecVersion: cyclonedx.SpecVersion1_6,
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef:     "pkg:test/lib@1.0.0",
					PackageURL: "pkg:test/lib@1.0.0",
				},
			},
			Components:   &[]cyclonedx.Component{},
			Dependencies: &[]cyclonedx.Dependency{},
		}

		sbomPath := filepath.Join(tmpDir, "test.json")
		f, err := os.Create(sbomPath)
		require.NoError(t, err)
		encoder := cyclonedx.NewBOMEncoder(f, cyclonedx.BOMFileFormatJSON)
		err = encoder.Encode(&sbom)
		require.NoError(t, err)
		f.Close()

		// Create config file
		config := MergeSBOMsConfigFile{
			Purl:  "pkg:test/app@1.0.0",
			SBOMs: []string{sbomPath},
		}

		configPath := filepath.Join(tmpDir, "config.json")
		configData, err := json.Marshal(config)
		require.NoError(t, err)
		err = os.WriteFile(configPath, configData, 0644)
		require.NoError(t, err)

		// Redirect stdout
		oldStdout := os.Stdout
		tmpFile, err := os.CreateTemp(tmpDir, "output")
		require.NoError(t, err)
		os.Stdout = tmpFile
		defer func() {
			os.Stdout = oldStdout
			tmpFile.Close()
		}()

		cmd := NewMergeSBOMSCommand()
		err = runMergeSBOMs(cmd, []string{configPath})
		assert.NoError(t, err)
	})

	t.Run("invalid json in config file", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid.json")
		err := os.WriteFile(configPath, []byte("invalid json"), 0644)
		require.NoError(t, err)

		cmd := NewMergeSBOMSCommand()
		err = runMergeSBOMs(cmd, []string{configPath})
		assert.Error(t, err)
	})
}
