package commands

import (
	"os"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/stretchr/testify/assert"
)

func ptrStr(s string) *string { return &s }
func ptrInt(i int) *int       { return &i }

func buildSarifScan(uri string, startLine, endLine int, originalSnippet string) *sarif.SarifSchema210Json {
	return &sarif.SarifSchema210Json{
		Runs: []sarif.Run{
			{
				Results: []sarif.Result{
					{
						Locations: []sarif.Location{
							{
								PhysicalLocation: sarif.PhysicalLocation{
									ArtifactLocation: sarif.ArtifactLocation{
										URI: ptrStr(uri),
									},
									Region: &sarif.Region{
										StartLine: ptrInt(startLine),
										EndLine:   ptrInt(endLine),
										Snippet: &sarif.ArtifactContent{
											Text: ptrStr(originalSnippet),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func writeTempFile(t *testing.T, lines []string) string {
	t.Helper()
	f, err := os.CreateTemp("", "sarif-snippet-test-*.txt")
	assert.NoError(t, err)
	t.Cleanup(func() { os.Remove(f.Name()) })
	_, err = f.WriteString(strings.Join(lines, "\n"))
	assert.NoError(t, err)
	f.Close()
	return f.Name()
}

// TestExpandAndObfuscateSnippetLargeSnippetDiscarded verifies that a snippet
// whose expanded form exceeds 10 KB is discarded (snippet text left unchanged).
func TestExpandAndObfuscateSnippetLargeSnippetDiscarded(t *testing.T) {
	// Lines of ~1100 chars so the ~10 expanded lines exceed 10 KB
	longLine := "SECRET " + strings.Repeat("x", 1093)
	var lines []string
	for range 20 {
		lines = append(lines, longLine)
	}

	uri := writeTempFile(t, lines)
	original := "SECRET"
	scan := buildSarifScan(uri, 6, 6, original)

	expandAndObfuscateSnippet(scan, "")

	got := scan.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text
	assert.Equal(t, original, *got, "large snippet should be discarded, leaving the original text")
}

// TestExpandAndObfuscateSnippetSmallSnippetKept verifies that a snippet whose
// expanded form stays under 10 KB is expanded and obfuscated as expected.
func TestExpandAndObfuscateSnippetSmallSnippetKept(t *testing.T) {
	shortLine := "SECRET short"
	var lines []string
	for range 20 {
		lines = append(lines, shortLine)
	}

	uri := writeTempFile(t, lines)
	original := "SECRET"
	scan := buildSarifScan(uri, 6, 6, original)

	expandAndObfuscateSnippet(scan, "")

	got := scan.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text
	assert.NotNil(t, got)
	assert.NotEqual(t, original, *got, "small snippet should be replaced with the expanded value")
	assert.Contains(t, *got, "+++", "expanded snippet should contain context markers")
}
