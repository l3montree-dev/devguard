// Copyright (C) 2025 l3montree GmbH
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

package scanner

import (
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/common"
	"github.com/stretchr/testify/assert"
)

var exampleSarifResult = common.SarifResult{
	Runs: []common.Run{
		{
			Tool: common.Tool{
				Driver: common.Driver{
					Name:  "ExampleTool",
					Rules: []common.Rule{},
				},
			},
			Results: []common.Result{
				{
					RuleID: "EXAMPLE001",
					Message: common.Text{
						Text: "This is an example message.",
					},
					Locations: []common.Location{
						{
							PhysicalLocation: common.PhysicalLocation{
								ArtifactLocation: common.ArtifactLocation{
									URI:       "file:///example/path",
									URIBaseID: "SRCROOT",
								},
								Region: common.Region{
									StartLine:   10,
									StartColumn: 5,
									EndLine:     10,
									EndColumn:   20,
									Snippet: common.Text{
										Text: "that is an example code snippet, which are very long and should be obfuscated",
									},
								},
							},
						},
					},
					Properties: &common.Properties{
						Precision: "high",
						Tags:      []string{"example", "test"},
					},
					Fingerprints: &common.Fingerprints{
						MatchBasedID: "12345",
					},
					PartialFingerprints: &common.PartialFingerprints{
						CommitSha:     "abcde12345",
						Email:         "example@example.com",
						Author:        "Example Author",
						Date:          "2023-01-01",
						CommitMessage: "Initial commit",
					},
				},
			},
		},
	},
}

func TestObfuscateSnippet(t *testing.T) {

	t.Run("it should obfuscate the snippet", func(t *testing.T) {

		//original snippet
		originalSnippet := exampleSarifResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text

		//expected obfuscated snippet
		expectedSnippet := "that is an example c*********************************************************"

		// Call the function with the example data
		ObfuscateSecretAndAddFingerprint(&exampleSarifResult)

		// Check if the original snippet is not present in the obfuscated result
		assert.NotContains(t, exampleSarifResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text, originalSnippet)

		//check if the obfuscated snippet is as expected
		assert.Equal(t, expectedSnippet, exampleSarifResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text)
	})

	t.Run("it should not obfuscate the snippet if it is shorter then 20 characters", func(t *testing.T) {

		//original snippet
		originalSnippet := "short snippet"

		//expected obfuscated snippet
		expectedSnippet := "short *******"

		//override the original snippet
		exampleSarifResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text = originalSnippet

		// Call the function with the example data
		ObfuscateSecretAndAddFingerprint(&exampleSarifResult)

		// Check if the original snippet is not present in the obfuscated result
		assert.NotContains(t, exampleSarifResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text, originalSnippet)

		//check if the obfuscated snippet is as expected
		assert.Equal(t, expectedSnippet, exampleSarifResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text)
	})
}

func TestObfuscateString(t *testing.T) {
	t.Run("it should obfuscate the string", func(t *testing.T) {
		// Test case with a string longer than 20 characters
		input := "password='SBDAlKzSdqpSYpmC6aCe'"
		expected := "password='SBDAlK***************"

		result := ObfuscateString(input)
		assert.Equal(t, expected, result)
	})

	t.Run("it should have a look at individual words", func(t *testing.T) {
		input := "# COPY .badge-api.yaml /.badge-api.yaml"
		expected := "# COPY .badge-api.yaml /.badge-api.yaml"
		result := ObfuscateString(input)

		assert.Equal(t, expected, result)
	})
}

// Test that ObfuscateString preserves tab characters when obfuscating
func TestObfuscateStringPreservesTabs(t *testing.T) {
	// prepare input containing a high-entropy "secret" token separated by tabs
	// we use a string with a likely high Shannon entropy (mix of letters and numbers)
	input := "prefix\tsecretTokenABC123xyz\tsuffix"

	out := ObfuscateString(input)

	// ensure tabs are preserved
	if strings.Count(out, "\t") != strings.Count(input, "\t") {
		t.Fatalf("tabs were not preserved: expected %d tabs, got %d\ninput: %q\noutput: %q", strings.Count(input, "\t"), strings.Count(out, "\t"), input, out)
	}

	// ensure output still contains the prefix and suffix around the tabs
	partsIn := strings.Split(input, "\t")
	partsOut := strings.Split(out, "\t")
	if partsOut[0] != partsIn[0] {
		t.Fatalf("prefix changed: expected %q got %q", partsIn[0], partsOut[0])
	}
	if partsOut[2] != partsIn[2] {
		t.Fatalf("suffix changed: expected %q got %q", partsIn[2], partsOut[2])
	}

	// the middle part should be obfuscated: shorter or containing asterisks
	if partsOut[1] == partsIn[1] {
		t.Fatalf("middle token was not obfuscated: %q", partsOut[1])
	}
	if !strings.Contains(partsOut[1], "*") {
		t.Fatalf("expected obfuscated token to contain '*', got %q", partsOut[1])
	}
}

func TestObfuscateStringTable(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantContains string
		wantTabs     int
	}{
		{name: "preserve tabs", input: "prefix\tsecretTokenABC123xyz\tsuffix", wantContains: "prefix\t", wantTabs: 2},
		{name: "preserve spaces", input: "a b   c", wantContains: "a b   c", wantTabs: 0},
		{name: "newlines preserved", input: "line1\nsecretTOK123\nline3", wantContains: "line1\n", wantTabs: 0},
		{name: "obfuscate high entropy", input: "start ABCdefGhijkL12345 end", wantContains: "start ", wantTabs: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := ObfuscateString(tt.input)

			// whitespace: tabs count
			if got := strings.Count(out, "\t"); got != tt.wantTabs {
				t.Fatalf("%s: unexpected tab count: want=%d got=%d\ninput:%q\noutput:%q", tt.name, tt.wantTabs, got, tt.input, out)
			}

			// ensure the expected substring (including whitespace) is present
			if !strings.Contains(out, tt.wantContains) {
				t.Fatalf("%s: output does not contain expected substring\ninput: %q\noutput: %q\nexpected substring: %q", tt.name, tt.input, out, tt.wantContains)
			}

			// for the high-entropy case ensure obfuscation occurred
			if tt.name == "obfuscate high entropy" {
				if out == tt.input {
					t.Fatalf("%s: expected obfuscation but output equals input", tt.name)
				}
			}
		})
	}
}
