package commands

import (
	"fmt"
	"testing"

	"github.com/l3montree-dev/devguard/internal/common"
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
					RuleId: "EXAMPLE001",
					Message: common.Text{
						Text: "This is an example message.",
					},
					Locations: []common.Location{
						{
							PhysicalLocation: common.PhysicalLocation{
								ArtifactLocation: common.ArtifactLocation{
									URI:       "file:///example/path",
									URIBaseId: "SRCROOT",
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
						MatchBasedId: "12345",
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
		obfuscateSecret(&exampleSarifResult)

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
		obfuscateSecret(&exampleSarifResult)

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

		result := obfuscateString(input)
		assert.Equal(t, expected, result)
	})

	t.Run("it should have a look at individual words", func(t *testing.T) {
		input := "# COPY .badge-api.yaml /.badge-api.yaml"
		expected := "# COPY .badge-api.yaml /.badge-api.yaml"
		result := obfuscateString(input)

		assert.Equal(t, expected, result)
	})
}
func TestExpandSnippet(t *testing.T) {
	t.Run("it should expand the snippet correctly", func(t *testing.T) {
		fileContent := []byte(`line1
line2
line3
line4
line5
line6
line7
line8
line9
line10
line11
line12
line13
line14
line15`)
		startLine := 10
		endLine := 10
		original := "line10"

		expected := `line5
line6
line7
line8
line9
+++
line10
+++
line11
line12
line13
line14
line15`

		result, err := expandSnippet(fileContent, startLine, endLine, original)
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})

	t.Run("it should handle start line out of range", func(t *testing.T) {
		fileContent := []byte(`line1
+++
line2
+++
line3
line4
line5`)
		startLine := -1
		endLine := 2
		original := "line2"

		_, err := expandSnippet(fileContent, startLine, endLine, original)
		assert.Error(t, err)
		assert.Equal(t, "start line or end line is out of range", err.Error())
	})

	t.Run("it should handle end line out of range", func(t *testing.T) {
		fileContent := []byte(`line1
line2
line3
line4
line5`)
		startLine := 2
		endLine := 10
		original := "line3"

		_, err := expandSnippet(fileContent, startLine, endLine, original)
		assert.Error(t, err)
		assert.Equal(t, "start line or end line is out of range", err.Error())
	})

	t.Run("it should expand snippet with limited lines at the start", func(t *testing.T) {
		fileContent := []byte(`line1
line2
line3
line4
line5
line6
line7
line8
line9
line10`)
		startLine := 2
		endLine := 2
		original := "line2"

		expected := `line1
+++
line2
+++
line3
line4
line5
line6
line7`

		result, err := expandSnippet(fileContent, startLine, endLine, original)
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})

	t.Run("it should expand snippet with limited lines at the end", func(t *testing.T) {
		fileContent := []byte(`line1
line2
line3
line4
line5
line6
line7
line8
line9
line10`)
		startLine := 8
		endLine := 8
		original := "line8"

		expected := `line3
line4
line5
line6
line7
+++
line8
+++
line9
line10`

		result, err := expandSnippet(fileContent, startLine, endLine, original)
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})

	t.Run("it should expand snippet when start line is first line", func(t *testing.T) {
		fileContent := []byte(`line1
line2
line3
line4
line5
line6
line7
line8
line9
line10`)
		startLine := 1
		endLine := 1
		original := "line1"
		expected := `+++
line1
+++
line2
line3
line4
line5
line6`
		result, err := expandSnippet(fileContent, startLine, endLine, original)
		assert.NoError(t, err)
		fmt.Println(result)
		assert.Equal(t, expected, result)
	})

	t.Run("it should expand snippet when end line is last line", func(t *testing.T) {
		fileContent := []byte(`line1
line2
line3
line4
line5
line6
line7
line8
line9
line10`)
		startLine := 10
		endLine := 10
		original := "line10"
		expected := `line5
line6
line7
line8
line9
+++
line10
+++`
		result, err := expandSnippet(fileContent, startLine, endLine, original)
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})

	t.Run("it should expand snippet with password", func(t *testing.T) {
		fileContent := []byte(`line1
line2
line3
line4
line5
line6
line7
line8
line9
password='SBDAlKzSdqpSYpmC6aCe'
line11
line12
line13
line14
line15`)
		startLine := 10
		endLine := 10
		original := "SBDAlKzSd****"

		expected := `line5
line6
line7
line8
line9
+++
password='SBDAlKzSd****
+++
line11
line12
line13
line14
line15`

		result, err := expandSnippet(fileContent, startLine, endLine, original)
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})

}
