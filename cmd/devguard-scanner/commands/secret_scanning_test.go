package commands

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/stretchr/testify/assert"
)

var exampleSarifResult = common.SarifResult{
	Runs: []common.Run{
		{
			Tool: struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			}{
				Driver: struct {
					Name string `json:"name"`
				}{
					Name: "ExampleTool",
				},
			},
			Results: []common.Result{
				{
					RuleId: "EXAMPLE001",
					Message: struct {
						Text string `json:"text"`
					}{
						Text: "This is an example message.",
					},
					Locations: []struct {
						PhysicalLocation struct {
							ArtifactLocation struct {
								Uri       string `json:"uri"`
								UriBaseId string `json:"uriBaseId"`
							} `json:"artifactLocation"`
							Region struct {
								StartLine   int `json:"startLine"`
								StartColumn int `json:"startColumn"`
								EndLine     int `json:"endLine"`
								EndColumn   int `json:"endColumn"`
								Snippet     struct {
									Text string `json:"text"`
								} `json:"snippet"`
							} `json:"region"`
						} `json:"physicalLocation"`
					}{
						{
							PhysicalLocation: struct {
								ArtifactLocation struct {
									Uri       string `json:"uri"`
									UriBaseId string `json:"uriBaseId"`
								} `json:"artifactLocation"`
								Region struct {
									StartLine   int `json:"startLine"`
									StartColumn int `json:"startColumn"`
									EndLine     int `json:"endLine"`
									EndColumn   int `json:"endColumn"`
									Snippet     struct {
										Text string `json:"text"`
									} `json:"snippet"`
								} `json:"region"`
							}{
								ArtifactLocation: struct {
									Uri       string `json:"uri"`
									UriBaseId string `json:"uriBaseId"`
								}{
									Uri:       "file:///example/path",
									UriBaseId: "SRCROOT",
								},
								Region: struct {
									StartLine   int `json:"startLine"`
									StartColumn int `json:"startColumn"`
									EndLine     int `json:"endLine"`
									EndColumn   int `json:"endColumn"`
									Snippet     struct {
										Text string `json:"text"`
									} `json:"snippet"`
								}{
									StartLine:   10,
									StartColumn: 5,
									EndLine:     10,
									EndColumn:   20,
									Snippet: struct {
										Text string `json:"text"`
									}{
										Text: "that is an example code snippet, which are very long and should be obfuscated",
									},
								},
							},
						},
					},
					Properties: struct {
						Precision string   `json:"precision"`
						Tags      []string `json:"tags"`
					}{
						Precision: "high",
						Tags:      []string{"example", "test"},
					},
					Fingerprints: struct {
						MatchBasedId string `json:"matchBasedId/v1"`
					}{
						MatchBasedId: "12345",
					},
					PartialFingerprints: struct {
						CommitSha     string `json:"commitSha"`
						Email         string `json:"email"`
						Author        string `json:"author"`
						Date          string `json:"date"`
						CommitMessage string `json:"commitMessage"`
					}{
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
		expectedSnippet := "that is an example c****"

		// Call the function with the example data
		obfuscatedResult := obfuscateSecret(exampleSarifResult)

		// Check if the original snippet is not present in the obfuscated result
		assert.NotContains(t, obfuscatedResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text, originalSnippet)

		//check if the obfuscated snippet is as expected
		assert.Equal(t, expectedSnippet, obfuscatedResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text)
	})

	t.Run("it should not obfuscate the snippet if it is shorter then 20 characters", func(t *testing.T) {

		//original snippet
		originalSnippet := "short snippet"

		//expected obfuscated snippet
		expectedSnippet := "short ****"

		//override the original snippet
		exampleSarifResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text = originalSnippet

		// Call the function with the example data
		obfuscatedResult := obfuscateSecret(exampleSarifResult)

		// Check if the original snippet is not present in the obfuscated result
		assert.NotContains(t, obfuscatedResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text, originalSnippet)

		//check if the obfuscated snippet is as expected
		assert.Equal(t, expectedSnippet, obfuscatedResult.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.Snippet.Text)
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
}
