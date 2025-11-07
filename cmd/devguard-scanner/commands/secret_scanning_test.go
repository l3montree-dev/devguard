package commands

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
