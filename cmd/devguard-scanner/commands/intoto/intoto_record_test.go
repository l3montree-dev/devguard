package intotocmd

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseGitIgnore(t *testing.T) {
	t.Run("parseGitIgnore with empty strings", func(t *testing.T) {
		// create temp dir for testing
		dir, err := os.MkdirTemp("", "test")
		assert.NoError(t, err, "failed to create temporary directory")

		defer os.RemoveAll(dir)

		// Create a temporary .gitignore file for testing
		gitignoreContent := "\n.DS_Store\n\t\t\t\n"

		filepath := path.Join(dir, ".gitignore")

		err = os.WriteFile(filepath, []byte(gitignoreContent), 0600)
		assert.NoError(t, err, "failed to create temporary .gitignore file")

		ignorePaths, err := parseGitIgnore(filepath)
		assert.NoError(t, err, "expected no error when reading .gitignore")
		assert.Equal(t, []string{".DS_Store"}, ignorePaths, "unexpected ignore paths")

	})
}
