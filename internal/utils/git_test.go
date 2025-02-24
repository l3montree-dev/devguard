package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCurrentBranchName(t *testing.T) {
	t.Run("it should use the CI_COMMIT_REF_NAME variable if it is set", func(t *testing.T) {
		// Test when CI_COMMIT_REF_NAME is set
		os.Setenv("CI_COMMIT_REF_NAME", "test-branch")
		branchName, err := getCurrentBranchName(".")
		assert.NoError(t, err)
		assert.Equal(t, "test-branch", branchName)
	})
}
