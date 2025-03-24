package scan

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/database/models"
)

func TestShouldCreateIssue(t *testing.T) {
	t.Run("Function should return false if the assetVersion is the default branch", func(t *testing.T) {
		assetVersion := models.AssetVersion{
			DefaultBranch: false,
		}

		defaultBranch := shouldCreateIssue(assetVersion)
		if defaultBranch {
			t.Fail()
		}
	})
	t.Run("Function should return true if the assetVersion is the default branch", func(t *testing.T) {
		assetVersion := models.AssetVersion{
			DefaultBranch: true,
		}

		defaultBranch := shouldCreateIssue(assetVersion)
		if !defaultBranch {
			t.Fail()
		}
	})

}
