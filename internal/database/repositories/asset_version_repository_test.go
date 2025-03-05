package repositories

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/stretchr/testify/assert"
)

func TestAssetVersionFactory(t *testing.T) {
	repo := &assetVersionRepository{}

	assetVersionName := "Test Asset Version"
	assetID := uuid.New()
	assetVersionType := models.AssetVersionType("branch")
	defaultBranch := true

	expectedSlug := "test-asset-version"

	assetVersion := repo.assetVersionFactory(assetVersionName, assetID, assetVersionType, defaultBranch)

	assert.Equal(t, assetVersionName, assetVersion.Name)
	assert.Equal(t, assetID, assetVersion.AssetID)
	assert.Equal(t, expectedSlug, assetVersion.Slug)
	assert.Equal(t, assetVersionType, assetVersion.Type)
	assert.Equal(t, defaultBranch, assetVersion.DefaultBranch)
}
