package transformer_test

import (
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransformPackagistToDepsDev(t *testing.T) {
	t.Run("maps the selected version even when source and dist are nil", func(t *testing.T) {
		packagistResponse := dtos.PackagistPackageResponse{
			Packages: map[string][]dtos.PackagistPackageVersion{
				"vendor/package": {
					{
						Name:    "vendor/package",
						Version: "1.0.0",
						License: []string{"MIT"},
					},
					{
						Name:    "vendor/package",
						Version: "2.0.0",
						License: []string{"MIT"},
						Time:    "2024-01-02T03:04:05Z",
					},
				},
			},
		}

		response, err := transformer.TransformPackagistToDepsDev(packagistResponse, "vendor/package", "2.0.0")
		require.NoError(t, err)
		assert.Equal(t, "COMPOSER", response.VersionKey.System)
		assert.Equal(t, "vendor/package", response.VersionKey.Name)
		assert.Equal(t, "2.0.0", response.VersionKey.Version)
		assert.Equal(t, []string{"MIT"}, response.Licenses)
		assert.Equal(t, []string{"https://packagist.org"}, response.Registries)
		assert.Empty(t, response.Links)
		assert.Empty(t, response.RelatedProjects)
		assert.Equal(t, time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC), response.PublishedAt)
	})

	t.Run("returns an error when the package list is empty", func(t *testing.T) {
		_, err := transformer.TransformPackagistToDepsDev(dtos.PackagistPackageResponse{Packages: map[string][]dtos.PackagistPackageVersion{}}, "vendor/package", "2.0.0")
		require.Error(t, err)
		assert.Equal(t, "packagist list empty", err.Error())
	})

	t.Run("returns an error when the requested version is missing", func(t *testing.T) {
		packagistResponse := dtos.PackagistPackageResponse{
			Packages: map[string][]dtos.PackagistPackageVersion{
				"vendor/package": {
					{
						Name:    "vendor/package",
						Version: "1.0.0",
						License: []string{"MIT"},
					},
				},
			},
		}

		_, err := transformer.TransformPackagistToDepsDev(packagistResponse, "vendor/package", "2.0.0")
		require.Error(t, err)
		assert.Equal(t, "no version matching specified package version from packagist", err.Error())
	})
}