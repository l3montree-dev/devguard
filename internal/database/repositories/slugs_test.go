package repositories

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/stretchr/testify/assert"
)

func TestInjectUniqueSlugs(t *testing.T) {
	t.Run("should keep slug unchanged for same project with external entity", func(t *testing.T) {
		externalID := "ext-123"
		providerID := "provider-xyz"
		existing := []*models.Project{
			{
				Slug:                     "alpha",
				ExternalEntityID:         &externalID,
				ExternalEntityProviderID: &providerID,
			},
		}
		projects := []*models.Project{
			{
				Slug:                     "alpha",
				ExternalEntityID:         &externalID,
				ExternalEntityProviderID: &providerID,
			},
		}
		err := injectUniqueSlugs(existing, projects)
		assert.NoError(t, err)
		assert.Equal(t, "alpha", projects[0].Slug)
	})

	t.Run("should assign new slug for different external entity with same slug", func(t *testing.T) {
		externalID := "ext-123"
		providerID := "provider-xyz"
		existing := []*models.Project{
			{
				Slug:                     "alpha",
				ExternalEntityID:         &externalID,
				ExternalEntityProviderID: &providerID,
			},
		}
		otherExternalID := "ext-456"
		projects := []*models.Project{
			{
				Slug:                     "alpha",
				ExternalEntityID:         &otherExternalID,
				ExternalEntityProviderID: &providerID,
			},
		}
		err := injectUniqueSlugs(existing, projects)
		assert.NoError(t, err)
		assert.Equal(t, "alpha-1", projects[0].Slug)
	})

	t.Run("should keep slug unchanged for same project with nil external entity", func(t *testing.T) {
		id := uuid.New()
		existing := []*models.Project{
			{Slug: "alpha", Model: models.Model{ID: id}, ExternalEntityID: nil, ExternalEntityProviderID: nil},
		}
		projects := []*models.Project{
			{Slug: "alpha", Model: models.Model{ID: id}, ExternalEntityID: nil, ExternalEntityProviderID: nil},
		}
		err := injectUniqueSlugs(existing, projects)
		assert.NoError(t, err)
		assert.Equal(t, "alpha", projects[0].Slug)
	})

	t.Run("should assign new slug for different project with nil external entity", func(t *testing.T) {
		id1 := uuid.New()
		id2 := uuid.New()
		existing := []*models.Project{
			{Slug: "alpha", Model: models.Model{ID: id1}, ExternalEntityID: nil, ExternalEntityProviderID: nil},
		}
		projects := []*models.Project{
			{Slug: "alpha", Model: models.Model{ID: id2}, ExternalEntityID: nil, ExternalEntityProviderID: nil},
		}
		err := injectUniqueSlugs(existing, projects)
		assert.NoError(t, err)
		assert.Equal(t, "alpha-1", projects[0].Slug)
	})
}
