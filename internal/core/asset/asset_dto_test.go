package asset

import (
	"testing"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestApplyToModel(t *testing.T) {
	tests := []struct {
		name     string
		patch    patchRequest
		initial  models.Asset
		expected models.Asset
		updated  bool
	}{
		{
			name: "Update Name and Description",
			patch: patchRequest{
				Name:        utils.Ptr("New Name"),
				Description: utils.Ptr("New Description"),
			},
			initial: models.Asset{
				Name:        "Old Name",
				Description: "Old Description",
			},
			expected: models.Asset{
				Name:        "New Name",
				Slug:        "new-name",
				Description: "New Description",
			},
			updated: true,
		},
		{
			name: "Update CentralDependencyVulnManagement",
			patch: patchRequest{
				CentralDependencyVulnManagement: utils.Ptr(true),
			},
			initial: models.Asset{
				CentralDependencyVulnManagement: false,
			},
			expected: models.Asset{
				CentralDependencyVulnManagement: true,
			},
			updated: true,
		},
		{
			name: "Update ReachableFromInternet",
			patch: patchRequest{
				ReachableFromInternet: utils.Ptr(true),
			},
			initial: models.Asset{
				ReachableFromInternet: false,
			},
			expected: models.Asset{
				ReachableFromInternet: true,
			},
			updated: true,
		},
		{
			name: "Update RepositoryID and RepositoryName",
			patch: patchRequest{
				RepositoryID:   utils.Ptr("new-repo-id"),
				RepositoryName: utils.Ptr("new-repo-name"),
			},
			initial: models.Asset{
				RepositoryID:   utils.Ptr("old-repo-id"),
				RepositoryName: utils.Ptr("old-repo-name"),
			},
			expected: models.Asset{
				RepositoryID:   utils.Ptr("new-repo-id"),
				RepositoryName: utils.Ptr("new-repo-name"),
			},
			updated: true,
		},
		{
			name: "Update CVSSAutomaticTicketThreshold and RiskAutomaticTicketThreshold",
			patch: patchRequest{
				CVSSAutomaticTicketThreshold: utils.Ptr(5.0),
				RiskAutomaticTicketThreshold: utils.Ptr(7.0),
			},
			initial: models.Asset{
				CVSSAutomaticTicketThreshold: utils.Ptr(3.0),
				RiskAutomaticTicketThreshold: utils.Ptr(6.0),
			},
			expected: models.Asset{
				CVSSAutomaticTicketThreshold: utils.Ptr(5.0),
				RiskAutomaticTicketThreshold: utils.Ptr(7.0),
			},
			updated: true,
		},
		{
			name:  "No Updates",
			patch: patchRequest{},
			initial: models.Asset{
				Name:        "Old Name",
				Description: "Old Description",
			},
			expected: models.Asset{
				Name:        "Old Name",
				Description: "Old Description",
			},
			updated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := tt.initial
			updated := tt.patch.applyToModel(&asset)
			assert.Equal(t, tt.updated, updated)
			assert.Equal(t, tt.expected, asset)
		})
	}
}
