package asset

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestApplyToModel(t *testing.T) {

	webhookSecret := uuid.New()
	badgeSecret := uuid.New()

	tests := []struct {
		name     string
		patch    PatchRequest
		initial  models.Asset
		expected models.Asset
		updated  bool
	}{
		{
			name: "Update Name and Description",
			patch: PatchRequest{
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
			patch: PatchRequest{
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
			patch: PatchRequest{
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
			patch: PatchRequest{
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
			name:  "No Updates",
			patch: PatchRequest{},
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
		{
			name: "Update nil Badge Secret",
			patch: PatchRequest{
				WebhookSecret: utils.Ptr(webhookSecret.String()),
			},
			initial: models.Asset{
				WebhookSecret: nil,
			},
			expected: models.Asset{
				WebhookSecret: &webhookSecret,
			},
			updated: true,
		},
		{
			name: "Update nil Webhook Secret",
			patch: PatchRequest{
				BadgeSecret: utils.Ptr(badgeSecret.String()),
			},
			initial: models.Asset{
				BadgeSecret: nil,
			},
			expected: models.Asset{
				BadgeSecret: &badgeSecret,
			},
			updated: true,
		},
		{
			name: "Update Webhook Secret",
			patch: PatchRequest{
				WebhookSecret: utils.Ptr(webhookSecret.String()),
			},
			initial: models.Asset{
				WebhookSecret: utils.Ptr(uuid.New()),
			},
			expected: models.Asset{
				WebhookSecret: &webhookSecret,
			},
			updated: true,
		},
		{
			name: "Update Badge Secret",
			patch: PatchRequest{
				BadgeSecret: utils.Ptr(badgeSecret.String()),
			},
			initial: models.Asset{
				BadgeSecret: utils.Ptr(uuid.New()),
			},
			expected: models.Asset{
				BadgeSecret: &badgeSecret,
			},
			updated: true,
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
