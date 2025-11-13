package dtos

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

func TestApplyToModel(t *testing.T) {

	webhookSecret := uuid.New()
	badgeSecret := uuid.New()

	tests := []struct {
		name     string
		patch    AssetPatchRequest
		initial  AssetDTO
		expected AssetDTO
		updated  bool
	}{
		{
			name: "Update Name and Description",
			patch: AssetPatchRequest{
				Name:        utils.Ptr("New Name"),
				Description: utils.Ptr("New Description"),
			},
			initial: AssetDTO{
				Name:        "Old Name",
				Description: "Old Description",
			},
			expected: AssetDTO{
				Name:        "New Name",
				Slug:        "new-name",
				Description: "New Description",
			},
			updated: true,
		},
		{
			name: "Update CentralDependencyVulnManagement",
			patch: AssetPatchRequest{
				CentralDependencyVulnManagement: utils.Ptr(true),
			},
			initial: AssetDTO{
				CentralDependencyVulnManagement: false,
			},
			expected: AssetDTO{
				CentralDependencyVulnManagement: true,
			},
			updated: true,
		},
		{
			name: "Update ReachableFromInternet",
			patch: AssetPatchRequest{
				ReachableFromInternet: utils.Ptr(true),
			},
			initial: AssetDTO{
				ReachableFromInternet: false,
			},
			expected: AssetDTO{
				ReachableFromInternet: true,
			},
			updated: true,
		},
		{
			name: "Update RepositoryID and RepositoryName",
			patch: AssetPatchRequest{
				RepositoryID:   utils.Ptr("new-repo-id"),
				RepositoryName: utils.Ptr("new-repo-name"),
			},
			initial: AssetDTO{
				RepositoryID:   utils.Ptr("old-repo-id"),
				RepositoryName: utils.Ptr("old-repo-name"),
			},
			expected: AssetDTO{
				RepositoryID:   utils.Ptr("new-repo-id"),
				RepositoryName: utils.Ptr("new-repo-name"),
			},
			updated: true,
		},
		{
			name:  "No Updates",
			patch: AssetPatchRequest{},
			initial: AssetDTO{
				Name:        "Old Name",
				Description: "Old Description",
			},
			expected: AssetDTO{
				Name:        "Old Name",
				Description: "Old Description",
			},
			updated: false,
		},
		{
			name: "Update nil Badge Secret",
			patch: AssetPatchRequest{
				WebhookSecret: utils.Ptr(webhookSecret.String()),
			},
			initial: AssetDTO{
				WebhookSecret: nil,
			},
			expected: AssetDTO{
				WebhookSecret: &webhookSecret,
			},
			updated: true,
		},
		{
			name: "Update nil Webhook Secret",
			patch: AssetPatchRequest{
				BadgeSecret: utils.Ptr(badgeSecret.String()),
			},
			initial: AssetDTO{
				BadgeSecret: nil,
			},
			expected: AssetDTO{
				BadgeSecret: &badgeSecret,
			},
			updated: true,
		},
		{
			name: "Update Webhook Secret",
			patch: AssetPatchRequest{
				WebhookSecret: utils.Ptr(webhookSecret.String()),
			},
			initial: AssetDTO{
				WebhookSecret: utils.Ptr(uuid.New()),
			},
			expected: AssetDTO{
				WebhookSecret: &webhookSecret,
			},
			updated: true,
		},
		{
			name: "Update Badge Secret",
			patch: AssetPatchRequest{
				BadgeSecret: utils.Ptr(badgeSecret.String()),
			},
			initial: AssetDTO{
				BadgeSecret: utils.Ptr(uuid.New()),
			},
			expected: AssetDTO{
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
