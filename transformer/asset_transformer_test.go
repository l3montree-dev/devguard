package transformer_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/stretchr/testify/assert"
)

func TestApplyToModel(t *testing.T) {

	webhookSecret := uuid.New()

	tests := []struct {
		name     string
		patch    dtos.AssetPatchRequest
		initial  models.Asset
		expected models.Asset
		updated  bool
	}{
		{
			name: "Update Name and Description",
			patch: dtos.AssetPatchRequest{
				Name:        new("New Name"),
				Description: new("New Description"),
			},
			initial: models.Asset{
				Name:        "Old Name",
				Description: "Old Description",
			},
			expected: models.Asset{
				Name:        "New Name",
				Description: "New Description",
			},
			updated: true,
		},
		{
			name: "Update ReachableFromInternet",
			patch: dtos.AssetPatchRequest{
				ReachableFromInternet: new(true),
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
			patch: dtos.AssetPatchRequest{
				RepositoryID:   new("new-repo-id"),
				RepositoryName: new("new-repo-name"),
			},
			initial: models.Asset{

				RepositoryID:   new("old-repo-id"),
				RepositoryName: new("old-repo-name"),
			},
			expected: models.Asset{

				RepositoryID:   new("new-repo-id"),
				RepositoryName: new("new-repo-name"),
			},
			updated: true,
		},
		{
			name:  "No Updates",
			patch: dtos.AssetPatchRequest{},
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
			patch: dtos.AssetPatchRequest{
				WebhookSecret: new(webhookSecret.String()),
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
			name: "Update Webhook Secret",
			patch: dtos.AssetPatchRequest{
				WebhookSecret: new(webhookSecret.String()),
			},
			initial: models.Asset{
				WebhookSecret: new(uuid.New()),
			},
			expected: models.Asset{
				WebhookSecret: &webhookSecret,
			},
			updated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := tt.initial
			updated := transformer.ApplyAssetPatchRequestToModel(tt.patch, &asset)
			assert.Equal(t, tt.updated, updated)
			assert.Equal(t, tt.expected, asset)
		})
	}
}
