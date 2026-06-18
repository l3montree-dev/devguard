// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newLicenseRisk(componentPurl, assetVersionName string, assetID uuid.UUID) models.LicenseRisk {
	return models.LicenseRisk{
		Vulnerability: models.Vulnerability{
			AssetVersionName: assetVersionName,
			AssetID:          assetID,
			State:            dtos.VulnStateOpen,
		},
		ComponentPurl: componentPurl,
	}
}

func TestDeduplicateLicenseRisksByID(t *testing.T) {
	assetID := uuid.New()

	t.Run("collapses risks that share the same deterministic id", func(t *testing.T) {
		// same component reachable via multiple paths/artifacts -> identical id
		risks := []models.LicenseRisk{
			newLicenseRisk("pkg:npm/dup@1.0.0", "main", assetID),
			newLicenseRisk("pkg:npm/dup@1.0.0", "main", assetID),
		}

		deduped := deduplicateLicenseRisksByID(risks)

		assert.Len(t, deduped, 1)
		assert.Equal(t, risks[0].CalculateHash(), deduped[0].CalculateHash())
	})

	t.Run("keeps risks with distinct ids", func(t *testing.T) {
		risks := []models.LicenseRisk{
			newLicenseRisk("pkg:npm/a@1.0.0", "main", assetID),
			newLicenseRisk("pkg:npm/b@1.0.0", "main", assetID),
			newLicenseRisk("pkg:npm/a@1.0.0", "feature", assetID),
		}

		deduped := deduplicateLicenseRisksByID(risks)

		assert.Len(t, deduped, 3)
	})

	t.Run("handles empty input", func(t *testing.T) {
		assert.Empty(t, deduplicateLicenseRisksByID(nil))
	})
}

// regression for: INSERT ... ON CONFLICT ("id") DO UPDATE rejects a batch that
// proposes the same id twice. The service must deduplicate before SaveBatch.
func TestUserFixedLicenseRisksDeduplicatesBeforeSaveBatch(t *testing.T) {
	assetID := uuid.New()

	licenseRiskRepository := mocks.NewLicenseRiskRepository(t)
	vulnEventRepository := mocks.NewVulnEventRepository(t)
	s := NewLicenseRiskService(licenseRiskRepository, vulnEventRepository)

	// the same logical risk detected via two paths -> duplicate ids in one batch
	risks := []models.LicenseRisk{
		newLicenseRisk("pkg:npm/dup@1.0.0", "main", assetID),
		newLicenseRisk("pkg:npm/dup@1.0.0", "main", assetID),
	}

	var saved []models.LicenseRisk
	licenseRiskRepository.EXPECT().SaveBatch(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ shared.DB, ts []models.LicenseRisk) {
			saved = ts
		}).
		Return(nil)
	vulnEventRepository.EXPECT().SaveBatch(mock.Anything, mock.Anything, mock.Anything).Return(nil)

	err := s.UserFixedLicenseRisks(context.Background(), nil, "system", nil, risks)
	assert.NoError(t, err)

	// only one row reaches the batch, so Postgres never sees the duplicate id
	assert.Len(t, saved, 1)
}
