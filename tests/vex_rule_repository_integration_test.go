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

package tests

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func TestVexRuleRepositoryFindOpenVexRulesByAssetIDs(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, _, asset, _ := CreateOrgProjectAndAssetAssetVersion(db)
	repo := repositories.NewVEXRuleRepository(db)
	ctx := context.Background()

	newRule := func(eventType dtos.VulnEventType) models.VEXRule {
		rule := models.VEXRule{
			AssetID:     asset.ID,
			CreatedByID: "test-user",
			UpstreamVEXRule: models.UpstreamVEXRule{
				VexSource:     "test-source",
				Title:         "Test Rule",
				Justification: "test justification",
				EventType:     eventType,
			},
		}
		rule.SetCELExpression(`vuln.cveId == "CVE-2025-0000" && ` + string(eventType))
		require.NoError(t, db.Create(&rule).Error)
		return rule
	}

	accepted := newRule(dtos.EventTypeAccepted)
	falsePositive := newRule(dtos.EventTypeFalsePositive)
	reopened := newRule(dtos.EventTypeReopened)

	rules, err := repo.FindOpenVexRulesByAssetIDs(ctx, nil, []uuid.UUID{asset.ID})
	require.NoError(t, err)

	gotIDs := make([]string, 0, len(rules))
	for _, r := range rules {
		gotIDs = append(gotIDs, r.ID)
	}

	assert.Contains(t, gotIDs, accepted.ID)
	assert.Contains(t, gotIDs, falsePositive.ID)
	assert.NotContains(t, gotIDs, reopened.ID)
}
