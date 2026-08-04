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

package controllers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/assert"
)

func TestVexRuleRecommendationDedupKey(t *testing.T) {
	t.Run("returns the VEXRuleID when set", func(t *testing.T) {
		id := "vex-rule-1"
		key, ok := vexRuleRecommendationDedupKey(models.VEXRuleRecommendation{VEXRuleID: &id})
		assert.True(t, ok)
		assert.Equal(t, "vex-rule-1", key)
	})

	t.Run("returns the UpstreamVEXRuleID when VEXRuleID is unset", func(t *testing.T) {
		id := "upstream-rule-1"
		key, ok := vexRuleRecommendationDedupKey(models.VEXRuleRecommendation{UpstreamVEXRuleID: &id})
		assert.True(t, ok)
		assert.Equal(t, "upstream-rule-1", key)
	})

	t.Run("prefers VEXRuleID over UpstreamVEXRuleID when both are set", func(t *testing.T) {
		vexID := "vex-rule-1"
		upstreamID := "upstream-rule-1"
		key, ok := vexRuleRecommendationDedupKey(models.VEXRuleRecommendation{VEXRuleID: &vexID, UpstreamVEXRuleID: &upstreamID})
		assert.True(t, ok)
		assert.Equal(t, "vex-rule-1", key)
	})

	t.Run("returns false when neither ID is set", func(t *testing.T) {
		_, ok := vexRuleRecommendationDedupKey(models.VEXRuleRecommendation{})
		assert.False(t, ok)
	})
}

func TestBuildDedupedVexRuleRecommendations(t *testing.T) {
	t.Run("deduplicates stored recommendations matching the same VEX rule", func(t *testing.T) {
		vulnA, vulnB := uuid.New(), uuid.New()
		ruleID := "vex-rule-1"

		storedRecommendations := map[uuid.UUID]models.VEXRuleRecommendation{
			vulnA: {DependencyVulnID: vulnA, VEXRuleID: &ruleID, VEXRule: models.VEXRule{UpstreamVEXRule: models.UpstreamVEXRule{ID: ruleID, Title: "rule 1"}}},
			vulnB: {DependencyVulnID: vulnB, VEXRuleID: &ruleID, VEXRule: models.VEXRule{UpstreamVEXRule: models.UpstreamVEXRule{ID: ruleID, Title: "rule 1"}}},
		}

		recommendations := buildDedupedVexRuleRecommendations(nil, storedRecommendations, nil)

		assert.Len(t, recommendations, 1)
	})

	t.Run("deduplicates a session rule matched by multiple vulns into a single entry", func(t *testing.T) {
		vulnA, vulnB := uuid.New(), uuid.New()
		assetID := uuid.New()
		rule := models.VEXRule{AssetID: assetID, UpstreamVEXRule: models.UpstreamVEXRule{ID: "vex-rule-1", Title: "rule 1"}}

		matchingSessionRules := map[uuid.UUID][]models.VEXRule{
			vulnA: {rule},
			vulnB: {rule},
		}
		assetsByID := map[uuid.UUID]models.Asset{
			assetID: {Slug: "asset-1", Project: models.Project{Slug: "project-1"}},
		}

		recommendations := buildDedupedVexRuleRecommendations(matchingSessionRules, nil, assetsByID)

		assert.Len(t, recommendations, 1)
	})

	t.Run("keeps every distinct session rule matched by the same vuln", func(t *testing.T) {
		vulnA := uuid.New()
		assetID := uuid.New()

		matchingSessionRules := map[uuid.UUID][]models.VEXRule{
			vulnA: {
				{AssetID: assetID, UpstreamVEXRule: models.UpstreamVEXRule{ID: "session-rule-1", Title: "rule 1"}},
				{AssetID: assetID, UpstreamVEXRule: models.UpstreamVEXRule{ID: "session-rule-2", Title: "rule 2"}},
			},
		}
		assetsByID := map[uuid.UUID]models.Asset{
			assetID: {Slug: "asset-1", Project: models.Project{Slug: "project-1"}},
		}

		recommendations := buildDedupedVexRuleRecommendations(matchingSessionRules, nil, assetsByID)

		assert.Len(t, recommendations, 2)
	})

	t.Run("keeps session rules and stored recommendations separate when they reference different rules", func(t *testing.T) {
		vulnA, vulnB := uuid.New(), uuid.New()
		assetID := uuid.New()
		storedRuleID := "stored-rule-1"

		matchingSessionRules := map[uuid.UUID][]models.VEXRule{
			vulnA: {{AssetID: assetID, UpstreamVEXRule: models.UpstreamVEXRule{ID: "session-rule-1", Title: "session rule"}}},
		}
		storedRecommendations := map[uuid.UUID]models.VEXRuleRecommendation{
			vulnB: {DependencyVulnID: vulnB, VEXRuleID: &storedRuleID, VEXRule: models.VEXRule{UpstreamVEXRule: models.UpstreamVEXRule{ID: storedRuleID, Title: "stored rule"}}},
		}
		assetsByID := map[uuid.UUID]models.Asset{
			assetID: {Slug: "asset-1", Project: models.Project{Slug: "project-1"}},
		}

		recommendations := buildDedupedVexRuleRecommendations(matchingSessionRules, storedRecommendations, assetsByID)

		assert.Len(t, recommendations, 2)
	})

	t.Run("a stored recommendation and a session rule for the same rule ID collapse into one entry", func(t *testing.T) {
		vulnA, vulnB := uuid.New(), uuid.New()
		assetID := uuid.New()
		ruleID := "vex-rule-1"

		matchingSessionRules := map[uuid.UUID][]models.VEXRule{
			vulnA: {{AssetID: assetID, UpstreamVEXRule: models.UpstreamVEXRule{ID: ruleID, Title: "session rule"}}},
		}
		storedRecommendations := map[uuid.UUID]models.VEXRuleRecommendation{
			vulnB: {DependencyVulnID: vulnB, VEXRuleID: &ruleID, VEXRule: models.VEXRule{UpstreamVEXRule: models.UpstreamVEXRule{ID: ruleID, Title: "stored rule"}}},
		}
		assetsByID := map[uuid.UUID]models.Asset{
			assetID: {Slug: "asset-1", Project: models.Project{Slug: "project-1"}},
		}

		recommendations := buildDedupedVexRuleRecommendations(matchingSessionRules, storedRecommendations, assetsByID)

		assert.Len(t, recommendations, 1)
	})
}
