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
	"context"
	"fmt"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
)

func ingestVEXRules(
	ctx context.Context,
	tx shared.DB,
	vexRuleRepository shared.VEXRuleRepository,
	dependencyVulnRepository shared.DependencyVulnRepository,
	vulnEventRepository shared.VulnEventRepository,
	asset models.Asset,
	rules []models.VEXRule,
) error {
	if len(rules) == 0 {
		return nil
	}

	services.SetVEXRulesEnabledFromParanoidMode(rules, asset.ParanoidMode)

	existingRules, err := vexRuleRepository.FindByAssetID(ctx, tx, asset.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch existing VEX rules: %w", err)
	}

	rulesToAdd, rulesToRemove := services.DiffVEXRules(rules, existingRules)

	if len(rulesToRemove) > 0 {
		if err := vexRuleRepository.DeleteBatch(ctx, tx, rulesToRemove); err != nil {
			return fmt.Errorf("failed to remove old VEX rules: %w", err)
		}
	}

	if len(rulesToAdd) == 0 {
		return nil
	}

	if err := vexRuleRepository.UpsertBatch(ctx, tx, rulesToAdd); err != nil {
		return fmt.Errorf("failed to add new VEX rules: %w", err)
	}

	var vulns []models.DependencyVuln
	for batch, err := range dependencyVulnRepository.GetAllOpenVulnsByAssetID(ctx, tx, asset.ID, 1000) {
		if err != nil {
			return fmt.Errorf("failed to fetch existing vulns for asset: %w", err)
		}
		vulns = append(vulns, batch...)
	}

	updatedVulns, events, err := services.ApplyVEXRulesToVulns(ctx, rulesToAdd, vulns)
	if err != nil {
		return fmt.Errorf("failed to apply VEX rules to vulns: %w", err)
	}
	if len(updatedVulns) == 0 {
		return nil
	}

	if err := dependencyVulnRepository.SaveBatch(ctx, tx, updatedVulns); err != nil {
		return fmt.Errorf("failed to save updated vulns: %w", err)
	}
	if err := vulnEventRepository.SaveBatch(ctx, tx, events); err != nil {
		return fmt.Errorf("failed to save events: %w", err)
	}

	return nil
}
