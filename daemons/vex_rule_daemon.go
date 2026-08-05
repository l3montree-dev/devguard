package daemons

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/pkg/errors"
)

func (runner *DaemonRunner) ingestVEXRules(ctx context.Context, tx shared.DB, assetsByID map[uuid.UUID]models.Asset, rulesByAssetID map[uuid.UUID][]models.VEXRule) error {
	assetIDs := make([]uuid.UUID, 0, len(rulesByAssetID))
	var newRules []models.VEXRule
	for assetID, rules := range rulesByAssetID {
		if len(rules) == 0 {
			continue
		}
		services.SetVEXRulesEnabledFromParanoidMode(rules, assetsByID[assetID].ParanoidMode)
		assetIDs = append(assetIDs, assetID)
		newRules = append(newRules, rules...)
	}
	if len(assetIDs) == 0 {
		return nil
	}

	existingRules, err := runner.vexRuleRepository.FindByAssetIDs(ctx, tx, assetIDs)
	if err != nil {
		return errors.Wrap(err, "failed to fetch existing VEX rules")
	}

	newByGroup := services.GroupRulesByAssetAndSource(newRules)
	existingByGroup := services.GroupRulesByAssetAndSource(existingRules)

	var rulesToAdd, rulesToRemove []models.VEXRule
	for key, group := range newByGroup {
		add, remove := services.DiffVEXRulesForSource(group, existingByGroup[key])
		rulesToAdd = append(rulesToAdd, add...)
		rulesToRemove = append(rulesToRemove, remove...)
	}

	if len(rulesToRemove) > 0 {
		if err := runner.vexRuleRepository.DeleteBatch(ctx, tx, rulesToRemove); err != nil {
			return errors.Wrap(err, "failed to remove old VEX rules")
		}
	}

	if len(rulesToAdd) == 0 {
		return nil
	}

	return errors.Wrap(runner.vexRuleRepository.UpsertBatch(ctx, tx, rulesToAdd), "failed to add new VEX rules")
}
