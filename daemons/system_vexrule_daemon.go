package daemons

import (
	"context"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
)

func (runner *DaemonRunner) ApplySystemVEXRules(ctx context.Context) error {
	tx := runner.systemVEXRuleRepository.GetDB(ctx, nil)
	var err error
	var assetVersions []models.AssetVersion
	var systemVEXRules []models.SystemVEXRule
	// Gather all AssetVersions
	// Check paranoid mode or settings if auto apply is enabled (can be found in asset)
	// Add application setting in asset model
	// Change application setting when paranoid mode is changed
	assetVersions, err = runner.assetVersionRepository.FindSystemVEXRuleApplicableAssetVersions(ctx, tx)
	if err != nil {
		slog.Error("failed to fetch assetVersions from database", "error", err)
		return err
	}

	if len(assetVersions) < 1 {
		slog.Info("No assetversions in database yet, skipping SystemVEXRule application")
		return nil
	}
	// Gather all system vexrules
	systemVEXRules, err = runner.systemVEXRuleRepository.All(ctx, tx)
	if err != nil {
		slog.Error("failed to fetch systemVEXRules from database", "error", err)
		return err
	}

	if len(systemVEXRules) < 1 {
		slog.Info("No SystemVEXRules in database yet, skipping SystemVEXRule application")
		return nil
	}
	// Create VexRules from all AssetVersions and System vexrules
	var applicableRules []models.VEXRule
	for _, assetVersion := range assetVersions {
		for _, systemVEXRule := range systemVEXRules {
			// This VEXRule is only created temporarily for the execution of the daemon, because
			// storing the VEXRule would interfere with the crowdsourced vexing
			rule := models.VEXRule{
				AssetID:                 assetVersion.Asset.ID,
				AssetVersionName:        assetVersion.Name,
				CVEID:                   systemVEXRule.CVEID,
				VexSource:               systemVEXRule.VexSource,
				Asset:                   assetVersion.Asset,
				CVE:                     systemVEXRule.CVE,
				AssetVersion:            assetVersion,
				Justification:           systemVEXRule.Justification,
				EventType:               systemVEXRule.EventType,
				PathPattern:             systemVEXRule.PathPattern,
				MechanicalJustification: systemVEXRule.MechanicalJustification,
				CreatedByID:             "system",
				Enabled:                 true,
			}
			rule.SetPathPattern(systemVEXRule.PathPattern)
			applicableRules = append(applicableRules, rule)
		}
	}
	// ApplyRulesToExistingVulns()
	_, err = runner.vexRuleService.ApplyRulesToExistingVulns(ctx, tx, applicableRules)
	if err != nil {
		slog.Error("failed to apply system VEX rules", "error", err)
		return err
	}
	return nil
}
