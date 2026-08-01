package daemons

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
)

func (runner *DaemonRunner) RunVEXRuleRecommendationDaemon(ctx context.Context) error {
	return runner.db.WithContext(ctx).Transaction(func(tx shared.DB) error {
		allVulns, err := runner.dependencyVulnRepository.GetAllOpenVulnsWithoutEvents(ctx, tx)
		if err != nil {
			return errors.Wrap(err, "failed to fetch all open vulns")
		}

		allRules, err := runner.vexRuleRepository.All(ctx, tx)
		if err != nil {
			return errors.Wrap(err, "failed to fetch all VEX rules")
		}

		upstreamRules, err := runner.upstreamVEXRuleRepository.All(ctx, tx)
		if err != nil {
			return errors.Wrap(err, "failed to fetch all upstream VEX rules")
		}

		crowdsourcedCtx, err := runner.buildCrowdsourcedVexingContext(ctx, tx, allRules)
		if err != nil {
			return errors.Wrap(err, "failed to build crowdsourced vexing context")
		}

		ruleRecommendations, err := services.ComputeVEXRuleRecommendations(ctx, allVulns, allRules, upstreamRules, crowdsourcedCtx)
		if err != nil {
			return errors.Wrap(err, "failed to compute VEX rule recommendations")
		}

		if err := runner.vexRuleRecommendationRepository.DeleteAll(ctx, tx); err != nil {
			return errors.Wrap(err, "failed to delete all VEX rule recommendations")
		}

		return errors.Wrap(runner.vexRuleRecommendationRepository.CreateBatch(ctx, tx, ruleRecommendations), "failed to save VEX rule recommendations")
	})
}

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

	if err := runner.vexRuleRepository.UpsertBatch(ctx, tx, rulesToAdd); err != nil {
		return errors.Wrap(err, "failed to add new VEX rules")
	}

	vulns, err := runner.dependencyVulnRepository.GetAllOpenVulnsByAssetIDs(ctx, tx, assetIDs)
	if err != nil {
		return errors.Wrap(err, "failed to fetch existing vulns for assets")
	}
	vulnsByAsset := make(map[uuid.UUID][]models.DependencyVuln, len(assetIDs))
	for _, v := range vulns {
		vulnsByAsset[v.AssetID] = append(vulnsByAsset[v.AssetID], v)
	}
	addedByAsset := make(map[uuid.UUID][]models.VEXRule, len(assetIDs))
	for _, r := range rulesToAdd {
		addedByAsset[r.AssetID] = append(addedByAsset[r.AssetID], r)
	}

	var updatedVulns []models.DependencyVuln
	var events []models.VulnEvent
	for assetID, rules := range addedByAsset {
		assetUpdatedVulns, assetEvents := services.ApplyVEXRulesToVulns(ctx, rules, vulnsByAsset[assetID])
		updatedVulns = append(updatedVulns, assetUpdatedVulns...)
		events = append(events, assetEvents...)
	}
	if len(updatedVulns) == 0 {
		return nil
	}

	if err := runner.dependencyVulnRepository.SaveBatchBestEffort(ctx, tx, updatedVulns); err != nil {
		return errors.Wrap(err, "failed to save updated vulns")
	}
	return errors.Wrap(runner.vulnEventRepository.SaveBatchBestEffort(ctx, tx, events), "failed to save events")
}

func (runner *DaemonRunner) buildCrowdsourcedVexingContext(ctx context.Context, tx shared.DB, vexRules []models.VEXRule) (services.CrowdsourcedVexingContext, error) {
	projectIDs := utils.Map(vexRules, func(r models.VEXRule) uuid.UUID { return r.Asset.ProjectID })

	projects, err := runner.projectRepository.GetByProjectIDs(ctx, tx, projectIDs)
	if err != nil {
		return services.CrowdsourcedVexingContext{}, err
	}

	orgIDs := utils.Map(projects, func(p models.Project) uuid.UUID { return p.OrganizationID })

	orgs, err := runner.orgRepository.GetOrgByIDs(ctx, tx, orgIDs)
	if err != nil {
		return services.CrowdsourcedVexingContext{}, err
	}

	projectTrustedEntities, err := runner.trustedEntityRepository.GetTrustedEntitiesByProjectIDs(ctx, tx, projectIDs)
	if err != nil {
		return services.CrowdsourcedVexingContext{}, err
	}
	projectTrustScores := trustScoreMap(projectTrustedEntities, func(te models.TrustedEntity) uuid.UUID { return *te.ProjectID })

	orgTrustedEntities, err := runner.trustedEntityRepository.GetTrustedEntitiesByOrganizationIDs(ctx, tx, orgIDs)
	if err != nil {
		return services.CrowdsourcedVexingContext{}, err
	}
	orgTrustScores := trustScoreMap(orgTrustedEntities, func(te models.TrustedEntity) uuid.UUID { return *te.OrganizationID })

	orgRBACData := make([]services.OrgRBACData, len(orgs))
	eg := utils.ErrGroup[struct{}](8)
	for i, org := range orgs {
		i, org := i, org
		eg.Go(func() (struct{}, error) {
			domainRBAC := runner.rbacProvider.GetDomainRBAC(org.ID.String())
			memberIDs, err := domainRBAC.GetAllMembersOfOrganization()
			if err != nil {
				return struct{}{}, err
			}
			ownerID, err := domainRBAC.GetOwnerOfOrganization()
			if err != nil {
				return struct{}{}, err
			}
			orgRBACData[i] = services.OrgRBACData{OrgID: org.ID, OwnerID: ownerID, MemberIDs: memberIDs}
			return struct{}{}, nil
		})
	}
	if _, err := eg.WaitAndCollect(); err != nil {
		return services.CrowdsourcedVexingContext{}, err
	}

	return services.BuildCrowdsourcedVexingContext(vexRules, projects, orgs, projectTrustScores, orgTrustScores, orgRBACData), nil
}

func trustScoreMap(entities []models.TrustedEntity, key func(models.TrustedEntity) uuid.UUID) map[uuid.UUID]float64 {
	scores := make(map[uuid.UUID]float64, len(entities))
	for _, te := range entities {
		scores[key(te)] = te.TrustScore
	}
	return scores
}
