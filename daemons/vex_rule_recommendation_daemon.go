package daemons

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/crowdsourcevexing"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

func (runner *DaemonRunner) RunVEXRuleRecommendationDaemon(ctx context.Context) error {
	return runner.db.WithContext(ctx).Transaction(func(tx shared.DB) error {
		// clear the whole table.
		tx.Exec("DELETE FROM vex_rule_recommendations;")

		unmatchedRepresentatives, err := runner.matchUpstreamRules(ctx, tx)
		if err != nil {
			return err
		}

		matchedVEXRules, softMatchedSignatures, err := runner.softMatchCrowdsourcedRules(ctx, tx, unmatchedRepresentatives)
		if err != nil {
			return err
		}

		return runner.confirmCrowdsourcedRecommendations(ctx, tx, matchedVEXRules, softMatchedSignatures)
	})
}

// matchUpstreamRules matches every upstream VEX rule against one
// representative vuln per distinct signature, saving a recommendation for
// each match, and returns the representatives left unmatched.
func (runner *DaemonRunner) matchUpstreamRules(ctx context.Context, tx shared.DB) ([]map[string]any, error) {
	var unmatchedRepresentatives []map[string]any
	for representativeVulns, err := range runner.dependencyVulnRepository.GetAllOpenVulnsDistinctBySignature(ctx, tx, 10_000) {
		if err != nil {
			return nil, errors.Wrap(err, "failed to fetch distinct representative vulns")
		}

		cveIDs := make(map[string][]models.DependencyVuln, len(representativeVulns))
		for _, vuln := range representativeVulns {
			if cveIDs[vuln.CVEID] == nil {
				cveIDs[vuln.CVEID] = make([]models.DependencyVuln, 0)
			}
			cveIDs[vuln.CVEID] = append(cveIDs[vuln.CVEID], vuln)
		}

		vulnsMaps, err := vexrules.PrepareVulnsForEvalMap(ctx, representativeVulns)
		if err != nil {
			return nil, errors.Wrap(err, "failed to prepare representative vulns for evaluation")
		}

		for rules, err := range runner.upstreamVEXRuleRepository.ByCveScopes(ctx, tx, utils.Keys(cveIDs), 10_000) {
			if err != nil {
				return nil, errors.Wrap(err, "failed to fetch upstream rules")
			}

			compiled, err := vexrules.CompileRules(ctx, rules)
			if err != nil {
				return nil, errors.Wrap(err, "failed to compile VEX rules and vulns")
			}

			recommendations, err := vexrules.EvalCompiledRules(ctx, compiled, utils.Values(vulnsMaps))
			if err != nil {
				return nil, errors.Wrap(err, "failed to evaluate VEX rules against representative vulns")
			}
			recModels := make([]models.VEXRuleRecommendation, 0, len(recommendations))
			for vulnID, rules := range recommendations {
				delete(vulnsMaps, vulnID)
				recModels = append(recModels, models.VEXRuleRecommendation{
					UpstreamVEXRuleID:       new(rules[0]),
					DependencyVulnSignature: int64(vulnsMaps[vulnID]["signature"].(float64)),
				})
			}

			if err := runner.vexRuleRecommendationRepository.SaveBatchBestEffort(ctx, tx, recModels); err != nil {
				return nil, errors.Wrap(err, "failed to save VEX rule recommendations")
			}
		}

		for _, vuln := range vulnsMaps {
			unmatchedRepresentatives = append(unmatchedRepresentatives, vuln)
		}
	}
	return unmatchedRepresentatives, nil
}

// softMatchCrowdsourcedRules matches crowdsourced VEX rules against
// artifact-less representative vulns (see PathPattern.SoftMatches /
// SoftMatchCelEnv): a "no match" here is certain, a "match" only a candidate
// to confirm once real artifacts are loaded. Returns the full models.VEXRule
// for rules that matched at least once, since the confirm phase needs to
// recompile them against the strict CelEnv and CrowdsourcedVexing needs
// their Asset/CreatedAt.
func (runner *DaemonRunner) softMatchCrowdsourcedRules(ctx context.Context, tx shared.DB, unmatchedRepresentatives []map[string]any) (map[string]models.VEXRule, map[int64]struct{}, error) {
	representativeByID := make(map[string]map[string]any, len(unmatchedRepresentatives))
	for _, vuln := range unmatchedRepresentatives {
		representativeByID[vuln["id"].(string)] = vuln
	}

	matchedVEXRules := make(map[string]models.VEXRule)
	softMatchedSignatures := make(map[int64]struct{})
	var vexRules []models.VEXRule
	err := runner.vexRuleRepository.GetDB(ctx, tx).FindInBatches(&vexRules, 10_000, func(_ *gorm.DB, _ int) error {
		rulesByID := make(map[string]models.VEXRule, len(vexRules))
		for _, rule := range vexRules {
			rulesByID[rule.ID] = rule
		}

		compiled, err := vexrules.CompileRulesForSoftMatching(ctx, utils.Map(vexRules, func(r models.VEXRule) models.UpstreamVEXRule {
			return r.UpstreamVEXRule
		}))
		if err != nil {
			return errors.Wrap(err, "failed to compile VEX rules for crowdsourced vexing")
		}

		matches, err := vexrules.EvalCompiledRules(ctx, compiled, unmatchedRepresentatives)
		if err != nil {
			return errors.Wrap(err, "failed to soft-match VEX rules for crowdsourced vexing")
		}

		for vulnID, ruleIDs := range matches {
			softMatchedSignatures[int64(representativeByID[vulnID]["signature"].(float64))] = struct{}{}
			for _, ruleID := range ruleIDs {
				matchedVEXRules[ruleID] = rulesByID[ruleID]
			}
		}
		return nil
	}).Error
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to soft-match crowdsourced VEX rules")
	}

	return matchedVEXRules, softMatchedSignatures, nil
}

// confirmCrowdsourcedRecommendations loads the real, artifact-aware vulns for
// every soft-matched signature and runs them through crowdsourced vexing
// against the soft-matched rules, recompiled against the strict CelEnv.
func (runner *DaemonRunner) confirmCrowdsourcedRecommendations(ctx context.Context, tx shared.DB, matchedVEXRules map[string]models.VEXRule, softMatchedSignatures map[int64]struct{}) error {
	crowdsourcedCtx, err := runner.buildCrowdsourcedVexingContext(ctx, tx, utils.Values(matchedVEXRules))
	if err != nil {
		return errors.Wrap(err, "failed to build crowdsourced vexing context")
	}

	compiledMatchedRules, err := vexrules.CompileRules(ctx, utils.Map(utils.Values(matchedVEXRules), func(r models.VEXRule) models.UpstreamVEXRule {
		return r.UpstreamVEXRule
	}))
	if err != nil {
		return errors.Wrap(err, "failed to compile soft-matched VEX rules for crowdsourced vexing")
	}

	for vulns, err := range runner.dependencyVulnRepository.GetOpenVulnsBySignaturesWithoutEvents(ctx, tx, utils.Keys(softMatchedSignatures), 10_000) {
		if err != nil {
			return errors.Wrap(err, "failed to fetch soft-matched vulns for crowdsourced vexing")
		}

		// convert the vulns into a map for easy lookup, keyed by vuln ID
		vulnMaps, err := vexrules.PrepareVulnsForEvalMap(ctx, vulns)
		if err != nil {
			return errors.Wrap(err, "failed to prepare vulns for evaluation")
		}

		matches, err := vexrules.EvalCompiledRules(ctx, compiledMatchedRules, utils.Values(vulnMaps))
		if err != nil {
			return errors.Wrap(err, "failed to evaluate VEX rules for crowdsourced vexing")
		}

		recModels, err := crowdsourcedRecommendationsForVulns(matches, vulnMaps, matchedVEXRules, crowdsourcedCtx)
		if err != nil {
			return err
		}

		if err := runner.vexRuleRecommendationRepository.SaveBatchBestEffort(ctx, tx, recModels); err != nil {
			return errors.Wrap(err, "failed to save crowdsourced VEX rule recommendations")
		}
	}
	return nil
}

// crowdsourcedRecommendationsForVulns runs CrowdsourcedVexing once per vuln
// in matches, picking a single winning rule out of its matching candidates.
// Vulns with no winning rule (ErrNoRecommendation) are silently skipped.
func crowdsourcedRecommendationsForVulns(matches map[string][]string, vulnMaps map[string]map[string]any, matchedVEXRules map[string]models.VEXRule, crowdsourcedCtx services.CrowdsourcedVexingContext) ([]models.VEXRuleRecommendation, error) {
	recModels := make([]models.VEXRuleRecommendation, 0, len(matches))
	for vulnID, ruleIDs := range matches {
		matchingRules := utils.Map(ruleIDs, func(ruleID string) models.VEXRule {
			return matchedVEXRules[ruleID]
		})

		recommendedRule, confidence, votes, err := crowdsourcevexing.CrowdsourcedVexing(
			matchingRules,
			crowdsourcedCtx.CrowdSourceVexingOrgs,
			crowdsourcedCtx.CrowdSourceVexingProj,
			crowdsourcedCtx.Assets,
		)
		if err != nil {
			if errors.Is(err, crowdsourcevexing.ErrNoRecommendation) {
				continue
			}
			return nil, errors.Wrap(err, "failed to compute crowdsourced VEX rule recommendation")
		}

		recModels = append(recModels, models.VEXRuleRecommendation{
			DependencyVulnID:        uuid.MustParse(vulnID),
			VEXRuleID:               new(recommendedRule.ID),
			DependencyVulnSignature: int64(vulnMaps[vulnID]["signature"].(float64)),
			Confidence:              confidence,
			VerifiedVotes:           votes.Verified,
			TotalVotes:              votes.Total,
		})
	}
	return recModels, nil
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
