package daemons

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/crowdsourcevexing"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/pkg/errors"
)

const vexRuleRecommendationLastRunKey = "vexrules.recommendations.lastRun"

func (runner *DaemonRunner) RunVEXRuleRecommendationDaemon(ctx context.Context) error {
	runStart := time.Now()
	lastRun, err := getLastMirrorTime(ctx, runner.configService, vexRuleRecommendationLastRunKey)
	if err != nil {
		return err
	}

	err = runner.db.WithContext(ctx).Transaction(func(tx shared.DB) error {
		// first we delete unusable vex rule recommendations to reduce the amount of work
		if err := tx.Exec(`
			DELETE FROM vex_rule_recommendations r
			WHERE NOT EXISTS (SELECT 1 FROM dependency_vulns dv WHERE dv.signature = r.dependency_vuln_signature AND dv.state = 'open')
		`).Error; err != nil {
			return errors.Wrap(err, "failed to clean up stale VEX rule recommendations")
		} // combine these 2 statements
		if err := tx.Exec(`DELETE FROM vex_rule_recommendations WHERE vex_rule_id IS NOT NULL`).Error; err != nil {
			return errors.Wrap(err, "failed to clear crowdsourced VEX rule recommendations")
		} // why delete crowdsourced rules?

		start := time.Now()
		if err := runner.matchScopedUpstreamRules(ctx, tx, lastRun); err != nil {
			return err
		}
		slog.Info("vex rule recommendation daemon: matched upstream rules", "duration", time.Since(start))

		start = time.Now()
		matchedVEXRules, softMatchedSignatures, err := runner.softMatchCrowdsourcedRules(ctx, tx)
		if err != nil {
			return err
		}
		slog.Info("vex rule recommendation daemon: soft-matched crowdsourced rules", "duration", time.Since(start), "matchedRules", len(matchedVEXRules), "softMatchedSignatures", len(softMatchedSignatures))

		start = time.Now()
		if err := runner.confirmCrowdsourcedRecommendations(ctx, tx, matchedVEXRules, softMatchedSignatures); err != nil {
			return err
		}
		slog.Info("vex rule recommendation daemon: confirmed crowdsourced recommendations", "duration", time.Since(start))
		return nil
	})
	if err != nil {
		return err
	}

	return runner.configService.SetJSONConfig(ctx, vexRuleRecommendationLastRunKey, struct {
		Time time.Time `json:"time"`
	}{Time: runStart})
}

// matchScopedUpstreamRules joins dependency_vulns to upstream_vex_rules on
// cve_scope = cve_id, restricted to (dv.created_at > lastRun OR r.created_at
// > lastRun) so an old rule against an old vuln - already evaluated together
// in a prior run, neither side changed - isn't re-evaluated.
func (runner *DaemonRunner) matchScopedUpstreamRules(ctx context.Context, tx shared.DB, lastRun time.Time) error {
	rows, err := tx.Raw(`
		SELECT DISTINCT dv.signature, r.id AS rule_id
		FROM dependency_vulns dv
		JOIN upstream_vex_rules r ON r.cve_scope = dv.cve_id
		WHERE dv.state = ? AND (dv.created_at > ? OR r.created_at > ?)
	`, dtos.VulnStateOpen, lastRun, lastRun).Rows()
	if err != nil {
		return errors.Wrap(err, "failed to query scoped VEX rule candidates")
	}

	ruleIDsBySignature := make(map[int64][]string)
	for rows.Next() {
		var signature int64
		var ruleID string
		if err := rows.Scan(&signature, &ruleID); err != nil {
			rows.Close()
			return errors.Wrap(err, "failed to scan scoped VEX rule candidate row")
		}
		ruleIDsBySignature[signature] = append(ruleIDsBySignature[signature], ruleID)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return errors.Wrap(rowsErr, "failed to iterate scoped VEX rule candidates")
	}

	const batchThreshold = 2_000
	batch := make(map[int64][]string, batchThreshold)
	for signature, ruleIDs := range ruleIDsBySignature {
		batch[signature] = ruleIDs
		if len(batch) >= batchThreshold {
			if err := runner.evalScopedUpstreamCandidates(ctx, tx, batch); err != nil {
				return err
			}
			batch = make(map[int64][]string, batchThreshold)
		}
	}
	if len(batch) > 0 {
		if err := runner.evalScopedUpstreamCandidates(ctx, tx, batch); err != nil {
			return err
		}
	}

	return nil
}

// evalScopedUpstreamCandidates fetches the representative vulns and rules for
// one flushed batch from matchScopedUpstreamRules, evaluates each rule's full
// CEL expression against its candidate vulns, and saves whatever matches.
func (runner *DaemonRunner) evalScopedUpstreamCandidates(ctx context.Context, tx shared.DB, ruleIDsBySignature map[int64][]string) error {
	ruleIDSet := make(map[string]struct{})
	for _, ids := range ruleIDsBySignature {
		for _, id := range ids {
			ruleIDSet[id] = struct{}{}
		}
	}

	representativeVulns, err := runner.dependencyVulnRepository.GetOpenVulnsDistinctBySignatureIn(ctx, tx, utils.Keys(ruleIDsBySignature))
	if err != nil {
		return errors.Wrap(err, "failed to fetch representative vulns for scoped VEX rule candidates")
	}
	if len(representativeVulns) == 0 {
		return nil
	}

	var rules []models.UpstreamVEXRule
	if err := runner.upstreamVEXRuleRepository.GetDB(ctx, tx).Where("id = ANY ?", utils.Keys(ruleIDSet)).Find(&rules).Error; err != nil {
		return errors.Wrap(err, "failed to fetch scoped VEX rule candidates")
	}

	vulnsMaps, err := vexrules.PrepareVulnsForEvalMap(ctx, representativeVulns)
	if err != nil {
		return errors.Wrap(err, "failed to prepare representative vulns for evaluation")
	}

	compiled, err := vexrules.CompileRules(ctx, rules)
	if err != nil {
		return errors.Wrap(err, "failed to compile scoped VEX rule candidates")
	}

	recommendations, err := vexrules.EvalCompiledRules(ctx, compiled, utils.Values(vulnsMaps))
	if err != nil {
		return errors.Wrap(err, "failed to evaluate scoped VEX rule candidates")
	}

	recModels := make([]models.VEXRuleRecommendation, 0, len(recommendations))
	for vulnID, ruleIDs := range recommendations {
		recModels = append(recModels, models.VEXRuleRecommendation{
			UpstreamVEXRuleID:       new(ruleIDs[0]),
			DependencyVulnSignature: int64(vulnsMaps[vulnID]["signature"].(float64)),
		})
	}

	return runner.vexRuleRecommendationRepository.SaveBatchBestEffort(ctx, tx, recModels)
}

// softMatchCrowdsourcedRules matches crowdsourced VEX rules against
// artifact-less representative vulns (see PathPattern.SoftMatches /
// SoftMatchCelEnv): a "no match" here is certain, a "match" only a candidate
// to confirm once real artifacts are loaded. Returns the full models.VEXRule
// for rules that matched at least once, since the confirm phase needs to
// recompile them against the strict CelEnv and CrowdsourcedVexing needs
// their Asset/CreatedAt.
func (runner *DaemonRunner) softMatchCrowdsourcedRules(ctx context.Context, tx shared.DB) (map[string]models.VEXRule, map[int64]struct{}, error) {
	matchedVEXRules := make(map[string]models.VEXRule)
	softMatchedSignatures := make(map[int64]struct{})

	var allRules []models.VEXRule
	if err := runner.vexRuleRepository.GetDB(ctx, tx).Where("event_type != ? AND cve_scope IS NOT NULL", dtos.EventTypeReopened).Find(&allRules).Error; err != nil {
		return nil, nil, errors.Wrap(err, "failed to fetch crowdsourced VEX rules")
	}
	if len(allRules) == 0 {
		return matchedVEXRules, softMatchedSignatures, nil
	}

	rulesByID := make(map[string]models.VEXRule, len(allRules))
	for _, rule := range allRules {
		rulesByID[rule.ID] = rule
	}

	// vex_rules is small (a few thousand rows at most) - compiling and
	// evaluating against the full set here, relying on EvalCompiledRules to
	// narrow each scoped rule to just the vulns sharing its CVE, is cheaper
	// than a separate join-based candidate-finding pass would be; that only
	// pays off for upstream_vex_rules, which is orders of magnitude bigger.
	compiled, err := vexrules.CompileRulesForSoftMatching(ctx, utils.Map(allRules, func(r models.VEXRule) models.UpstreamVEXRule {
		return r.UpstreamVEXRule
	}))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to compile VEX rules for crowdsourced vexing")
	}

	for representativeVulns, err := range runner.dependencyVulnRepository.GetOpenVulnsDistinctBySignatureWithoutUpstreamRecommendation(ctx, tx, 10_000) {
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to fetch distinct representative vulns")
		}

		vulnsMaps, err := vexrules.PrepareVulnsForEvalMap(ctx, representativeVulns)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to prepare representative vulns for evaluation")
		}

		matches, err := vexrules.EvalCompiledRules(ctx, compiled, utils.Values(vulnsMaps))
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to soft-match VEX rules for crowdsourced vexing")
		}

		for vulnID, ruleIDs := range matches {
			softMatchedSignatures[int64(vulnsMaps[vulnID]["signature"].(float64))] = struct{}{}
			for _, ruleID := range ruleIDs {
				matchedVEXRules[ruleID] = rulesByID[ruleID]
			}
		}
	}

	return matchedVEXRules, softMatchedSignatures, nil
}

// confirmCrowdsourcedRecommendations loads the real, artifact-aware vulns for
// every soft-matched signature and runs them through crowdsourced vexing
// against the soft-matched rules, recompiled against the strict CelEnv.
func (runner *DaemonRunner) confirmCrowdsourcedRecommendations(ctx context.Context, tx shared.DB, matchedVEXRules map[string]models.VEXRule, softMatchedSignatures map[int64]struct{}) error {
	// matchedVEXRules' Asset isn't preloaded during soft-matching (most rules
	// never match, so preloading Asset for every rule there would be wasted
	// work) - only the ones that did match need it, for the org/project
	// lookups CrowdsourcedVexing does.
	var rulesWithAsset []models.VEXRule
	if err := runner.vexRuleRepository.GetDB(ctx, tx).Preload("Asset").Where("id = ANY ?", utils.Keys(matchedVEXRules)).Find(&rulesWithAsset).Error; err != nil {
		return errors.Wrap(err, "failed to load assets for soft-matched VEX rules")
	}
	for _, rule := range rulesWithAsset {
		matchedVEXRules[rule.ID] = rule
	}

	crowdsourcedCtx, err := runner.buildCrowdsourcedVexingContext(ctx, tx, utils.Values(matchedVEXRules))
	if err != nil {
		return errors.Wrap(err, "failed to build crowdsourced vexing context")
	}
	createdRecommendationsCount := 0

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
		createdRecommendationsCount += len(recModels)
	}

	slog.Info("created recommendations", "count", createdRecommendationsCount)

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
