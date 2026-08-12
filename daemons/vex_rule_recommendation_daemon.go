package daemons

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
)

func (runner *DaemonRunner) RunVEXRuleRecommendationDaemon(ctx context.Context) error {
	ctx, span := daemonTracer.Start(ctx, "daemon.vex-rule-recommendation")
	defer span.End()

	slog.Info("running vex rule recommendation daemon", "traceID", span.SpanContext().TraceID().String())

	err := runner.db.WithContext(ctx).Transaction(func(tx shared.DB) error {

		t := time.Now()
		fetchRulesCtx, fetchRulesSpan := daemonTracer.Start(ctx, "daemon.vex-rule-recommendation.fetch-rules")
		allRules, err := runner.vexRuleRepository.All(fetchRulesCtx, tx)
		if err != nil {
			return utils.EndSpanWithError(fetchRulesSpan, errors.Wrap(err, "failed to fetch all VEX rules"))
		}
		fetchRulesSpan.SetAttributes(attribute.Int("rules.count", len(allRules)))
		fetchRulesSpan.End()
		slog.Info("step: fetch-rules", "count", len(allRules), "took", time.Since(t))
		t = time.Now()
		buildCtxCtx, buildCtxSpan := daemonTracer.Start(ctx, "daemon.vex-rule-recommendation.build-crowdsourced-context")

		// we cannot batch anything related to rules since we need them to build the crowdsourced context
		// we can only batch over dependency vulns.
		crowdsourcedCtx, err := runner.buildCrowdsourcedVexingContext(buildCtxCtx, tx, allRules)
		if err != nil {
			return utils.EndSpanWithError(buildCtxSpan, errors.Wrap(err, "failed to build crowdsourced vexing context"))
		}
		buildCtxSpan.End()
		slog.Info("step: build-crowdsourced-context", "took", time.Since(t))

		t = time.Now()
		deleteCtx, deleteSpan := daemonTracer.Start(ctx, "daemon.vex-rule-recommendation.delete-all")
		if err := runner.vexRuleRecommendationRepository.DeleteAll(deleteCtx, tx); err != nil {
			return utils.EndSpanWithError(deleteSpan, errors.Wrap(err, "failed to delete all VEX rule recommendations"))
		}
		deleteSpan.End()
		slog.Info("step: delete-all", "took", time.Since(t))

		fetchVulnsCtx, fetchVulnsSpan := daemonTracer.Start(ctx, "daemon.vex-rule-recommendation.fetch-vulns")
		defer fetchVulnsSpan.End()
		for allVulns, err := range runner.dependencyVulnRepository.GetAllOpenVulnsByAssetIDs(fetchVulnsCtx, tx, nil, 10_000) {
			if err != nil {
				return utils.EndSpanWithError(fetchVulnsSpan, errors.Wrap(err, "failed to fetch all open vulns"))
			}
			fetchVulnsSpan.SetAttributes(attribute.Int("vulns.count", len(allVulns)))
			slog.Info("step: fetch-vulns", "count", len(allVulns), "took", time.Since(t))

			t = time.Now()
			fetchUpstreamCtx, fetchUpstreamSpan := daemonTracer.Start(ctx, "daemon.vex-rule-recommendation.fetch-upstream-rules")
			upstreamRules, err := runner.upstreamVEXRuleRepository.All(fetchUpstreamCtx, tx)
			if err != nil {
				return utils.EndSpanWithError(fetchUpstreamSpan, errors.Wrap(err, "failed to fetch all upstream VEX rules"))
			}
			fetchUpstreamSpan.SetAttributes(attribute.Int("upstream_rules.count", len(upstreamRules)))
			fetchUpstreamSpan.End()
			slog.Info("step: fetch-upstream-rules", "count", len(upstreamRules), "took", time.Since(t))

			t = time.Now()
			computeCtx, computeSpan := daemonTracer.Start(ctx, "daemon.vex-rule-recommendation.compute")
			ruleRecommendations, err := services.ComputeVEXRuleRecommendations(computeCtx, allVulns, allRules, upstreamRules, crowdsourcedCtx)
			if err != nil {
				return utils.EndSpanWithError(computeSpan, errors.Wrap(err, "failed to compute VEX rule recommendations"))
			}
			computeSpan.SetAttributes(attribute.Int("recommendations.count", len(ruleRecommendations)))
			computeSpan.End()
			slog.Info("step: compute", "count", len(ruleRecommendations), "took", time.Since(t))

			span.SetAttributes(
				attribute.Int("vulns.count", len(allVulns)),
				attribute.Int("recommendations.count", len(ruleRecommendations)),
			)
			slog.Info("finished rule recommendation calculation", "amount", len(ruleRecommendations), "traceID", span.SpanContext().TraceID().String())

			t = time.Now()
			saveCtx, saveSpan := daemonTracer.Start(ctx, "daemon.vex-rule-recommendation.save-batch")
			if err := runner.vexRuleRecommendationRepository.SaveBatchBestEffort(saveCtx, tx, ruleRecommendations); err != nil {
				return utils.EndSpanWithError(saveSpan, errors.Wrap(err, "failed to save VEX rule recommendations"))
			}
			saveSpan.End()
			slog.Info("step: save-batch", "took", time.Since(t))
		}
		return nil
	})

	if err != nil {
		utils.RecordSpanError(span, err)
	}

	return err
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
