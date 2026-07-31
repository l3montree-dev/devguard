package services

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/crowdsourcevexing"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vexrules"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type CrowdsourcedVexingService struct {
	vexRuleRepository        shared.VEXRuleRepository
	systemVexRuleRepository  shared.SystemVEXRuleRepository
	organisationRepository   shared.OrganizationRepository
	projectRepository        shared.ProjectRepository
	assetVersionRepository   shared.AssetVersionRepository
	dependencyVulnRepository shared.DependencyVulnRepository
	trustedEntityRepository  shared.TrustedEntityRepository
	rbacProvider             shared.RBACProvider
	vexRuleService           shared.VEXRuleService
	assetRepository          shared.AssetRepository
}

func mapOrg(org models.Org, orgTrustscore float64, ownerID string, organizationMemberIDs []string) crowdsourcevexing.Organization {
	return crowdsourcevexing.Organization{
		ID:         org.ID,
		Trustscore: orgTrustscore,
		CreatedAt:  org.CreatedAt,
		CreatedBy:  ownerID,
		UserIDs:    organizationMemberIDs,
	}
}

func mapProject(project models.Project, projectTrustscore float64) crowdsourcevexing.Project {
	return crowdsourcevexing.Project{
		ID:             project.ID,
		OrganizationID: project.OrganizationID,
		Trustscore:     projectTrustscore,
	}
}

func NewCrowdsourcedVexingService(vexRuleRepository shared.VEXRuleRepository, systemVexRuleRepository shared.SystemVEXRuleRepository, organisationRepository shared.OrganizationRepository, projectRepository shared.ProjectRepository, assetVersionRepository shared.AssetVersionRepository, dependencyVulnRepository shared.DependencyVulnRepository, trustedEntityRepository shared.TrustedEntityRepository, rbacProvider shared.RBACProvider, vexRuleService shared.VEXRuleService, assetRepository shared.AssetRepository) *CrowdsourcedVexingService {
	return &CrowdsourcedVexingService{
		vexRuleRepository:        vexRuleRepository,
		systemVexRuleRepository:  systemVexRuleRepository,
		organisationRepository:   organisationRepository,
		projectRepository:        projectRepository,
		assetVersionRepository:   assetVersionRepository,
		dependencyVulnRepository: dependencyVulnRepository,
		trustedEntityRepository:  trustedEntityRepository,
		rbacProvider:             rbacProvider,
		vexRuleService:           vexRuleService,
		assetRepository:          assetRepository,
	}
}

type crowdsourcedVexingContext struct {
	vexRules              []models.VEXRule
	crowdSourceVexingOrgs []crowdsourcevexing.Organization
	crowdSourceVexingProj []crowdsourcevexing.Project
	assets                []models.Asset
}

func (s *CrowdsourcedVexingService) buildCrowdsourcedVexingContext(ctx context.Context, tx shared.DB, vexRules []models.VEXRule) (crowdsourcedVexingContext, error) {
	projectIDs := utils.Map(vexRules, func(r models.VEXRule) uuid.UUID { return r.Asset.ProjectID })

	projects, err := s.projectRepository.GetByProjectIDs(ctx, tx, projectIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}

	orgIDs := utils.Map(projects, func(p models.Project) uuid.UUID { return p.OrganizationID })

	orgs, err := s.organisationRepository.GetOrgByIDs(ctx, tx, orgIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}

	projectTrustedEntities, err := s.trustedEntityRepository.GetTrustedEntitiesByProjectIDs(ctx, tx, projectIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}
	projectTrustScores := make(map[uuid.UUID]float64, len(projectTrustedEntities))
	for _, te := range projectTrustedEntities {
		projectTrustScores[*te.ProjectID] = te.TrustScore
	}

	orgTrustedEntities, err := s.trustedEntityRepository.GetTrustedEntitiesByOrganizationIDs(ctx, tx, orgIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}
	orgTrustScores := make(map[uuid.UUID]float64, len(orgTrustedEntities))
	for _, te := range orgTrustedEntities {
		orgTrustScores[*te.OrganizationID] = te.TrustScore
	}

	crowdSourceVexingOrgs := make([]crowdsourcevexing.Organization, len(orgs))
	for i, org := range orgs {
		domainRBAC := s.rbacProvider.GetDomainRBAC(org.ID.String())
		memberIDs, err := domainRBAC.GetAllMembersOfOrganization()
		if err != nil {
			return crowdsourcedVexingContext{}, err
		}
		ownerID, err := domainRBAC.GetOwnerOfOrganization()
		if err != nil {
			return crowdsourcedVexingContext{}, err
		}
		crowdSourceVexingOrgs[i] = mapOrg(org, orgTrustScores[org.ID], ownerID, memberIDs)
	}

	return crowdsourcedVexingContext{
		vexRules:              vexRules,
		crowdSourceVexingOrgs: crowdSourceVexingOrgs,
		crowdSourceVexingProj: utils.Map(projects, func(p models.Project) crowdsourcevexing.Project {
			return mapProject(p, projectTrustScores[p.ID])
		}),
		assets: utils.Map(vexRules, func(r models.VEXRule) models.Asset { return r.Asset }),
	}, nil
}

func (s *CrowdsourcedVexingService) recommend(ctx context.Context, vexCtx crowdsourcedVexingContext, vuln models.DependencyVuln) (models.VEXRule, float64, crowdsourcevexing.Votes, error) {
	matches, err := vexrules.EvalRules(ctx, utils.Map(vexCtx.vexRules, transformer.VEXRuleToSystemVEXRuleDTO), vuln)
	if err != nil {
		return models.VEXRule{}, 0, crowdsourcevexing.Votes{}, err
	}

	matchedRules := []models.VEXRule{}
	for _, rule := range vexCtx.vexRules {
		if matches[rule.ID] {
			matchedRules = append(matchedRules, rule)
		}
	}

	recommendedRule, confidence, votes, err := crowdsourcevexing.CrowdsourcedVexing(
		matchedRules,
		vexCtx.crowdSourceVexingOrgs,
		vexCtx.crowdSourceVexingProj,
		vexCtx.assets,
	)
	if err != nil {
		return models.VEXRule{}, 0, crowdsourcevexing.Votes{}, err
	}

	return recommendedRule, confidence, votes, nil
}

func (s *CrowdsourcedVexingService) rulesInSessionOrg(ctx shared.Context, vexRules []models.VEXRule) (map[string]struct{}, error) {
	rbac := shared.GetRBAC(ctx)
	assetIDs, err := rbac.GetAllAssetsForSession(ctx.Request().Context(), shared.GetSession(ctx))
	if err != nil {
		return nil, err
	}
	assetIDSet := make(map[string]struct{}, len(assetIDs))
	for _, id := range assetIDs {
		assetIDSet[id] = struct{}{}
	}

	result := make(map[string]struct{})
	for _, rule := range vexRules {
		if _, ok := assetIDSet[rule.AssetID.String()]; ok {
			result[rule.ID] = struct{}{}
		}
	}
	return result, nil
}

func (s *CrowdsourcedVexingService) checkIfUserHasAccessToMatchingRule(ctx context.Context, vexRules []models.VEXRule, rulesInSessionOrg map[string]struct{}, vuln models.DependencyVuln) (models.VEXRule, bool, error) {
	if len(rulesInSessionOrg) == 0 {
		return models.VEXRule{}, false, nil
	}

	matches, err := vexrules.EvalRules(ctx, utils.Map(vexRules, transformer.VEXRuleToSystemVEXRuleDTO), vuln)
	if err != nil {
		return models.VEXRule{}, false, err
	}

	for _, rule := range vexRules {
		if !matches[rule.ID] {
			continue
		}
		if _, ok := rulesInSessionOrg[rule.ID]; ok {
			return rule, true, nil
		}
	}
	return models.VEXRule{}, false, nil
}

func checkIfSystemVexRuleMatchesVuln(ctx context.Context, vexRules []models.SystemVEXRule, vuln models.DependencyVuln) (models.SystemVEXRule, bool, error) {

	matches, err := vexrules.EvalRules(ctx, vexRules, vuln)
	if err != nil {
		return models.SystemVEXRule{}, false, err
	}

	for _, rule := range vexRules {
		if !matches[rule.ID] {
			continue
		}
		// just use the first rule and return it.
		return rule, true, nil
	}
	return models.SystemVEXRule{}, false, nil
}

func (s *CrowdsourcedVexingService) Recommend(ctx shared.Context, tx shared.DB, vulnID uuid.UUID) (dtos.VexRuleRecommendation, error) {
	requestCtx, span := servicesTracer.Start(ctx.Request().Context(), "CrowdsourcedVexingService.Recommend")
	defer span.End()
	span.SetAttributes(attribute.String("dependencyVuln.id", vulnID.String()))

	traceErr := func(err error) (dtos.VexRuleRecommendation, error) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return dtos.VexRuleRecommendation{}, err
	}

	vuln, err := s.dependencyVulnRepository.Read(requestCtx, tx, vulnID)
	if err != nil {
		return traceErr(err)
	}

	vexRules, err := s.vexRuleRepository.All(requestCtx, tx)
	if err != nil {
		return traceErr(err)
	}

	rulesInSessionOrg, err := s.rulesInSessionOrg(ctx, vexRules)
	if err != nil {
		return traceErr(err)
	}

	if rule, ok, err := s.checkIfUserHasAccessToMatchingRule(requestCtx, vexRules, rulesInSessionOrg, vuln); err != nil {
		return traceErr(err)
	} else if ok {
		project, err := s.assetRepository.ReadWithProject(requestCtx, tx, rule.AssetID)
		if err != nil {
			return traceErr(err)
		}
		return transformer.VEXRuleToOriginRecommendationDTO(rule, project.Slug, rule.Asset.Slug), nil
	}

	vexCtx, err := s.buildCrowdsourcedVexingContext(requestCtx, tx, vexRules)
	if err != nil {
		return traceErr(err)
	}

	rule, confidence, votes, err := s.recommend(requestCtx, vexCtx, vuln)
	if err != nil {
		return traceErr(err)
	}
	return transformer.VEXRuleToRecommendationDTO(rule, confidence, votes.Verified, votes.Total), nil
}

// return type is keyed by dependency vuln ID
func (s *CrowdsourcedVexingService) RecommendBatch(ctx shared.Context, tx shared.DB, vulns []models.DependencyVuln) (map[string]dtos.VexRuleRecommendation, error) {
	requestCtx, span := servicesTracer.Start(ctx.Request().Context(), "CrowdsourcedVexingService.RecommendBatch")
	defer span.End()
	span.SetAttributes(attribute.Int("dependencyVulns.total", len(vulns)))

	traceErr := func(err error) (map[string]dtos.VexRuleRecommendation, error) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	vexRules, err := s.vexRuleRepository.All(requestCtx, tx)
	if err != nil {
		return traceErr(err)
	}

	rulesInSessionOrg, err := s.rulesInSessionOrg(ctx, vexRules)
	if err != nil {
		return traceErr(err)
	}

	type vulnRecommendation struct {
		id  string
		dto dtos.VexRuleRecommendation
	}

	var vexCtx crowdsourcedVexingContext
	var vexCtxErr error
	var buildVexCtxOnce sync.Once
	getVexCtx := func() (crowdsourcedVexingContext, error) {
		buildVexCtxOnce.Do(func() {
			vexCtx, vexCtxErr = s.buildCrowdsourcedVexingContext(requestCtx, tx, vexRules)
		})
		return vexCtx, vexCtxErr
	}

	eg := utils.ErrGroup[*vulnRecommendation](100)
	for _, vuln := range vulns {
		eg.Go(func() (*vulnRecommendation, error) {
			if rule, ok, err := s.checkIfUserHasAccessToMatchingRule(requestCtx, vexRules, rulesInSessionOrg, vuln); err != nil {
				return nil, err
			} else if ok {
				// we have the asset id, we need assetSlug and projectSlug to return the recommendation DTO
				asset, err := s.assetRepository.ReadWithProject(ctx.Request().Context(), nil, rule.AssetID)
				if err != nil {
					return nil, err
				}
				id, err := vexrules.IdentityOfRule(models.SystemVEXRule{
					CELExpression:           rule.CELExpression,
					MechanicalJustification: rule.MechanicalJustification,
					EventType:               rule.EventType,
				})
				if err != nil {
					slog.Warn("could not calculate identity of rule", "err", err)
					return nil, nil
				}
				return &vulnRecommendation{id: id, dto: transformer.VEXRuleToOriginRecommendationDTO(rule, asset.Slug, asset.Project.Slug)}, nil
			}

			vexCtx, err := getVexCtx()
			if err != nil {
				return nil, err
			}

			rule, confidence, votes, err := s.recommend(requestCtx, vexCtx, vuln)
			if err != nil {
				if errors.Is(err, crowdsourcevexing.ErrNoRecommendation) {
					return nil, nil
				}
				return nil, err
			}
			id, err := vexrules.IdentityOfRule(models.SystemVEXRule{
				CELExpression:           rule.CELExpression,
				MechanicalJustification: rule.MechanicalJustification,
				EventType:               rule.EventType,
			})
			if err != nil {
				slog.Warn("could not calculate identity of rule", "err", err)
				return nil, nil
			}
			return &vulnRecommendation{id: id, dto: transformer.VEXRuleToRecommendationDTO(rule, confidence, votes.Verified, votes.Total)}, nil
		})
	}
	results, err := eg.WaitAndCollect()
	if err != nil {
		return traceErr(err)
	}

	found := utils.Filter(results, func(res *vulnRecommendation) bool { return res != nil })
	recommendations := utils.Reduce(found, func(acc map[string]dtos.VexRuleRecommendation, res *vulnRecommendation) map[string]dtos.VexRuleRecommendation {
		if r, ok := acc[res.id]; ok {
			r.AppliesToAmountOfDependencyVulns++
			acc[res.id] = r
		} else {
			res.dto.AppliesToAmountOfDependencyVulns = 1
			acc[res.id] = res.dto
		}
		return acc
	}, make(map[string]dtos.VexRuleRecommendation, len(found)))
	span.SetAttributes(attribute.Int("recommendations.total", len(recommendations)))

	return recommendations, nil
}
