package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/crowdsourcevexing"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vexrules"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type CrowdsourcedVexingService struct {
	vexRuleRepository        shared.VEXRuleRepository
	organisationRepository   shared.OrganizationRepository
	projectRepository        shared.ProjectRepository
	assetVersionRepository   shared.AssetVersionRepository
	dependencyVulnRepository shared.DependencyVulnRepository
	trustedEntityRepository  shared.TrustedEntityRepository
	rbacProvider             shared.RBACProvider
	vexRuleService           shared.VEXRuleService
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

func NewCrowdsourcedVexingService(vexRuleRepository shared.VEXRuleRepository, organisationRepository shared.OrganizationRepository, projectRepository shared.ProjectRepository, assetVersionRepository shared.AssetVersionRepository, dependencyVulnRepository shared.DependencyVulnRepository, trustedEntityRepository shared.TrustedEntityRepository, rbacProvider shared.RBACProvider, vexRuleService shared.VEXRuleService) *CrowdsourcedVexingService {
	return &CrowdsourcedVexingService{
		vexRuleRepository:        vexRuleRepository,
		organisationRepository:   organisationRepository,
		projectRepository:        projectRepository,
		assetVersionRepository:   assetVersionRepository,
		dependencyVulnRepository: dependencyVulnRepository,
		trustedEntityRepository:  trustedEntityRepository,
		rbacProvider:             rbacProvider,
		vexRuleService:           vexRuleService,
	}
}

// crowdsourcedVexingContext holds all data that is shared across every
// dependency vuln being evaluated in a single batch: the full set of VEX
// rules plus the projects/organizations/trust scores they reference. This is
// fetched exactly once per batch instead of once per vuln.
type crowdsourcedVexingContext struct {
	vexRules              []models.VEXRule
	crowdSourceVexingOrgs []crowdsourcevexing.Organization
	crowdSourceVexingProj []crowdsourcevexing.Project
	assets                []models.Asset
}

func (s *CrowdsourcedVexingService) loadCrowdsourcedVexingContext(requestCtx context.Context, tx shared.DB) (crowdsourcedVexingContext, error) {
	vexRules, err := s.vexRuleRepository.All(requestCtx, tx)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}

	projectIDs := utils.Map(vexRules, func(r models.VEXRule) uuid.UUID { return r.Asset.ProjectID })

	projects, err := s.projectRepository.GetByProjectIDs(requestCtx, tx, projectIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}

	orgIDs := utils.Map(projects, func(p models.Project) uuid.UUID { return p.OrganizationID })

	orgs, err := s.organisationRepository.GetOrgByIDs(requestCtx, tx, orgIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}

	projectTrustedEntities, err := s.trustedEntityRepository.GetTrustedEntitiesByProjectIDs(requestCtx, tx, projectIDs)
	if err != nil {
		return crowdsourcedVexingContext{}, err
	}
	projectTrustScores := make(map[uuid.UUID]float64, len(projectTrustedEntities))
	for _, te := range projectTrustedEntities {
		projectTrustScores[*te.ProjectID] = te.TrustScore
	}

	orgTrustedEntities, err := s.trustedEntityRepository.GetTrustedEntitiesByOrganizationIDs(requestCtx, tx, orgIDs)
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

// recommend computes the crowdsourced VEX recommendation for a single vuln
// against an already-loaded crowdsourcedVexingContext. It performs no DB
// access itself - callers evaluating multiple vulns should load the context
// once and call this per vuln.
func (s *CrowdsourcedVexingService) recommend(requestCtx context.Context, vexCtx crowdsourcedVexingContext, vuln models.DependencyVuln) (models.VEXRule, error) {
	matchedRules := []models.VEXRule{}
	for _, rule := range vexCtx.vexRules {
		match, err := vexrules.EvalRule(requestCtx, rule, vuln)
		if err != nil {
			return models.VEXRule{}, err
		}
		if match {
			matchedRules = append(matchedRules, rule)
		}
	}

	recommendedRule, err := crowdsourcevexing.CrowdsourcedVexing(
		matchedRules,
		vexCtx.crowdSourceVexingOrgs,
		vexCtx.crowdSourceVexingProj,
		vexCtx.assets,
	)
	if err != nil {
		return models.VEXRule{}, err
	}

	rule, ok := utils.Find(vexCtx.vexRules, func(r models.VEXRule) bool { return r.ID == recommendedRule.ID })
	if !ok {
		return models.VEXRule{}, fmt.Errorf("could not find vex rule - even though it HAS to exist")
	}
	return rule, nil
}

func (s *CrowdsourcedVexingService) Recommend(ctx shared.Context, tx shared.DB, vulnID uuid.UUID) (models.VEXRule, error) {
	requestCtx, span := servicesTracer.Start(ctx.Request().Context(), "CrowdsourcedVexingService.Recommend")
	defer span.End()
	span.SetAttributes(attribute.String("dependencyVuln.id", vulnID.String()))

	traceErr := func(err error) (models.VEXRule, error) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return models.VEXRule{}, err
	}

	vuln, err := s.dependencyVulnRepository.Read(requestCtx, tx, vulnID)
	if err != nil {
		return traceErr(err)
	}

	vexCtx, err := s.loadCrowdsourcedVexingContext(requestCtx, tx)
	if err != nil {
		return traceErr(err)
	}

	rule, err := s.recommend(requestCtx, vexCtx, vuln)
	if err != nil {
		return traceErr(err)
	}
	return rule, nil
}

// RecommendBatch computes crowdsourced VEX recommendations for many vulns at
// once, fetching the shared VEX rule/project/organization/trust-score data
// exactly once instead of once per vuln. Vulns without a recommendation are
// simply omitted from the result map.
func (s *CrowdsourcedVexingService) RecommendBatch(ctx shared.Context, tx shared.DB, vulns []models.DependencyVuln) (map[uuid.UUID]models.VEXRule, error) {
	requestCtx, span := servicesTracer.Start(ctx.Request().Context(), "CrowdsourcedVexingService.RecommendBatch")
	defer span.End()
	span.SetAttributes(attribute.Int("dependencyVulns.total", len(vulns)))

	traceErr := func(err error) (map[uuid.UUID]models.VEXRule, error) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	vexCtx, err := s.loadCrowdsourcedVexingContext(requestCtx, tx)
	if err != nil {
		return traceErr(err)
	}

	recommendations := make(map[uuid.UUID]models.VEXRule, len(vulns))
	for _, vuln := range vulns {
		rule, err := s.recommend(requestCtx, vexCtx, vuln)
		if err != nil {
			if errors.Is(err, crowdsourcevexing.ErrNoRecommendation) {
				continue
			}
			return traceErr(err)
		}
		recommendations[vuln.ID] = rule
	}
	span.SetAttributes(attribute.Int("recommendations.total", len(recommendations)))

	return recommendations, nil
}
