package services

import (
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

	vexRules, err := s.vexRuleRepository.All(requestCtx, tx)
	if err != nil {
		return traceErr(err)
	}

	matchedRules := []models.VEXRule{}

	for _, rule := range vexRules {
		match, err := vexrules.EvalRule(requestCtx, rule, vuln)
		if err != nil {
			return traceErr(err)
		}
		if match {
			matchedRules = append(matchedRules, rule)
		}
	}
	span.SetAttributes(
		attribute.Int("vexRules.total", len(vexRules)),
		attribute.Int("vexRules.matched", len(matchedRules)),
	)

	projectIDs := utils.Map(vexRules, func(r models.VEXRule) uuid.UUID { return r.Asset.ProjectID })

	projects, err := s.projectRepository.GetByProjectIDs(requestCtx, tx, projectIDs)
	if err != nil {
		return traceErr(err)
	}

	orgIDs := utils.Map(projects, func(p models.Project) uuid.UUID { return p.OrganizationID })

	orgs, err := s.organisationRepository.GetOrgByIDs(requestCtx, tx, orgIDs)
	if err != nil {
		return traceErr(err)
	}

	projectTrustedEntities, err := s.trustedEntityRepository.GetTrustedEntitiesByProjectIDs(requestCtx, tx, projectIDs)
	if err != nil {
		return traceErr(err)
	}
	projectTrustScores := make(map[uuid.UUID]float64, len(projectTrustedEntities))
	for _, te := range projectTrustedEntities {
		projectTrustScores[*te.ProjectID] = te.TrustScore
	}

	orgTrustedEntities, err := s.trustedEntityRepository.GetTrustedEntitiesByOrganizationIDs(requestCtx, tx, orgIDs)
	if err != nil {
		return traceErr(err)
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
			return traceErr(err)
		}
		ownerID, err := domainRBAC.GetOwnerOfOrganization()
		if err != nil {
			return traceErr(err)
		}
		crowdSourceVexingOrgs[i] = mapOrg(org, orgTrustScores[org.ID], ownerID, memberIDs)
	}

	recommendedRule, err := crowdsourcevexing.CrowdsourcedVexing(
		matchedRules,
		crowdSourceVexingOrgs,
		utils.Map(projects, func(p models.Project) crowdsourcevexing.Project {
			return mapProject(p, projectTrustScores[p.ID])
		}),
		utils.Map(vexRules, func(r models.VEXRule) models.Asset { return r.Asset }),
	)
	if err != nil {
		return traceErr(err)
	}

	rule, ok := utils.Find(vexRules, func(r models.VEXRule) bool { return r.ID == recommendedRule.ID })
	if !ok {
		return traceErr(fmt.Errorf("could not find vex rule - even though it HAS to exist"))
	}
	return rule, nil
}
