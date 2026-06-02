package services

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/crowdsourcevexing"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
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
}

func mapOrg(org models.Org, orgTrustscore float64, ownerID string, organizationMemberIDs []string) crowdsourcevexing.Organization {
	return crowdsourcevexing.Organization{
		ID:         org.ID.String(),
		Trustscore: orgTrustscore,
		CreatedAt:  org.CreatedAt,
		CreatedBy:  ownerID,
		UserIDs:    organizationMemberIDs,
	}
}

func mapProject(project models.Project, projectTrustscore float64) crowdsourcevexing.Project {
	return crowdsourcevexing.Project{
		ID:             project.ID.String(),
		OrganizationID: project.OrganizationID.String(),
		Trustscore:     projectTrustscore,
	}
}

func mapVexRule(vexrule models.VEXRule) crowdsourcevexing.VexRule {
	return crowdsourcevexing.VexRule{
		ID:               vexrule.ID,
		PathPattern:      vexrule.PathPattern,
		CVE:              crowdsourcevexing.CVE{CVE: vexrule.CVEID},
		AssetID:          vexrule.AssetID.String(),
		AssetVersionName: vexrule.AssetVersionName,
		Reasoning:        vexrule.Justification,
		Assessment:       string(vexrule.MechanicalJustification),
		UpdatedAt:        vexrule.UpdatedAt,
	}
}

func mapAsset(asset models.Asset) crowdsourcevexing.Asset {
	return crowdsourcevexing.Asset{
		ID:        asset.ID.String(),
		ProjectID: asset.ProjectID.String(),
	}
}

func NewCrowdsourcedVexingService(vexRuleRepository shared.VEXRuleRepository, systemVexRuleRepository shared.SystemVEXRuleRepository, organisationRepository shared.OrganizationRepository, projectRepository shared.ProjectRepository, assetVersionRepository shared.AssetVersionRepository, dependencyVulnRepository shared.DependencyVulnRepository, trustedEntityRepository shared.TrustedEntityRepository, rbacProvider shared.RBACProvider) *CrowdsourcedVexingService {
	return &CrowdsourcedVexingService{
		vexRuleRepository:        vexRuleRepository,
		systemVexRuleRepository:  systemVexRuleRepository,
		organisationRepository:   organisationRepository,
		projectRepository:        projectRepository,
		assetVersionRepository:   assetVersionRepository,
		dependencyVulnRepository: dependencyVulnRepository,
		trustedEntityRepository:  trustedEntityRepository,
		rbacProvider:             rbacProvider,
	}
}

func (s *CrowdsourcedVexingService) Recommend(ctx shared.Context, tx shared.DB, vulnID uuid.UUID) (models.VEXRule, error) {
	assetversion := shared.GetAssetVersion(ctx)
	requestCtx := ctx.Request().Context()

	vuln, err := s.dependencyVulnRepository.Read(requestCtx, tx, vulnID)
	if err != nil {
		return models.VEXRule{}, err
	}
	if vuln.AssetID != assetversion.AssetID || vuln.AssetVersionName != assetversion.Name {
		return models.VEXRule{}, fmt.Errorf("vuln does not belong to this asset")
	}

	systemVexRule, err := s.RecommendSystemVEXRule(ctx, tx, vuln.CVEID, vuln.VulnerabilityPath)
	if err == nil {
		return transformer.SystemVEXRuleToVEXRule(systemVexRule), nil
	}
	slog.Info("no suitable system VEXRule for this vuln. continuing with crowdsourced vexing", "err", err)

	vexRules, err := s.vexRuleRepository.FindByCVE(requestCtx, tx, vuln.CVEID)
	if err != nil {
		return models.VEXRule{}, err
	}

	projectIDs := utils.Map(vexRules, func(r models.VEXRule) uuid.UUID { return r.Asset.ProjectID })

	projects, err := s.projectRepository.GetByProjectIDs(requestCtx, tx, projectIDs)
	if err != nil {
		return models.VEXRule{}, err
	}

	orgIDs := utils.Map(projects, func(p models.Project) uuid.UUID { return p.OrganizationID })

	orgs, err := s.organisationRepository.GetOrgByIDs(requestCtx, tx, orgIDs)
	if err != nil {
		return models.VEXRule{}, err
	}

	projectTrustedEntities, err := s.trustedEntityRepository.GetTrustedEntitiesByProjectIDs(requestCtx, tx, projectIDs)
	if err != nil {
		return models.VEXRule{}, err
	}
	projectTrustScores := make(map[uuid.UUID]float64, len(projectTrustedEntities))
	for _, te := range projectTrustedEntities {
		projectTrustScores[*te.ProjectID] = te.TrustScore
	}

	orgTrustedEntities, err := s.trustedEntityRepository.GetTrustedEntitiesByOrganizationIDs(requestCtx, tx, orgIDs)
	if err != nil {
		return models.VEXRule{}, err
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
			return models.VEXRule{}, err
		}
		ownerID, err := domainRBAC.GetOwnerOfOrganization()
		if err != nil {
			return models.VEXRule{}, err
		}
		crowdSourceVexingOrgs[i] = mapOrg(org, orgTrustScores[org.ID], ownerID, memberIDs)
	}

	recommendedRule, err := crowdsourcevexing.CrowdsourcedVexing(
		vuln.VulnerabilityPath,
		crowdsourcevexing.CVE{CVE: vuln.CVEID},
		utils.Map(vexRules, mapVexRule),
		crowdSourceVexingOrgs,
		utils.Map(projects, func(p models.Project) crowdsourcevexing.Project {
			return mapProject(p, projectTrustScores[p.ID])
		}),
		utils.Map(vexRules, func(r models.VEXRule) crowdsourcevexing.Asset { return mapAsset(r.Asset) }),
	)
	if err != nil {
		return models.VEXRule{}, err
	}

	rule, ok := utils.Find(vexRules, func(r models.VEXRule) bool { return r.ID == recommendedRule.ID })
	if !ok {
		return models.VEXRule{}, fmt.Errorf("could not find vex rule - even though it HAS to exist")
	}
	return rule, nil
}

func (s *CrowdsourcedVexingService) RecommendSystemVEXRule(ctx shared.Context, tx shared.DB, cveID string, dependencyPath []string) (models.SystemVEXRule, error) {
	rules, err := s.systemVexRuleRepository.FindByCVE(ctx.Request().Context(), tx, cveID)
	if err != nil {
		return models.SystemVEXRule{}, err
	}
	validRules := utils.Filter(rules, func(rule models.SystemVEXRule) bool {
		return dtos.PathPattern(rule.PathPattern).MatchesSuffix(dependencyPath)
	})
	if len(validRules) == 0 {
		return models.SystemVEXRule{}, fmt.Errorf("no system VEX rules found for CVE: %s", cveID)
	}
	if len(validRules) > 1 {
		return models.SystemVEXRule{}, fmt.Errorf("multiple system VEX rules found for CVE: %s, cannot determine which one to recommend", cveID)
	}
	return validRules[0], nil
}
