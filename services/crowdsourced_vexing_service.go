package services

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/crowdsourcevexing"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type CrowdsourcedVexingService struct {
	vexRuleRepository        shared.VEXRuleRepository
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
		AssetversionName: vexrule.AssetVersionName,
		Reasoning:        vexrule.Justification,
		Assessment:       string(vexrule.MechanicalJustification),
	}
}

func mapAsset(assetVersion models.AssetVersion) crowdsourcevexing.Asset {
	return crowdsourcevexing.Asset{
		ID:        assetVersion.AssetID.String(),
		ProjectID: assetVersion.Asset.ProjectID.String(),
	}
}

func NewCrowdsourcedVexingService(vexRuleRepository shared.VEXRuleRepository, organisationRepository shared.OrganizationRepository, projectRepository shared.ProjectRepository, assetVersionRepository shared.AssetVersionRepository, dependencyVulnRepository shared.DependencyVulnRepository, trustedEntityRepository shared.TrustedEntityRepository, rbacProvider shared.RBACProvider) *CrowdsourcedVexingService {
	return &CrowdsourcedVexingService{
		vexRuleRepository:        vexRuleRepository,
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

	// Find dependency path using the vulnID.
	vuln, err := s.dependencyVulnRepository.Read(requestCtx, tx, vulnID)
	if err != nil {
		return models.VEXRule{}, err
	}
	if vuln.AssetID != assetversion.AssetID || vuln.AssetVersionName != assetversion.Name {
		return models.VEXRule{}, fmt.Errorf("vuln does not belong to this asset")
	}

	rawVexRules, err := s.vexRuleRepository.FindByCVE(requestCtx, tx, vuln.CVEID)
	if err != nil {
		return models.VEXRule{}, err
	}
	formattedVexRules := make([]crowdsourcevexing.VexRule, len(rawVexRules))
	accordingAssetIDs := make([]uuid.UUID, len(rawVexRules))
	for i, vexrule := range rawVexRules {
		accordingAssetIDs[i] = vexrule.AssetID
		formattedVexRules[i] = mapVexRule(vexrule)
	}

	rawAssetVersions, err := s.assetVersionRepository.GetAssetVersionsByAssetIDs(requestCtx, tx, accordingAssetIDs)
	if err != nil {
		return models.VEXRule{}, err
	}
	formattedAssets := make([]crowdsourcevexing.Asset, len(rawAssetVersions))
	accordingProjectIDs := make([]uuid.UUID, len(rawAssetVersions))
	for i, assetVersion := range rawAssetVersions {
		accordingProjectIDs[i] = assetVersion.Asset.ProjectID
		formattedAssets[i] = mapAsset(assetVersion)
	}

	rawProjects, err := s.projectRepository.GetByProjectIDs(requestCtx, tx, accordingProjectIDs)
	if err != nil {
		return models.VEXRule{}, err
	}
	rawTrustedEntitiesByProject, err := s.trustedEntityRepository.GetTrustedEntitiesByProjectIDs(requestCtx, tx, accordingProjectIDs)
	if err != nil {
		return models.VEXRule{}, err
	}
	trustedEntitiesByProjectTrustscores := make(map[string]float64, len(rawTrustedEntitiesByProject))
	for _, te := range rawTrustedEntitiesByProject {
		if te.OrganizationID != nil {
			trustedEntitiesByProjectTrustscores[te.OrganizationID.String()] = te.TrustScore
		}
	}
	formattedProjects := make([]crowdsourcevexing.Project, len(rawProjects))
	accordingOrganizationIDs := make([]uuid.UUID, len(rawProjects))
	for i, proj := range rawProjects {
		projTrustscore := trustedEntitiesByProjectTrustscores[proj.ID.String()]
		accordingOrganizationIDs[i] = proj.OrganizationID
		formattedProjects[i] = mapProject(proj, projTrustscore)
	}

	rawOrganisations, err := s.organisationRepository.GetOrgByIDs(requestCtx, tx, accordingOrganizationIDs)
	if err != nil {
		return models.VEXRule{}, err
	}
	rawTrustedEntitiesByOrg, err := s.trustedEntityRepository.GetTrustedEntitiesByOrganizationIDs(requestCtx, tx, accordingOrganizationIDs)
	if err != nil {
		return models.VEXRule{}, err
	}
	trustedEntitiesByOrgTrustscores := make(map[string]float64, len(rawTrustedEntitiesByOrg))
	for _, te := range rawTrustedEntitiesByOrg {
		if te.OrganizationID != nil {
			trustedEntitiesByOrgTrustscores[te.OrganizationID.String()] = te.TrustScore
		}
	}
	formattedOrganizations := make([]crowdsourcevexing.Organization, len(rawOrganisations))
	for i, org := range rawOrganisations {
		domainRBAC := s.rbacProvider.GetDomainRBAC(org.ID.String())

		orgTrustscore := trustedEntitiesByOrgTrustscores[org.ID.String()]

		organizationMemberIDs, err := domainRBAC.GetAllMembersOfOrganization()
		if err != nil {
			return models.VEXRule{}, err
		}

		ownerID, err := domainRBAC.GetOwnerOfOrganization()
		if err != nil {
			return models.VEXRule{}, err
		}

		formattedOrganizations[i] = mapOrg(org, orgTrustscore, ownerID, organizationMemberIDs)
	}

	recommendedRule, err := crowdsourcevexing.CrowdsourcedVexing(
		vuln.VulnerabilityPath,
		crowdsourcevexing.CVE{CVE: vuln.CVE.CVE},
		formattedVexRules,
		formattedOrganizations,
		formattedProjects,
		formattedAssets,
	)
	if err != nil || recommendedRule.ID == "" {
		return models.VEXRule{}, err
	}

	finalRecommendation, err := s.vexRuleRepository.FindByID(requestCtx, tx, recommendedRule.ID)
	if err != nil {
		return models.VEXRule{}, err
	}

	return finalRecommendation, nil
}
