package services

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/crowdsourcevexing"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type CrowdsourcedVexingService struct {
	vexRuleRepository        shared.VEXRuleRepository
	organisationRepository   shared.OrganizationRepository
	projectRepository        shared.ProjectRepository
	assetRepository          shared.AssetRepository
	assetVersionRepository   shared.AssetVersionRepository
	dependencyVulnRepository shared.DependencyVulnRepository
	trustedEntityRepository  shared.TrustedEntityRepository
	rbacProvider             shared.RBACProvider
}

func NewCrowdsourcedVexingService(vexRuleRepository shared.VEXRuleRepository, organisationRepository shared.OrganizationRepository, projectRepository shared.ProjectRepository, assetRepository shared.AssetRepository, assetVersionRepository shared.AssetVersionRepository, dependencyVulnRepository shared.DependencyVulnRepository, trustedEntityRepository shared.TrustedEntityRepository, rbacProvider shared.RBACProvider) *CrowdsourcedVexingService {
	return &CrowdsourcedVexingService{
		vexRuleRepository:        vexRuleRepository,
		organisationRepository:   organisationRepository,
		projectRepository:        projectRepository,
		assetRepository:          assetRepository,
		assetVersionRepository:   assetVersionRepository,
		dependencyVulnRepository: dependencyVulnRepository,
		trustedEntityRepository:  trustedEntityRepository,
		rbacProvider:             rbacProvider,
	}
}

func (s *CrowdsourcedVexingService) Recommend(ctx shared.Context, tx shared.DB, vulnId uuid.UUID) (models.VEXRule, error) {
	var formattedOrganizations []crowdsourcevexing.Organization
	var formattedProjects []crowdsourcevexing.Project
	var formattedAssets []crowdsourcevexing.Asset
	var formattedVexRules []crowdsourcevexing.VexRule

	// Find dependency path using the vulnID.
	vuln, err := s.dependencyVulnRepository.Read(ctx.Request().Context(), nil, vulnId)
	if err != nil {
		return models.VEXRule{}, err
	}

	// Find all organizations.
	rawOrganisations, err := s.organisationRepository.All(ctx.Request().Context(), nil)
	if err != nil {
		return models.VEXRule{}, err
	}

	for _, org := range rawOrganisations {
		domainRBAC := s.rbacProvider.GetDomainRBAC(org.ID.String())

		// Format orgs to the recommendation input type.
		trustedOrg, err := s.trustedEntityRepository.GetOrganizationTrust(ctx.Request().Context(), nil, org.ID)
		var orgTrustscore float64
		if err != nil {
			orgTrustscore = 0
		} else {
			orgTrustscore = trustedOrg.TrustScore
		}

		organizationMemberIds, err := domainRBAC.GetAllMembersOfOrganization()
		if err != nil {
			return models.VEXRule{}, err
		}

		ownerID, err := domainRBAC.GetOwnerOfOrganization()
		if err != nil {
			return models.VEXRule{}, err
		}

		formattedOrganizations = append(formattedOrganizations, crowdsourcevexing.Organization{
			ID:         org.ID.String(),
			Trustscore: orgTrustscore,
			CreatedAt:  org.CreatedAt,
			CreatedBy:  ownerID,
			UserIDs:    organizationMemberIds,
		})

		rawProjects, err := s.projectRepository.GetByOrgID(ctx.Request().Context(), nil, org.ID)
		if err != nil {
			return models.VEXRule{}, err
		}

		for _, proj := range rawProjects {
			trustedProj, err := s.trustedEntityRepository.GetProjectTrust(ctx.Request().Context(), nil, proj.ID)
			var projTrustscore float64
			if err != nil {
				projTrustscore = 0
			} else {
				projTrustscore = trustedProj.TrustScore
			}

			formattedProjects = append(formattedProjects, crowdsourcevexing.Project{
				ID:             proj.ID.String(),
				OrganizationID: org.ID.String(),
				Trustscore:     projTrustscore,
			})
		}
	}

	rawAssetVersions, err := s.assetVersionRepository.All(ctx.Request().Context(), nil)
	if err != nil {
		return models.VEXRule{}, err
	}

	for _, assetVersion := range rawAssetVersions {
		formattedAssets = append(formattedAssets, crowdsourcevexing.Asset{
			ID:        assetVersion.AssetID.String(),
			ProjectID: assetVersion.Asset.ProjectID.String(),
		})

		allVexRules, err := s.vexRuleRepository.FindByAssetVersion(ctx.Request().Context(), nil, assetVersion.AssetID, assetVersion.Name)
		if err != nil {
			return models.VEXRule{}, err
		}

		for _, vexrule := range allVexRules {
			formattedVexRules = append(formattedVexRules, crowdsourcevexing.VexRule{
				ID:               vexrule.ID,
				PathPattern:      vexrule.PathPattern,
				CVE:              crowdsourcevexing.CVE{CVE: vexrule.CVEID},
				AssetID:          vexrule.AssetID.String(),
				AssetversionName: vexrule.AssetVersionName,
				Reasoning:        vexrule.Justification,
				Assessment:       string(vexrule.MechanicalJustification),
			})
		}
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

	finalRecommendation, err := s.vexRuleRepository.FindByID(ctx.Request().Context(), nil, recommendedRule.ID)
	if err != nil {
		return models.VEXRule{}, err
	}

	return finalRecommendation, nil
}
