package services

import (
	"context"
	_ "embed"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/licenses"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

type ComponentService struct {
	componentRepository        shared.ComponentRepository
	sbomRepository             shared.SBOMRepository
	openSourceInsightsService  shared.OpenSourceInsightService
	componentProjectRepository shared.ComponentProjectRepository
	licenseRiskService         shared.LicenseRiskService
	artifactRepository         shared.ArtifactRepository
	utils.FireAndForgetSynchronizer
}

var _ shared.ComponentService = (*ComponentService)(nil) // Ensure ComponentService implements shared.ComponentService interface

func NewComponentService(openSourceInsightsService shared.OpenSourceInsightService, componentProjectRepository shared.ComponentProjectRepository, componentRepository shared.ComponentRepository, sbomRepository shared.SBOMRepository, licenseRiskService shared.LicenseRiskService, artifactRepository shared.ArtifactRepository, synchronizer utils.FireAndForgetSynchronizer) *ComponentService {

	return &ComponentService{
		componentRepository:        componentRepository,
		sbomRepository:             sbomRepository,
		componentProjectRepository: componentProjectRepository,
		openSourceInsightsService:  openSourceInsightsService,
		licenseRiskService:         licenseRiskService,
		artifactRepository:         artifactRepository,
		FireAndForgetSynchronizer:  synchronizer,
	}
}

func (s *ComponentService) RefreshComponentProjectInformation(ctx context.Context, project models.ComponentProject) {
	projectKey := project.ProjectKey
	projectResp, err := s.openSourceInsightsService.GetProject(ctx, projectKey)
	if err != nil {
		slog.Warn("could not get project information", "err", err, "projectKey", projectKey)
		return
	}

	var jsonbScorecard *databasetypes.JSONB = nil
	if projectResp.Scorecard != nil {
		jsonb, err := databasetypes.JSONBFromStruct(*projectResp.Scorecard)
		if err != nil {
			slog.Warn("could not convert scorecard to jsonb", "err", err)
		} else {
			jsonbScorecard = &jsonb
		}
	}

	// update the project information
	project.StarsCount = projectResp.StarsCount
	project.ForksCount = projectResp.ForksCount
	project.License = projectResp.License
	project.Description = projectResp.Description
	project.Homepage = projectResp.Homepage
	project.ScoreCard = jsonbScorecard

	// save the project
	if err := s.componentProjectRepository.Save(ctx, nil, &project); err != nil {
		slog.Warn("could not save project", "err", err)
	} else {
		slog.Info("updated project", "projectKey", projectKey)
	}
}

func (s *ComponentService) GetLicense(ctx context.Context, component models.Component) (models.Component, error) {
	pURL := component.ID
	parsedPurl, err := packageurl.FromString(pURL)
	if err != nil {
		// swallow the error
		component.License = new("unknown")
		return component, nil
	}

	// check the pURL type, if its a debian or alpine package we get the license from memory
	switch parsedPurl.Type {
	case "deb":
		l := licenses.GetDebianLicense(parsedPurl)
		if l == "" {
			slog.Warn("could not get license information", "err", err, "purl", pURL)
			component.License = new("unknown")
		} else {
			component.License = &l
		}
	case "apk":
		l := licenses.GetAlpineLicense(parsedPurl)
		if l == "" {
			slog.Warn("could not get license information", "err", err, "purl", pURL)
			component.License = new("unknown")
		} else {
			component.License = &l
		}
	default:
		resp, err := s.openSourceInsightsService.GetVersion(
			ctx,
			parsedPurl,
		)

		if err != nil {
			slog.Warn("could not get license information", "err", err, "purl", pURL)
			component.License = new("unknown")
			return component, nil
		}

		if len(resp.Licenses) > 0 {
			component.License = &resp.Licenses[0]
			component.Published = &resp.PublishedAt
		} else {
			component.License = new("unknown")
		}
	}
	return component, nil
}

func (s *ComponentService) FetchComponentProject(ctx context.Context, component models.Component) (models.Component, error) {
	pURL := component.ID
	parsedPurl, err := packageurl.FromString(pURL)
	if err != nil {
		return component, nil
	}

	resp, err := s.openSourceInsightsService.GetVersion(
		ctx,
		parsedPurl,
	)
	if err != nil {
		slog.Warn("could not get version information for component project", "err", err, "purl", pURL)
		return component, nil
	}

	for _, project := range resp.RelatedProjects {
		if project.RelationType == "SOURCE_REPO" {
			projectKey := project.ProjectKey.ID

			projectResp, err := s.openSourceInsightsService.GetProject(ctx, projectKey)
			if err != nil {
				slog.Warn("could not get project information", "err", err, "projectKey", projectKey)
				return component, nil
			}

			var jsonbScorecard *databasetypes.JSONB = nil
			var scoreCardScore *float64 = nil
			if projectResp.Scorecard != nil {
				jsonb, err := databasetypes.JSONBFromStruct(*projectResp.Scorecard)
				scoreCardScore = &projectResp.Scorecard.OverallScore
				if err != nil {
					slog.Warn("could not convert scorecard to jsonb", "err", err)
				} else {
					jsonbScorecard = &jsonb
				}
			}

			component.ComponentProject = &models.ComponentProject{
				ProjectKey:     projectKey,
				StarsCount:     projectResp.StarsCount,
				ForksCount:     projectResp.ForksCount,
				License:        projectResp.License,
				Description:    projectResp.Description,
				Homepage:       projectResp.Homepage,
				ScoreCard:      jsonbScorecard,
				ScoreCardScore: scoreCardScore,
			}
			component.ComponentProjectKey = &projectKey
			break
		}
	}
	return component, nil
}

func (s *ComponentService) GetAndSaveLicenseInformation(ctx context.Context, tx shared.DB, assetVersion models.AssetVersion, artifactName *string, forceRefresh bool) ([]models.Component, error) {
	var sboms []models.SBOM
	var err error
	if artifactName != nil {
		sboms, err = s.sbomRepository.FindByArtifact(ctx, tx, assetVersion.AssetID, assetVersion.Name, *artifactName)
	} else {
		sboms, err = s.sbomRepository.FindByAssetVersion(ctx, tx, assetVersion.AssetID, assetVersion.Name)
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not load sboms")
	}

	forest := make(normalize.MerkleForest, 0, len(sboms))
	for _, sbom := range sboms {
		tree, err := s.sbomRepository.LoadTree(ctx, tx, sbom.RootSubtreeHash)
		if err != nil {
			return nil, errors.Wrap(err, "could not load sbom tree")
		}
		forest = append(forest, tree)
	}

	ids := forest.ComponentIDs()
	known, err := s.componentRepository.FindByIDs(ctx, tx, ids)
	if err != nil {
		return nil, errors.Wrap(err, "could not load components")
	}
	byID := make(map[string]models.Component, len(known))
	for _, component := range known {
		byID[component.ID] = component
	}

	// a component with no row yet has no licence either, so it always needs fetching
	componentsWithoutLicense := make([]models.Component, 0)
	for _, id := range ids {
		component, exists := byID[id]
		if !exists {
			component = models.Component{ID: id}
		}
		if forceRefresh || component.License == nil {
			componentsWithoutLicense = append(componentsWithoutLicense, component)
		}
	}

	slog.Info("getting license information for components", "amount", len(componentsWithoutLicense))
	errGroup := utils.ErrGroup[models.Component](10)
	for _, component := range componentsWithoutLicense {
		errGroup.Go(func() (models.Component, error) {
			comp, err := s.GetLicense(ctx, component)
			if err != nil {
				return comp, err
			}
			return s.FetchComponentProject(ctx, comp)
		})
	}

	// wait for all components to be processed
	components, err := errGroup.WaitAndCollect()

	if err != nil {
		return nil, err
	}

	// save the components
	if err := s.componentRepository.SaveBatch(ctx, nil, components); err != nil {
		return nil, err
	}

	// the freshly fetched ones, plus those that already had a licence
	allComponents := components
	refreshed := make(map[string]bool, len(components))
	for _, component := range components {
		refreshed[component.ID] = true
	}
	for _, id := range ids {
		if component, exists := byID[id]; exists && !refreshed[id] {
			allComponents = append(allComponents, component)
		}
	}

	// Detach cancellation but KEEP the trace context
	bgCtx := context.WithoutCancel(ctx)

	s.FireAndForget(func() {
		allComponents = utils.Filter(allComponents, func(component models.Component) bool {
			//check if the purl is valid and has a version
			_, err = packageurl.FromString(component.ID)
			return err == nil
		})
		// find potential license risks
		if artifactName == nil {
			// fetch all artifacts for the asset version - we need this to link the license risks to the artifacts
			artifacts, err := s.artifactRepository.GetByAssetIDAndAssetVersionName(bgCtx, nil, assetVersion.AssetID, assetVersion.Name)
			if err != nil {
				slog.Error("could not fetch artifacts for asset version", "err", err, "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID)
				return
			}
			for _, artifact := range artifacts {
				err = s.licenseRiskService.FindLicenseRisksInComponents(bgCtx, nil, "system", nil, assetVersion, allComponents, artifact.ArtifactName)
				if err != nil {
					slog.Error("could not find license risks in components", "err", err, "artifactName", artifact.ArtifactName)
				}
			}
		} else {
			err = s.licenseRiskService.FindLicenseRisksInComponents(ctx, nil, "system", nil, assetVersion, allComponents, *artifactName)
			if err != nil {
				slog.Error("could not find license risks in components", "err", err, "artifactName", *artifactName)
			}
		}
	})

	return allComponents, nil
}
