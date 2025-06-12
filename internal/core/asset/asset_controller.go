package asset

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type httpController struct {
	assetRepository        core.AssetRepository
	assetVersionRepository core.AssetVersionRepository
	assetService           core.AssetService
	dependencyVulnService  core.DependencyVulnService
	statisticsService      core.StatisticsService
}

func NewHttpController(repository core.AssetRepository, assetVersionRepository core.AssetVersionRepository, assetService core.AssetService, dependencyVulnService core.DependencyVulnService, statisticsService core.StatisticsService) *httpController {
	return &httpController{
		assetRepository:        repository,
		assetVersionRepository: assetVersionRepository,
		assetService:           assetService,
		dependencyVulnService:  dependencyVulnService,
		statisticsService:      statisticsService,
	}
}

func (a *httpController) HandleLookup(ctx core.Context) error {
	provider := ctx.QueryParam("provider")
	if provider == "" {
		return echo.NewHTTPError(400, "missing provider")
	}

	id := ctx.QueryParam("id")
	if id == "" {
		return echo.NewHTTPError(400, "missing repositoryId")
	}

	asset, err := a.assetRepository.FindAssetByExternalProviderId(provider, id)

	if err != nil {
		return echo.NewHTTPError(404, "asset not found").WithInternal(err)
	}

	assetFqn, err := a.assetRepository.GetFQNByID(asset.ID)

	// split the fqn into organization, project and asset
	if err != nil {
		return echo.NewHTTPError(500, "could not get asset FQN").WithInternal(err)
	}
	parts := strings.Split(assetFqn, "/")
	if len(parts) != 3 {
		return echo.NewHTTPError(500, "invalid asset FQN format")
	}

	response := LookupResponse{
		Org:     parts[0],
		Project: parts[1],
		Asset:   parts[2],
		Link:    fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/%s", parts[0], parts[1], parts[2]),
	}

	return ctx.JSON(200, response)
}

func (a *httpController) List(ctx core.Context) error {

	project := core.GetProject(ctx)

	apps, err := a.assetRepository.GetByProjectID(project.GetID())
	if err != nil {
		return err
	}

	return ctx.JSON(200, toDTOs(apps))
}

func (a *httpController) AttachSigningKey(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	// read the fingerprint from request body
	var req struct {
		PubKey string `json:"publicKey"`
	}

	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	asset.SigningPubKey = &req.PubKey
	// save the asset
	err := a.assetRepository.Update(nil, &asset)
	if err != nil {
		return echo.NewHTTPError(500, "could not attach signing key").WithInternal(err)
	}

	return nil
}

func (a *httpController) Delete(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	err := a.assetRepository.Delete(nil, asset.GetID())
	if err != nil {
		return err
	}
	return ctx.NoContent(200)
}

func (a *httpController) GetSecrets(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	secrets := map[string]string{}

	if asset.BadgeSecret != nil {
		secrets["badgeSecret"] = asset.BadgeSecret.String()
	}

	if asset.WebhookSecret != nil {
		secrets["webhookSecret"] = asset.WebhookSecret.String()
	}

	return ctx.JSON(200, secrets)
}

func (a *httpController) Create(ctx core.Context) error {
	var req createRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	project := core.GetProject(ctx)

	newAsset := req.toModel(project.GetID())
	newAsset.ProjectID = project.GetID()

	asset, err := a.assetService.CreateAsset(newAsset)
	if err != nil {
		return err
	}

	return ctx.JSON(200, toDTO(*asset))
}

func (a *httpController) Read(ctx core.Context) error {
	app := core.GetAsset(ctx)

	return ctx.JSON(200, toDTO(app))
}

func (a *httpController) Update(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	req := ctx.Request().Body
	defer req.Close()

	var patchRequest PatchRequest

	err := json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return fmt.Errorf("error decoding request: %v", err)
	}

	var justification = ""
	if patchRequest.ConfidentialityRequirement != nil && *patchRequest.ConfidentialityRequirement != asset.ConfidentialityRequirement {
		justification += "Confidentiality Requirement updated: " + string(asset.ConfidentialityRequirement) + " -> " + string(*patchRequest.ConfidentialityRequirement)
		asset.ConfidentialityRequirement = *patchRequest.ConfidentialityRequirement
	}

	if patchRequest.IntegrityRequirement != nil && *patchRequest.IntegrityRequirement != asset.IntegrityRequirement {
		if justification != "" {
			justification += ", "
		}
		justification += "Integrity Requirement updated: " + string(asset.IntegrityRequirement) + " -> " + string(*patchRequest.IntegrityRequirement)
		asset.IntegrityRequirement = *patchRequest.IntegrityRequirement
	}

	if patchRequest.AvailabilityRequirement != nil && *patchRequest.AvailabilityRequirement != asset.AvailabilityRequirement {
		if justification != "" {
			justification += ", "
		}
		justification += "Availability Requirement updated: " + string(asset.AvailabilityRequirement) + " -> " + string(*patchRequest.AvailabilityRequirement)
		asset.AvailabilityRequirement = *patchRequest.AvailabilityRequirement
	}

	if justification != "" {
		err = a.assetService.UpdateAssetRequirements(asset, core.GetSession(ctx).GetUserID(), justification)
		if err != nil {
			return fmt.Errorf("error updating requirements: %v", err)
		}
	}

	enableTicketRangeUpdated := false

	if patchRequest.EnableTicketRange {
		if patchRequest.CVSSAutomaticTicketThreshold != nil {
			if asset.CVSSAutomaticTicketThreshold != nil {
				if !utils.CompareFirstTwoDecimals(*patchRequest.CVSSAutomaticTicketThreshold, *asset.CVSSAutomaticTicketThreshold) {
					enableTicketRangeUpdated = true
					asset.CVSSAutomaticTicketThreshold = patchRequest.CVSSAutomaticTicketThreshold
				}
			} else {
				enableTicketRangeUpdated = true
				asset.CVSSAutomaticTicketThreshold = patchRequest.CVSSAutomaticTicketThreshold
			}
		} else {
			if asset.CVSSAutomaticTicketThreshold != nil {
				enableTicketRangeUpdated = true
				asset.CVSSAutomaticTicketThreshold = nil
			}
		}

		if patchRequest.RiskAutomaticTicketThreshold != nil {
			if asset.RiskAutomaticTicketThreshold != nil {
				if !utils.CompareFirstTwoDecimals(*patchRequest.RiskAutomaticTicketThreshold, *asset.RiskAutomaticTicketThreshold) {
					enableTicketRangeUpdated = true
					asset.RiskAutomaticTicketThreshold = patchRequest.RiskAutomaticTicketThreshold
				}
			} else {
				enableTicketRangeUpdated = true
				asset.RiskAutomaticTicketThreshold = patchRequest.RiskAutomaticTicketThreshold
			}
		} else {
			if asset.RiskAutomaticTicketThreshold != nil {
				enableTicketRangeUpdated = true
				asset.RiskAutomaticTicketThreshold = nil
			}
		}

	} else {
		// if the enableTicketRange is set to false, we do need to call the ticket sync
		asset.CVSSAutomaticTicketThreshold = nil
		asset.RiskAutomaticTicketThreshold = nil
	}

	org := core.GetOrg(ctx)
	project := core.GetProject(ctx)
	if enableTicketRangeUpdated || justification != "" {
		go func() {
			defaultAssetVersion, err := a.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
			if err != nil {
				slog.Error("could not get default asset version", "err", err)
				return
			}

			if err := a.dependencyVulnService.SyncAllIssues(org, project, asset, defaultAssetVersion); err != nil {
				slog.Warn("could not sync tickets", "err", err)
			}
		}()
	}

	updated := patchRequest.applyToModel(&asset)
	if asset.Name == "" || asset.Slug == "" {
		return echo.NewHTTPError(409, "assets with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("assets with an empty name or an empty slug are not allowed"))
	}

	if updated || enableTicketRangeUpdated {
		err = a.assetRepository.Update(nil, &asset)
		if err != nil {
			return fmt.Errorf("error updating asset: %v", err)
		}
	}

	return ctx.JSON(200, toDTOWithSecrets(asset))
}

func (a *httpController) GetConfigFile(ctx core.Context) error {
	organization := core.GetOrg(ctx)
	project := core.GetProject(ctx)
	asset := core.GetAsset(ctx)
	configID := ctx.Param("config-file")

	configContent, ok := asset.ConfigFiles[configID]
	if !ok { //if we have no config files in this asset we want to look in the corresponding project and then in the organization
		configContent, ok = project.ConfigFiles[configID]
		if !ok {
			configContent, ok = organization.ConfigFiles[configID]
			if !ok {
				return ctx.NoContent(404)
			}
			return ctx.JSON(200, configContent)
		}
		return ctx.JSON(200, configContent)
	}
	return ctx.JSON(200, configContent)
}

func (a *httpController) GetBadges(ctx core.Context) error {

	badgeSecret := ctx.Param("badgeSecret")
	if badgeSecret == "" {
		return echo.NewHTTPError(400, "missing badge secret")
	}

	badge := ctx.Param("badge")
	if badge == "" {
		return echo.NewHTTPError(400, "missing badge")
	}

	//delete the slashes from the badge secret
	badgeSecret = strings.ReplaceAll(badgeSecret, "/", "")

	badgeSecretUUID, err := uuid.Parse(badgeSecret)
	if err != nil {
		return echo.NewHTTPError(400, "invalid badge secret").WithInternal(err)
	}

	asset, err := a.assetRepository.GetAssetIDByBadgeSecret(badgeSecretUUID)
	if err != nil {
		return echo.NewHTTPError(404, "asset not found").WithInternal(err)
	}

	assetVersion, err := a.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
	if err != nil {
		slog.Error("Error getting default asset version", "error", err)
	}

	svg := ""

	if badge == "cvss" {
		results, err := a.statisticsService.GetAssetVersionCvssDistribution(assetVersion.Name, asset.ID, asset.Name)
		if err != nil {
			return err
		}

		svg = a.assetService.GetCVSSBadgeSVG(results)
		if svg == "" {
			return echo.NewHTTPError(404, "badge not found")
		}
	} else {
		return echo.NewHTTPError(400, "invalid badge type")
	}

	ctx.Response().Header().Set(echo.HeaderContentType, "image/svg+xml")
	ctx.Response().Header().Set(echo.HeaderCacheControl, "no-cache, no-store")

	return ctx.String(200, svg)
}
