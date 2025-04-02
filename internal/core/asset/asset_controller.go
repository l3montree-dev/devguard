package asset

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/labstack/echo/v4"
)

type httpController struct {
	assetRepository core.AssetRepository
	assetService    core.AssetService
}

func NewHttpController(repository core.AssetRepository, assetService core.AssetService) *httpController {
	return &httpController{
		assetRepository: repository,
		assetService:    assetService,
	}
}

func (a *httpController) List(ctx core.Context) error {

	project := core.GetProject(ctx)

	apps, err := a.assetRepository.GetByProjectID(project.GetID())
	if err != nil {
		return err
	}

	return ctx.JSON(200, apps)
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

	if newAsset.Name == "" || newAsset.Slug == "" {
		return echo.NewHTTPError(409, "assets with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("assets with an empty name or an empty slug are not allowed"))
	}
	err := a.assetRepository.Create(nil, &newAsset)

	if err != nil {
		if database.IsDuplicateKeyError(err) {
			// get the asset by slug and project id unscoped
			asset, err := a.assetRepository.ReadBySlugUnscoped(project.GetID(), newAsset.Slug)
			if err != nil {
				return echo.NewHTTPError(500, "could not read asset").WithInternal(err)
			}

			if err = a.assetRepository.Activate(nil, asset.GetID()); err != nil {
				return echo.NewHTTPError(500, "could not activate asset").WithInternal(err)
			}
			slog.Info("Asset activated", "assetSlug", asset.Slug, "projectID", project.GetID())
			newAsset = asset
		} else {
			return echo.NewHTTPError(500, "could not create asset").WithInternal(err)
		}
	}

	return ctx.JSON(200, newAsset)
}

func (a *httpController) Read(ctx core.Context) error {
	app := core.GetAsset(ctx)

	return ctx.JSON(200, app)
}

func (c *httpController) Update(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	req := ctx.Request().Body
	defer req.Close()

	var patchRequest patchRequest

	err := json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return fmt.Errorf("Error decoding request: %v", err)
	}

	var justification string = ""
	if patchRequest.ConfidentialityRequirement != nil && *patchRequest.ConfidentialityRequirement != asset.ConfidentialityRequirement {
		justification += "Confidentiality Requirement updated: " + string(asset.ConfidentialityRequirement) + " -> " + string(*patchRequest.ConfidentialityRequirement)
		asset.ConfidentialityRequirement = *patchRequest.ConfidentialityRequirement
	}

	if patchRequest.IntegrityRequirement != nil && *patchRequest.IntegrityRequirement != asset.IntegrityRequirement {
		justification += ", Integrity Requirement updated: " + string(asset.IntegrityRequirement) + " -> " + string(*patchRequest.IntegrityRequirement)
		asset.IntegrityRequirement = *patchRequest.IntegrityRequirement
	}

	if patchRequest.AvailabilityRequirement != nil && *patchRequest.AvailabilityRequirement != asset.AvailabilityRequirement {
		justification += ", Availability Requirement updated: " + string(asset.AvailabilityRequirement) + " -> " + string(*patchRequest.AvailabilityRequirement)
		asset.AvailabilityRequirement = *patchRequest.AvailabilityRequirement
	}

	if justification != "" {
		err = c.assetService.UpdateAssetRequirements(asset, core.GetSession(ctx).GetUserID(), justification)
		if err != nil {
			return fmt.Errorf("Error updating requirements: %v", err)
		}
	}

	enableTicketRangeUpdated := false

	if patchRequest.EnableTicketRange {

		if *patchRequest.CVSSAutomaticTicketThreshold != *asset.CVSSAutomaticTicketThreshold {
			enableTicketRangeUpdated = true
			asset.CVSSAutomaticTicketThreshold = patchRequest.CVSSAutomaticTicketThreshold
		}

		if *patchRequest.RiskAutomaticTicketThreshold != *asset.RiskAutomaticTicketThreshold {
			enableTicketRangeUpdated = true
			asset.RiskAutomaticTicketThreshold = patchRequest.RiskAutomaticTicketThreshold
		}

	} else {
		if asset.CVSSAutomaticTicketThreshold != nil {
			enableTicketRangeUpdated = true
			asset.CVSSAutomaticTicketThreshold = nil
		}
		if asset.RiskAutomaticTicketThreshold != nil {
			enableTicketRangeUpdated = true
			asset.RiskAutomaticTicketThreshold = nil
		}
	}

	if enableTicketRangeUpdated {
		err = c.assetService.UpdateAssetTickets(asset)
	}

	updated := patchRequest.applyToModel(&asset)
	if asset.Name == "" || asset.Slug == "" {
		return echo.NewHTTPError(409, "assets with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("assets with an empty name or an empty slug are not allowed"))
	}

	if updated {
		err = c.assetRepository.Update(nil, &asset)
		if err != nil {
			return fmt.Errorf("error updating asset: %v", err)
		}
	}

	return ctx.JSON(200, asset)
}
