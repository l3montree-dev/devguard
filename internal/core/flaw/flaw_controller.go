package flaw

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/database/repositories"
	"github.com/l3montree-dev/flawfix/internal/obj"
	"github.com/labstack/echo/v4"
)

type repository interface {
	repositories.Repository[uuid.UUID, models.Flaw, core.DB]

	GetByAssetId(tx core.DB, assetId uuid.UUID) ([]models.Flaw, error)
	GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.Flaw], error)
}

type assetRepository interface {
	GetComponentDepth(assetID uuid.UUID) []obj.ComponentDepth
}

type flawHttpController struct {
	flawRepository  repository
	assetRepository assetRepository
}

func NewHttpController(flawRepository repository, assetRepository assetRepository) *flawHttpController {
	return &flawHttpController{
		flawRepository:  flawRepository,
		assetRepository: assetRepository,
	}
}

func (c flawHttpController) ListPaged(ctx core.Context) error {
	// get the asset
	asset := core.GetAsset(ctx)

	c.assetRepository.GetComponentDepth(asset.GetID())

	pagedResp, err := c.flawRepository.GetByAssetIdPaged(
		nil,
		core.GetPageInfo(ctx),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
		asset.GetID(),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get flaws").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(flaw models.Flaw) interface{} {
		/*
			type pagedFlawDTO struct {
				ID                string           `json:"id"`
				ScannerID         string           `json:"scanner"`
				Message           *string          `json:"message"`
				AssetID           string           `json:"assetId"`
				State             models.FlawState `json:"state"`
				CVE               *models.CVE      `json:"cve"`
				CVEID             string           `json:"cveId"`
				Effort            *int             `json:"effort"`
				RiskAssessment    *int             `json:"riskAssessment"`
				RawRiskAssessment *int             `json:"rawRiskAssessment"`
				Priority          *int             `json:"priority"`
				ArbitraryJsonData    map[string]any   `json:"arbitraryJsonData"`
				LastDetected      time.Time        `json:"lastDetected"`
				CreatedAt         time.Time        `json:"createdAt"`
			}

		*/
		return pagedFlawDTO{
			ID:                 flaw.ID,
			ScannerID:          flaw.ScannerID,
			Message:            flaw.Message,
			AssetID:            flaw.AssetID.String(),
			State:              flaw.State,
			CVE:                flaw.CVE,
			Component:          flaw.Component,
			CVEID:              flaw.CVEID,
			ComponentPurlOrCpe: flaw.ComponentPurlOrCpe,
			Effort:             flaw.Effort,
			RiskAssessment:     flaw.RiskAssessment,
			RawRiskAssessment:  flaw.RawRiskAssessment,
			Priority:           flaw.Priority,
			ArbitraryJsonData:  flaw.GetArbitraryJsonData(),
			LastDetected:       flaw.LastDetected,
			CreatedAt:          flaw.CreatedAt,
		}
	}))
}

func (c flawHttpController) Read(ctx core.Context) error {
	flawId, err := core.GetFlawID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid flaw id")
	}

	flaw, err := c.flawRepository.Read(flawId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find flaw")
	}

	// get all the associated cwes

	return ctx.JSON(200, flaw)
}
