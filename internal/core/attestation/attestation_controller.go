package attestation

import (
	"encoding/json"
	"io"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type attestationController struct {
	attestationRepository  core.AttestationRepository
	assetVersionRepository core.AssetVersionRepository
}

func NewAttestationController(repository core.AttestationRepository, assetVersionRepository core.AssetVersionRepository) *attestationController {
	return &attestationController{
		attestationRepository:  repository,
		assetVersionRepository: assetVersionRepository,
	}
}

func (a *attestationController) List(ctx core.Context) error {

	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)

	attestationList, err := a.attestationRepository.GetByAssetVersionAndAssetID(asset.GetID(), assetVersion.Name)
	if err != nil {
		return err
	}

	return ctx.JSON(200, attestationList)
}

func (a *attestationController) Create(ctx core.Context) error {
	var attestation models.Attestation
	jsonContent := make(map[string]any)

	asset := core.GetAsset(ctx)

	isTag := ctx.Request().Header.Get("X-Tag")
	defaultBranch := ctx.Request().Header.Get("X-Asset-Default-Branch")
	assetVersionName := ctx.Request().Header.Get("X-Asset-Ref")
	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
	}

	assetVersion, err := a.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, isTag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		return err
	}

	attestation.AssetVersionName = assetVersion.Name
	attestation.AssetID = asset.ID
	attestation.PredicateType = ctx.Request().Header.Get("X-Attestation-Name")
	attestation.ScannerID = ctx.Request().Header.Get("X-Scanner")

	content, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return echo.NewHTTPError(400, "unable to bind data to attestation model").WithInternal(err)
	}

	err = json.Unmarshal(content, &jsonContent) //convert the byte array from io.ReadAll into a readable json
	if err != nil {
		return err
	}

	err = core.V.Struct(attestation)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	attestation.Content = jsonContent
	err = a.attestationRepository.Create(nil, &attestation)
	if err != nil {
		return err
	}

	return nil
}
