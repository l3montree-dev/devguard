package attestation

import (
	"encoding/json"
	"io"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/compliance"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type attestationController struct {
	attestationRepository     core.AttestationRepository
	assetVersionRepository    core.AssetVersionRepository
	policyViolationRepository core.PolicyViolationRepository
	complianceService         core.ComplianceService
}

func NewAttestationController(repository core.AttestationRepository, assetVersionRepository core.AssetVersionRepository, policyViolationRepository core.PolicyViolationRepository, complianceService core.ComplianceService) *attestationController {
	return &attestationController{
		attestationRepository:     repository,
		assetVersionRepository:    assetVersionRepository,
		policyViolationRepository: policyViolationRepository,
		complianceService:         complianceService,
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

	defaultBranch := ctx.Request().Header.Get("X-Asset-Default-Branch")
	assetVersionName := ctx.Request().Header.Get("X-Asset-Ref")
	if assetVersionName == "" {
		slog.Warn("no X-Asset-Ref header found. Using main as ref name")
		assetVersionName = "main"
	}

	assetVersion, err := a.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, assetVersionName, defaultBranch)
	if err != nil {
		slog.Error("could not find or create asset version", "err", err)
		return err
	}

	attestation.AssetVersionName = assetVersion.Name
	attestation.AssetID = asset.ID
	attestation.AttestationName = ctx.Request().Header.Get("X-Attestation-Name")

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

	// validate the attestation against the policies
	evals, err := a.complianceService.EvalPolicies([]models.Attestation{attestation})
	foundViolations := compliance.ViolationsFromEvals(assetVersionName, asset.ID, evals)
	// get the current policy state for this
	existingPolicyViolations, err := a.policyViolationRepository.GetByAttestationName(attestation.AttestationName, assetVersionName, asset.ID)
	if err != nil {
		return err
	}

	// diff the existing policy violations with the new ones
	comparison := utils.CompareSlices(existingPolicyViolations, foundViolations, func(el models.PolicyViolation) string {
		return el.PolicyID
	})

	return nil
}
