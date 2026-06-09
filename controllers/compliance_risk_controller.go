package controllers

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type ComplianceRiskController struct {
	complianceRiskRepository shared.ComplianceRiskRepository
	complianceRiskService    shared.ComplianceRiskService
	complianceService        shared.ComplianceService
	attestationService       shared.AttestationService
	artifactRepository       shared.ArtifactRepository
}

func NewComplianceRiskController(
	repo shared.ComplianceRiskRepository,
	svc shared.ComplianceRiskService,
	complianceService shared.ComplianceService,
	attestationService shared.AttestationService,
	artifactRepository shared.ArtifactRepository,
) *ComplianceRiskController {
	return &ComplianceRiskController{
		complianceRiskRepository: repo,
		complianceRiskService:    svc,
		complianceService:        complianceService,
		attestationService:       attestationService,
		artifactRepository:       artifactRepository,
	}
}

type complianceRiskStatus struct {
	StatusType              string                           `json:"status"`
	Justification           string                           `json:"justification"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification"`
}

func convertComplianceRiskToDetailedDTO(r models.ComplianceRisk) dtos.DetailedComplianceRiskDTO {
	return dtos.DetailedComplianceRiskDTO{
		ComplianceRiskDTO: transformer.ComplianceRiskToDTO(r),
		Events: utils.Map(r.Events, func(ev models.VulnEvent) dtos.VulnEventDTO {
			return dtos.VulnEventDTO{
				ID:                       ev.ID,
				Type:                     ev.Type,
				VulnID:                   ev.GetVulnID(),
				UserID:                   ev.UserID,
				Justification:            ev.Justification,
				MechanicalJustification:  ev.MechanicalJustification,
				OriginalAssetVersionName: ev.OriginalAssetVersionName,
				VulnerabilityName:        r.PolicyID,
				ArbitraryJSONData:        ev.GetArbitraryJSONData(),
				CreatedAt:                ev.CreatedAt,
				CreatedByVexRule:         ev.CreatedByVexRule,
			}
		}),
	}
}

func (c *ComplianceRiskController) ListPaged(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)

	pagedResp, err := c.complianceRiskRepository.GetAllComplianceRisksForAssetVersionPaged(
		ctx.Request().Context(), nil,
		assetVersion.AssetID,
		assetVersion.Name,
		shared.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get compliance risks").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(r models.ComplianceRisk) any {
		return convertComplianceRiskToDetailedDTO(r)
	}))
}

func (c *ComplianceRiskController) Read(ctx shared.Context) error {
	riskID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "could not get compliance risk ID")
	}
	risk, err := c.complianceRiskRepository.Read(ctx.Request().Context(), nil, riskID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find compliance risk")
	}
	return ctx.JSON(200, convertComplianceRiskToDetailedDTO(risk))
}

func (c *ComplianceRiskController) CreateEvent(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	riskID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid compliance risk id")
	}

	risk, err := c.complianceRiskRepository.Read(ctx.Request().Context(), nil, riskID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find compliance risk")
	}

	var status complianceRiskStatus
	if err := json.NewDecoder(ctx.Request().Body).Decode(&status); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}
	if err := models.CheckStatusType(status.StatusType); err != nil {
		return echo.NewHTTPError(400, "invalid status type")
	}

	userID := shared.GetSession(ctx).GetUserID()
	userAgent := ctx.Request().UserAgent()

	event, err := c.complianceRiskService.UpdateComplianceRiskState(ctx.Request().Context(), nil, userID, &risk, status.StatusType, status.Justification, status.MechanicalJustification, &userAgent)
	if err != nil {
		return echo.NewHTTPError(500, "could not create compliance risk event").WithInternal(err)
	}

	if err := thirdPartyIntegration.HandleEvent(ctx.Request().Context(), shared.VulnEvent{
		Ctx:   ctx,
		Event: event,
	}, &userAgent); err != nil {
		slog.Error("could not handle third-party event for compliance risk", "err", err)
		return echo.NewHTTPError(500, "could not create compliance risk event").WithInternal(err)
	}

	return ctx.JSON(200, convertComplianceRiskToDetailedDTO(risk))
}

func (c *ComplianceRiskController) Mitigate(ctx shared.Context) error {
	var justification struct {
		Comment string `json:"comment"`
	}
	if err := ctx.Bind(&justification); err != nil {
		return echo.NewHTTPError(500, "could not bind the request to a justification")
	}

	riskID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid compliance risk id")
	}

	userAgent := ctx.Request().UserAgent()
	thirdPartyIntegrations := shared.GetThirdPartyIntegration(ctx)

	if err := thirdPartyIntegrations.HandleEvent(ctx.Request().Context(), shared.ManualMitigateEvent{
		Ctx:           ctx,
		Justification: justification.Comment,
	}, &userAgent); err != nil {
		return echo.NewHTTPError(500, "could not mitigate compliance risk").WithInternal(err)
	}

	risk, err := c.complianceRiskRepository.Read(ctx.Request().Context(), nil, riskID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find compliance risk")
	}
	return ctx.JSON(200, convertComplianceRiskToDetailedDTO(risk))
}

// EvaluateArtifactCompliance fetches evaluations via complianceService.ArtifactCompliance and recalculates risks.
func (c *ComplianceRiskController) EvaluateArtifactCompliance(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	artifact := shared.GetArtifact(ctx)
	project := shared.GetProject(ctx)
	userAgent := ctx.Request().UserAgent()
	userID := shared.GetSession(ctx).GetUserID()

	sarifDoc, err := c.complianceService.ArtifactCompliance(ctx.Request().Context(), project.ID, assetVersion, artifact)
	if err != nil {
		return echo.NewHTTPError(500, "could not evaluate artifact compliance").WithInternal(err)
	}

	if err := c.complianceRiskService.HandleArtifactCompliance(ctx.Request().Context(), nil, userID, &userAgent, assetVersion, artifact, sarifDoc); err != nil {
		return echo.NewHTTPError(500, "could not handle artifact compliance risks").WithInternal(err)
	}

	return ctx.JSON(200, sarifDoc)
}

// UploadZip accepts a ZIP file containing attestation files and an evaluations.json.
// It saves each attestation and then recalculates compliance risks based on the evaluations.
func (c *ComplianceRiskController) UploadZip(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	artifact := shared.GetArtifact(ctx)
	userAgent := ctx.Request().UserAgent()
	userID := shared.GetSession(ctx).GetUserID()

	file, err := ctx.FormFile("file")
	if err != nil {
		return echo.NewHTTPError(400, "missing zip file").WithInternal(err)
	}

	src, err := file.Open()
	if err != nil {
		return echo.NewHTTPError(500, "could not open zip file").WithInternal(err)
	}
	defer src.Close()

	data, err := io.ReadAll(src)
	if err != nil {
		return echo.NewHTTPError(500, "could not read zip file").WithInternal(err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return echo.NewHTTPError(400, "invalid zip file").WithInternal(err)
	}

	var sarifDoc *sarif.SarifSchema210Json

	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			slog.Warn("could not open file in zip", "name", f.Name, "err", err)
			continue
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			slog.Warn("could not read file in zip", "name", f.Name, "err", err)
			continue
		}

		if f.Name == "sarif.json" {
			var doc sarif.SarifSchema210Json
			if err := json.Unmarshal(content, &doc); err != nil {
				return echo.NewHTTPError(400, "invalid sarif.json in zip").WithInternal(err)
			}
			sarifDoc = &doc
			continue
		}

		// treat remaining files as attestations; predicateType is read from the JSON content
		var contentMap map[string]any
		if err := json.Unmarshal(content, &contentMap); err != nil {
			slog.Warn("skipping non-JSON attestation file in zip", "name", f.Name, "err", err)
			continue
		}

		predicateType, ok := contentMap["predicateType"].(string)
		if !ok || predicateType == "" {
			slog.Warn("attestation file missing predicateType field, skipping", "name", f.Name)
			continue
		}

		attestation := models.Attestation{
			AssetID:          assetVersion.AssetID,
			AssetVersionName: assetVersion.Name,
			ArtifactName:     artifact.ArtifactName,
			PredicateType:    predicateType,
			Content:          contentMap,
		}
		if err := c.attestationService.Create(ctx.Request().Context(), nil, &attestation); err != nil {
			slog.Error("could not save attestation from zip", "name", f.Name, "err", err)
		}
	}

	if sarifDoc == nil {
		return echo.NewHTTPError(400, "sarif.json not found in zip")
	}

	if err := c.complianceRiskService.HandleArtifactCompliance(ctx.Request().Context(), nil, userID, &userAgent, assetVersion, artifact, *sarifDoc); err != nil {
		return echo.NewHTTPError(500, "could not handle artifact compliance risks").WithInternal(err)
	}

	return ctx.JSON(200, sarifDoc)
}
