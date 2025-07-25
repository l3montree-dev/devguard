// TODO: rename the package name to vuln
package vuln

import (
	"encoding/json"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type firstPartyVulnController struct {
	firstPartyVulnRepository core.FirstPartyVulnRepository
	firstPartyVulnService    core.FirstPartyVulnService
	projectService           core.ProjectService
}

type FirstPartyVulnStatus struct {
	StatusType              string                             `json:"status"`
	Justification           string                             `json:"justification"`
	MechanicalJustification models.MechanicalJustificationType `json:"mechanicalJustification"`
}

func NewFirstPartyVulnController(firstPartyVulnRepository core.FirstPartyVulnRepository, firstPartyVulnService core.FirstPartyVulnService, projectService core.ProjectService) *firstPartyVulnController {
	return &firstPartyVulnController{
		firstPartyVulnRepository: firstPartyVulnRepository,
		firstPartyVulnService:    firstPartyVulnService,
		projectService:           projectService,
	}
}

func (c firstPartyVulnController) ListByOrgPaged(ctx core.Context) error {

	userAllowedProjectIds, err := c.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get projects").WithInternal(err)
	}

	pagedResp, err := c.firstPartyVulnRepository.GetDefaultFirstPartyVulnsByOrgIDPaged(
		nil,

		utils.Map(userAllowedProjectIds, func(p models.Project) string {
			return p.GetID().String()
		}),
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get first party vulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(firstPartyVuln models.FirstPartyVuln) any {
		return convertFirstPartyVulnToDetailedDTO(firstPartyVuln)
	}))
}

func (c firstPartyVulnController) ListByProjectPaged(ctx core.Context) error {
	project := core.GetProject(ctx)

	pagedResp, err := c.firstPartyVulnRepository.GetDefaultFirstPartyVulnsByProjectIDPaged(
		nil,
		project.ID,

		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get first party vulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(firstPartyVuln models.FirstPartyVuln) any {
		return convertFirstPartyVulnToDetailedDTO(firstPartyVuln)
	}))
}

func (c firstPartyVulnController) Mitigate(ctx core.Context) error {
	firstPartyVulnID, _, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid firstPartyVulnID")
	}

	thirdPartyIntegrations := core.GetThirdPartyIntegration(ctx)

	var j struct {
		Justification string `json:"justification"`
	}

	err = json.NewDecoder(ctx.Request().Body).Decode(&j)
	if err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	if err = thirdPartyIntegrations.HandleEvent(core.ManualMitigateEvent{
		Justification: j.Justification,
		Ctx:           ctx,
	}); err != nil {
		return echo.NewHTTPError(500, "could not mitigate firstPartyVuln").WithInternal(err)
	}

	// fetch the firstPartyVuln again from the database. We do not know anything what might have changed. The third party integrations might have changed the state of the vuln.
	firstPartyVuln, err := c.firstPartyVulnRepository.Read(firstPartyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find firstPartyVuln")
	}

	return ctx.JSON(200, convertFirstPartyVulnToDetailedDTO(firstPartyVuln))
}

func (c firstPartyVulnController) Read(ctx core.Context) error {
	firstPartyVulnID, _, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid firstPartyVulnID")
	}

	firstPartyVuln, err := c.firstPartyVulnRepository.Read(firstPartyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find firstPartyVuln")
	}

	return ctx.JSON(200, convertFirstPartyVulnToDetailedDTO(firstPartyVuln))
}
func (c firstPartyVulnController) CreateEvent(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	firstPartyVulnID, _, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid firstPartyVulnID")
	}

	firstPartyVuln, err := c.firstPartyVulnRepository.Read(firstPartyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find firstPartyVuln")
	}
	userID := core.GetSession(ctx).GetUserID()

	var status FirstPartyVulnStatus
	err = json.NewDecoder(ctx.Request().Body).Decode(&status)
	if err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	statusType := status.StatusType
	err = models.CheckStatusType(statusType)
	if err != nil {
		slog.Error("invalid status type", "statusType", statusType, "err", err)
		return echo.NewHTTPError(400, "invalid status type")
	}
	justification := status.Justification

	mechanicalJustification := status.MechanicalJustification

	ev, err := c.firstPartyVulnService.UpdateFirstPartyVulnState(nil, userID, &firstPartyVuln, statusType, justification, mechanicalJustification)
	if err != nil {
		return err
	}

	err = thirdPartyIntegration.HandleEvent(core.VulnEvent{
		Ctx:   ctx,
		Event: ev,
	})
	// we do not want the transaction to be rolled back if the third party integration fails
	if err != nil {
		// just log the error
		slog.Error("could not handle event", "err", err)
	}

	return ctx.JSON(200, convertFirstPartyVulnToDetailedDTO(firstPartyVuln))
}

func (c firstPartyVulnController) ListPaged(ctx core.Context) error {
	// get the asset
	assetVersion := core.GetAssetVersion(ctx)

	pagedResp, _, err := c.firstPartyVulnRepository.GetByAssetVersionPaged(
		nil,
		assetVersion.Name,
		assetVersion.AssetID,
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get first party vulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(firstPartyVuln models.FirstPartyVuln) any {
		return convertFirstPartyVulnToDetailedDTO(firstPartyVuln)
	}))
}

func (c firstPartyVulnController) Sarif(ctx core.Context) error {
	// get the asset
	assetVersion := core.GetAssetVersion(ctx)

	vulns, err := c.firstPartyVulnRepository.GetByAssetVersion(
		nil,
		assetVersion.Name,
		assetVersion.AssetID,
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get first party vulns").WithInternal(err)
	}
	sarif := common.SarifResult{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/123e95847b13fbdd4cbe2120fa5e33355d4a042b/Schemata/sarif-schema-2.1.0.json",
		Runs:    make([]common.Run, 0),
	}

	// group the vulns by scanner
	scannerVulns := make(map[string][]models.FirstPartyVuln)
	for _, vuln := range vulns {
		if vuln.ScannerIDs == "" {
			slog.Warn("firstPartyVuln has no scannerIDs", "vulnID", vuln.ID)
			continue
		}
		scannerID := vuln.ScannerIDs
		if _, ok := scannerVulns[scannerID]; !ok {
			scannerVulns[scannerID] = make([]models.FirstPartyVuln, 0)
		}
		scannerVulns[scannerID] = append(scannerVulns[scannerID], vuln)
	}

	// create a run for each scanner
	for scannerID, vulns := range scannerVulns {
		run := common.Run{
			Tool: common.Tool{
				Driver: common.Driver{
					Name:  scannerID,
					Rules: make([]common.Rule, 0),
				},
			},
			Results: make([]common.Result, 0),
		}

		addedRuleIDs := make(map[string]bool)
		for _, vuln := range vulns {
			if _, exists := addedRuleIDs[vuln.RuleID]; !exists {
				rule := common.Rule{
					ID:               vuln.RuleID,
					Name:             vuln.RuleName,
					FullDescription:  common.Text{Text: vuln.RuleDescription},
					Help:             common.Text{Text: vuln.RuleHelp},
					HelpURI:          vuln.RuleHelpURI,
					ShortDescription: common.Text{Text: vuln.RuleName},
					Properties:       vuln.RuleProperties,
				}
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
				addedRuleIDs[vuln.RuleID] = true
			}
			result := common.Result{
				Kind:   "issue",
				RuleID: vuln.RuleID,
				Message: common.Text{
					Text: vuln.RuleDescription,
				},
				Locations: []common.Location{
					{
						PhysicalLocation: common.PhysicalLocation{
							ArtifactLocation: common.ArtifactLocation{
								URI: vuln.URI,
							},
							Region: common.Region{
								StartLine:   vuln.StartLine,
								StartColumn: vuln.StartColumn,
								EndLine:     vuln.EndLine,
								EndColumn:   vuln.EndColumn,
								Snippet: common.Text{
									Text: vuln.Snippet,
								},
							},
						},
					},
				},
			}
			run.Results = append(run.Results, result)
		}
		sarif.Runs = append(sarif.Runs, run)
	}

	return ctx.JSON(200, sarif)
}

func convertFirstPartyVulnToDetailedDTO(firstPartyVuln models.FirstPartyVuln) detailedFirstPartyVulnDTO {
	return detailedFirstPartyVulnDTO{
		FirstPartyVulnDTO: FirstPartyVulnToDto(firstPartyVuln),
		Events: utils.Map(firstPartyVuln.Events, func(ev models.VulnEvent) events.VulnEventDTO {
			return events.VulnEventDTO{
				ID:                      ev.ID,
				Type:                    ev.Type,
				VulnID:                  ev.VulnID,
				UserID:                  ev.UserID,
				Justification:           ev.Justification,
				MechanicalJustification: ev.MechanicalJustification,
				AssetVersionName:        firstPartyVuln.AssetVersionName,
				VulnerabilityName:       firstPartyVuln.RuleName,
				ArbitraryJSONData:       ev.GetArbitraryJSONData(),
				CreatedAt:               ev.CreatedAt,
			}
		}),
	}
}
