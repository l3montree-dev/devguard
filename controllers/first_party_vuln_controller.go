// TODO: rename the package name to vuln
package controllers

import (
	"encoding/json"
	"log/slog"

	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type firstPartyVulnController struct {
	firstPartyVulnRepository shared.FirstPartyVulnRepository
	firstPartyVulnService    shared.FirstPartyVulnService
	projectService           shared.ProjectService
}

type FirstPartyVulnStatus struct {
	StatusType              string                           `json:"status"`
	Justification           string                           `json:"justification"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification"`
}

func NewFirstPartyVulnController(firstPartyVulnRepository shared.FirstPartyVulnRepository, firstPartyVulnService shared.FirstPartyVulnService, projectService shared.ProjectService) *firstPartyVulnController {
	return &firstPartyVulnController{
		firstPartyVulnRepository: firstPartyVulnRepository,
		firstPartyVulnService:    firstPartyVulnService,
		projectService:           projectService,
	}
}

func (c firstPartyVulnController) ListByOrgPaged(ctx shared.Context) error {

	userAllowedProjectIds, err := c.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get projects").WithInternal(err)
	}

	pagedResp, err := c.firstPartyVulnRepository.GetDefaultFirstPartyVulnsByOrgIDPaged(
		nil,

		utils.Map(userAllowedProjectIds, func(p models.Project) string {
			return p.GetID().String()
		}),
		shared.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get first party vulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(firstPartyVuln models.FirstPartyVuln) any {
		return convertFirstPartyVulnToDetailedDTO(firstPartyVuln)
	}))
}

func (c firstPartyVulnController) ListByProjectPaged(ctx shared.Context) error {
	project := shared.GetProject(ctx)

	pagedResp, err := c.firstPartyVulnRepository.GetDefaultFirstPartyVulnsByProjectIDPaged(
		nil,
		project.ID,

		shared.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get first party vulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(firstPartyVuln models.FirstPartyVuln) any {
		return convertFirstPartyVulnToDetailedDTO(firstPartyVuln)
	}))
}

func (c firstPartyVulnController) Mitigate(ctx shared.Context) error {
	firstPartyVulnID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid firstPartyVulnID")
	}

	thirdPartyIntegrations := shared.GetThirdPartyIntegration(ctx)

	var j struct {
		Justification string `json:"justification"`
	}

	err = json.NewDecoder(ctx.Request().Body).Decode(&j)
	if err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	if err = thirdPartyIntegrations.HandleEvent(shared.ManualMitigateEvent{
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

func (c firstPartyVulnController) Read(ctx shared.Context) error {
	firstPartyVulnID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid firstPartyVulnID")
	}

	firstPartyVuln, err := c.firstPartyVulnRepository.Read(firstPartyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find firstPartyVuln")
	}

	return ctx.JSON(200, convertFirstPartyVulnToDetailedDTO(firstPartyVuln))
}
func (c firstPartyVulnController) CreateEvent(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	firstPartyVulnID, _, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid firstPartyVulnID")
	}

	firstPartyVuln, err := c.firstPartyVulnRepository.Read(firstPartyVulnID)
	if err != nil {
		return echo.NewHTTPError(404, "could not find firstPartyVuln")
	}
	userID := shared.GetSession(ctx).GetUserID()

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

	err = thirdPartyIntegration.HandleEvent(shared.VulnEvent{
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

func (c firstPartyVulnController) ListPaged(ctx shared.Context) error {
	// get the asset
	assetVersion := shared.GetAssetVersion(ctx)

	pagedResp, _, err := c.firstPartyVulnRepository.GetByAssetVersionPaged(
		nil,
		assetVersion.Name,
		assetVersion.AssetID,
		shared.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get first party vulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(firstPartyVuln models.FirstPartyVuln) any {
		return convertFirstPartyVulnToDetailedDTO(firstPartyVuln)
	}))
}

func (c firstPartyVulnController) Sarif(ctx shared.Context) error {
	// get the asset
	assetVersion := shared.GetAssetVersion(ctx)

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
			}

			snippet, err := transformer.FromJSONSnippetContents(vuln)
			if err != nil {
				slog.Error("could not marshal snippet contents", "err", err)
			}
			locations := make([]common.Location, 0, len(snippet.Snippets))
			for _, snippetContent := range snippet.Snippets {
				locations = append(locations, common.Location{
					PhysicalLocation: common.PhysicalLocation{
						ArtifactLocation: common.ArtifactLocation{
							URI: vuln.URI,
						},
						Region: common.Region{
							StartLine:   snippetContent.StartLine,
							StartColumn: snippetContent.StartColumn,
							EndLine:     snippetContent.EndLine,
							EndColumn:   snippetContent.EndColumn,
							Snippet: common.Text{
								Text: snippetContent.Snippet,
							},
						},
					},
				})
			}
			result.Locations = append(result.Locations, locations...)

			run.Results = append(run.Results, result)
		}
		sarif.Runs = append(sarif.Runs, run)
	}

	return ctx.JSON(200, sarif)
}

func convertFirstPartyVulnToDetailedDTO(firstPartyVuln models.FirstPartyVuln) dtos.DetailedFirstPartyVulnDTO {
	return dtos.DetailedFirstPartyVulnDTO{
		FirstPartyVulnDTO: transformer.FirstPartyVulnToDto(firstPartyVuln),
		Events: utils.Map(firstPartyVuln.Events, func(ev models.VulnEvent) dtos.VulnEventDTO {
			return dtos.VulnEventDTO{
				ID:                      ev.ID,
				Type:                    ev.Type,
				VulnID:                  ev.VulnID,
				UserID:                  ev.UserID,
				Justification:           ev.Justification,
				MechanicalJustification: ev.MechanicalJustification,
				AssetVersionName:        getAssetVersionName(firstPartyVuln.Vulnerability, ev),
				VulnerabilityName:       firstPartyVuln.RuleName,
				ArbitraryJSONData:       ev.GetArbitraryJSONData(),
				CreatedAt:               ev.CreatedAt,
			}
		}),
	}
}
