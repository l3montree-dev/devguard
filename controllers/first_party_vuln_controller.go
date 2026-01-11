// TODO: rename the package name to vuln
package controllers

import (
	"encoding/json"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type FirstPartyVulnController struct {
	firstPartyVulnRepository shared.FirstPartyVulnRepository
	firstPartyVulnService    shared.FirstPartyVulnService
	projectService           shared.ProjectService
}

type FirstPartyVulnStatus struct {
	StatusType              string                           `json:"status"`
	Justification           string                           `json:"justification"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification"`
}

func NewFirstPartyVulnController(firstPartyVulnRepository shared.FirstPartyVulnRepository, firstPartyVulnService shared.FirstPartyVulnService, projectService shared.ProjectService) *FirstPartyVulnController {
	return &FirstPartyVulnController{
		firstPartyVulnRepository: firstPartyVulnRepository,
		firstPartyVulnService:    firstPartyVulnService,
		projectService:           projectService,
	}
}

// @Summary List first-party vulnerabilities by organization
// @Tags Vulnerabilities
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param search query string false "Search term"
// @Success 200 {object} object
// @Router /organizations/{organization}/vulns [get]
func (c FirstPartyVulnController) ListByOrgPaged(ctx shared.Context) error {

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

// @Summary List first-party vulnerabilities by project
// @Tags Vulnerabilities
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param search query string false "Search term"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/vulns [get]
func (c FirstPartyVulnController) ListByProjectPaged(ctx shared.Context) error {
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

func (c FirstPartyVulnController) Mitigate(ctx shared.Context) error {
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

// @Summary Get first-party vulnerability details
// @Tags Vulnerabilities
// @Security CookieAuth
// @Security PATAuth
// @Param vulnID path string true "Vulnerability ID"
// @Success 200 {object} dtos.DetailedFirstPartyVulnDTO
// @Router /vulns/{vulnID} [get]
func (c FirstPartyVulnController) Read(ctx shared.Context) error {
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
// @Summary Create first-party vulnerability event
// @Tags Vulnerabilities
// @Security CookieAuth
// @Security PATAuth
// @Param vulnID path string true "Vulnerability ID"
// @Param body body object true "Event data"
// @Success 200 {object} dtos.DetailedFirstPartyVulnDTO
// @Router /vulns/{vulnID}/events [post]
func (c FirstPartyVulnController) CreateEvent(ctx shared.Context) error {
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

// @Summary List first-party vulnerabilities by asset version
// @Tags Vulnerabilities
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param search query string false "Search term"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/vulns [get]
func (c FirstPartyVulnController) ListPaged(ctx shared.Context) error {
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

// @Summary Get first-party vulnerabilities as SARIF
// @Tags Vulnerabilities
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/vulns.sarif [get]
func (c FirstPartyVulnController) Sarif(ctx shared.Context) error {
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
	report := sarif.SarifSchema210Json{
		Version: "2.1.0",
		Schema:  utils.Ptr("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/123e95847b13fbdd4cbe2120fa5e33355d4a042b/Schemata/sarif-schema-2.1.0.json"),
		Runs:    make([]sarif.Run, 0),
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
		run := sarif.Run{
			Tool: sarif.Tool{
				Driver: sarif.ToolComponent{
					Name:  scannerID,
					Rules: make([]sarif.ReportingDescriptor, 0),
				},
			},
			Results: make([]sarif.Result, 0),
		}

		addedRuleIDs := make(map[string]bool)
		for _, vuln := range vulns {
			if _, exists := addedRuleIDs[vuln.RuleID]; !exists {
				rule := sarif.ReportingDescriptor{
					ID:               vuln.RuleID,
					Name:             &vuln.RuleName,
					FullDescription:  &sarif.MultiformatMessageString{Text: vuln.RuleDescription},
					Help:             &sarif.MultiformatMessageString{Text: vuln.RuleHelp},
					HelpURI:          &vuln.RuleHelpURI,
					ShortDescription: &sarif.MultiformatMessageString{Text: vuln.RuleName},
					Properties: &sarif.PropertyBag{
						AdditionalProperties: vuln.RuleProperties,
					},
				}
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
				addedRuleIDs[vuln.RuleID] = true
			}
			result := sarif.Result{
				Kind:   "issue",
				RuleID: &vuln.RuleID,
				Message: sarif.Message{
					Text: vuln.RuleDescription,
				},
			}

			snippet, err := transformer.FromJSONSnippetContents(vuln)
			if err != nil {
				slog.Error("could not marshal snippet contents", "err", err)
			}
			locations := make([]sarif.Location, 0, len(snippet.Snippets))
			for _, snippetContent := range snippet.Snippets {
				locations = append(locations, sarif.Location{
					PhysicalLocation: sarif.PhysicalLocation{
						ArtifactLocation: sarif.ArtifactLocation{
							URI: &vuln.URI,
						},
						Region: &sarif.Region{
							StartLine:   &snippetContent.StartLine,
							StartColumn: &snippetContent.StartColumn,
							EndLine:     &snippetContent.EndLine,
							EndColumn:   &snippetContent.EndColumn,
							Snippet: &sarif.ArtifactContent{
								Text: &snippetContent.Snippet,
							},
						},
					},
				})
			}
			result.Locations = append(result.Locations, locations...)

			run.Results = append(run.Results, result)
		}
		report.Runs = append(report.Runs, run)
	}

	return ctx.JSON(200, report)
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
				AssetVersionName:        transformer.GetAssetVersionName(firstPartyVuln.Vulnerability, ev),
				VulnerabilityName:       firstPartyVuln.RuleName,
				ArbitraryJSONData:       ev.GetArbitraryJSONData(),
				CreatedAt:               ev.CreatedAt,
			}
		}),
	}
}
