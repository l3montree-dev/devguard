// TODO: rename the package name to vuln
package dependency_vuln

import (
	"encoding/json"
	"log/slog"

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
	StatusType    string `json:"statusType"`
	Justification string `json:"justification"`
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

	pagedResp, err := c.firstPartyVulnRepository.GetDefaultFirstPartyVulnsByOrgIdPaged(
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
		return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(firstPartyVuln models.FirstPartyVulnerability) any {
		return convertFirstPartyVulnToDetailedDTO(firstPartyVuln)
	}))
}

func (c firstPartyVulnController) ListByProjectPaged(ctx core.Context) error {
	project := core.GetProject(ctx)

	pagedResp, err := c.firstPartyVulnRepository.GetDefaultFirstPartyVulnsByProjectIdPaged(
		nil,
		project.ID,

		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(firstPartyVuln models.FirstPartyVulnerability) any {
		return convertFirstPartyVulnToDetailedDTO(firstPartyVuln)
	}))
}

func (c firstPartyVulnController) Mitigate(ctx core.Context) error {
	firstPartyVulnId, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid firstPartyVulnId")
	}

	thirdPartyIntegrations := core.GetThirdPartyIntegration(ctx)

	if err = thirdPartyIntegrations.HandleEvent(core.ManualMitigateEvent{
		Ctx: ctx,
	}); err != nil {
		return echo.NewHTTPError(500, "could not mitigate firstPartyVuln").WithInternal(err)
	}

	// fetch the firstPartyVuln again from the database. We do not know anything what might have changed. The third party integrations might have changed the state of the dependency_vuln.
	firstPartyVuln, err := c.firstPartyVulnRepository.Read(firstPartyVulnId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find dependencyVuln")
	}

	return ctx.JSON(200, convertFirstPartyVulnToDetailedDTO(firstPartyVuln))
}

func (c firstPartyVulnController) Read(ctx core.Context) error {
	firstPartyVulnId, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid firstPartyVulnId")
	}

	firstPartyVuln, err := c.firstPartyVulnRepository.Read(firstPartyVulnId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find firstPartyVuln")
	}

	return ctx.JSON(200, convertFirstPartyVulnToDetailedDTO(firstPartyVuln))
}
func (c firstPartyVulnController) CreateEvent(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	firstPartyVulnId, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid firstPartyVulnId")
	}

	firstPartyVuln, err := c.firstPartyVulnRepository.Read(firstPartyVulnId)
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
		return echo.NewHTTPError(400, "invalid status type")
	}
	justification := status.Justification

	err = c.firstPartyVulnRepository.Transaction(func(tx core.DB) error {
		ev, err := c.firstPartyVulnService.UpdateFirstPartyVulnState(tx, userID, &firstPartyVuln, statusType, justification)
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
		return nil
	})
	if err != nil {
		return echo.NewHTTPError(500, "could not create dependencyVuln event").WithInternal(err)
	}

	return ctx.JSON(200, convertFirstPartyVulnToDetailedDTO(firstPartyVuln))
}

func (c firstPartyVulnController) ListPaged(ctx core.Context) error {
	// get the asset
	assetVersion := core.GetAssetVersion(ctx)

	// check if we should list flat - this means not grouped by package
	if ctx.QueryParam("flat") == "true" {
		firstPartyVulns, err := c.firstPartyVulnRepository.GetFirstPartyVulnsByAssetIdPagedAndFlat(nil, assetVersion.Name, assetVersion.AssetID, core.GetPageInfo(ctx), ctx.QueryParam("search"), core.GetFilterQuery(ctx), core.GetSortQuery(ctx))
		if err != nil {
			return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
		}

		return ctx.JSON(200, firstPartyVulns.Map(func(firstPartyVuln models.FirstPartyVulnerability) any {
			return convertFirstPartyVulnToDetailedDTO(firstPartyVuln)
		}))
	}

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
		return echo.NewHTTPError(500, "could not get dependencyVulns").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(firstPartyVuln models.FirstPartyVulnerability) any {
		return convertFirstPartyVulnToDetailedDTO(firstPartyVuln)
	}))

}

func convertFirstPartyVulnToDetailedDTO(firstPartyVuln models.FirstPartyVulnerability) detailedFirstPartyVulnDTO {
	return detailedFirstPartyVulnDTO{
		FirstPartyVulnDTO: FirstPartyVulnDTO{
			ID:          firstPartyVuln.ID,
			ScannerIDs:  firstPartyVuln.ScannerIDs,
			Message:     firstPartyVuln.Message,
			AssetID:     firstPartyVuln.AssetID.String(),
			State:       firstPartyVuln.State,
			RuleID:      firstPartyVuln.RuleID,
			Uri:         firstPartyVuln.Uri,
			StartLine:   firstPartyVuln.StartLine,
			StartColumn: firstPartyVuln.StartColumn,
			EndLine:     firstPartyVuln.EndLine,
			EndColumn:   firstPartyVuln.EndColumn,
			Snippet:     firstPartyVuln.Snippet,
			CreatedAt:   firstPartyVuln.CreatedAt,
			TicketID:    firstPartyVuln.TicketID,
			TicketURL:   firstPartyVuln.TicketURL,
			Commit:      firstPartyVuln.Commit,
			Email:       firstPartyVuln.Email,
			Author:      firstPartyVuln.Author,
			Date:        firstPartyVuln.Date,
		},
		Events: utils.Map(firstPartyVuln.Events, func(ev models.VulnEvent) events.VulnEventDTO {
			return events.VulnEventDTO{
				ID:                ev.ID,
				Type:              ev.Type,
				VulnID:            ev.VulnID,
				UserID:            ev.UserID,
				Justification:     ev.Justification,
				ArbitraryJsonData: ev.GetArbitraryJsonData(),
				CreatedAt:         ev.CreatedAt,
			}
		}),
	}
}
