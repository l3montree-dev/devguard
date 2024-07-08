package vulndb

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

type repository interface {
	FindAllListPaged(tx database.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.CVE], error)
	FindCVE(tx database.DB, cveId string) (any, error)
}

type cveHttpController struct {
	cveRepository repository
}

func NewHttpController(cveRepository repository) *cveHttpController {
	return &cveHttpController{
		cveRepository: cveRepository,
	}
}

// @Summary List all CVEs with pagination
// @Description Get a paginated list of CVEs with optional filtering and sorting
// @Tags CVE
// @Produce json
// @Param page query int false "Page number"
// @Param limit query int false "Number of items per page"
// @Param sort query string false "Sort by field, e.g. 'sort[cve]=asc"
// @Param filter query string false "Filter query, e.g. 'filterQuery[cvss][is greater than]=4'"
// @Param confidentialityRequirements query string false "Confidentiality Requirements (low, medium, high), default is medium"
// @Param integrityRequirements query string false "Integrity Requirements (low, medium, high), default is medium"
// @Param availabilityRequirements query string false "Availability Requirements (low, medium, high), default is medium"
// @Success 200 {object} object{pageSize=int,page=int,total=int,data=[]models.CVE} "A paginated list of CVEs"
// @Failure 500 {object} object{message=string} "Internal server error"
// @Router /vulndb [get]
func (c cveHttpController) ListPaged(ctx core.Context) error {
	pagedResp, err := c.cveRepository.FindAllListPaged(
		nil,
		core.GetPageInfo(ctx),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get CVEs").WithInternal(err)
	}

	env := core.GetEnvironmental(ctx)

	for i, cve := range pagedResp.Data {
		risk, vector := risk.RiskCalculation(cve, env)
		pagedResp.Data[i].Vector = vector
		pagedResp.Data[i].Risk = risk
	}

	return ctx.JSON(200, pagedResp)
}

// @Summary Get a specific CVE by ID
// @Description Retrieve details of a specific CVE by its ID, including risk and vector calculations
// @Tags CVE
// @Produce json
// @Param cveId path string true "CVE ID"
// @Param confidentialityRequirements query string false "Confidentiality Requirements (low, medium, high), default is medium"
// @Param integrityRequirements query string false "Integrity Requirements (low, medium, high), default is medium"
// @Param availabilityRequirements query string false "Availability Requirements (low, medium, high), default is medium"
// @Success 200 {object} models.CVE "Details of the specified CVE"
// @Failure 500 {object} object{message=string} "Internal server error"
// @Router /vulndb/{cveId}/ [get]
func (c cveHttpController) Read(ctx core.Context) error {
	pagedResp, err := c.cveRepository.FindCVE(
		nil,
		core.GetParam(ctx, "cveId"),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get CVEs").WithInternal(err)
	}
	cve := pagedResp.(models.CVE)

	e := core.GetEnvironmental(ctx)

	risk, vector := risk.RiskCalculation(cve, e)
	cve.Risk = risk
	cve.Vector = vector

	return ctx.JSON(200, cve)
}
