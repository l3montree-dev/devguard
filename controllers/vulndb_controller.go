package controllers

import (
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/labstack/echo/v4"
)

type VulnDBController struct {
	cveRepository shared.CveRepository
}

func NewVulnDBController(cveRepository shared.CveRepository) *VulnDBController {
	return &VulnDBController{
		cveRepository: cveRepository,
	}
}

// @Summary List all CVEs with pagination
// @Tags CVE Database
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
func (c VulnDBController) ListPaged(ctx shared.Context) error {
	pagedResp, err := c.cveRepository.FindAllListPaged(
		nil,
		shared.GetPageInfo(ctx),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get CVEs").WithInternal(err)
	}

	env := shared.GetEnvironmental(ctx)

	for i, cve := range pagedResp.Data {
		risk, vector := vulndb.RiskCalculation(cve, env)
		pagedResp.Data[i].Vector = vector
		pagedResp.Data[i].Risk = risk
	}

	return ctx.JSON(200, pagedResp)
}

// @Summary Get a specific CVE by ID
// @Tags CVE Database
// @Description Retrieve details of a specific CVE by its ID, including risk and vector calculations
// @Tags CVE
// @Produce json
// @Param cveID path string true "CVE ID"
// @Param confidentialityRequirements query string false "Confidentiality Requirements (low, medium, high), default is medium"
// @Param integrityRequirements query string false "Integrity Requirements (low, medium, high), default is medium"
// @Param availabilityRequirements query string false "Availability Requirements (low, medium, high), default is medium"
// @Success 200 {object} models.CVE "Details of the specified CVE"
// @Failure 500 {object} object{message=string} "Internal server error"
// @Router /vulndb/{cveID}/ [get]
func (c VulnDBController) Read(ctx shared.Context) error {
	cve, err := c.cveRepository.FindCVE(
		nil,
		shared.GetParam(ctx, "cveID"),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get CVEs").WithInternal(err)
	}

	e := shared.GetEnvironmental(ctx)

	risk, vector := vulndb.RiskCalculation(cve, e)
	cve.Risk = risk
	cve.Vector = vector

	return ctx.JSON(200, cve)
}
