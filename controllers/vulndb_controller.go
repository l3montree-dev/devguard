package controllers

import (
	"net/url"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/labstack/echo/v4"
	"github.com/package-url/packageurl-go"
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

// @Summary Inspect a package URL (PURL) for vulnerabilities
// @Description Analyze a given PURL, determine its match context, and return affected components and related vulnerabilities
// @Tags VulnDB
// @Produce json
// @Param purl path string true "Package URL (PURL) to inspect"
// @Success 200 {object} object "Inspection result including PURL, match context, affected components, and vulnerabilities"
// @Failure 400 {object} object{message=string} "Invalid PURL provided"
// @Failure 500 {object} object{message=string} "Internal server error"
// @Router /vulndb/purl/{purl}/ [get]
func (c VulnDBController) PURLInspect(ctx shared.Context) error {
	purlString := shared.GetParam(ctx, "purl")

	purlString, err := url.QueryUnescape(purlString)
	if err != nil {
		return echo.NewHTTPError(400, "invalid URL encoding in PURL").WithInternal(err)
	}

	//delete the last slash if exists
	purlString = strings.TrimSuffix(purlString, "/")

	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return echo.NewHTTPError(400, "invalid PURL").WithInternal(err)
	}

	matchCtx := normalize.ParsePurlForMatching(purl)

	purlComparer := scan.NewPurlComparer(c.cveRepository.GetDB(nil))

	affectedComponents, err := purlComparer.GetAffectedComponents(purl)
	if err != nil {
		return echo.NewHTTPError(500, "failed to retrieve affected components for PURL").WithInternal(err)
	}

	vulns, err := purlComparer.GetVulns(purl)
	if err != nil {
		return echo.NewHTTPError(500, "failed to retrieve vulnerabilities for PURL").WithInternal(err)
	}

	return ctx.JSON(200, struct {
		PURL               packageurl.PackageURL       `json:"purl"`
		MatchContext       *normalize.PurlMatchContext `json:"matchContext"`
		AffectedComponents []models.AffectedComponent  `json:"affectedComponents"`
		Vulns              []models.VulnInPackage      `json:"vulns"`
	}{
		PURL:               purl,
		MatchContext:       matchCtx,
		AffectedComponents: affectedComponents,
		Vulns:              vulns,
	})
}
