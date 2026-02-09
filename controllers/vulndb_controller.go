package controllers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/config"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/labstack/echo/v4"
	"github.com/package-url/packageurl-go"
)

type VulnDBController struct {
	cveRepository               shared.CveRepository
	maliciousPackageChecker     shared.MaliciousPackageChecker
	affectedComponentRepository shared.AffectedComponentRepository
}

func NewVulnDBController(cveRepository shared.CveRepository, maliciousPackageChecker shared.MaliciousPackageChecker, affectedComponentRepository shared.AffectedComponentRepository) *VulnDBController {
	return &VulnDBController{
		cveRepository:               cveRepository,
		maliciousPackageChecker:     maliciousPackageChecker,
		affectedComponentRepository: affectedComponentRepository,
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

	_, maliciousPackage := c.maliciousPackageChecker.IsMalicious(purl.Type, fmt.Sprintf("%s/%s", purl.Namespace, purl.Name), purl.Version)

	return ctx.JSON(200, struct {
		PURL               packageurl.PackageURL       `json:"purl"`
		MatchContext       *normalize.PurlMatchContext `json:"matchContext"`
		AffectedComponents []models.AffectedComponent  `json:"affectedComponents"`
		Vulns              []models.VulnInPackage      `json:"vulns"`
		MaliciousPackage   *dtos.OSV                   `json:"maliciousPackage"`
	}{
		PURL:               purl,
		MatchContext:       matchCtx,
		AffectedComponents: affectedComponents,
		Vulns:              vulns,
		MaliciousPackage:   maliciousPackage,
	})
}

// returns a list of cve ids sorted by the creation date as well as the total amount of entries
// query parameter offset: offset the fetched data by the provided amount
// query parameter limit: limit the amount of entries in the data
func (c VulnDBController) ListIDsByCreationDate(ctx shared.Context) error {
	type listIDsRow struct {
		CVEID     string    `gorm:"column:cve"`
		CreatedAt time.Time `gorm:"column:created_at"`
	}
	type responseDTO struct {
		Count   int          `json:"total"`
		CVEData []listIDsRow `json:"data"`
	}

	// use an offset to query only a part of the data
	offset := 0
	offsetParam := ctx.QueryParam("offset")
	if offsetParam != "" {
		var err error
		offset, err = strconv.Atoi(offsetParam)
		if err != nil || offset < 0 {
			return echo.NewHTTPError(400, "invalid offset value").WithInternal(err)
		}
	}

	var err error
	results := make([]listIDsRow, 0, 1<<18)

	// use optional limit parameter to limit the amount of fetched data
	limit := 0
	limitParam := ctx.QueryParam("limit")
	if limitParam != "" {
		limit, err = strconv.Atoi(limitParam)
		if err != nil || limit <= 0 {
			return echo.NewHTTPError(400, "invalid limit value").WithInternal(err)
		}

		sql := `SELECT cve,created_at FROM cves ORDER BY created_at DESC OFFSET ? LIMIT ?;`
		err = c.cveRepository.GetDB(nil).Raw(sql, offset, limit).Find(&results).Error
	} else {
		sql := `SELECT cve,created_at FROM cves ORDER BY created_at DESC OFFSET ?;`
		err = c.cveRepository.GetDB(nil).Raw(sql, offset).Find(&results).Error
	}
	if err != nil {
		return echo.NewHTTPError(500, "could not get cve ids").WithInternal(err)
	}

	// build the response and return it
	response := responseDTO{
		Count:   len(results),
		CVEData: results,
	}
	return ctx.JSON(200, response)
}

type ecosystemRow struct {
	Ecosystem string `gorm:"ecosystem" json:"ecosystem"`
	Count     int    `gorm:"count" json:"count"`
}

// return the number of affected packages by ecosystem
func (c VulnDBController) GetEcosystemDistribution(ctx shared.Context) error {
	results := make([]ecosystemRow, 1024)

	// static sql to get amount of packages by ecosystem
	sql := `SELECT ecosystem, COUNT(*) FROM affected_components GROUP BY ecosystem;`
	err := c.affectedComponentRepository.GetDB(nil).Raw(sql).Find(&results).Error
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch data from database").WithInternal(err)
	}

	// since ecosystem have tags behind the : character we want to group them by their prefix
	jsonResults := buildResultsJSON(results)

	return ctx.String(200, jsonResults)
}

// group ecosystem by prefix ecosystem string and return the equivalent json encoding
func buildResultsJSON(rows []ecosystemRow) string {
	// map to deduplicate ecosystem with different tags
	aggregatedResults := make(map[string]int)

	// fill the map with the value of the rows
	for _, row := range rows {
		before, _, _ := strings.Cut(row.Ecosystem, ":")
		aggregatedResults[before] += row.Count
	}

	// marshal to JSON with proper indentation
	data, _ := json.MarshalIndent(aggregatedResults, "", config.PrettyJSONIndent)
	return string(data)
}
