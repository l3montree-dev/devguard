package controllers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/config"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/labstack/echo/v4"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"
)

type VulnDBController struct {
	cveRepository               shared.CveRepository
	maliciousPackageChecker     shared.MaliciousPackageChecker
	affectedComponentRepository shared.AffectedComponentRepository
	componentRepository         shared.ComponentRepository
	componentService            shared.ComponentService
	fixedVersionResolver        shared.FixedVersionResolver
	dependencyVulnRepository    shared.DependencyVulnRepository

	// pointer, so the value-receiver methods share one cache instead of copying the lock
	ecosystemDistributionCache *ecosystemDistributionCache
}

func NewVulnDBController(cveRepository shared.CveRepository, maliciousPackageChecker shared.MaliciousPackageChecker, affectedComponentRepository shared.AffectedComponentRepository, componentRepository shared.ComponentRepository, componentService shared.ComponentService, fixedVersionResolver shared.FixedVersionResolver, dependencyVulnRepository shared.DependencyVulnRepository) *VulnDBController {
	return &VulnDBController{
		cveRepository:               cveRepository,
		maliciousPackageChecker:     maliciousPackageChecker,
		affectedComponentRepository: affectedComponentRepository,
		componentRepository:         componentRepository,
		componentService:            componentService,
		fixedVersionResolver:        fixedVersionResolver,
		dependencyVulnRepository:    dependencyVulnRepository,
		ecosystemDistributionCache:  &ecosystemDistributionCache{},
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
		ctx.Request().Context(), nil,
		shared.GetPageInfo(ctx),
		shared.GetFilterQuery(ctx),
		shared.GetSortQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get CVEs").WithInternal(err)
	}

	env := shared.GetEnvironmental(ctx)

	for i := range pagedResp.Data {
		risk, vector := vulndb.RiskCalculation(&pagedResp.Data[i], env)
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
// @Success 200 {object} models.CVE "Details of the specified CVE" and optional advisories
// @Failure 500 {object} object{message=string} "Internal server error"
// @Router /vulndb/{cveID}/ [get]
func (c VulnDBController) Read(ctx shared.Context) error {
	cve, err := c.cveRepository.FindCVE(
		ctx.Request().Context(), nil,
		shared.GetParam(ctx, "cveID"),
	)

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(404, "could not get CVEs").WithInternal(err)
		}
		return echo.NewHTTPError(500, "could not get CVEs").WithInternal(err)
	}

	related, err := c.cveRepository.GetAllRelatedCVEsForCVE(ctx.Request().Context(), nil, cve.CVE)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch advisories for cve").WithInternal(err)
	}

	relatedDTOs := map[dtos.RelationshipType][]dtos.CVEDTO{}
	for relation, relatedCVEs := range related {
		relatedDTOs[relation] = utils.Map(relatedCVEs, func(cve models.CVE) dtos.CVEDTO {
			return transformer.CVEToDTO(cve)
		})
	}

	e := shared.GetEnvironmental(ctx)

	risk, vector := vulndb.RiskCalculation(&cve, e)
	cve.Risk = risk
	cve.Vector = vector

	return ctx.JSON(200, dtos.CVEWithRelationsDTO{CVEDTO: transformer.CVEToDTO(cve), Related: relatedDTOs})
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

	purlString, err := url.PathUnescape(purlString)
	if err != nil {
		return echo.NewHTTPError(400, "invalid URL encoding in PURL").WithInternal(err)
	}

	//delete the last slash if exists
	purlString = strings.TrimSuffix(purlString, "/")

	// validate the purl structure first
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return echo.NewHTTPError(400, "invalid PURL format").WithInternal(err)
	}

	// then validate the individual fields as well
	if err := utils.ValidatePurlFields(purl); err != nil {
		return echo.NewHTTPError(400, "PURL contains invalid characters").WithInternal(err)
	}

	matchCtx := normalize.ParsePurlForMatching(purl)

	purlComparer := scan.NewPurlComparer(c.cveRepository.GetDB(ctx.Request().Context(), nil))

	affectedComponents, err := purlComparer.GetAffectedComponents(ctx.Request().Context(), purl)
	if err != nil {
		return echo.NewHTTPError(500, "failed to retrieve affected components for PURL").WithInternal(err)
	}

	vulns, err := purlComparer.GetVulns(ctx.Request().Context(), purl)
	if err != nil {
		return echo.NewHTTPError(500, "failed to retrieve vulnerabilities for PURL").WithInternal(err)
	}

	_, maliciousPackage, err := c.maliciousPackageChecker.IsMalicious(ctx.Request().Context(), purl.Type, fmt.Sprintf("%s/%s", purl.Namespace, purl.Name), purl.Version)
	if err != nil {
		return echo.NewHTTPError(400, "failed to check if package is malicious").WithInternal(err)
	}

	var componentDTO *dtos.ComponentDTO
	comp := models.Component{ID: purlString}
	if err := c.componentRepository.GetDB(ctx.Request().Context(), nil).Preload("ComponentProject").First(&comp, "id = ?", purlString).Error; err != nil { // nosemgrep: bola-gorm-first-by-id-only -- component ID is a PURL (public package identifier), not a tenant-scoped UUID; the component table has no tenant column
		// Component not in DB yet — fetch license and project info on-demand and create it
		comp, _ = c.componentService.GetLicense(ctx.Request().Context(), comp)
		comp, _ = c.componentService.FetchComponentProject(ctx.Request().Context(), comp)
		_ = c.componentRepository.SaveBatch(ctx.Request().Context(), nil, []models.Component{comp})
	} else if comp.ComponentProject == nil {
		// Component exists but has no project info yet — fetch it now
		comp, _ = c.componentService.FetchComponentProject(ctx.Request().Context(), comp)
		_ = c.componentRepository.SaveBatch(ctx.Request().Context(), nil, []models.Component{comp})
	}
	if comp.ComponentProject != nil || comp.License != nil {
		dto := transformer.ComponentModelToDTO(comp)
		componentDTO = &dto
	}

	return ctx.JSON(200, struct {
		PURL               string                      `json:"purl"`
		MatchContext       *normalize.PurlMatchContext `json:"matchContext"`
		Component          *dtos.ComponentDTO          `json:"component"`
		AffectedComponents []dtos.AffectedComponentDTO `json:"affectedComponents"`
		Vulns              []dtos.VulnInPackageDTO     `json:"vulns"`
		MaliciousPackage   *dtos.OSV                   `json:"maliciousPackage"`
	}{
		PURL:               purl.ToString(),
		MatchContext:       matchCtx,
		Component:          componentDTO,
		AffectedComponents: utils.Map(affectedComponents, transformer.AffectedComponentToDTO),
		Vulns:              utils.Map(vulns, transformer.VulnInPackageToDTO),
		MaliciousPackage:   maliciousPackage,
	})
}

// returns a list of cve ids sorted by the creation date as well as the total amount of entries
// query parameter offset: offset the fetched data by the provided amount
// query parameter limit: limit the amount of entries in the data
func (c VulnDBController) ListIDsByCreationDate(ctx shared.Context) error {
	type listIDsRow struct {
		CVEID         string    `gorm:"column:cve"`
		CreatedAt     time.Time `gorm:"column:created_at"`
		DatePublished time.Time `gorm:"column:date_published"`
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

		sql := `SELECT cve, date_published AS created_at, date_published FROM cves ORDER BY date_published DESC OFFSET ? LIMIT ?;`
		err = c.cveRepository.GetDB(ctx.Request().Context(), nil).Raw(sql, offset, limit).Find(&results).Error
	} else {
		sql := `SELECT cve, date_published AS created_at, date_published FROM cves ORDER BY date_published DESC OFFSET ?;`
		err = c.cveRepository.GetDB(ctx.Request().Context(), nil).Raw(sql, offset).Find(&results).Error
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

// the distribution aggregates the whole global vuln db (no org/user/request dimension),
// only changes when the vulndb mirror runs (~hourly) and is expensive to compute (15-20s),
// so a single cached value with a long TTL is safe
const ecosystemDistributionExpiryTime = 1 * time.Hour

type ecosystemDistributionCache struct {
	mutex      sync.RWMutex
	group      singleflight.Group
	value      map[string]int
	expiryTime time.Time
}

// nosemgrep: service-method-missing-ctx -- private in-memory cache helper; no I/O
func (c *ecosystemDistributionCache) get() (map[string]int, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if c.value == nil || c.expiryTime.Before(time.Now()) {
		return nil, false
	}
	return c.value, true
}

// nosemgrep: service-method-missing-ctx -- private in-memory cache helper; no I/O
func (c *ecosystemDistributionCache) set(value map[string]int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.value = value
	c.expiryTime = time.Now().Add(ecosystemDistributionExpiryTime)
}

// return the number of vulnerabilities in affected packages per ecosystem
func (c VulnDBController) GetCVEEcosystemDistribution(ctx shared.Context) error {
	if distribution, found := c.ecosystemDistributionCache.get(); found {
		return ctx.JSONPretty(200, distribution, config.PrettyJSONIndent)
	}

	// use singleflight to avoid concurrent recomputations of the expensive aggregation
	result, err, _ := c.ecosystemDistributionCache.group.Do("cve-ecosystem-distribution", func() (any, error) {
		if distribution, found := c.ecosystemDistributionCache.get(); found {
			return distribution, nil
		}
		distribution, err := c.computeCVEEcosystemDistribution(ctx.Request().Context())
		if err != nil {
			return nil, err
		}
		c.ecosystemDistributionCache.set(distribution)
		return distribution, nil
	})
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch data from database").WithInternal(err)
	}

	return ctx.JSONPretty(200, result.(map[string]int), config.PrettyJSONIndent)
}

func (c VulnDBController) computeCVEEcosystemDistribution(ctx context.Context) (map[string]int, error) {
	cveResults := make([]ecosystemRow, 0, 1024)
	maliciousPackageResults := make([]ecosystemRow, 0, 64)

	// count distinct CVEs per ecosystem (not cve_affected_component rows)
	cveSQL := `SELECT LOWER(b.ecosystem) as ecosystem, COUNT(DISTINCT a.cve_id) FROM cve_affected_component a
	LEFT JOIN affected_components b ON b.id = a.affected_component_id
	GROUP BY LOWER(b.ecosystem);`
	err := c.affectedComponentRepository.GetDB(ctx, nil).Raw(cveSQL).Find(&cveResults).Error
	if err != nil {
		return nil, err
	}

	// do the same thing for malicious packages
	maliciousPackagesSQL := `SELECT LOWER(b.ecosystem) as ecosystem, COUNT(*) FROM malicious_packages a
	LEFT JOIN malicious_affected_components b ON a.id = b.malicious_package_id
	GROUP BY LOWER(b.ecosystem);`
	err = c.affectedComponentRepository.GetDB(ctx, nil).Raw(maliciousPackagesSQL).Find(&maliciousPackageResults).Error
	if err != nil {
		return nil, err
	}

	// group the results in a map by cutting the ecosystem identifier before the ':'
	ecosystemToAmount := make(map[string]int, len(cveResults))
	for _, row := range append(cveResults, maliciousPackageResults...) {
		key, _, _ := strings.Cut(row.Ecosystem, ":")
		ecosystemToAmount[key] += row.Count
	}

	return ecosystemToAmount, nil
}
