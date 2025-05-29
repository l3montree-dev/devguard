package scan_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestScanning(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	controller := initHttpController(t, db)

	// scan the vulnerable sbom
	app := echo.New()
	createCVE2025_46569(db)
	org, project, asset := createOrgProjectAndAsset(db)
	setupContext := func(ctx core.Context) {
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetSession(ctx, authSession)
	}

	t.Run("should find a vulnerability in the SBOM", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithVulnerability()

		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-1")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse

		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)

		assert.Equal(t, 1, response.AmountOpened)
		assert.Equal(t, 0, response.AmountClosed)
		assert.Len(t, response.DependencyVulns, 1)
		assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
	})

	t.Run("should add the scanner id, if the vulnerability is found with another scanner", func(t *testing.T) {
		// we found the CVE - Make sure, that if we scan again but with a different scanner, the scanner ids get updated
		recorder := httptest.NewRecorder()
		// reopen file
		sbomFile := sbomWithVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-2")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, 1, response.AmountOpened) // first time detected with this scanner
		assert.Equal(t, 0, response.AmountClosed)
		assert.Len(t, response.DependencyVulns, 1)
		assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
		// the scanner id should be updated
		assert.Equal(t, "scanner-1 scanner-2", response.DependencyVulns[0].ScannerIDs)
	})

	t.Run("should only return vulnerabilities, which are found by the current scanner", func(t *testing.T) {
		// scan the sbom without the vulnerability
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-3")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)

		assert.Equal(t, 0, response.AmountOpened) // no new vulnerabilities found
		assert.Equal(t, 0, response.AmountClosed)
		assert.Len(t, response.DependencyVulns, 0) // no vulnerabilities returned
	})

	t.Run("should return amount of closed 1, if the vulnerability is not detected by a scanner anymore", func(t *testing.T) {
		// we found the CVE - Make sure, that if we scan again but with a different scanner, the scanner ids get updated
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-1")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)

		assert.Equal(t, 0, response.AmountOpened)  // no new vulnerabilities found
		assert.Equal(t, 1, response.AmountClosed)  // the vulnerability was closed
		assert.Len(t, response.DependencyVulns, 0) // no vulnerabilities returned
	})
}

func createCVE2025_46569(db core.DB) {
	cve := models.CVE{
		CVE: "CVE-2025-46569",
	}

	err := db.Create(&cve).Error
	if err != nil {
		panic(err)
	}

	affectedComponent := models.AffectedComponent{
		PURL:        "pkg:golang/github.com/open-policy-agent/opa",
		SemverFixed: utils.Ptr("1.4.0"),
	}

	err = db.Create(&affectedComponent).Error
	if err != nil {
		panic(err)
	}

	// create the relationship between the CVE and the affected component
	err = db.Model(&cve).Association("AffectedComponents").Append(&affectedComponent)
	if err != nil {
		panic(err)
	}
}

func createOrgProjectAndAsset(db core.DB) (models.Org, models.Project, models.Asset) {
	org := models.Org{
		Name: "Test Org",
	}
	err := db.Create(&org).Error
	if err != nil {
		panic(err)
	}
	project := models.Project{
		Name:           "Test Project",
		OrganizationID: org.ID,
	}
	err = db.Create(&project).Error
	if err != nil {
		panic(err)
	}

	asset := models.Asset{
		Name:      "Test Asset",
		ProjectID: project.ID,
	}

	err = db.Create(&asset).Error
	if err != nil {
		panic(err)
	}

	return org, project, asset
}

func sbomWithVulnerability() *os.File {
	file, err := os.Open("./testdata/sbom-with-cve-2025-46569.json")
	if err != nil {
		panic(err)
	}
	return file
}

func sbomWithoutVulnerability() *os.File {
	file, err := os.Open("./testdata/sbom-without-cve-2025-46569.json")
	if err != nil {
		panic(err)
	}
	return file
}

func initHttpController(t *testing.T, db core.DB) *scan.HttpController {
	// there are a lot of repositories and services that need to be initialized...

	// Initialize repositories
	githubIntegration := integrations.NewGithubIntegration(db)
	gitlabIntegration := integrations.NewGitLabIntegration(db)
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(githubIntegration, gitlabIntegration)
	assetRepository := repositories.NewAssetRepository(db)
	assetRiskAggregationRepository := repositories.NewAssetRiskHistoryRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	statisticsRepository := repositories.NewStatisticsRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	orgRepository := repositories.NewOrgRepository(db)
	cveRepository := repositories.NewCVERepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(db)

	// just to run the migrations
	repositories.NewExploitRepository(db)

	// Initialize services
	dependencyVulnService := vuln.NewService(dependencyVulnRepository, vulnEventRepository, assetRepository, cveRepository, orgRepository, projectRepository, thirdPartyIntegration, assetVersionRepository)
	firstPartyVulnService := vuln.NewFirstPartyVulnService(firstPartyVulnRepository, vulnEventRepository, assetRepository)

	// mock the depsDevService to avoid any external calls during tests
	depsDevService := mocks.NewDepsDevService(t)
	depsDevService.On("GetVersion", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(common.DepsDevVersionResponse{}, nil)

	componentProjectRepository := repositories.NewComponentProjectRepository(db)
	componentService := component.NewComponentService(depsDevService, componentProjectRepository, componentRepository)
	assetVersionService := assetversion.NewService(assetVersionRepository, componentRepository, dependencyVulnRepository, firstPartyVulnRepository, dependencyVulnService, firstPartyVulnService, assetRepository, vulnEventRepository, &componentService)
	statisticsService := statistics.NewService(statisticsRepository, componentRepository, assetRiskAggregationRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, repositories.NewProjectRiskHistoryRepository(db))

	// finally, create the controller
	controller := scan.NewHttpController(db, cveRepository, componentRepository, assetRepository, assetVersionRepository, assetVersionService, statisticsService, dependencyVulnService)
	return controller
}
