package controllers

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/internal/core/csaf"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/tests"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestUpstreamCSAFReportIntegration(t *testing.T) {
	// lets do that against devguard itself - so that we have data to work with
	// Initialize test database
	db, terminate := tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	// Create artifact service and controller
	artifactRepository := repositories.NewArtifactRepository(db)
	cveRepository := mocks.NewCveRepository(t)
	componentRepository := repositories.NewComponentRepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	assetVersionService := mocks.NewAssetVersionService(t)
	dependencyVulnService := mocks.NewDependencyVulnService(t)

	httpsClient := http.Client{
		Timeout: 30 * time.Second,
	}
	httpsClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	artifactService := services.NewArtifactService(artifactRepository, csaf.NewCSAFService(httpsClient), cveRepository, componentRepository, dependencyVulnRepository, assetRepository, assetVersionRepository, assetVersionService, dependencyVulnService)

	csafController := csaf.NewCSAFController(dependencyVulnRepository, repositories.NewVulnEventRepository(db), assetVersionRepository, assetRepository, repositories.NewProjectRepository(db), repositories.NewOrgRepository(db), cveRepository, artifactRepository)

	// Create test organization, project, asset, and asset version
	org, project, asset, assetVersion := tests.CreateOrgProjectAndAssetAssetVersion(db)
	// create an artifact in this asset version
	artifact := models.Artifact{
		ArtifactName:     "pkg:golang/github.com/l3montree-dev/devguard",
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
	}
	assert.Nil(t, db.Create(&artifact).Error)

	// Setup echo app
	app := echo.New()

	t.Run("should return 404 if the asset has no vuln sharing enabled (this tests the csaf middleware function)", func(t *testing.T) {
		testserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := app.NewContext(r, w)
			ctx.SetParamNames("organization", "projectSlug", "assetSlug")
			ctx.SetParamValues(org.Slug, project.Slug, asset.Slug)
			// set the params - we need todo that manually
			// we can even test the csaf middleware right here.
			assert.NotNil(t, api.CsafMiddleware(false, repositories.NewOrgRepository(db), repositories.NewProjectRepository(db), repositories.NewAssetRepository(db), repositories.NewAssetVersionRepository(db), artifactRepository)(csafController.ServeCSAFReportRequest)(ctx))
		}))

		csafURL := testserver.URL + "/provider-metadata.json"

		// we create a fake bom for the same artifact which has the same purl
		_, _, invalidURLs := artifactService.FetchBomsFromUpstream(artifact.ArtifactName, []string{csafURL})
		assert.Equal(t, 1, len(invalidURLs))
	})

	// now mark the asset as having vuln sharing enabled
	asset.SharesInformation = true
	assert.Nil(t, db.Save(&asset).Error)

	createDependencyVulns(db, asset.ID, assetVersion.Name, artifact)
	t.Run("should consume own produced csaf reports", func(t *testing.T) {
		csafMiddleware := api.CsafMiddleware(false, repositories.NewOrgRepository(db), repositories.NewProjectRepository(db), repositories.NewAssetRepository(db), repositories.NewAssetVersionRepository(db), artifactRepository)

		testserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// lets do some routing here
			if strings.HasSuffix(r.URL.Path, "provider-metadata.json") {
				ctx := app.NewContext(r, w)
				ctx.SetParamNames("organization")
				ctx.SetParamValues(org.Slug)
				assert.Nil(t, api.CsafMiddleware(true, repositories.NewOrgRepository(db), repositories.NewProjectRepository(db), repositories.NewAssetRepository(db), repositories.NewAssetVersionRepository(db), artifactRepository)(csafController.GetProviderMetadataForOrganization)(ctx))
				return
			} else if strings.Contains(r.URL.Path, "/openpgp/") {
				ctx := app.NewContext(r, w)
				ctx.SetParamNames("organization", "projectSlug", "assetSlug", "file")
				// extract the last part of the url as file name
				fileName := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
				ctx.SetParamValues(org.Slug, project.Slug, asset.Slug, fileName)
				assert.Nil(t, csafMiddleware(csafController.GetOpenPGPFile)(ctx))
				return
			} else if strings.HasSuffix(r.URL.Path, "/white/changes.csv") {
				ctx := app.NewContext(r, w)
				ctx.SetParamNames("organization", "projectSlug", "assetSlug")
				ctx.SetParamValues(org.Slug, project.Slug, asset.Slug)
				assert.Nil(t, csafMiddleware(csafController.GetChangesCSVFile)(ctx))
				return
			} else if strings.HasSuffix(r.URL.Path, "/white/index.txt") {
				ctx := app.NewContext(r, w)
				ctx.SetParamNames("organization", "projectSlug", "assetSlug")
				ctx.SetParamValues(org.Slug, project.Slug, asset.Slug)
				assert.Nil(t, csafMiddleware(csafController.GetIndexFile)(ctx))
			}

			// the url should contain something like this: white/:year/:version/
			// we need to set those param values manually here
			pathParts := strings.Split(r.URL.Path, "/white/")
			fmt.Println(r.URL.Path)
			yearAndMaybeVersion := pathParts[1]
			yearAndMaybeVersionParts := strings.Split(yearAndMaybeVersion, "/")
			year := yearAndMaybeVersionParts[0]
			version := ""
			if len(yearAndMaybeVersionParts) > 1 {
				version = yearAndMaybeVersionParts[1]
			}

			ctx := app.NewContext(r, w)
			ctx.SetParamNames("organization", "projectSlug", "assetSlug", "year", "version")
			ctx.SetParamValues(org.Slug, project.Slug, asset.Slug, year, version)
			// set the params - we need todo that manually
			// we can even test the csaf middleware right here.
			assert.Nil(t, csafMiddleware(csafController.ServeCSAFReportRequest)(ctx))

		}))
		os.Setenv("API_URL", testserver.URL)
		os.Setenv("CSAF_OPENPGP_PUBLIC_KEY_PATH", "testdata/test-openpgp-public-key.asc")
		os.Setenv("CSAF_OPENPGP_PRIVATE_KEY_PATH", "testdata/test-openpgp-private-key.asc")
		os.Setenv("CSAF_OPENPGP_PASSPHRASE", "Ag%cdaA&EhoM#qCHLRXqoRH%oWAg%cdaA&EhoM#qCHLRXqoRH%oW")
		os.Setenv("CSAF_OPENPGP_FINGERPRINT", "A8725AE729DAFAF6B95761207D9096D47B06F5F4")

		// we need to add the purl to the url
		purl := normalize.Purlify(artifact.ArtifactName, assetVersion.Name)
		csafURL := purl + ":" + testserver.URL + "/provider-metadata.json"

		// we create a fake bom for the same artifact which has the same purl
		boms, _, invalidURLs := artifactService.FetchBomsFromUpstream(artifact.ArtifactName, []string{csafURL})
		assert.Equal(t, 0, len(invalidURLs))
		assert.Equal(t, 1, len(boms))

		// iterate over the vulns.
		// expect CVE-2024-0001 and CVE-2024-0002 to be present,
		// CVE-2024-0001 should be open, CVE-2024-0002 should be marked as false positive
		for _, vuln := range *boms[0].GetVulnerabilities() {
			switch vuln.ID {
			case "CVE-2024-0001":
				assert.Equal(t, cyclonedx.IASInTriage, vuln.Analysis.State)
			case "CVE-2024-0002":
				assert.Equal(t, cyclonedx.IASNotAffected, vuln.Analysis.State)
			}
		}
	})
}

func createDependencyVulns(db shared.DB, assetID uuid.UUID, assetVersionName string, artifact models.Artifact) (models.DependencyVuln, models.DependencyVuln) {
	var err error

	cve := models.CVE{
		CVE:         "CVE-2024-0001",
		Description: "Test usage",
		CVSS:        7.50,
	}
	if err = db.Create(&cve).Error; err != nil {
		panic(err)
	}

	cve2 := models.CVE{
		CVE:         "CVE-2024-0002",
		Description: "Test usage",
		CVSS:        7.50,
	}
	if err = db.Create(&cve2).Error; err != nil {
		panic(err)
	}

	//create our 2 dependency vuln referencing the cve
	vuln1 := models.DependencyVuln{
		Vulnerability:     models.Vulnerability{AssetVersionName: assetVersionName, AssetID: assetID, State: "open"},
		ComponentPurl:     utils.Ptr("pkg:npm/next@14.2.13"),
		CVE:               &cve,
		CVEID:             &cve.CVE,
		RawRiskAssessment: utils.Ptr(4.83),
		ComponentDepth:    utils.Ptr(8),
		Artifacts:         []models.Artifact{artifact},
	}

	if err = db.Create(&vuln1).Error; err != nil {
		panic(err)
	}
	vuln2 := models.DependencyVuln{
		Vulnerability:     models.Vulnerability{AssetVersionName: assetVersionName, AssetID: assetID, State: "open"},
		ComponentPurl:     utils.Ptr("pkg:npm/axios@1.7.7"),
		CVE:               &cve2,
		CVEID:             &cve2.CVE,
		RawRiskAssessment: utils.Ptr(8.89),
		ComponentDepth:    utils.Ptr(2),
		Artifacts:         []models.Artifact{artifact},
	}
	if err = db.Create(&vuln2).Error; err != nil {
		panic(err)
	}

	// save the relation to the artifact
	if err = db.Model(&artifact).Association("DependencyVuln").Append(&vuln1, &vuln2); err != nil {
		panic(err)
	}

	//lastly create the vuln events regarding the two dependency vulns where as one dependencyVuln has 2 updates and the other one just has 1 update being the fix
	vuln1DetectedEvent := models.VulnEvent{
		VulnID:   vuln1.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-10 * time.Minute), UpdatedAt: time.Now().Add(-5 * time.Minute)},
		Type:     "detected",
		UserID:   "system",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1DetectedEvent).Error; err != nil {
		panic(err)
	}

	vuln1CommentEvent := models.VulnEvent{
		VulnID:   vuln1.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-7 * time.Minute), UpdatedAt: time.Now().Add(-7 * time.Minute)},
		Type:     "comment",
		UserID:   "system",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1CommentEvent).Error; err != nil {
		panic(err)
	}

	vuln2DetectedEvent := models.VulnEvent{
		VulnID:   vuln2.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-3 * time.Minute), UpdatedAt: time.Now().Add(-2 * time.Minute)},
		Type:     "detected",
		UserID:   "system",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln2DetectedEvent).Error; err != nil {
		panic(err)
	}

	vuln2FalsePositiveEvent := models.VulnEvent{
		VulnID:   vuln2.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-1 * time.Minute), UpdatedAt: time.Now().Add(-1 * time.Minute)},
		Type:     "falsePositive",
		UserID:   "xyz",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln2FalsePositiveEvent).Error; err != nil {
		panic(err)
	}
	return vuln1, vuln2
}
