package csaf_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/artifact"
	"github.com/l3montree-dev/devguard/internal/core/csaf"
	"github.com/l3montree-dev/devguard/internal/core/normalize"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestUpstreamCSAFReportIntegration(t *testing.T) {
	// lets do that against devguard itself - so that we have data to work with
	// Initialize test database
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
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

	artifactService := artifact.NewService(artifactRepository, csaf.NewCSAFService(httpsClient), cveRepository, componentRepository, dependencyVulnRepository, assetRepository, assetVersionRepository, assetVersionService, dependencyVulnService)

	csafController := csaf.NewCSAFController(dependencyVulnRepository, repositories.NewVulnEventRepository(db), assetVersionRepository, assetRepository, repositories.NewProjectRepository(db), repositories.NewOrgRepository(db), cveRepository, artifactRepository)

	// Create test organization, project, asset, and asset version
	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
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

func TestServeCSAFReportRequest(t *testing.T) {
	// Initialize test database
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	// Create artifact service and controller
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)

	// Create test organization, project, asset, and asset version
	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	csafController := csaf.NewCSAFController(dependencyVulnRepository, vulnEventRepository, assetVersionRepository, repositories.NewAssetRepository(db), repositories.NewProjectRepository(db), repositories.NewOrgRepository(db), repositories.NewCVERepository(db), repositories.NewArtifactRepository(db))
	// Setup echo app
	app := echo.New()

	// Setup context helper
	setupContext := func(ctx core.Context) {
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetAssetVersion(ctx, assetVersion)
	}

	timeStamp, err := time.Parse(time.RFC3339, "2025-10-20T18:24:55+02:00")
	if err != nil {
		t.Fail()
	}

	cve1 := models.CVE{CVE: "CVE-2025-50181"}
	cve2 := models.CVE{CVE: "CVE-2025-22871"}
	cve3 := models.CVE{CVE: "CVE-2025-22777"}

	vuln1 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: "main", AssetID: asset.ID, State: "open", CreatedAt: timeStamp}, CVE: &cve1, ComponentPurl: utils.Ptr("pkg:golang/stdlib@v1.24.4"), RiskAssessment: utils.Ptr(10)}
	vulnExtra := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: "main", AssetID: asset.ID, State: "open", CreatedAt: timeStamp}, CVE: &cve1, ComponentPurl: utils.Ptr("pkg:golang/stdlib@v1.24.5"), RiskAssessment: utils.Ptr(10)}
	vuln2 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: "main", AssetID: asset.ID, State: "fixed", CreatedAt: timeStamp}, CVE: &cve1, ComponentPurl: utils.Ptr("pkg:golang/github.com/hashicorp/go-getter@v1.7.8"), RiskAssessment: utils.Ptr(10)}
	vuln3 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: "main", AssetID: asset.ID, State: "accepted", CreatedAt: timeStamp}, CVE: &cve2, ComponentPurl: utils.Ptr("pkg:golang/helm.sh/helm/v3@v3.18.4"), RiskAssessment: utils.Ptr(10)}
	vuln4 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: "v1", AssetID: asset.ID, State: "falsePositive", CreatedAt: timeStamp}, CVE: &cve3, ComponentPurl: utils.Ptr("pkg:golang/github.com/ulikunitz/xz@v0.5.12"), RiskAssessment: utils.Ptr(10)}
	vuln5 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: "v2", AssetID: asset.ID, State: "accepted", CreatedAt: timeStamp}, CVE: &cve3, ComponentPurl: utils.Ptr("pkg:golang/stdlib@v1.24.1"), RiskAssessment: utils.Ptr(10)}

	tag1 := models.AssetVersion{AssetID: asset.ID, Name: "v1", Slug: "v1", Type: "tag"}
	tag2 := models.AssetVersion{AssetID: asset.ID, Name: "v2", Slug: "v2", Type: "tag"}

	event1 := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(0 * time.Minute)}, Type: models.EventTypeDetected, VulnID: vuln1.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}

	eventExtra := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(0 * time.Minute)}, Type: models.EventTypeDetected, VulnID: vulnExtra.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}

	event2 := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(0 * time.Minute)}, Type: models.EventTypeDetected, VulnID: vuln2.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}
	event3 := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(2 * time.Minute)}, Type: models.EventTypeAccepted, VulnID: vuln2.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}
	event4 := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(4 * time.Minute)}, Type: models.EventTypeFixed, VulnID: vuln2.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}

	event5 := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(0 * time.Minute)}, Type: models.EventTypeDetected, VulnID: vuln3.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}
	event6 := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(2 * time.Minute)}, Type: models.EventTypeAccepted, VulnID: vuln3.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}

	event7 := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(0 * time.Minute)}, Type: models.EventTypeDetected, VulnID: vuln4.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}
	event8 := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(2 * time.Minute)}, Type: models.EventTypeFalsePositive, VulnID: vuln4.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}

	event9 := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(0 * time.Minute)}, Type: models.EventTypeDetected, VulnID: vuln5.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}
	event10 := models.VulnEvent{Model: models.Model{CreatedAt: timeStamp.Add(2 * time.Minute)}, Type: models.EventTypeAccepted, VulnID: vuln5.CalculateHash(), ArbitraryJSONData: `{"risk" : 7.77}`}

	artifactMain := models.Artifact{
		ArtifactName:     "pkg:devguard/bizzareorganization/jojoasset/adventurerepo",
		AssetVersionName: "main",
		AssetID:          asset.ID,
		AssetVersion:     assetVersion,
	}
	artifactv1 := models.Artifact{
		ArtifactName:     "pkg:devguard/bizzareorganization/jojoasset/adventurerepo",
		AssetVersionName: "v1",
		AssetID:          asset.ID,
		AssetVersion:     tag1,
		DependencyVuln:   []models.DependencyVuln{},
	}
	artifactv2 := models.Artifact{
		ArtifactName:     "pkg:devguard/bizzareorganization/jojoasset/adventurerepo",
		AssetVersionName: "v2",
		AssetID:          asset.ID,
		AssetVersion:     tag2,
		DependencyVuln:   []models.DependencyVuln{},
	}
	t.Run("should fail if we do not provide a (valid) documentID", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/csaf/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)
		err := csafController.ServeCSAFReportRequest(ctx)
		assert.Error(t, err)
		ctx.SetParamNames("version")
		ctx.SetParamValues("version")
		err = csafController.ServeCSAFReportRequest(ctx)
		assert.Error(t, err)
	})
	t.Run("if we do not have a vulnerability history yet for an asset we should find an empty vuln object as well as the category set as csaf_base", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/csaf/", nil)
		ctx := app.NewContext(req, recorder)

		ctx.SetParamNames("organization", "project", "asset", "version")
		ctx.SetParamValues(org.Slug, project.Slug, asset.Slug, fmt.Sprintf("csaf_report_%s_1.json", asset.Slug))
		setupContext(ctx)

		err := repositories.NewArtifactRepository(db).Save(nil, &artifactMain)
		assert.Nil(t, err)

		err = csafController.ServeCSAFReportRequest(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "200 OK", recorder.Result().Status)

		body := recorder.Result().Body
		defer body.Close()
		buf := bytes.Buffer{}
		_, err = io.Copy(&buf, body)
		assert.Nil(t, err)
		csafDoc := gocsaf.Advisory{}
		err = json.Unmarshal(buf.Bytes(), &csafDoc)
		assert.Nil(t, err)

		assert.Equal(t, gocsaf.DocumentCategory("csaf_base"), *csafDoc.Document.Category)
		assert.Equal(t, gocsaf.Version("2.0"), *csafDoc.Document.CSAFVersion)
		assert.Equal(t, gocsaf.Category("vendor"), *csafDoc.Document.Publisher.Category)
		assert.Equal(t, org.Name, *csafDoc.Document.Publisher.Name)
		assert.Equal(t, "https://devguard.org", *csafDoc.Document.Publisher.Namespace)

		assert.Equal(t, 1, len(*csafDoc.ProductTree.FullProductNames))
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", string(*(*csafDoc.ProductTree.FullProductNames)[0].ProductID))
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", string(*(*csafDoc.ProductTree.FullProductNames)[0].Name))
	})
	t.Run("test product_tree functionality for more complex product trees", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/csaf/", nil)
		ctx := app.NewContext(req, recorder)

		ctx.SetParamNames("organization", "project", "asset", "version")
		ctx.SetParamValues(org.Slug, project.Slug, asset.Slug, fmt.Sprintf("csaf_report_%s_1.json", asset.Slug))
		setupContext(ctx)

		// add more tags and asset versions to the mix
		irrelevantAssetVersion := models.AssetVersion{AssetID: asset.ID, Name: "v1", Slug: "v1", Type: "branch", DefaultBranch: false}
		err := assetVersionRepository.Save(nil, &irrelevantAssetVersion)
		assert.Nil(t, err)

		err = assetVersionRepository.Save(nil, &tag1)
		assert.Nil(t, err)

		err = assetVersionRepository.Save(nil, &tag2)
		assert.Nil(t, err)

		err = repositories.NewArtifactRepository(db).Create(nil, &artifactv1)
		assert.Nil(t, err)
		err = repositories.NewArtifactRepository(db).Create(nil, &artifactv2)
		assert.Nil(t, err)

		err = csafController.ServeCSAFReportRequest(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "200 OK", recorder.Result().Status)

		body := recorder.Result().Body
		defer body.Close()
		buf := bytes.Buffer{}
		_, err = io.Copy(&buf, body)
		assert.Nil(t, err)
		csafDoc := gocsaf.Advisory{}
		err = json.Unmarshal(buf.Bytes(), &csafDoc)
		assert.Nil(t, err)

		// only test product tree here
		assert.Equal(t, 3, len(*csafDoc.ProductTree.FullProductNames))
		for i, expected := range []string{
			"pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main",
			"pkg:devguard/bizzareorganization/jojoasset/adventurerepo@v1",
			"pkg:devguard/bizzareorganization/jojoasset/adventurerepo@v2",
		} {
			assert.Equal(t, expected, string(*(*csafDoc.ProductTree.FullProductNames)[i].ProductID))
			assert.Equal(t, expected, string(*(*csafDoc.ProductTree.FullProductNames)[i].Name))
		}
	})
	t.Run("add vulnerabilities and vuln events to simulate a vulnerability history, use latest report version", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/csaf/", nil)
		ctx := app.NewContext(req, recorder)

		ctx.SetParamNames("organization", "project", "asset", "version")

		id := fmt.Sprintf("csaf_report_%s_4.json", asset.Slug)
		ctx.SetParamValues(org.Slug, project.Slug, asset.Slug, id)
		setupContext(ctx)

		err := repositories.NewCVERepository(db).SaveBatch(nil, []models.CVE{cve1, cve2, cve3})
		assert.Nil(t, err)

		err = repositories.NewDependencyVulnRepository(db).CreateBatch(nil, []models.DependencyVuln{vuln1, vuln2, vuln3, vuln4, vuln5, vulnExtra})
		assert.Nil(t, err)

		err = vulnEventRepository.CreateBatch(nil, []models.VulnEvent{event1, event2, event3, event4, event5, event6, event7, event8, event9, event10, eventExtra})
		assert.Nil(t, err)

		// relate vulns to main artifact
		artifactMain := models.Artifact{
			ArtifactName:     "pkg:devguard/bizzareorganization/jojoasset/adventurerepo",
			AssetVersionName: "main",
			AssetID:          asset.ID,
			AssetVersion:     assetVersion,
			DependencyVuln:   []models.DependencyVuln{vuln1, vuln2, vuln3, vuln4, vuln5, vulnExtra},
		}
		err = repositories.NewArtifactRepository(db).Save(nil, &artifactMain)
		assert.Nil(t, err)

		err = csafController.ServeCSAFReportRequest(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "200 OK", recorder.Result().Status)

		body := recorder.Result().Body
		defer body.Close()
		buf := bytes.Buffer{}
		_, err = io.Copy(&buf, body)
		assert.Nil(t, err)
		csafDoc := gocsaf.Advisory{}
		err = json.Unmarshal(buf.Bytes(), &csafDoc)
		assert.Nil(t, err)

		// since we have vulnerabilities the report should be categorized as security advisory
		assert.Equal(t, gocsaf.DocumentCategory("csaf_vex"), *csafDoc.Document.Category)
		assert.Equal(t, gocsaf.Version("2.0"), *csafDoc.Document.CSAFVersion)
		assert.Equal(t, gocsaf.Category("vendor"), *csafDoc.Document.Publisher.Category)
		assert.Equal(t, org.Name, *csafDoc.Document.Publisher.Name)
		assert.Equal(t, "https://devguard.org", *csafDoc.Document.Publisher.Namespace)
		assert.Equal(t, 3, len(*csafDoc.ProductTree.FullProductNames))

		// test the tracking object / revision history

		revHistory := csafDoc.Document.Tracking.RevisionHistory
		var date time.Time

		assert.Equal(t, 4, len(revHistory)) // version 4 of the document should result in 4 entries
		assert.Equal(t, strings.TrimRight(id, ".json"), string(*csafDoc.Document.Tracking.ID))
		assert.Equal(t, revHistory[3].Date, csafDoc.Document.Tracking.CurrentReleaseDate)
		assert.Equal(t, revHistory[0].Date, csafDoc.Document.Tracking.InitialReleaseDate)
		assert.Equal(t, "interim", string(*csafDoc.Document.Tracking.Status))
		assert.Equal(t, gocsaf.RevisionNumber("4"), *csafDoc.Document.Tracking.Version)

		assert.Equal(t, gocsaf.RevisionNumber("1"), *revHistory[0].Number)
		date, err = time.Parse(time.RFC3339, *revHistory[0].Date)
		assert.Nil(t, err)
		assetCreatedAt, err := time.Parse(time.RFC3339, asset.CreatedAt.Format(time.RFC3339))
		assert.Nil(t, err)
		assert.True(t, assetCreatedAt.Equal(date))
		assert.Equal(t, "Asset created, no vulnerabilities found", *revHistory[0].Summary)

		assert.Equal(t, gocsaf.RevisionNumber("2"), *revHistory[1].Number)
		date, err = time.Parse(time.RFC3339, *revHistory[1].Date)
		assert.Nil(t, err)
		assert.True(t, timeStamp.Add(0*time.Minute).Equal(date))
		assert.Equal(t, "Detected 6 new vulnerabilities (CVE-2025-22777, CVE-2025-22777, CVE-2025-22871, CVE-2025-50181, CVE-2025-50181, CVE-2025-50181).", *revHistory[1].Summary)

		assert.Equal(t, gocsaf.RevisionNumber("3"), *revHistory[2].Number)
		date, err = time.Parse(time.RFC3339, *revHistory[2].Date)
		assert.Nil(t, err)
		assert.True(t, timeStamp.Add(2*time.Minute).Equal(date))
		assert.Equal(t, "Accepted 3 existing vulnerabilities (CVE-2025-22777, CVE-2025-22871, CVE-2025-50181) | Marked 1 existing vulnerability as false positive (CVE-2025-22777).", *revHistory[2].Summary)

		assert.Equal(t, gocsaf.RevisionNumber("4"), *revHistory[3].Number)
		date, err = time.Parse(time.RFC3339, *revHistory[3].Date)
		assert.Nil(t, err)
		assert.True(t, timeStamp.Add(4*time.Minute).Equal(date))
		assert.Equal(t, "Fixed 1 existing vulnerability (CVE-2025-50181).", *revHistory[3].Summary)

		// test the vulnerabilities Object
		assert.Equal(t, 3, len(csafDoc.Vulnerabilities)) // 3 CVEs should result in 3 Vulnerability Groups

		assert.Equal(t, gocsaf.CVE("CVE-2025-50181"), *csafDoc.Vulnerabilities[0].CVE)
		date, err = time.Parse(time.RFC3339, *csafDoc.Vulnerabilities[0].DiscoveryDate)
		assert.Nil(t, err)
		assert.True(t, timeStamp.Equal(date))
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: unhandled for package pkg:golang/stdlib@v1.24.4, fixed for package pkg:golang/github.com/hashicorp/go-getter@v1.7.8, unhandled for package pkg:golang/stdlib@v1.24.5", *csafDoc.Vulnerabilities[0].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", string(*(*csafDoc.Vulnerabilities[0].ProductStatus.UnderInvestigation)[0]))

		assert.Equal(t, gocsaf.CVE("CVE-2025-22871"), *csafDoc.Vulnerabilities[1].CVE)
		date, err = time.Parse(time.RFC3339, *csafDoc.Vulnerabilities[1].DiscoveryDate)
		assert.Nil(t, err)
		assert.True(t, timeStamp.Equal(date))
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: accepted for package pkg:golang/helm.sh/helm/v3@v3.18.4", *csafDoc.Vulnerabilities[1].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", string(*(*csafDoc.Vulnerabilities[1].ProductStatus.KnownAffected)[0]))

		assert.Equal(t, gocsaf.CVE("CVE-2025-22777"), *csafDoc.Vulnerabilities[2].CVE)
		date, err = time.Parse(time.RFC3339, *csafDoc.Vulnerabilities[2].DiscoveryDate)
		assert.Nil(t, err)
		assert.True(t, timeStamp.Equal(date))
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: marked as false positive for package pkg:golang/github.com/ulikunitz/xz@v0.5.12, accepted for package pkg:golang/stdlib@v1.24.1", *csafDoc.Vulnerabilities[2].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", string(*(*csafDoc.Vulnerabilities[1].ProductStatus.KnownAffected)[0]))
	})
	t.Run("use an earlier version to test the time travel functionality", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/csaf/", nil)
		ctx := app.NewContext(req, recorder)

		ctx.SetParamNames("organization", "project", "asset", "version")

		version := "2" // get version 2 instead of the latest
		versionInt := 2
		id := fmt.Sprintf("csaf_report_%s_%s.json", asset.Slug, version)
		ctx.SetParamValues(org.Slug, project.Slug, asset.Slug, id)
		setupContext(ctx)

		err := csafController.ServeCSAFReportRequest(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "200 OK", recorder.Result().Status)

		body := recorder.Result().Body
		defer body.Close()
		buf := bytes.Buffer{}
		_, err = io.Copy(&buf, body)
		assert.Nil(t, err)
		csafDoc := gocsaf.Advisory{}
		err = json.Unmarshal(buf.Bytes(), &csafDoc)
		assert.Nil(t, err)

		// since we have vulnerabilities the report should be categorized as security advisory
		assert.Equal(t, gocsaf.DocumentCategory("csaf_vex"), *csafDoc.Document.Category)
		assert.Equal(t, gocsaf.Version("2.0"), *csafDoc.Document.CSAFVersion)
		assert.Equal(t, gocsaf.Category("vendor"), *csafDoc.Document.Publisher.Category)
		assert.Equal(t, org.Name, *csafDoc.Document.Publisher.Name)
		assert.Equal(t, "https://devguard.org", *csafDoc.Document.Publisher.Namespace)
		assert.Equal(t, 3, len(*csafDoc.ProductTree.FullProductNames))
		// test the tracking object / revision history

		revHistory := csafDoc.Document.Tracking.RevisionHistory

		assert.Equal(t, versionInt, len(revHistory)) // version 4 of the document should result in 4 entries
		assert.Equal(t, strings.TrimRight(id, ".json"), string(*csafDoc.Document.Tracking.ID))
		assert.Equal(t, revHistory[versionInt-1].Date, csafDoc.Document.Tracking.CurrentReleaseDate)
		assert.Equal(t, revHistory[0].Date, csafDoc.Document.Tracking.InitialReleaseDate)
		assert.Equal(t, "interim", string(*csafDoc.Document.Tracking.Status))
		assert.Equal(t, gocsaf.RevisionNumber(version), *csafDoc.Document.Tracking.Version)

		assert.Equal(t, gocsaf.RevisionNumber("1"), *revHistory[0].Number)
		assert.Equal(t, asset.CreatedAt.Format(time.RFC3339), *revHistory[0].Date)
		assert.Equal(t, "Asset created, no vulnerabilities found", *revHistory[0].Summary)

		assert.Equal(t, gocsaf.RevisionNumber("2"), *revHistory[1].Number)
		assert.Equal(t, "Detected 6 new vulnerabilities (CVE-2025-22777, CVE-2025-22777, CVE-2025-22871, CVE-2025-50181, CVE-2025-50181, CVE-2025-50181).", *revHistory[1].Summary)

		// test the vulnerabilities Object
		assert.Equal(t, 3, len(csafDoc.Vulnerabilities)) // 3 CVEs should result in 3 Vulnerability Groups

		assert.Equal(t, gocsaf.CVE("CVE-2025-50181"), *csafDoc.Vulnerabilities[0].CVE)
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: unhandled for package pkg:golang/stdlib@v1.24.4, unhandled for package pkg:golang/github.com/hashicorp/go-getter@v1.7.8, unhandled for package pkg:golang/stdlib@v1.24.5", *csafDoc.Vulnerabilities[0].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", string(*(*csafDoc.Vulnerabilities[0].ProductStatus.UnderInvestigation)[0]))

		assert.Equal(t, gocsaf.CVE("CVE-2025-22871"), *csafDoc.Vulnerabilities[1].CVE)
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: unhandled for package pkg:golang/helm.sh/helm/v3@v3.18.4", *csafDoc.Vulnerabilities[1].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", string(*(*csafDoc.Vulnerabilities[1].ProductStatus.UnderInvestigation)[0]))

		assert.Equal(t, gocsaf.CVE("CVE-2025-22777"), *csafDoc.Vulnerabilities[2].CVE)
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: unhandled for package pkg:golang/github.com/ulikunitz/xz@v0.5.12, unhandled for package pkg:golang/stdlib@v1.24.1", *csafDoc.Vulnerabilities[2].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", string(*(*csafDoc.Vulnerabilities[2].ProductStatus.UnderInvestigation)[0]))
	})
}

func createDependencyVulns(db core.DB, assetID uuid.UUID, assetVersionName string, artifact models.Artifact) (models.DependencyVuln, models.DependencyVuln) {
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
