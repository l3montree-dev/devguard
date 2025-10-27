package csaf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

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
	csafController := NewCSAFController(dependencyVulnRepository, vulnEventRepository, assetVersionRepository, repositories.NewAssetRepository(db), repositories.NewProjectRepository(db), repositories.NewOrgRepository(db), repositories.NewCVERepository(db), repositories.NewArtifactRepository(db))
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
		DependencyVulns:  []models.DependencyVuln{},
	}
	artifactv2 := models.Artifact{
		ArtifactName:     "pkg:devguard/bizzareorganization/jojoasset/adventurerepo",
		AssetVersionName: "v2",
		AssetID:          asset.ID,
		AssetVersion:     tag2,
		DependencyVulns:  []models.DependencyVuln{},
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
		if err != nil {
			t.Fail()
		}

		err = csafController.ServeCSAFReportRequest(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "200 OK", recorder.Result().Status)

		body := recorder.Result().Body
		defer body.Close()
		buf := bytes.Buffer{}
		_, err = io.Copy(&buf, body)
		if err != nil {
			t.Fail()
		}
		csafDoc := csaf{}
		err = json.Unmarshal(buf.Bytes(), &csafDoc)
		if err != nil {
			t.Fail()
		}

		assert.Equal(t, "csaf_base", csafDoc.Document.Category)
		assert.Equal(t, "2.0", csafDoc.Document.CSAFVersion)
		assert.Equal(t, "vendor", csafDoc.Document.Publisher.Category)
		assert.Equal(t, org.Name, csafDoc.Document.Publisher.Name)
		assert.Equal(t, "https://devguard.org", csafDoc.Document.Publisher.Namespace)

		assert.Equal(t, 1, len(csafDoc.ProductTree.Branches))
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.ProductTree.Branches[0].Name)
		assert.Equal(t, "product_version", csafDoc.ProductTree.Branches[0].Category)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.ProductTree.Branches[0].Product.ProductID)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.ProductTree.Branches[0].Product.Name)
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
		if err != nil {
			t.Fail()
		}

		err = assetVersionRepository.Save(nil, &tag1)
		if err != nil {
			t.Fail()
		}

		err = assetVersionRepository.Save(nil, &tag2)
		if err != nil {
			t.Fail()
		}

		err = repositories.NewArtifactRepository(db).Create(nil, &artifactv1)
		if err != nil {
			t.Fail()
		}
		err = repositories.NewArtifactRepository(db).Create(nil, &artifactv2)
		if err != nil {
			t.Fail()
		}

		err = csafController.ServeCSAFReportRequest(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "200 OK", recorder.Result().Status)

		body := recorder.Result().Body
		defer body.Close()
		buf := bytes.Buffer{}
		_, err = io.Copy(&buf, body)
		if err != nil {
			t.Fail()
		}
		csafDoc := csaf{}
		err = json.Unmarshal(buf.Bytes(), &csafDoc)
		if err != nil {
			t.Fail()
		}

		// only test product tree here
		assert.Equal(t, 3, len(csafDoc.ProductTree.Branches))

		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.ProductTree.Branches[0].Name)
		assert.Equal(t, "product_version", csafDoc.ProductTree.Branches[0].Category)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.ProductTree.Branches[0].Product.ProductID)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.ProductTree.Branches[0].Product.Name)

		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@v1", csafDoc.ProductTree.Branches[1].Name)
		assert.Equal(t, "product_version", csafDoc.ProductTree.Branches[1].Category)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@v1", csafDoc.ProductTree.Branches[1].Product.ProductID)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@v1", csafDoc.ProductTree.Branches[1].Product.Name)

		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@v2", csafDoc.ProductTree.Branches[2].Name)
		assert.Equal(t, "product_version", csafDoc.ProductTree.Branches[2].Category)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@v2", csafDoc.ProductTree.Branches[2].Product.ProductID)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@v2", csafDoc.ProductTree.Branches[2].Product.Name)
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
		if err != nil {
			t.Fail()
		}

		err = repositories.NewDependencyVulnRepository(db).CreateBatch(nil, []models.DependencyVuln{vuln1, vuln2, vuln3, vuln4, vuln5, vulnExtra})
		if err != nil {
			t.Fail()
		}

		err = vulnEventRepository.CreateBatch(nil, []models.VulnEvent{event1, event2, event3, event4, event5, event6, event7, event8, event9, event10, eventExtra})
		if err != nil {
			t.Fail()
		}

		// relate vulns to main artifact
		artifactMain := models.Artifact{
			ArtifactName:     "pkg:devguard/bizzareorganization/jojoasset/adventurerepo",
			AssetVersionName: "main",
			AssetID:          asset.ID,
			AssetVersion:     assetVersion,
			DependencyVulns:  []models.DependencyVuln{vuln1, vuln2, vuln3, vuln4, vuln5, vulnExtra},
		}
		err = repositories.NewArtifactRepository(db).Save(nil, &artifactMain)
		if err != nil {
			t.Fail()
		}

		err = csafController.ServeCSAFReportRequest(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "200 OK", recorder.Result().Status)

		body := recorder.Result().Body
		defer body.Close()
		buf := bytes.Buffer{}
		_, err = io.Copy(&buf, body)
		if err != nil {
			t.Fail()
		}
		csafDoc := csaf{}
		err = json.Unmarshal(buf.Bytes(), &csafDoc)
		if err != nil {
			t.Fail()
		}

		// since we have vulnerabilities the report should be categorized as security advisory
		assert.Equal(t, "csaf_security_advisory", csafDoc.Document.Category)
		assert.Equal(t, "2.0", csafDoc.Document.CSAFVersion)
		assert.Equal(t, "vendor", csafDoc.Document.Publisher.Category)
		assert.Equal(t, org.Name, csafDoc.Document.Publisher.Name)
		assert.Equal(t, "https://devguard.org", csafDoc.Document.Publisher.Namespace)
		assert.Equal(t, 3, len(csafDoc.ProductTree.Branches))

		// test the tracking object / revision history

		revHistory := csafDoc.Document.Tracking.RevisionHistory
		var date time.Time

		assert.Equal(t, 4, len(revHistory)) // version 4 of the document should result in 4 entries
		assert.Equal(t, strings.TrimRight(id, ".json"), csafDoc.Document.Tracking.ID)
		assert.Equal(t, revHistory[3].Date, csafDoc.Document.Tracking.CurrentReleaseDate)
		assert.Equal(t, revHistory[0].Date, csafDoc.Document.Tracking.InitialReleaseDate)
		assert.Equal(t, "interim", csafDoc.Document.Tracking.Status)
		assert.Equal(t, "4", csafDoc.Document.Tracking.Version)

		assert.Equal(t, "1", revHistory[0].Number)
		date, err = time.Parse(time.RFC3339, revHistory[0].Date)
		if err != nil {
			t.Fail()
		}
		assetCreatedAt, err := time.Parse(time.RFC3339, asset.CreatedAt.Format(time.RFC3339))
		if err != nil {
			t.Fail()
		}
		assert.True(t, assetCreatedAt.Equal(date))
		assert.Equal(t, "Asset created, no vulnerabilities found", revHistory[0].Summary)

		assert.Equal(t, "2", revHistory[1].Number)
		date, err = time.Parse(time.RFC3339, revHistory[1].Date)
		if err != nil {
			t.Fail()
		}
		assert.True(t, timeStamp.Add(0*time.Minute).Equal(date))
		assert.Equal(t, "Detected 6 new vulnerabilities (CVE-2025-50181, CVE-2025-50181, CVE-2025-50181, CVE-2025-22871, CVE-2025-50181, CVE-2025-22777, CVE-2025-22777).", revHistory[1].Summary)

		assert.Equal(t, "3", revHistory[2].Number)
		date, err = time.Parse(time.RFC3339, revHistory[2].Date)
		if err != nil {
			t.Fail()
		}
		assert.True(t, timeStamp.Add(2*time.Minute).Equal(date))
		assert.Equal(t, "Accepted 3 existing vulnerabilities (CVE-2025-50181, CVE-2025-50181, CVE-2025-22871, CVE-2025-22777)| Marked 1 existing vulnerability as false positive (CVE-2025-22777).", revHistory[2].Summary)

		assert.Equal(t, "4", revHistory[3].Number)
		date, err = time.Parse(time.RFC3339, revHistory[3].Date)
		if err != nil {
			t.Fail()
		}
		assert.True(t, timeStamp.Add(4*time.Minute).Equal(date))
		assert.Equal(t, "Fixed 1 existing vulnerability (CVE-2025-50181).", revHistory[3].Summary)

		// test the vulnerabilities Object
		assert.Equal(t, 3, len(csafDoc.Vulnerabilities)) // 3 CVEs should result in 3 Vulnerability Groups

		assert.Equal(t, "CVE-2025-50181", csafDoc.Vulnerabilities[0].CVE, csafDoc.Vulnerabilities[0].Title)
		date, err = time.Parse(time.RFC3339, csafDoc.Vulnerabilities[0].DiscoveryDate)
		if err != nil {
			t.Fail()
		}
		assert.True(t, timeStamp.Equal(date))
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: unhandled for package pkg:golang/stdlib@v1.24.4, unhandled for package pkg:golang/stdlib@v1.24.5", csafDoc.Vulnerabilities[0].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.Vulnerabilities[0].ProductStatus.KnownAffected[0])

		assert.Equal(t, "CVE-2025-22871", csafDoc.Vulnerabilities[1].CVE, csafDoc.Vulnerabilities[1].Title)
		date, err = time.Parse(time.RFC3339, csafDoc.Vulnerabilities[1].DiscoveryDate)
		if err != nil {
			t.Fail()
		}
		assert.True(t, timeStamp.Equal(date))
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: accepted for package pkg:golang/helm.sh/helm/v3@v3.18.4", csafDoc.Vulnerabilities[1].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.Vulnerabilities[1].ProductStatus.KnownAffected[0])

		assert.Equal(t, "CVE-2025-22777", csafDoc.Vulnerabilities[2].CVE, csafDoc.Vulnerabilities[2].Title)
		date, err = time.Parse(time.RFC3339, csafDoc.Vulnerabilities[2].DiscoveryDate)
		if err != nil {
			t.Fail()
		}
		assert.True(t, timeStamp.Equal(date))
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: unhandled for package pkg:golang/github.com/ulikunitz/xz@v0.5.12, accepted for package pkg:golang/stdlib@v1.24.1", csafDoc.Vulnerabilities[2].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.Vulnerabilities[1].ProductStatus.KnownAffected[0])
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
		if err != nil {
			t.Fail()
		}
		csafDoc := csaf{}
		err = json.Unmarshal(buf.Bytes(), &csafDoc)
		if err != nil {
			t.Fail()
		}

		// since we have vulnerabilities the report should be categorized as security advisory
		assert.Equal(t, "csaf_security_advisory", csafDoc.Document.Category)
		assert.Equal(t, "2.0", csafDoc.Document.CSAFVersion)
		assert.Equal(t, "vendor", csafDoc.Document.Publisher.Category)
		assert.Equal(t, org.Name, csafDoc.Document.Publisher.Name)
		assert.Equal(t, "https://devguard.org", csafDoc.Document.Publisher.Namespace)
		assert.Equal(t, 3, len(csafDoc.ProductTree.Branches))

		// test the tracking object / revision history

		revHistory := csafDoc.Document.Tracking.RevisionHistory

		assert.Equal(t, versionInt, len(revHistory)) // version 4 of the document should result in 4 entries
		assert.Equal(t, strings.TrimRight(id, ".json"), csafDoc.Document.Tracking.ID)
		assert.Equal(t, revHistory[versionInt-1].Date, csafDoc.Document.Tracking.CurrentReleaseDate)
		assert.Equal(t, revHistory[0].Date, csafDoc.Document.Tracking.InitialReleaseDate)
		assert.Equal(t, "interim", csafDoc.Document.Tracking.Status)
		assert.Equal(t, version, csafDoc.Document.Tracking.Version)

		assert.Equal(t, "1", revHistory[0].Number)
		assert.Equal(t, asset.CreatedAt.Format(time.RFC3339), revHistory[0].Date)
		assert.Equal(t, "Asset created, no vulnerabilities found", revHistory[0].Summary)

		assert.Equal(t, "2", revHistory[1].Number)
		assert.Equal(t, "Detected 6 new vulnerabilities (CVE-2025-50181, CVE-2025-50181, CVE-2025-50181, CVE-2025-22871, CVE-2025-50181, CVE-2025-22777, CVE-2025-22777).", revHistory[1].Summary)

		// test the vulnerabilities Object
		assert.Equal(t, 3, len(csafDoc.Vulnerabilities)) // 3 CVEs should result in 3 Vulnerability Groups

		assert.Equal(t, "CVE-2025-50181", csafDoc.Vulnerabilities[0].CVE, csafDoc.Vulnerabilities[0].Title)
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: unhandled for package pkg:golang/stdlib@v1.24.4, unhandled for package pkg:golang/stdlib@v1.24.5", csafDoc.Vulnerabilities[0].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.Vulnerabilities[0].ProductStatus.KnownAffected[0])

		assert.Equal(t, "CVE-2025-22871", csafDoc.Vulnerabilities[1].CVE, csafDoc.Vulnerabilities[1].Title)
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: unhandled for package pkg:golang/helm.sh/helm/v3@v3.18.4", csafDoc.Vulnerabilities[1].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.Vulnerabilities[1].ProductStatus.KnownAffected[0])

		assert.Equal(t, "CVE-2025-22777", csafDoc.Vulnerabilities[2].CVE, csafDoc.Vulnerabilities[2].Title)
		assert.Equal(t, "ProductID pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main: unhandled for package pkg:golang/github.com/ulikunitz/xz@v0.5.12, unhandled for package pkg:golang/stdlib@v1.24.1", csafDoc.Vulnerabilities[2].Notes[0].Text)
		assert.Equal(t, "pkg:devguard/bizzareorganization/jojoasset/adventurerepo@main", csafDoc.Vulnerabilities[2].ProductStatus.KnownAffected[0])
	})
}
