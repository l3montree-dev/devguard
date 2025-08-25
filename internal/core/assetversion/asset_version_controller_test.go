package assetversion_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/inithelper"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestBuildVEX(t *testing.T) {
	//Build up a foundation for all the upcoming tests
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()
	app := echo.New()
	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	assetVersionController := inithelper.CreateAssetVersionController(db, nil, nil, integration_tests.TestGitlabClientFactory{GitlabClientFacade: nil}, nil)
	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	setupContext := func(ctx *core.Context) {
		// set basic context values
		core.SetAsset(*ctx, asset)
		core.SetProject(*ctx, project)
		core.SetOrg(*ctx, org)
		core.SetAssetVersion(*ctx, assetVersion)
	}
	t.Run("test with empty db should return vex bom with no vulnerabilities", func(t *testing.T) {
		//setup function call
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/vex-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		err := assetVersionController.VEXJSON(ctx)
		assert.Nil(t, err)

		//prep results for testing
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)
		var VEXResult cyclonedx.BOM
		err = json.Unmarshal(body, &VEXResult)
		assert.Nil(t, err)

		//test general metadata
		assert.Equal(t, VEXResult.Metadata.Component.BOMRef, "main")
		assert.Equal(t, VEXResult.Metadata.Component.Name, "Test Asset")
		assert.Equal(t, VEXResult.Metadata.Component.Author, "Test Org")

		assert.Empty(t, VEXResult.Vulnerabilities)
	})
	vuln1, vuln2 := createDependencyVulns(db, asset.ID, assetVersion.Name)
	t.Run("build Vex with everything set as intended", func(t *testing.T) {
		//setup function call
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/vex-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		err := assetVersionController.VEXJSON(ctx)
		assert.Nil(t, err)

		//prep results for testing
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)
		var VEXResult cyclonedx.BOM
		err = json.Unmarshal(body, &VEXResult)
		assert.Nil(t, err)

		//test timestamps if they have the right format
		propertyValue1 := (*(*VEXResult.Vulnerabilities)[0].Properties)[0].Value
		responseTime1, err := time.Parse(time.RFC3339, propertyValue1)
		assert.Nil(t, err)
		propertyValue2 := (*(*VEXResult.Vulnerabilities)[1].Properties)[0].Value
		responseTime2, err := time.Parse(time.RFC3339, propertyValue2)
		assert.Nil(t, err)
		//test if the first responded timestamp is calculated about right
		assert.True(t, responseTime1.Before(time.Now().Add(-7*time.Minute).UTC()) && responseTime1.After(time.Now().Add(-7*time.Minute-time.Second).UTC()))
		assert.True(t, responseTime2.Before(time.Now().Add(-1*time.Minute)) && responseTime2.After(time.Now().Add(-1*time.Minute-time.Second)))
		//last updated should be the same as first responded when only 1 updateEvent happens
		assert.Equal(t, (*VEXResult.Vulnerabilities)[1].Analysis.LastUpdated, (*(*VEXResult.Vulnerabilities)[1].Properties)[0].Value)

		//test Vulnerability id as well as purls
		assert.Len(t, *VEXResult.Vulnerabilities, 2)
		assert.Equal(t, (*VEXResult.Vulnerabilities)[1].ID, "CVE-2024-51479", (*VEXResult.Vulnerabilities)[0].ID)
		assert.Equal(t, (*(*VEXResult.Vulnerabilities)[0].Affects)[0].Ref, "pkg:npm/next@14.2.13")
		assert.Equal(t, (*(*VEXResult.Vulnerabilities)[1].Affects)[0].Ref, "pkg:npm/axios@1.7.7")
	})

	t.Run("build Vex but one vuln never gets handled should return empty properties for that vulnerability", func(t *testing.T) {
		//setup function call
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/vex-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		if err := db.Delete(&models.VulnEvent{}, "vuln_id = ? AND type = ?", vuln2.ID, "fixed").Error; err != nil {
			panic(err)
		}

		err := assetVersionController.VEXJSON(ctx)
		assert.Nil(t, err)

		//prep results for testing
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)

		var VEXResult cyclonedx.BOM
		err = json.Unmarshal(body, &VEXResult)
		assert.Nil(t, err)

		//if the vulnerability never gets handled we should have no first responded field and first issued and last updated should be the same
		assert.Nil(t, (*VEXResult.Vulnerabilities)[1].Properties)
		assert.Equal(t, (*VEXResult.Vulnerabilities)[1].Analysis.FirstIssued, (*VEXResult.Vulnerabilities)[1].Analysis.LastUpdated)
	})

	t.Run("should not list vulnerabilities which are already fixed", func(t *testing.T) {
		//setup function call
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/vex-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)

		// update the vuln1 to be fixed
		vuln1.State = "fixed"
		if err := db.Save(&vuln1).Error; err != nil {
			panic(err)
		}
		err := assetVersionController.VEXJSON(ctx)
		assert.Nil(t, err)

		//prep results for testing
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)

		var VEXResult cyclonedx.BOM
		err = json.Unmarshal(body, &VEXResult)
		assert.Nil(t, err)

		assert.Len(t, *VEXResult.Vulnerabilities, 1)
		assert.Equal(t, (*VEXResult.Vulnerabilities)[0].ID, "CVE-2024-51479")
	})
}

func createDependencyVulns(db core.DB, assetID uuid.UUID, assetVersionName string) (models.DependencyVuln, models.DependencyVuln) {
	//first add cves
	var err error
	if err = db.AutoMigrate(&models.Exploit{}); err != nil {
		panic(err)
	}

	cve := models.CVE{
		CVE:         "CVE-2024-51479",
		Description: "Test usage",
		CVSS:        7.50,
	}
	if err = db.Create(&cve).Error; err != nil {
		panic(err)
	}
	//create an exploit for the cve
	exploit := models.Exploit{
		ID:       "exploitdb:1",
		CVE:      cve,
		CVEID:    cve.CVE,
		Author:   "mats schummels",
		Verified: false,
	}
	if err = db.Create(&exploit).Error; err != nil {
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
	}
	if err = db.Create(&vuln1).Error; err != nil {
		panic(err)
	}
	vuln2 := models.DependencyVuln{
		Vulnerability:     models.Vulnerability{AssetVersionName: assetVersionName, AssetID: assetID, State: "open"},
		ComponentPurl:     utils.Ptr("pkg:npm/axios@1.7.7"),
		CVE:               &cve,
		CVEID:             &cve.CVE,
		RawRiskAssessment: utils.Ptr(8.89),
		ComponentDepth:    utils.Ptr(2),
	}
	if err = db.Create(&vuln2).Error; err != nil {
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
	vuln1FixedEvent := models.VulnEvent{
		VulnID:   vuln1.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-3 * time.Minute), UpdatedAt: time.Now().Add(-3 * time.Minute)},
		Type:     "fixed",
		UserID:   "system",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1FixedEvent).Error; err != nil {
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

	vuln2FixedEvent := models.VulnEvent{
		VulnID:   vuln2.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-1 * time.Minute), UpdatedAt: time.Now().Add(-1 * time.Minute)},
		Type:     "fixed",
		UserID:   "system",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln2FixedEvent).Error; err != nil {
		panic(err)
	}
	return vuln1, vuln2
}

func TestUploadVEX(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()
	app := echo.New()
	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	assetVersionController := inithelper.CreateAssetVersionController(db, nil, nil, integration_tests.TestGitlabClientFactory{GitlabClientFacade: nil}, nil)
	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	setupContext := func(ctx *core.Context) {
		core.SetAsset(*ctx, asset)
		core.SetProject(*ctx, project)
		core.SetOrg(*ctx, org)
		core.SetAssetVersion(*ctx, assetVersion)

		// attach an authenticated session for UploadVEX handler
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		core.SetSession(*ctx, authSession)
	}

	// create fresh dependency vulns (two entries for same new CVE) so they are not pre-fixed
	var err error
	newCVE := models.CVE{
		CVE:         "CVE-2025-00001",
		Description: "Test upload vex",
		CVSS:        5.00,
	}
	if err = db.Create(&newCVE).Error; err != nil {
		t.Fatalf("could not create cve: %v", err)
	}

	newCVE2 := models.CVE{
		CVE:         "CVE-2025-00002",
		Description: "Test upload vex 2",
		CVSS:        6.00,
	}
	if err = db.Create(&newCVE2).Error; err != nil {
		t.Fatalf("could not create cve 2: %v", err)
	}

	dv1 := models.DependencyVuln{
		Vulnerability:     models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open"},
		ComponentPurl:     utils.Ptr("pkg:npm/example1@1.0.0"),
		CVE:               &newCVE,
		CVEID:             &newCVE.CVE,
		RawRiskAssessment: utils.Ptr(1.23),
		ComponentDepth:    utils.Ptr(1),
	}
	if err = db.Create(&dv1).Error; err != nil {
		t.Fatalf("could not create dependency vuln 1: %v", err)
	}

	dv2 := models.DependencyVuln{
		Vulnerability:     models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open"},
		ComponentPurl:     utils.Ptr("pkg:npm/example2@2.0.0"),
		CVE:               &newCVE2,
		CVEID:             &newCVE2.CVE,
		RawRiskAssessment: utils.Ptr(2.34),
		ComponentDepth:    utils.Ptr(2),
	}
	if err = db.Create(&dv2).Error; err != nil {
		t.Fatalf("could not create dependency vuln 2: %v", err)
	}

	// build a CycloneDX BOM with a single vulnerability (CVE) marked as resolved
	vuln := cyclonedx.Vulnerability{
		ID: "CVE-2025-00001",
		Source: &cyclonedx.Source{
			Name: "NVD",
			URL:  "https://nvd.nist.gov/vuln/detail/CVE-2025-00001",
		},
		Analysis: &cyclonedx.VulnerabilityAnalysis{
			State:  cyclonedx.IASFalsePositive,
			Detail: "We are never using this dependency, so marking as false positive",
		},
	}
	bom := cyclonedx.BOM{
		BOMFormat:       "CycloneDX",
		SpecVersion:     cyclonedx.SpecVersion1_6,
		Version:         1,
		Vulnerabilities: &[]cyclonedx.Vulnerability{vuln},
	}

	// encode BOM into multipart form
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "vex.json")
	if err != nil {
		t.Fatalf("could not create form file: %v", err)
	}
	if err := cyclonedx.NewBOMEncoder(fw, cyclonedx.BOMFileFormatJSON).Encode(&bom); err != nil {
		t.Fatalf("could not encode bom: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("could not close multipart writer: %v", err)
	}

	// perform POST request to UploadVEX
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/vex-file/", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	ctx := app.NewContext(req, recorder)
	setupContext(&ctx)

	err = assetVersionController.UploadVEX(ctx)
	assert.Nil(t, err)

	resp := recorder.Result()
	respBody, err := io.ReadAll(resp.Body)
	assert.Nil(t, err)

	var result map[string]int
	err = json.Unmarshal(respBody, &result)
	assert.Nil(t, err)

	// both dependency vulns should be updated (two entries share the CVE)
	assert.Equal(t, 1, result["updated"])
	assert.Equal(t, 0, result["notFound"])

	// verify DB: both dependency vulns should now be fixed
	var dv []models.DependencyVuln
	if err := db.Where("asset_version_name = ? AND asset_id = ?", assetVersion.Name, asset.ID).Preload("Events").Find(&dv).Error; err != nil {
		t.Fatalf("could not query dependency vulns: %v", err)
	}
	assert.GreaterOrEqual(t, len(dv), 2)

	for _, d := range dv {
		switch *d.CVEID {
		case "CVE-2025-00001":
			assert.Equal(t, models.VulnStateFalsePositive, d.State)
			assert.Equal(t, "[VEX-Upload] We are never using this dependency, so marking as false positive", *d.Events[0].Justification)
		case "CVE-2025-00002":
			assert.Equal(t, models.VulnStateOpen, d.State) // was not part of the uploaded vex.
		}
	}
}
