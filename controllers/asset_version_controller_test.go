package controllers

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/tests"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestBuildVEX(t *testing.T) {
	//Build up a foundation for all the upcoming tests
	db, terminate := tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()
	app := echo.New()
	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	assetVersionController := tests.CreateAssetVersionController(db, nil, nil, tests.TestGitlabClientFactory{GitlabClientFacade: nil}, nil)
	org, project, asset, assetVersion := tests.CreateOrgProjectAndAssetAssetVersion(db)
	artifactName := "test-artifact"

	setupContext := func(ctx *shared.Context) {
		// set basic context values
		shared.SetAsset(*ctx, asset)
		shared.SetProject(*ctx, project)
		shared.SetOrg(*ctx, org)
		shared.SetAssetVersion(*ctx, assetVersion)
		shared.SetArtifact(*ctx, models.Artifact{ArtifactName: artifactName, AssetVersionName: assetVersion.Name, AssetID: asset.ID})
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
		assert.Equal(t, "test-artifact@main", VEXResult.Metadata.Component.BOMRef)
		assert.Equal(t, "test-artifact@main", VEXResult.Metadata.Component.Name)

		assert.Empty(t, VEXResult.Vulnerabilities)
	})
	vuln1, vuln2 := createDependencyVulns(db, asset.ID, assetVersion.Name, artifactName)
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

func createDependencyVulns(db shared.DB, assetID uuid.UUID, assetVersionName string, artifactName string) (models.DependencyVuln, models.DependencyVuln) {

	var err error

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

	artifact := models.Artifact{
		ArtifactName:     artifactName,
		AssetVersionName: assetVersionName,
		AssetID:          assetID,
	}
	if err := db.Create(&artifact).Error; err != nil {
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
		CVE:               &cve,
		CVEID:             &cve.CVE,
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
		VulnType: dtos.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1DetectedEvent).Error; err != nil {
		panic(err)
	}

	vuln1CommentEvent := models.VulnEvent{
		VulnID:   vuln1.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-7 * time.Minute), UpdatedAt: time.Now().Add(-7 * time.Minute)},
		Type:     "comment",
		UserID:   "system",
		VulnType: dtos.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1CommentEvent).Error; err != nil {
		panic(err)
	}
	vuln1FixedEvent := models.VulnEvent{
		VulnID:   vuln1.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-3 * time.Minute), UpdatedAt: time.Now().Add(-3 * time.Minute)},
		Type:     "fixed",
		UserID:   "system",
		VulnType: dtos.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1FixedEvent).Error; err != nil {
		panic(err)
	}
	vuln2DetectedEvent := models.VulnEvent{
		VulnID:   vuln2.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-3 * time.Minute), UpdatedAt: time.Now().Add(-2 * time.Minute)},
		Type:     "detected",
		UserID:   "system",
		VulnType: dtos.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln2DetectedEvent).Error; err != nil {
		panic(err)
	}

	vuln2FixedEvent := models.VulnEvent{
		VulnID:   vuln2.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-1 * time.Minute), UpdatedAt: time.Now().Add(-1 * time.Minute)},
		Type:     "fixed",
		UserID:   "system",
		VulnType: dtos.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln2FixedEvent).Error; err != nil {
		panic(err)
	}
	return vuln1, vuln2
}
