package assetversion_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/inithelper"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/package-url/packageurl-go"
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
		core.SetAsset(*ctx, asset)
		core.SetProject(*ctx, project)
		core.SetOrg(*ctx, org)
		core.SetAssetVersion(*ctx, assetVersion)
	}
	t.Run("default test", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/vex-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		createDependencyVulns(db, asset.ID, assetVersion.Name)
		err := assetVersionController.VEXJSON(ctx)
		if err != nil {
			t.Fail()
		}

		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fail()
		}
		var VEXResult cyclonedx.BOM
		if err = json.Unmarshal(body, &VEXResult); err != nil {
			t.Fail()
		}

		fmt.Printf("%s", string(body))

	})
}

func TestBuildSBOM(t *testing.T) {
	//Build up a foundation for all the upcoming tests
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
	}
	t.Run("test with empty db", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		err := assetVersionController.SBOMJSON(ctx)
		if err != nil {
			t.Fail()
		}

		//Process the results into an BOM
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fail()
		}
		var BOMResult cyclonedx.BOM
		if err = json.Unmarshal(body, &BOMResult); err != nil {
			t.Fail()
		}

		//Test the bom
		assert.Empty(t, BOMResult.Components)
		assert.Empty(t, BOMResult.Dependencies)
		assert.Equal(t, "Test Org", BOMResult.Metadata.Component.Author)
		assert.Equal(t, "github.com/l3montree-dev/devguard", BOMResult.Metadata.Component.Publisher)
		assert.Equal(t, "main", BOMResult.Metadata.Component.BOMRef)
		assert.Equal(t, "latest", BOMResult.Metadata.Component.Version)
	})
	t.Run("test with only components in the db with no specific version", func(t *testing.T) {
		createComponents(db)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		err := assetVersionController.SBOMJSON(ctx)
		if err != nil {
			t.Fail()
		}

		//Process the results into an BOM
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fail()
		}
		var BOMResult cyclonedx.BOM
		if err = json.Unmarshal(body, &BOMResult); err != nil {
			t.Fail()
		}

		//Test the bom
		assert.Empty(t, BOMResult.Components)
		assert.Empty(t, BOMResult.Dependencies)
		testSBOMProperties(t, BOMResult)
		assert.Equal(t, "latest", BOMResult.Metadata.Component.Version)
	})
	t.Run("test with only components in the db with an invalid version set should return an error", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		params := ctx.QueryParams()
		params.Add("version", "special version")
		err := assetVersionController.SBOMJSON(ctx)
		//should return an error
		if err == nil {
			t.Fail()
		}
	})
	t.Run("test with only components in the db with a valid version set", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		params := ctx.QueryParams()
		params.Add("version", "2.1.9")

		err := assetVersionController.SBOMJSON(ctx)
		if err != nil {
			t.Fail()
		}

		//Process the results into a BOM
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fail()
		}
		var BOMResult cyclonedx.BOM
		if err = json.Unmarshal(body, &BOMResult); err != nil {
			t.Fail()
		}

		//Test the bom
		assert.Empty(t, BOMResult.Components)
		assert.Empty(t, BOMResult.Dependencies)
		testSBOMProperties(t, BOMResult)
		assert.Equal(t, "2.1.9", BOMResult.Metadata.Component.Version)

	})
	t.Run("create a normal sbom with components and dependencies but no license overwrite ", func(t *testing.T) {
		//Setup environment for this test
		createDependencies(db, org.ID, asset.ID, assetVersion.Name)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-1")
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		err := assetVersionController.SBOMJSON(ctx)
		if err != nil {
			t.Fail()
		}

		//Process the results into a BOM
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fail()
		}
		var BOMResult cyclonedx.BOM
		if err = json.Unmarshal(body, &BOMResult); err != nil {
			t.Fail()
		}

		//Test the BOM
		componentPURL0, err := packageurl.FromString((*BOMResult.Components)[0].PackageURL)
		if err != nil {
			t.Fail()
		}
		componentPURL1, err := packageurl.FromString((*BOMResult.Components)[1].PackageURL)
		if err != nil {
			t.Fail()
		}
		license := cyclonedx.Licenses{cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: "MIT"}}}

		assert.Equal(t, packageurl.PackageURL{Type: "npm", Namespace: "@xyflow", Name: "react", Version: "12.3.0", Qualifiers: packageurl.Qualifiers{}}, componentPURL0)
		assert.Equal(t, license[0].License.ID, (*(*BOMResult.Components)[0].Licenses)[0].License.ID)
		assert.Equal(t, packageurl.PackageURL{Type: "npm", Namespace: "@xyflow", Name: "system", Version: "0.0.42", Qualifiers: packageurl.Qualifiers{}}, componentPURL1)
		assert.Equal(t, license[0].License.ID, (*(*BOMResult.Components)[1].Licenses)[0].License.ID)

		assert.Equal(t, []cyclonedx.Dependency{
			{Ref: "pkg:npm/@xyflow/system@0.0.42", Dependencies: &[]string{"pkg:npm/@xyflow/react@12.3.0"}},
			{Ref: "main", Dependencies: &[]string{"pkg:npm/@xyflow/system@0.0.42"}},
		}, *BOMResult.Dependencies)

		testSBOMProperties(t, BOMResult)
		assert.Equal(t, "latest", BOMResult.Metadata.Component.Version)
	})
	t.Run("create a normal sbom with components and dependencies but the license of one of the components is now overwritten", func(t *testing.T) {
		//Setup environment for this test
		createLicenseOverwrite(db, org.ID)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-1")
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		err := assetVersionController.SBOMJSON(ctx)
		if err != nil {
			t.Fail()
		}

		//Process the results into an BOM
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fail()
		}
		var BOMResult cyclonedx.BOM
		if err = json.Unmarshal(body, &BOMResult); err != nil {
			t.Fail()
		}

		//Test the BOM
		componentPURL0, err := packageurl.FromString((*BOMResult.Components)[0].PackageURL)
		if err != nil {
			t.Fail()
		}
		componentPURL1, err := packageurl.FromString((*BOMResult.Components)[1].PackageURL)
		if err != nil {
			t.Fail()
		}
		licenseMIT := cyclonedx.Licenses{cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: "MIT"}}}

		licenseApache := cyclonedx.Licenses{cyclonedx.LicenseChoice{License: &cyclonedx.License{ID: "Apache-2.0"}}}
		assert.Equal(t, packageurl.PackageURL{Type: "npm", Namespace: "@xyflow", Name: "react", Version: "12.3.0", Qualifiers: packageurl.Qualifiers{}}, componentPURL0)
		assert.Equal(t, licenseMIT[0].License.ID, (*(*BOMResult.Components)[0].Licenses)[0].License.ID)
		assert.Equal(t, packageurl.PackageURL{Type: "npm", Namespace: "@xyflow", Name: "system", Version: "0.0.42", Qualifiers: packageurl.Qualifiers{}}, componentPURL1)
		assert.Equal(t, licenseApache[0].License.ID, (*(*BOMResult.Components)[1].Licenses)[0].License.ID)

		assert.Equal(t, []cyclonedx.Dependency{
			{Ref: "pkg:npm/@xyflow/system@0.0.42", Dependencies: &[]string{"pkg:npm/@xyflow/react@12.3.0"}},
			{Ref: "main", Dependencies: &[]string{"pkg:npm/@xyflow/system@0.0.42"}},
		}, *BOMResult.Dependencies)
		testSBOMProperties(t, BOMResult)
		assert.Equal(t, "latest", BOMResult.Metadata.Component.Version)
	})
}

func createDependencyVulns(db core.DB, assetID uuid.UUID, assetVersionName string) {
	//first add cves
	db.AutoMigrate(&models.Exploit{})
	var err error
	cve := models.CVE{
		CVE:         "CVE-2024-51479",
		Description: "Test usage",
		Severity:    models.SeverityHigh,
		CVSS:        7.50,
	}
	if err = db.Create(&cve).Error; err != nil {
		panic(err)
	}
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
	vuln1 := models.DependencyVuln{
		Vulnerability:     models.Vulnerability{ID: "bf2609eb45b7e40d9f59a0555ce267b1bbc565363f765428f638c8d8c39f1604", AssetVersionName: assetVersionName, AssetID: assetID, State: "open"},
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
		Vulnerability:     models.Vulnerability{ID: "8374855f8bf1d188f28183e7e1960700ba5864e415a0e62b4feeba5f4d566562", AssetVersionName: assetVersionName, AssetID: assetID, State: "open"},
		ComponentPurl:     utils.Ptr("pkg:npm/axios@1.7.7"),
		CVE:               &cve,
		CVEID:             &cve.CVE,
		RawRiskAssessment: utils.Ptr(8.89),
		ComponentDepth:    utils.Ptr(2),
	}
	if err = db.Create(&vuln2).Error; err != nil {
		panic(err)
	}
	vuln1DetectedEvent := models.VulnEvent{
		VulnID:   vuln1.Vulnerability.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-10 * time.Minute), UpdatedAt: time.Now().Add(-5 * time.Minute)},
		Type:     "detected",
		UserID:   "system",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1DetectedEvent).Error; err != nil {
		panic(err)
	}

	vuln1CommentEvent := models.VulnEvent{
		VulnID:   vuln1.Vulnerability.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-7 * time.Minute), UpdatedAt: time.Now().Add(-7 * time.Minute)},
		Type:     "comment",
		UserID:   "system",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1CommentEvent).Error; err != nil {
		panic(err)
	}
	vuln1FixedEvent := models.VulnEvent{
		VulnID:   vuln1.Vulnerability.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-3 * time.Minute), UpdatedAt: time.Now().Add(-3 * time.Minute)},
		Type:     "fixed",
		UserID:   "system",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln1FixedEvent).Error; err != nil {
		panic(err)
	}
	vuln2DetectedEvent := models.VulnEvent{
		VulnID:   vuln2.Vulnerability.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-3 * time.Minute), UpdatedAt: time.Now().Add(-2 * time.Minute)},
		Type:     "detected",
		UserID:   "system",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln2DetectedEvent).Error; err != nil {
		panic(err)
	}

	vuln2FixedEvent := models.VulnEvent{
		VulnID:   vuln2.Vulnerability.ID,
		Model:    models.Model{CreatedAt: time.Now().Add(-1 * time.Minute), UpdatedAt: time.Now().Add(-1 * time.Minute)},
		Type:     "fixed",
		UserID:   "system",
		VulnType: models.VulnTypeDependencyVuln,
	}
	if err = db.Create(&vuln2FixedEvent).Error; err != nil {
		panic(err)
	}
}

func createComponents(db core.DB) {
	componentProject := models.ComponentProject{
		ProjectKey:      "github.com/xyflow/xyflow",
		StarsCount:      2993,
		ForksCount:      282,
		OpenIssuesCount: 0,
		License:         "MIT",
		ScoreCardScore:  utils.Ptr(5.2),
	}
	err := db.Create(&componentProject).Error
	if err != nil {
		panic(err)
	}
	component1 := models.Component{
		Purl:             "pkg:npm/@xyflow/system@0.0.42",
		ComponentType:    models.ComponentTypeLibrary,
		Version:          "0.0.42",
		License:          utils.Ptr("MIT"),
		Published:        utils.Ptr(time.Now()),
		ComponentProject: &componentProject,
	}
	err = db.Create(&component1).Error
	if err != nil {
		panic(err)
	}
	component2 := models.Component{
		Purl:             "pkg:npm/@xyflow/react@12.3.0",
		ComponentType:    models.ComponentTypeLibrary,
		Version:          "12.3.0",
		License:          utils.Ptr("MIT"),
		Published:        utils.Ptr(time.Now()),
		ComponentProject: &componentProject,
	}
	err = db.Create(&component2).Error
	if err != nil {
		panic(err)
	}
}

func testSBOMProperties(t *testing.T, BOMResult cyclonedx.BOM) {
	assert.Equal(t, "Test Org", BOMResult.Metadata.Component.Author)
	assert.Equal(t, "github.com/l3montree-dev/devguard", BOMResult.Metadata.Component.Publisher)
	assert.Equal(t, "main", BOMResult.Metadata.Component.BOMRef)
}

func createDependencies(db core.DB, orgID uuid.UUID, assetID uuid.UUID, assetVersionName string) {
	componentDependency0 := models.ComponentDependency{
		ComponentPurl:    nil,
		DependencyPurl:   "pkg:npm/@xyflow/system@0.0.42",
		AssetID:          assetID,
		AssetVersionName: assetVersionName,
		Depth:            0,
		ScannerIDs:       "SBOM-File-Upload",
	}
	err := db.Create(&componentDependency0).Error
	if err != nil {
		panic(err)
	}

	componentDependency1 := models.ComponentDependency{
		ComponentPurl:    utils.Ptr("pkg:npm/@xyflow/system@0.0.42"),
		DependencyPurl:   "pkg:npm/@xyflow/react@12.3.0",
		AssetID:          assetID,
		AssetVersionName: assetVersionName,
		Depth:            0,
		ScannerIDs:       "SBOM-File-Upload",
	}
	err = db.Create(&componentDependency1).Error
	if err != nil {
		panic(err)
	}
	componentDependency2 := models.ComponentDependency{
		ComponentPurl:    utils.Ptr("pkg:npm/@xyflow/react@12.3.0"),
		DependencyPurl:   "pkg:npm/@xyflow/system@0.0.42",
		AssetID:          assetID,
		AssetVersionName: assetVersionName,
		Depth:            0,
		ScannerIDs:       "SBOM-File-Upload",
	}
	err = db.Create(&componentDependency2).Error
	if err != nil {
		panic(err)
	}
}

func createLicenseOverwrite(db core.DB, orgID uuid.UUID) {
	lo := models.LicenseOverwrite{
		LicenseID:      "Apache-2.0",
		OrganizationId: orgID,
		ComponentPurl:  "pkg:npm/@xyflow/system@0.0.42",
		Justification:  "while the specifications place no limits on the magnitude or precision of JSON number literals, the widely used JavaScript implementation stores them as IEEE754 binary64 quantities. For interoperability, applications should avoid transmitting numbers that cannot be represented in this way, for example, 1E400 or 3.141592653589793238462643383279.",
	}
	err := db.Create(&lo).Error
	if err != nil {
		panic(err)
	}
}
