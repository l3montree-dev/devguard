package csaf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
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
	statisticsRepository := repositories.NewStatisticsRepository(db)

	// Create test organization, project, asset, and asset version
	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	csafController := NewCSAFController(dependencyVulnRepository, vulnEventRepository, assetVersionRepository, statisticsRepository)
	// Setup echo app
	app := echo.New()

	// Setup context helper
	setupContext := func(ctx core.Context) {
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetAssetVersion(ctx, assetVersion)
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
	t.Run("if we do not have a vulnerability hsitory yet for an asset we should find an empty vuln object as well as the category set as csaf_base", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/csaf/", nil)
		ctx := app.NewContext(req, recorder)

		ctx.SetParamNames("organization", "project", "asset", "version")
		ctx.SetParamValues(org.Slug, project.Slug, asset.Slug, fmt.Sprintf("csaf_report_%s_1.json", asset.Slug))
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
		assert.Equal(t, "csaf_base", csafDoc.Document.Category)
		assert.Equal(t, "2.0", csafDoc.Document.CSAFVersion)
		assert.Equal(t, "vendor", csafDoc.Document.Publisher.Category)
		assert.Equal(t, org.Slug, csafDoc.Document.Publisher.Name)
		assert.Equal(t, "https://devguard.org", csafDoc.Document.Publisher.Namespace)

		assert.Equal(t, 1, len(csafDoc.ProductTree.Branches))
		assert.Equal(t, "main", csafDoc.ProductTree.Branches[0].Name)
		assert.Equal(t, "product_version", csafDoc.ProductTree.Branches[0].Category)
		assert.Equal(t, "main", csafDoc.ProductTree.Branches[0].Product.ProductID)
		assert.Equal(t, "main", csafDoc.ProductTree.Branches[0].Product.Name)
	})
}
