package assetversion_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/inithelper"
	"github.com/labstack/echo/v4"
)

func TestBuildSBOM(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()
	assetVersionController := inithelper.CreateAssetVersionController(db, nil)
	app := echo.New()
	ctx := app.NewContext(nil, nil)
	t.Run("default test", func(t *testing.T) {
		assetVersionController.SBOMJSON(ctx)
	})
}
