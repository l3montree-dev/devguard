package assetversion_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/integration_tests"
)

func TestBuildSBOM(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()
	println("%s", db.Error)
	//assetVersionController := assetversion.NewAssetVersionController()
	t.Run("default test", func(t *testing.T) {

	})
}
