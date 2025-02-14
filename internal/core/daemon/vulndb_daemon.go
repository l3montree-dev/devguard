package daemon

import (
	"log/slog"
	"os"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func UpdateVulnDB(db core.DB) error {
	if os.Getenv("DISABLE_VULNDB_UPDATE") == "true" {
		slog.Info("vulndb update disabled")
		return nil
	}

	slog.Info("updating vulndb")
	cveRepository := repositories.NewCVERepository(db)
	cweRepository := repositories.NewCWERepository(db)
	exploitsRepository := repositories.NewExploitRepository(db)
	affectedComponentsRepository := repositories.NewAffectedComponentRepository(db)

	v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository)

	return v.Import(db, "latest")
}
