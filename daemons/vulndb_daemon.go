package daemons

import (
	"log/slog"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
)

func UpdateVulnDB(db shared.DB) error {
	begin := time.Now()
	defer func() {
		monitoring.VulnDBUpdateDuration.Observe(time.Since(begin).Minutes())
	}()
	if os.Getenv("DISABLE_VULNDB_UPDATE") == "true" {
		slog.Info("vulndb update disabled")
		return nil
	}

	slog.Info("updating vulndb")
	cveRepository := repositories.NewCVERepository(db)
	cweRepository := repositories.NewCWERepository(db)
	exploitsRepository := repositories.NewExploitRepository(db)
	affectedComponentsRepository := repositories.NewAffectedComponentRepository(db)
	configService := services.NewConfigService(db)

	v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService)

	err := v.ImportFromDiff(nil)
	if err != nil {
		slog.Error("failed to update vulndb", "error", err)
		return err
	}
	monitoring.VulnDBUpdateDaemonAmount.Inc()
	return nil
}
