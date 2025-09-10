package daemon

import (
	"log/slog"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/config"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
)

func UpdateVulnDB(db core.DB) error {
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
	configService := config.NewService(db)

	v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService)

	err := v.Import(db, "latest")
	if err != nil {
		slog.Error("failed to update vulndb", "error", err)
		return err
	}
	monitoring.VulnDBUpdateDaemonAmount.Inc()
	return nil
}
