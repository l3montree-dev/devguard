package daemons

import (
	"log/slog"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
)

func UpdateVulnDB(
	cveRepository shared.CveRepository,
	cweRepository shared.CweRepository,
	exploitsRepository shared.ExploitRepository,
	affectedComponentsRepository shared.AffectedComponentRepository,
	configService shared.ConfigService,
) error {
	begin := time.Now()
	defer func() {
		monitoring.VulnDBUpdateDuration.Observe(time.Since(begin).Minutes())
	}()
	if os.Getenv("DISABLE_VULNDB_UPDATE") == "true" {
		slog.Info("vulndb update disabled")
		return nil
	}

	slog.Info("updating vulndb")

	v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService)

	err := v.ImportFromDiff(nil)
	if err != nil {
		slog.Error("failed to update vulndb", "error", err)
		return err
	}
	monitoring.VulnDBUpdateDaemonAmount.Inc()
	return nil
}
