package daemons

import (
	"log/slog"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/monitoring"
)

func (runner *DaemonRunner) UpdateVulnDB() error {
	begin := time.Now()
	defer func() {
		monitoring.VulnDBUpdateDuration.Observe(time.Since(begin).Minutes())
	}()
	if os.Getenv("DISABLE_VULNDB_UPDATE") == "true" {
		slog.Info("vulndb update disabled")
		return nil
	}

	slog.Info("updating vulndb")

	err := runner.vulnDBImportService.ImportFromDiff(nil)
	if err != nil {
		slog.Error("failed to update vulndb", "error", err)
		return err
	}

	return nil
}
