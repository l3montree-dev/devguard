package daemons

import (
	"context"
	"log/slog"
	"os"

	"github.com/l3montree-dev/devguard/shared"
)

func (runner *DaemonRunner) UpdateVulnDB(ctx context.Context) error {
	if os.Getenv("DISABLE_VULNDB_UPDATE") == "true" {
		slog.Info("vulndb update disabled")
		return nil
	}

	slog.Info("updating vulndb")

	err := runner.vulnDBImportService.ImportRC(ctx, shared.ImportOptions{})
	if err != nil {
		slog.Error("failed to update vulndb", "error", err)
		return err
	}

	return nil
}
