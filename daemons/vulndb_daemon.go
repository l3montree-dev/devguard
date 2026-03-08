package daemons

import (
	"context"
	"log/slog"
	"os"
)

func (runner *DaemonRunner) UpdateVulnDB(ctx context.Context) error {
	if os.Getenv("DISABLE_VULNDB_UPDATE") == "true" {
		slog.Info("vulndb update disabled")
		return nil
	}

	slog.Info("updating vulndb")

	err := runner.vulnDBImportService.ImportFromDiff(ctx, nil)
	if err != nil {
		slog.Error("failed to update vulndb", "error", err)
		return err
	}

	return nil
}
