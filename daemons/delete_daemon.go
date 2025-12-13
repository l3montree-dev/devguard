// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package daemons

import (
	"log/slog"
)

func (runner DaemonRunner) DeleteOldAssetVersions() error {
	count, err := runner.assetVersionRepository.DeleteOldAssetVersions(7)
	if err != nil {
		return err
	}
	if count > 0 {
		slog.Info("Deleted old asset versions", "count", count)
	} else {
		slog.Info("No old asset versions to delete")
	}

	// Delete old vuln events
	err = runner.vulnEventRepository.DeleteEventsWithNotExistingVulnID()
	if err != nil {
		slog.Error("Failed to delete old vuln events", "err", err)
	}

	return nil
}
