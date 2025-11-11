// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package daemon

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/shared"
)

func DeleteOldAssetVersions(db shared.DB) error {
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)

	count, err := assetVersionRepository.DeleteOldAssetVersions(7)
	if err != nil {
		return err
	}
	if count > 0 {
		slog.Info("Deleted old asset versions", "count", count)
	} else {
		slog.Info("No old asset versions to delete")
	}

	// Delete old vuln events
	err = vulnEventRepository.DeleteEventsWithNotExistingVulnID()
	if err != nil {
		slog.Error("Failed to delete old vuln events", "err", err)
	}

	return nil
}
