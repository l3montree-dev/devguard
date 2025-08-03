// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package daemon

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func AutoReopenAcceptedVulnerabilities(db core.DB) error {

	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	assetRepository := repositories.NewAssetRepository(db)

	assets, err := assetRepository.All()
	if err != nil {
		return err
	}

	for _, asset := range assets {
		// check if the asset has auto-reopen enabled
		if asset.VulnAutoReopenAfterDays == nil {
			continue
		}

		// convert days to time.Duration
		reopenAfterDuration := time.Duration(*asset.VulnAutoReopenAfterDays) * 24 * time.Hour

		// get all closed/accepted vulnerabilities for the asset version
		vulnerabilities, err := dependencyVulnRepository.GetAllByAssetIDAndState(nil, asset.ID, models.VulnStateAccepted, reopenAfterDuration)
		if err != nil {
			return err
		}

		for _, vuln := range vulnerabilities {
			// create a new event for the vulnerability
			event := models.NewReopenedEvent(vuln.ID, models.VulnTypeDependencyVuln, "system", fmt.Sprintf("Automatically reopened since the vulnerability was accepted more than %d days ago", *asset.VulnAutoReopenAfterDays))

			if err := dependencyVulnRepository.ApplyAndSave(nil, &vuln, &event); err != nil {
				slog.Error("failed to apply and save vulnerability event", "vulnerabilityID", vuln.ID, "error", err)
			} else {
				slog.Info("reopened vulnerability since it was accepted more than the configured time", "vulnerabilityID", vuln.ID, "assetID", asset.ID, "reopenAfterDays", *asset.VulnAutoReopenAfterDays)
			}
		}
	}

	return nil
}
