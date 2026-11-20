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
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Masterminds/semver"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	buildconfig "github.com/l3montree-dev/devguard/config"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/telemetry"
	"github.com/l3montree-dev/devguard/utils"
)

var versionCheckOnce sync.Once

func WarnOnVersionMismatch() {
	versionCheckOnce.Do(func() {
		scannerVersion := telemetry.RuntimeVersion(buildconfig.Version)
		apiVersion, err := fetchAPIVersion()
		if err != nil {
			slog.Debug("could not determine DevGuard API version", "err", err)
			return
		}

		scannerSemver, err := semver.NewVersion(scannerVersion)
		if err != nil {
			slog.Debug("scanner version is not a valid semver, skipping version check", "version", scannerVersion)
			return
		}
		apiSemver, err := semver.NewVersion(apiVersion)
		if err != nil {
			slog.Debug("DevGuard API version is not a valid semver, skipping version check", "version", apiVersion)
			return
		}

		if scannerSemver.Major() != apiSemver.Major() || scannerSemver.Minor() != apiSemver.Minor() {
			config.AddWarning("VERSION MISMATCH", fmt.Sprintf("devguard-scanner %s and DevGuard API %s differ in minor version - compatibility is not guaranteed, please use a matching scanner version.", scannerVersion, apiVersion))
		}
	})
}

func fetchAPIVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/info/", config.RuntimeBaseConfig.APIURL), nil)
	if err != nil {
		return "", err
	}

	resp, err := utils.EgressClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var info dtos.InfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	return info.Build.Version, nil
}
