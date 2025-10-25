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
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/pkg/errors"
)

func UploadVEX(vex io.Reader, isFromUpstream bool) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/vex", config.RuntimeBaseConfig.APIURL), vex)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}

	err = pat.SignRequest(config.RuntimeBaseConfig.Token, req)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Origin", config.RuntimeBaseConfig.Origin+"-vex")
	req.Header.Set("X-Artifact-Name", config.RuntimeBaseConfig.ArtifactName)

	isFromUpstreamStr := "0"
	if isFromUpstream {
		isFromUpstreamStr = "1"
	}

	req.Header.Set("X-Is-Upstream", isFromUpstreamStr)
	config.SetXAssetHeaders(req)

	return http.DefaultClient.Do(req)
}

func UploadBOM(bom io.Reader) (*http.Response, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/scan", config.RuntimeBaseConfig.APIURL), bom)
	if err != nil {
		return nil, cancel, errors.Wrap(err, "could not create request")
	}

	err = pat.SignRequest(config.RuntimeBaseConfig.Token, req)
	if err != nil {
		return nil, cancel, errors.Wrap(err, "could not sign request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scanner", config.RuntimeBaseConfig.ScannerID)
	req.Header.Set("X-Artifact-Name", config.RuntimeBaseConfig.ArtifactName)
	req.Header.Set("X-Origin", config.RuntimeBaseConfig.Origin)
	config.SetXAssetHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	return resp, cancel, err
}
