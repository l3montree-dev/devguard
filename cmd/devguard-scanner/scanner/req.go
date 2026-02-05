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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/pkg/devguard"
	"github.com/l3montree-dev/devguard/services"
	"github.com/pkg/errors"
)

func UploadVEX(vex io.Reader) (*http.Response, error) {
	timeout := time.Duration(config.RuntimeBaseConfig.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/vex", config.RuntimeBaseConfig.APIURL), vex)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}

	err = services.SignRequest(config.RuntimeBaseConfig.Token, req)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Origin", config.RuntimeBaseConfig.Origin)
	req.Header.Set("X-Artifact-Name", config.RuntimeBaseConfig.ArtifactName)

	config.SetXAssetHeaders(req)

	return http.DefaultClient.Do(req)
}

func UploadBOM(bom io.Reader) (*http.Response, context.CancelFunc, error) {
	timeout := time.Duration(config.RuntimeBaseConfig.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	// read entire BOM into memory so we can decode and (optionally) re-encode it
	bodyBytes, err := io.ReadAll(bom)
	if err != nil {
		return nil, cancel, errors.Wrap(err, "could not read bom")
	}

	// try to parse it as cyclonedx into a non-nil value
	var cycloneDxBom cyclonedx.BOM
	if err := cyclonedx.NewBOMDecoder(bytes.NewReader(bodyBytes), cyclonedx.BOMFileFormatJSON).Decode(&cycloneDxBom); err != nil {
		slog.Warn("uploaded BOM is not a valid CycloneDX BOM", "err", err)
		return nil, cancel, err
	}

	if config.RuntimeBaseConfig.IgnoreExternalReferences && cycloneDxBom.ExternalReferences != nil {
		// remove all external references
		cycloneDxBom.ExternalReferences = &[]cyclonedx.ExternalReference{}
		// re-marshal modified BOM to use as request body
		bodyBytes, err = json.Marshal(cycloneDxBom)
		if err != nil {
			return nil, cancel, errors.Wrap(err, "could not marshal cycloneDX BOM")
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/scan", config.RuntimeBaseConfig.APIURL), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, cancel, errors.Wrap(err, "could not create request")
	}

	err = services.SignRequest(config.RuntimeBaseConfig.Token, req)
	if err != nil {
		return nil, cancel, errors.Wrap(err, "could not sign request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scanner", config.RuntimeBaseConfig.ScannerID)
	req.Header.Set("X-Artifact-Name", config.RuntimeBaseConfig.ArtifactName)
	req.Header.Set("X-Origin", config.RuntimeBaseConfig.Origin)
	req.Header.Set("X-Keep-Original-SBOM-Root-Component", fmt.Sprintf("%t", config.RuntimeBaseConfig.KeepOriginalSbomRootComponent))
	config.SetXAssetHeaders(req)

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		// check for timeout
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
			slog.Error("request timed out after configured or default timeout - as scan commands and upload can take a while consider increasing using the --timeout flag", "timeout", time.Duration(config.RuntimeBaseConfig.Timeout)*time.Second)
		}
		slog.Error("could not upload bom", "err", err)
	}

	return resp, cancel, err
}

func UploadPublicKey(ctx context.Context, token, apiURL, publicKeyPath, assetName string) error {
	devGuardClient, err := devguard.NewHTTPClient(token, apiURL)
	if err != nil {
		return err
	}

	var body = make(map[string]string)

	// read the public key from file
	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}

	body["publicKey"] = string(publicKey)
	// marshal
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/organizations/"+assetName+"/signing-key", bytes.NewBuffer(bodyBytes))

	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := devGuardClient.Do(req)
	if err != nil {
		// check for timeout
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
			slog.Error("request timed out after configured or default timeout - as scan commands and upload can take a while consider increasing using the --timeout flag", "timeout", time.Duration(config.RuntimeBaseConfig.Timeout)*time.Second)
		}
		slog.Error("could not upload public key", "err", err)
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not upload public key: %s", resp.Status)
	}

	return nil
}

func UploadAttestation(ctx context.Context, predicate string) error {
	// read the file
	file, err := os.ReadFile(predicate)
	if err != nil {
		slog.Error("could not read file", "err", err)
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/attestations", config.RuntimeBaseConfig.APIURL), bytes.NewReader(file))
	if err != nil {
		slog.Error("could not create request", "err", err)
		return err
	}

	err = services.SignRequest(config.RuntimeBaseConfig.Token, req)
	if err != nil {
		return err
	}

	req.Header.Set("X-Predicate-Type", config.RuntimeAttestationConfig.PredicateType)
	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Artifact-Name", config.RuntimeBaseConfig.ArtifactName)
	config.SetXAssetHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// check for timeout
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
			slog.Error("request timed out after configured or default timeout - as scan commands and upload can take a while consider increasing using the --timeout flag", "timeout", time.Duration(config.RuntimeBaseConfig.Timeout)*time.Second)
		}
		slog.Error("could not upload attestation", "err", err)
		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// read the body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not upload attestation: %s %s", resp.Status, string(body))
		}
		return fmt.Errorf("could not upload attestation: %s %s", resp.Status, string(body))
	}

	slog.Info("attestation uploaded successfully", "predicate", predicate, "predicateType", config.RuntimeAttestationConfig.PredicateType)
	return nil
}
