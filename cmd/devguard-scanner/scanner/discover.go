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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/pkg/errors"
)

type AttestationFileLine struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"` // base64 encoded AttestationPayload
}

func DiscoverAttestations(image string) ([]map[string]any, error) {
	// cosign download attestation image
	cosignCmd := exec.Command("cosign", "download", "attestation", image)

	stderrBuf := &bytes.Buffer{}
	stdoutBuf := &bytes.Buffer{}

	// get the output
	cosignCmd.Stderr = stderrBuf
	cosignCmd.Stdout = stdoutBuf

	err := cosignCmd.Run()
	if err != nil {
		return nil, errors.Wrap(err, stderrBuf.String())
	}

	stdoutStr := stdoutBuf.String()
	jsonLines := strings.Split(stdoutStr, "\n")
	if len(jsonLines) > 0 {
		// remove last element (empty line)
		jsonLines = jsonLines[:len(jsonLines)-1]
	}

	attestations := []map[string]any{}
	// go through each line (attestation) of the .jsonlines file
	for _, jsonLine := range jsonLines {
		var line AttestationFileLine
		err = json.Unmarshal([]byte(jsonLine), &line)
		if err != nil {
			return nil, err
		}

		// Extract base64 encoded payload
		data, err := base64.StdEncoding.DecodeString(line.Payload)
		if err != nil {
			log.Fatal("error:", err)
		}

		// Parse payload as attestation
		var attestation map[string]any
		err = json.Unmarshal([]byte(data), &attestation)
		if err != nil {
			return nil, err
		}

		attestations = append(attestations, attestation)
	}

	return attestations, nil
}

func GetVEX(ctx context.Context, imageRef string) (*cyclonedx.BOM, error) {
	var vex *cyclonedx.BOM

	attestations, err := DiscoverAttestations(imageRef)
	if err != nil {
		return nil, err
	}

	for _, attestation := range attestations {
		if strings.HasPrefix(attestation["predicateType"].(string), "https://cyclonedx.org/vex") {
			predicate, ok := attestation["predicate"].(map[string]any)
			if !ok {
				continue
			}

			// marshal the predicate back to json
			predicateBytes, err := json.Marshal(predicate)
			if err != nil {
				continue
			}
			vex, err = BomFromBytes(predicateBytes)
			if err != nil {
				continue
			}
			return vex, nil
		}
	}

	return nil, fmt.Errorf("no vex document found for image")
}
