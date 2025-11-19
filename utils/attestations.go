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

package utils

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/l3montree-dev/devguard/dtos"
)

func ExtractAttestationPayload(content string) (any, error) {
	// check if payload and signature are in content - then it is a dead simple signing envelope - otherwise it is already the payload
	if !strings.Contains(content, "payload") || !strings.Contains(content, "signature") {
		var input any
		if err := json.Unmarshal([]byte(content), &input); err != nil {
			return nil, err
		}
		return input, nil
	}

	var envelope dtos.DeadSimpleSigningEnvelope
	if err := json.Unmarshal([]byte(content), &envelope); err != nil {
		return nil, err
	}

	// decode the payload string from base64
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, err
	}

	escapedPayload := strings.ReplaceAll(string(payload), "\n", "\\n")

	// unmarshal the payload
	var input any
	if err := json.Unmarshal([]byte(escapedPayload), &input); err != nil {
		return nil, err
	}

	return input, nil
}
