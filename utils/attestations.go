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
	// parse as  map
	var m map[string]any
	if err := json.Unmarshal([]byte(content), &m); err != nil {
		return nil, err
	}

	// check if predicate and predicateType are in the map
	if predicate, ok := m["predicate"]; ok {
		return predicate, nil
	} else if m["payload"] != nil && m["signature"] != nil {
		// it is a dead simple signing envelope - extract the payload
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
	return m, nil
}
