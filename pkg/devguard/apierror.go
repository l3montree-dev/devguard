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
package devguard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type APIError struct {
	Status  string
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return e.Status
	}
	return fmt.Sprintf("%s: %s", e.Status, e.Message)
}

// NewAPIError consumes the response body.
func NewAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return &APIError{Status: resp.Status, Message: extractErrorMessage(body)}
}

// echo serializes errors either as a bare JSON string or as an object with "message" or "error".
func extractErrorMessage(body []byte) string {
	var s string
	if err := json.Unmarshal(body, &s); err == nil {
		return s
	}
	var obj struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(body, &obj) == nil {
		if obj.Message != "" {
			return obj.Message
		}
		if obj.Error != "" {
			return obj.Error
		}
	}
	return strings.TrimSpace(string(body))
}
