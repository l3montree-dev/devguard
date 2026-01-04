// Copyright (C) 2026 l3montree GmbH
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
package databasetypes

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

type JSONB map[string]any

// Value Marshal
func (jsonField JSONB) Value() (driver.Value, error) {
	return json.Marshal(jsonField)
}

// Scan Unmarshal
func (jsonField *JSONB) Scan(value any) error {
	data, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(data, &jsonField)
}

func JSONBFromStruct(m any) (JSONB, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var jsonb JSONB
	err = json.Unmarshal(data, &jsonb)
	if err != nil {
		return nil, err
	}
	return jsonb, nil
}

func MustJSONBFromStruct(m any) JSONB {
	jsonb, err := JSONBFromStruct(m)
	if err != nil {
		panic(err)
	}
	return jsonb
}
