// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package db

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type AppModel struct {
	ID        uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt sql.NullTime `gorm:"index"`
}

type Run struct {
	AppModel
	Driver        Driver
	ApplicationID uuid.UUID `json:"applicationId"`
	Results       []Result
}

type Driver struct {
	AppModel
	RunID          uuid.UUID
	FullName       string `json:"fullName"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationUri string `json:"informationUri"`
}

type Result struct {
	AppModel
	RunID     uuid.UUID      `json:"runId"`
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Locations map[string]any `gorm:"type:jsonb;default:'[]';not null"`
}

type Application struct {
	AppModel
	Runs []Run
	Name string `json:"name"`
}
