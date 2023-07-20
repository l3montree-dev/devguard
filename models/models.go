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

package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type AppModel struct {
	ID        uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt sql.NullTime `gorm:"index"`
}

type Run struct {
	AppModel
	ApplicationName      string  `json:"applicationName"`
	DriverName           string  `json:"driverName"`
	DriverVersion        *string `json:"driverVersion"`
	DriverInformationUri *string `json:"driverInformationUri"`
	Results              []Result
}

type Result struct {
	AppModel
	RunID     uuid.UUID      `json:"runId"`
	RuleID    *string        `json:"ruleId"`
	Level     *string        `json:"level"`
	Message   *string        `json:"message"`
	Locations datatypes.JSON `gorm:"type:jsonb;default:'[]';not null"`
}

type Application struct {
	Name      string `json:"name" gorm:"unique;primarykey;type:varchar(255)"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt sql.NullTime `gorm:"index"`
	Runs      []Run
}
