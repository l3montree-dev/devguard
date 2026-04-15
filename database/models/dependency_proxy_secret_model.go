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

package models

import (
	"github.com/google/uuid"
)

type DependencyProxySecret struct {
	Secret    uuid.UUID  `gorm:"type:text;primaryKey; default:gen_random_uuid()"`
	AssetID   *uuid.UUID `gorm:"type:uuid;"`
	ProjectID *uuid.UUID `gorm:"type:uuid;"`
	OrgID     *uuid.UUID `gorm:"type:uuid;"`
}

func (DependencyProxySecret) TableName() string {
	return "dependency_proxy_secrets"
}
