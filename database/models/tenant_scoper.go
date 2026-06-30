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

package models

import "github.com/google/uuid"

// TenantIDs holds the resolved tenant identifiers for the current request.
// Fields that are not applicable at a given route level are left as uuid.Nil.
type TenantIDs struct {
	AssetID   uuid.UUID
	ProjectID uuid.UUID
	OrgID     uuid.UUID
}
