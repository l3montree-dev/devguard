// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

type Component struct {
	// either cpe or purl is set
	PurlOrCpe string      `json:"purlOrCpe" gorm:"primaryKey;column:purl_or_cpe"`
	DependsOn []Component `json:"dependsOn" gorm:"many2many:component_dependencies;"`
}

func (c Component) TableName() string {
	return "components"
}
