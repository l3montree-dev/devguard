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
package dtos

type GitRepository struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Image       string `json:"image"`
	Description string `json:"description"`

	IsDeveloper  bool `json:"isDeveloper"`
	IsMaintainer bool `json:"isMaintainer"`
	IsOwner      bool `json:"isOwner"`

	GitProvider string `json:"gitProvider"`
}
