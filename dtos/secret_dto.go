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

package dtos

import "github.com/google/uuid"

type SecretScope string

const (
	ScopeOrganization SecretScope = "organization"
	ScopeProject      SecretScope = "project"
	ScopeAsset        SecretScope = "asset"
)

type SecretDTO struct {
	ID            uuid.UUID   `json:"id"`
	Name          string      `json:"name"`
	Scope         SecretScope `json:"scope"`
	Inherited     bool        `json:"inherited"`
	InheritedFrom string      `json:"inheritedFrom"`
	Overridden    bool        `json:"overridden"`
}

type SecretCreateRequest struct {
	Name  string `json:"name" validate:"required,max=256,alphanum"`
	Value string `json:"value" validate:"required,max=8192"`
}
