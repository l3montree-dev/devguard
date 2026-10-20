// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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

package dtos

import (
	"github.com/google/uuid"
)

var AllowedScopes = []string{"manage", "scan"}

type RevokeByPrivateKeyRequest struct {
	PrivateKey string `json:"privkey" validate:"required,max=8192"`
}

// PatCreateRequest creates either an asymmetric PAT (set PubKey) or a symmetric Bearer token PAT
// (leave PubKey empty — the server generates the token). Exactly one mode must be used.
type PatCreateRequest struct {
	Description    string  `json:"description" validate:"max=4000"`
	PubKey         *string `json:"pubKey" validate:"omitempty,max=8192"`
	Scopes         string  `json:"scopes" validate:"max=256"`
	ExpiryDateUnix int64   `json:"expiryDateUnix" validate:"required,future_max_1y"`
}

func (r PatCreateRequest) IsSymmetric() bool {
	return r.PubKey == nil || *r.PubKey == ""
}

func (r PatCreateRequest) IsAsymmetric() bool {
	return r.PubKey != nil && *r.PubKey != ""
}

type PAT struct {
	ID             string  `json:"id"`
	CreatedAt      string  `json:"createdAt"`
	Description    string  `json:"description"`
	Fingerprint    *string `json:"fingerprint"`
	LastUsedAt     *string `json:"lastUsedAt"`
	ExpiryDateUnix int64   `json:"expiryDateUnix"`
	Scopes         string  `json:"scopes"`
}

// PATCreateResponse is returned once on PAT creation.
// BearerToken is only populated for symmetric PATs and is never retrievable again.
type PATCreateResponse struct {
	PAT
	BearerToken string `json:"bearerToken,omitempty"`
}

type TokenOwner struct {
	Type string
	ID   uuid.UUID
}
