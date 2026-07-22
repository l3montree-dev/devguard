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

import "github.com/google/uuid"

var AllowedScopes = []string{"manage", "scan"}

type RevokeByPrivateKeyRequest struct {
	PrivateKey string `json:"privkey" validate:"required"`
}

// PatCreateRequest creates either an asymmetric PAT (set PubKey) or a symmetric Bearer token PAT
// (leave PubKey empty — the server generates the token). Exactly one mode must be used.
type PatCreateRequest struct {
	Description    string  `json:"description"`
	PubKey         *string `json:"pubKey"`
	Scopes         string  `json:"scopes"`
	ExpiryDateUnix int64   `json:"expiryDateUnix" validate:"required,future_max_1y"`
}

func (r PatCreateRequest) IsSymmetric() bool {
	return r.PubKey == nil || *r.PubKey == ""
}

func (r PatCreateRequest) IsAsymmetric() bool {
	return r.PubKey != nil && *r.PubKey != ""
}

type PATDTO struct {
	ID             string  `json:"id"`
	CreatedAt      string  `json:"createdAt"`
	Description    string  `json:"description"`
	Fingerprint    *string `json:"fingerprint"`
	LastUsedAt     *string `json:"lastUsedAt"`
	ExpiryDateUnix int64   `json:"expiryDateUnix"`
	Scopes         string  `json:"scopes"`
}

// PATCreateResponseDTO is returned once on PAT creation.
// BearerToken is only populated for symmetric PATs and is never retrievable again.
type PATCreateResponseDTO struct {
	PATDTO
	BearerToken string `json:"bearerToken,omitempty"`
}

type SessionActor string

const (
	SessionActorUser    SessionActor = "user"
	SessionActorOrg     SessionActor = "org"
	SessionActorProject SessionActor = "project"
	SessionActorAsset   SessionActor = "asset"
)

type TokenOwner struct {
	Type SessionActor
	ID   uuid.UUID
}
