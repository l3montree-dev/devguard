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

package shared

import "github.com/l3montree-dev/devguard/dtos"

type AuthSession interface {
	GetActorID() string
	GetScopes() []string
	IsInstanceAdmin() bool
	GetSessionActorType() dtos.SessionActor
	// GetActorName returns a human-readable, type-disambiguated identifier for
	// audit trails / actor stamps
	GetActorName() string
}

type session struct {
	ownerID         string
	scopes          []string
	isInstanceAdmin bool
	ownerType       dtos.SessionActor
}

func (a session) IsInstanceAdmin() bool {
	return a.isInstanceAdmin
}

func (a session) GetActorID() string {
	return a.ownerID
}

func (a session) GetSessionActorType() dtos.SessionActor {
	return a.ownerType
}

func (a session) GetScopes() []string {
	return a.scopes
}

func (a session) GetActorName() string {
	switch a.ownerType {
	case dtos.SessionActorUser:
		return a.ownerID
	case dtos.SessionActorOrg:
		return "Organization Access Token"
	case dtos.SessionActorProject:
		return "Project Access Token"
	case dtos.SessionActorAsset:
		return "Asset Access Token"
	default:
		return "Unknown Actor"
	}
}

func NewSession(ownerID string, ownerType dtos.SessionActor, scopes []string, isInstanceAdmin bool) session {
	return session{
		ownerID:         ownerID,
		ownerType:       ownerType,
		scopes:          scopes,
		isInstanceAdmin: isInstanceAdmin,
	}
}

var NoSession session = session{
	ownerID: "NO_SESSION",
}
