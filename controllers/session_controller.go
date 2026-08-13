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

package controllers

import "github.com/l3montree-dev/devguard/shared"

// @Summary Get current session info
// @Tags Authentication
// @Security CookieAuth
// @Security PATAuth
// @Success 200 {object} object{ownerID=string,ownerType=string}
// @Router /whoami [get]
func Whoami(ctx shared.Context) error {
	session := shared.GetSession(ctx)
	return ctx.JSON(200, map[string]string{
		"actorId":   session.GetActorID(),
		"actorType": string(session.GetSessionActorType()),
	})
}
