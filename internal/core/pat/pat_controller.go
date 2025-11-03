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

package pat

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"

	"github.com/labstack/echo/v4"
)

type PatController struct {
	patRepository core.PersonalAccessTokenRepository
	service       *PatService
}

func NewHTTPController(repository core.PersonalAccessTokenRepository) *PatController {
	return &PatController{
		patRepository: repository,
		service:       NewPatService(repository),
	}
}

func (p *PatController) Create(c core.Context) error {
	// get the user id from the session
	session := core.GetSession(c)
	userID := session.GetUserID()

	// get the json body
	var req CreateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	// validate the request
	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	patStruct := req.ToModel(userID)

	err := p.patRepository.Create(nil, &patStruct)
	if err != nil {
		return echo.NewHTTPError(500, "could not create personal access token").WithInternal(err)
	}

	return c.JSON(200, map[string]string{
		"createdAt":   patStruct.CreatedAt.String(),
		"description": patStruct.Description,
		"userID":      patStruct.UserID.String(),
		"pubKey":      patStruct.PubKey,
		"fingerprint": patStruct.Fingerprint,
		"scopes":      patStruct.Scopes,
		"id":          patStruct.ID.String(),
	})
}

func (p *PatController) RevokeByPrivateKey(c core.Context) error {
	// get the json body
	var req RevokeByPrivateKeyRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	// validate the request
	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	// get the pat by the fingerprint
	err := p.service.RevokeByPrivateKey(req.PrivateKey)
	if err != nil {
		return echo.NewHTTPError(500, "could not revoke personal access token").WithInternal(err)
	}

	return c.NoContent(200)
}

func (p *PatController) Delete(c core.Context) error {
	tokenID := core.SanitizeParam(c.Param("tokenID"))

	// check if the current user is allowed to delete the token
	pat, err := p.patRepository.Read(uuid.MustParse(tokenID))
	if err != nil {
		return echo.NewHTTPError(500, "could not read personal access token").WithInternal(err)
	}
	// check the owner of the token
	if pat.UserID.String() != core.GetSession(c).GetUserID() {
		return echo.NewHTTPError(403, "not allowed to delete this token")
	}
	err = p.patRepository.Delete(nil, uuid.MustParse(tokenID))

	if err != nil {
		return echo.NewHTTPError(500, "could not delete personal access token").WithInternal(err)
	}
	return c.NoContent(200)
}

func (p *PatController) List(c core.Context) error {
	// get the user id from the session
	session := core.GetSession(c)
	userID := session.GetUserID()

	pats, err := p.patRepository.ListByUserID(userID)
	if err != nil {
		return echo.NewHTTPError(500, "could not list personal access tokens").WithInternal(err)
	}

	return c.JSON(200, pats)
}
