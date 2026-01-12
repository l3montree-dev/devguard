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

package controllers

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"

	"github.com/labstack/echo/v4"
)

type PatController struct {
	patRepository shared.PersonalAccessTokenRepository
	service       shared.PersonalAccessTokenService
}

func NewPatController(service shared.PersonalAccessTokenService, repository shared.PersonalAccessTokenRepository) *PatController {
	return &PatController{
		patRepository: repository,
		service:       service,
	}
}

// @Summary Create personal access token
// @Tags Authentication
// @Security CookieAuth
// @Param body body dtos.PatCreateRequest true "Request body"
// @Success 200 {object} object{createdAt=string,description=string,userID=string,pubKey=string,fingerprint=string,scopes=string,id=string}
// @Router /pats [post]
func (p *PatController) Create(c shared.Context) error {
	// get the user id from the session
	session := shared.GetSession(c)
	userID := session.GetUserID()

	// get the json body
	var req dtos.PatCreateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	// validate the request
	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	patStruct := p.service.ToModel(req, userID)

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

// @Summary Revoke PAT by private key
// @Tags Authentication
// @Param body body dtos.RevokeByPrivateKeyRequest true "Request body"
// @Success 200
// @Router /pats/revoke-by-private-key [post]
func (p *PatController) RevokeByPrivateKey(c shared.Context) error {
	// get the json body
	var req dtos.RevokeByPrivateKeyRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	// validate the request
	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	// get the pat by the fingerprint
	err := p.service.RevokeByPrivateKey(req.PrivateKey)
	if err != nil {
		return echo.NewHTTPError(500, "could not revoke personal access token").WithInternal(err)
	}

	return c.NoContent(200)
}

// @Summary Delete personal access token
// @Tags Authentication
// @Security CookieAuth
// @Security PATAuth
// @Param tokenID path string true "Token ID"
// @Success 200
// @Router /pats/{tokenID} [delete]
func (p *PatController) Delete(c shared.Context) error {
	tokenID := shared.SanitizeParam(c.Param("tokenID"))

	// check if the current user is allowed to delete the token
	pat, err := p.patRepository.Read(uuid.MustParse(tokenID))
	if err != nil {
		return echo.NewHTTPError(500, "could not read personal access token").WithInternal(err)
	}
	// check the owner of the token
	if pat.UserID.String() != shared.GetSession(c).GetUserID() {
		return echo.NewHTTPError(403, "not allowed to delete this token")
	}
	err = p.patRepository.Delete(nil, uuid.MustParse(tokenID))

	if err != nil {
		return echo.NewHTTPError(500, "could not delete personal access token").WithInternal(err)
	}
	return c.NoContent(200)
}

// @Summary List personal access tokens
// @Tags Authentication
// @Security CookieAuth
// @Security PATAuth
// @Success 200 {array} models.PAT
// @Router /pats [get]
func (p *PatController) List(c shared.Context) error {
	// get the user id from the session
	session := shared.GetSession(c)
	userID := session.GetUserID()

	pats, err := p.patRepository.ListByUserID(userID)
	if err != nil {
		return echo.NewHTTPError(500, "could not list personal access tokens").WithInternal(err)
	}

	return c.JSON(200, pats)
}
