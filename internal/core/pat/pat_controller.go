// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/database/repositories"

	"github.com/labstack/echo/v4"
)

type repository interface {
	repositories.Repository[uuid.UUID, models.PAT, core.DB]
	ReadByToken(token string) (models.PAT, error)
	ListByUserID(userId string) ([]models.PAT, error)
	GetUserIDByToken(token string) (string, error)
}

type PatController struct {
	patRepository repository
}

func NewHttpController(repository repository) *PatController {
	return &PatController{
		patRepository: repository,
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
		return echo.NewHTTPError(400, err.Error())
	}

	patStruct, token := req.ToModel(userID)

	fmt.Println(patStruct)

	err := p.patRepository.Create(nil, &patStruct)
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.JSON(200, map[string]string{
		"createdAt":   patStruct.CreatedAt.String(),
		"description": patStruct.Description,
		"token":       token,
		"userId":      patStruct.UserID.String(),
	})
}

func (p *PatController) Delete(c core.Context) error {
	tokenId := core.SanitizeParam(c.Param("tokenId"))

	// check if the current user is allowed to delete the token
	pat, err := p.patRepository.Read(uuid.MustParse(tokenId))
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}
	// check the owner of the token
	if pat.UserID.String() != core.GetSession(c).GetUserID() {
		return echo.NewHTTPError(403, "not allowed to delete this token")
	}
	err = p.patRepository.Delete(nil, uuid.MustParse(tokenId))

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}
	return c.NoContent(200)
}

func (p *PatController) List(c core.Context) error {
	// get the user id from the session
	session := core.GetSession(c)
	userID := session.GetUserID()

	pats, err := p.patRepository.ListByUserID(userID)
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.JSON(200, pats)
}
