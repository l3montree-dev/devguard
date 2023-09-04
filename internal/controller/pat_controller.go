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

package controller

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/helpers"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/labstack/echo/v4"
)

type patRepository interface {
	Create(*models.PersonalAccessToken) error
	Delete(token string) error
	Read(token string) (models.PersonalAccessToken, error)
	List(userId string) ([]models.PersonalAccessToken, error)
}

type PatController struct {
	patRepository
}

func NewPatController(repository patRepository) *PatController {
	return &PatController{
		patRepository: repository,
	}
}

func (p *PatController) Create(c echo.Context) error {
	// get the user id from the session
	session := helpers.GetSession(c)
	userID := session.GetUserID()
	patStruct, token := models.NewPersonalAccessToken(uuid.MustParse(userID))

	err := p.patRepository.Create(&patStruct)
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.JSON(200, map[string]string{
		"token": token,
	})
}

func (p *PatController) Delete(c echo.Context) error {
	token := c.Param("token")

	err := p.patRepository.Delete(token)
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.NoContent(200)
}

func (p *PatController) Read(c echo.Context) error {
	token := c.Param("token")

	pat, err := p.patRepository.Read(token)
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.JSON(200, pat)
}

func (p *PatController) List(c echo.Context) error {
	// get the user id from the session
	session := helpers.GetSession(c)
	userID := session.GetUserID()

	pats, err := p.patRepository.List(userID)
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.JSON(200, pats)
}
