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

package dto

import (
	"encoding/base64"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/models"
)

type PatCreateRequest struct {
	Description string `json:"description" validate:"required"`
}

func (p *PatCreateRequest) ToModel(userID string) (models.PersonalAccessToken, string) {
	token := base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))

	pat := models.PersonalAccessToken{
		UserID:      uuid.MustParse(userID),
		Description: p.Description,
	}

	pat.Token = pat.HashToken(token)
	return pat, token // return the unhashed token. This is the token that will be sent to the user
}
