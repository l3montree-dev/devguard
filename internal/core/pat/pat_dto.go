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
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/database/models"
)

type CreateRequest struct {
	Description string `json:"description"`
	PubKey      string `json:"pubKey"`
}

func (p CreateRequest) ToModel(userID string) models.PAT {
	//token := base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))
	fingerprint, err := PubKeyToFingerprint(p.PubKey)
	if err != nil {
		slog.Error("could not convert public key to fingerprint", "err", err)
		return models.PAT{}
	}
	pat := models.PAT{
		UserID:      uuid.MustParse(userID),
		Description: p.Description,
		PubKey:      p.PubKey,
		Fingerprint: fingerprint,
	}

	//pat.Token = pat.HashToken(token)
	return pat // return the unhashed token. This is the token that will be sent to the user
}
