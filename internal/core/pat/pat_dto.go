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
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

var AllowedScopes = []string{"manage", "scan"}

type RevokeByPrivateKeyRequest struct {
	PrivateKey string `json:"privkey" validate:"required"`
}

type CreateRequest struct {
	Description string `json:"description"`
	PubKey      string `json:"pubKey"`
	Scopes      string `json:"scopes"`
}

func (p CreateRequest) ToModel(userID string) models.PAT {
	//token := base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))
	fingerprint, err := pubKeyToFingerprint(p.PubKey)
	if err != nil {
		slog.Error("could not convert public key to fingerprint", "err", err)
		return models.PAT{}
	}

	//check if the scopes are valid
	ok := utils.ContainsAll(AllowedScopes, strings.Fields(p.Scopes))
	if !ok {
		slog.Error("invalid scopes", "scopes", p.Scopes)
		return models.PAT{}
	}

	pat := models.PAT{
		UserID:      uuid.MustParse(userID),
		Description: p.Description,
		Scopes:      p.Scopes,
		PubKey:      p.PubKey,
		Fingerprint: fingerprint,
	}

	//pat.Token = pat.HashToken(token)
	return pat // return the unhashed token. This is the token that will be sent to the user
}
