// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package intoto

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"

	"github.com/google/uuid"
	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/pkg/errors"

	"github.com/l3montree-dev/devguard/internal/database/models"

	"github.com/labstack/echo/v4"
)

// we use this in multiple files in the asset package itself
type repository interface {
	FindByAssetAndOpaqueIdentifier(assetID uuid.UUID, opaqueIdentifier string) (models.InTotoLink, error)
	Save(tx core.DB, model *models.InTotoLink) error
}

type patRepository interface {
	GetByFingerprint(fingerprint string) (models.PAT, error)
}

type httpController struct {
	linkRepository repository

	patRepository patRepository
}

func NewHttpController(repository repository, patRepository patRepository) *httpController {
	return &httpController{
		linkRepository: repository,
		patRepository:  patRepository,
	}
}

func publicKeyToInTotoKey(hexPubKey string) (toto.Key, error) {
	ecdsaPubKey := pat.HexPubKeyToECDSA(hexPubKey)

	// marshal
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPubKey)

	// encode to pem
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// create new reader
	reader := bytes.NewReader(b)

	var key toto.Key
	err = key.LoadKeyReader(reader, "ecdsa-sha2-nistp521", []string{"sha256"})
	if err != nil {
		return toto.Key{}, errors.Wrap(err, "failed to load key")
	}

	return key, nil
}

func (a *httpController) Create(c core.Context) error {
	var req createInTotoLinkRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	// check if valid - get the signed pat
	pat, err := a.patRepository.GetByFingerprint(c.Request().Header.Get("X-Fingerprint"))
	if err != nil {
		return echo.NewHTTPError(401, "could not find pat").WithInternal(err)
	}

	tmpFileName := uuid.NewString()
	// write the link for a second to a temp file
	tmpfile, err := os.CreateTemp("", tmpFileName)
	if err != nil {
		return echo.NewHTTPError(500, "could not create temp file").WithInternal(err)
	}
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte(req.Payload))
	if err != nil {
		return echo.NewHTTPError(500, "could not write to temp file").WithInternal(err)
	}

	// check if the pat matches the signature of the in-toto link
	metadata, err := toto.LoadMetadata(tmpfile.Name())
	if err != nil {
		return echo.NewHTTPError(500, "could not load metadata").WithInternal(err)
	}

	pubKey, err := publicKeyToInTotoKey(pat.PubKey)
	if err != nil {
		return echo.NewHTTPError(500, "could not convert public key").WithInternal(err)
	}

	if err := metadata.VerifySignature(pubKey); err != nil {
		return echo.NewHTTPError(401, "could not verify signature").WithInternal(err)
	}

	asset := core.GetAsset(c)

	link := models.InTotoLink{
		AssetID:          asset.GetID(),
		OpaqueIdentifier: req.OpaqueIdentifier,
		Payload:          req.Payload,
		PatID:            pat.ID,
	}

	err = a.linkRepository.Save(nil, &link)

	if err != nil {
		return echo.NewHTTPError(500, "could not create link").WithInternal(err)
	}

	return c.JSON(200, link)
}

func (a *httpController) Read(c core.Context) error {
	app := core.GetAsset(c)
	// find a link with the corresponding opaque id
	link, err := a.linkRepository.FindByAssetAndOpaqueIdentifier(app.GetID(), c.Param("opaqueIdentifier"))
	if err != nil {
		return echo.NewHTTPError(404, "could not find in-toto link").WithInternal(err)
	}

	// we found the link
	// just return the payload
	var jsonLink map[string]interface{}
	err = json.Unmarshal([]byte(link.Payload), &jsonLink)
	if err != nil {
		return echo.NewHTTPError(500, "could not unmarshal in-toto link").WithInternal(err)
	}

	return c.JSON(200, jsonLink)
}
