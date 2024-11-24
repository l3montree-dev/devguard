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
	"encoding/pem"
	"os"
	"strings"
	"time"

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
	FindByUserIDs(userID []uuid.UUID) ([]models.PAT, error)
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
	if err != nil {
		return toto.Key{}, errors.Wrap(err, "failed to marshal public key")
	}

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
		AssetID:       asset.GetID(),
		SupplyChainID: strings.TrimSpace(req.SupplyChainID),
		Step:          strings.TrimSpace(req.Step),
		Payload:       req.Payload,
		PatID:         pat.ID,
		Filename:      req.Filename,
	}

	err = a.linkRepository.Save(nil, &link)

	if err != nil {
		return echo.NewHTTPError(500, "could not create link").WithInternal(err)
	}

	return c.JSON(200, link)
}

func (a *httpController) RootLayout(c core.Context) error {
	// get all pats which are part of the asset
	project := core.GetProject(c)
	org := core.GetTenant(c)
	accessControl := core.GetRBAC(c)

	users, err := accessControl.GetAllMembersOfProject(org.ID.String(), project.GetID().String())

	if err != nil {
		return echo.NewHTTPError(500, "could not get users").WithInternal(err)
	}

	userUuids := make([]uuid.UUID, 0, len(users))
	for _, user := range users {
		uuid, err := uuid.Parse(user)
		if err != nil {
			return echo.NewHTTPError(500, "could not parse user id").WithInternal(err)
		}

		userUuids = append(userUuids, uuid)
	}

	pats, err := a.patRepository.FindByUserIDs(userUuids)
	if err != nil {
		return echo.NewHTTPError(500, "could not get pats").WithInternal(err)
	}

	keyIds := make([]string, len(pats))
	totoKeys := make(map[string]toto.Key)
	for i, pat := range pats {
		key, err := publicKeyToInTotoKey(pat.PubKey)
		if err != nil {
			return echo.NewHTTPError(500, "could not convert public key").WithInternal(err)
		}

		keyIds[i] = key.KeyID
		totoKeys[key.KeyID] = key
	}

	t := time.Now()
	t = t.Add(30 * 24 * time.Hour)

	// create a new layout
	var metablock = toto.Metablock{
		Signed: toto.Layout{
			Type:    "layout",
			Expires: t.Format("2006-01-02T15:04:05Z"),
			Steps: []toto.Step{
				{
					Type:    "step",
					PubKeys: keyIds,
					SupplyChainItem: toto.SupplyChainItem{
						Name:              "post-commit",
						ExpectedMaterials: [][]string{{"ALLOW", "*"}}, // there is no way we can know what the materials are
						ExpectedProducts:  [][]string{{"ALLOW", "*"}},
					},
				},
				{
					Type:    "step",
					PubKeys: keyIds,
					SupplyChainItem: toto.SupplyChainItem{
						Name:              "build",
						ExpectedMaterials: [][]string{{"MATCH", "*", "WITH", "PRODUCTS", "FROM", "post-commit"}, {"DISALLOW", "*"}}, // we expect the post-commit step to
						ExpectedProducts:  [][]string{{"ALLOW", "*"}},
					},
				},
				{
					Type:    "step",
					PubKeys: keyIds,
					SupplyChainItem: toto.SupplyChainItem{
						Name:              "deploy",
						ExpectedMaterials: [][]string{{"MATCH", "*", "WITH", "PRODUCTS", "FROM", "build"}, {"DISALLOW", "*"}},
						ExpectedProducts:  [][]string{{"ALLOW", "*"}},
					},
				},
			},
			Inspect: []toto.Inspection{
				{
					// just do nothing - we will prepare the folders beforehand
					Run:  []string{"true"},
					Type: "inspection",
					SupplyChainItem: toto.SupplyChainItem{
						Name:              "verify-digest",
						ExpectedMaterials: [][]string{{"ALLOW", "*"}},
						ExpectedProducts: [][]string{
							{"MATCH", "*", "WITH", "PRODUCTS", "FROM", "deploy"},
							{"DISALLOW", "*"},
						},
					},
				},
			},
			Keys: totoKeys,
		},
	}

	var devguardKey toto.Key
	err = devguardKey.LoadKey("ecdsa_private.pem", "ecdsa-sha2-nistp256", []string{"sha256"})
	if err != nil {
		return echo.NewHTTPError(500, "could not load devguard key").WithInternal(err)
	}

	// write the layout to a temp file
	tmpFileName := uuid.NewString()
	tmpfile, err := os.CreateTemp("", tmpFileName)
	if err != nil {
		return echo.NewHTTPError(500, "could not create temp file").WithInternal(err)
	}

	defer os.Remove(tmpfile.Name())

	// sign the layout
	err = metablock.Sign(devguardKey)
	if err != nil {
		return echo.NewHTTPError(500, "could not sign layout").WithInternal(err)
	}

	err = metablock.Dump(tmpfile.Name())
	if err != nil {
		return echo.NewHTTPError(500, "could not dump layout").WithInternal(err)
	}

	// set the filename to root.layout
	c.Response().Header().Set("Content-Disposition", "attachment; filename=root.layout")

	return c.File(tmpfile.Name())
}

func (a *httpController) Read(c core.Context) error {
	app := core.GetAsset(c)
	// find a link with the corresponding opaque id
	link, err := a.linkRepository.FindByAssetAndOpaqueIdentifier(app.GetID(), c.Param("opaqueIdentifier"))
	if err != nil {
		return echo.NewHTTPError(404, "could not find in-toto link").WithInternal(err)
	}

	return c.JSON(200, link)
}
