// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

import (
	"archive/zip"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/shared"

	"github.com/l3montree-dev/devguard/internal/database/models"

	"github.com/labstack/echo/v4"
)

type httpController struct {
	linkRepository         shared.InTotoLinkRepository
	supplyChainRepository  shared.SupplyChainRepository
	assetVersionRepository shared.AssetVersionRepository
	patRepository          shared.PersonalAccessTokenRepository

	inTotoVerifierService shared.InTotoVerifierService
}

func NewHTTPController(repository shared.InTotoLinkRepository, supplyChainRepository shared.SupplyChainRepository, assetVersionRepository shared.AssetVersionRepository, patRepository shared.PersonalAccessTokenRepository, inTotoVerifierService shared.InTotoVerifierService) *httpController {
	return &httpController{
		linkRepository:         repository,
		supplyChainRepository:  supplyChainRepository,
		assetVersionRepository: assetVersionRepository,
		patRepository:          patRepository,
		inTotoVerifierService:  inTotoVerifierService,
	}
}

func (a *httpController) VerifySupplyChain(ctx shared.Context) error {
	imageNameOrSupplyChainID := ctx.QueryParam("supplyChainId")
	digest := ctx.QueryParam("digest")

	if imageNameOrSupplyChainID == "" {
		// just verify the digest
		valid, err := a.inTotoVerifierService.VerifySupplyChainByDigestOnly(digest)
		if err != nil {
			slog.Error("could not verify supply chain", "err", err)
			return echo.NewHTTPError(500, "could not verify supply chain").WithInternal(err)
		}

		if !valid {
			slog.Info("could not verify supply chain", "digest", digest)
			return echo.NewHTTPError(400, "could not verify supply chain")
		}
	}

	valid, err := a.inTotoVerifierService.VerifySupplyChainWithOutputDigest(imageNameOrSupplyChainID, digest)
	if err != nil {
		slog.Error("could not verify supply chain", "err", err)
		return echo.NewHTTPError(500, "could not verify supply chain").WithInternal(err)
	}

	if !valid {
		slog.Info("could not verify supply chain", "supplyChainID", imageNameOrSupplyChainID)
		return echo.NewHTTPError(400, "could not verify supply chain")
	}

	slog.Info("verified supply chain", "supplyChainID", imageNameOrSupplyChainID)
	return ctx.NoContent(200)
}

func (a *httpController) Create(ctx shared.Context) error {
	var req createInTotoLinkRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	// check if valid - get the signed pat
	pat, valid := a.patRepository.GetByFingerprint(ctx.Request().Header.Get("X-Fingerprint"))
	if valid != nil {
		return echo.NewHTTPError(401, "could not find pat").WithInternal(valid)
	}

	tmpFileName := uuid.NewString()
	// write the link for a second to a temp file
	tmpfile, valid := os.CreateTemp("", tmpFileName)
	if valid != nil {
		return echo.NewHTTPError(500, "could not create temp file").WithInternal(valid)
	}
	defer os.Remove(tmpfile.Name())

	_, valid = tmpfile.Write([]byte(req.Payload))
	if valid != nil {
		return echo.NewHTTPError(500, "could not write to temp file").WithInternal(valid)
	}

	// check if the pat matches the signature of the in-toto link
	metadata, valid := toto.LoadMetadata(tmpfile.Name())
	if valid != nil {
		return echo.NewHTTPError(500, "could not load metadata").WithInternal(valid)
	}

	pubKey, valid := hexPublicKeyToInTotoKey(pat.PubKey)
	if valid != nil {
		return echo.NewHTTPError(500, "could not convert public key").WithInternal(valid)
	}

	if err := metadata.VerifySignature(pubKey); err != nil {
		return echo.NewHTTPError(401, "could not verify signature").WithInternal(err)
	}
	// read the asset version name from the header
	assetVersionName := ctx.Request().Header.Get("X-Asset-Ref")
	if assetVersionName == "" {
		slog.Warn("could not get asset version name - assuming main")
		assetVersionName = "main"
	}

	asset := shared.GetAsset(ctx)
	tag := ctx.Request().Header.Get("X-Tag")
	defaultBranch := ctx.Request().Header.Get("X-Asset-Default-Branch")
	if defaultBranch == "" {
		defaultBranch = "main"
	}
	assetVersion, err := a.assetVersionRepository.FindOrCreate(assetVersionName, asset.ID, tag == "1", utils.EmptyThenNil(defaultBranch))
	if err != nil {
		return err
	}

	link := models.InTotoLink{
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
		SupplyChainID:    strings.TrimSpace(req.SupplyChainID),
		Step:             strings.TrimSpace(req.Step),
		Payload:          req.Payload,
		PatID:            pat.ID,
		Filename:         req.Filename,
	}

	valid = a.linkRepository.Save(nil, &link)
	if valid != nil {
		return echo.NewHTTPError(500, "could not save in-toto link").WithInternal(valid)
	}

	if req.SupplyChainOutputDigest != "" {
		verified, err := a.inTotoVerifierService.VerifySupplyChain(req.SupplyChainID)
		if err != nil {
			slog.Error("could not verify supply chain", "err", err)
		} else {
			supplyChain := models.SupplyChain{
				SupplyChainID:           strings.TrimSpace(req.SupplyChainID),
				SupplyChainOutputDigest: req.SupplyChainOutputDigest,
				Verified:                verified,
				AssetVersionName:        assetVersionName,
				AssetID:                 asset.ID,
			}

			// save the digest
			err = a.supplyChainRepository.Save(nil, &supplyChain)
			if err != nil {
				return echo.NewHTTPError(500, "could not create supply chain").WithInternal(valid)
			}
		}
	}

	return ctx.JSON(200, link)
}

func (a *httpController) RootLayout(ctx shared.Context) error {
	// get all pats which are part of the asset
	project := shared.GetProject(ctx)
	accessControl := shared.GetRBAC(ctx)

	users, err := accessControl.GetAllMembersOfProject(project.GetID().String())

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

	keyIDs := make([]string, len(pats))
	totoKeys := make(map[string]toto.Key)
	for i, pat := range pats {
		key, err := hexPublicKeyToInTotoKey(pat.PubKey)
		if err != nil {
			return echo.NewHTTPError(500, "could not convert public key").WithInternal(err)
		}

		keyIDs[i] = key.KeyID
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
					PubKeys: keyIDs,
					SupplyChainItem: toto.SupplyChainItem{
						Name:              "post-commit",
						ExpectedMaterials: [][]string{{"ALLOW", "*"}}, // there is no way we can know what the materials are
						ExpectedProducts:  [][]string{{"ALLOW", "*"}},
					},
				},
				{
					Type:    "step",
					PubKeys: keyIDs,
					SupplyChainItem: toto.SupplyChainItem{
						Name:              "build",
						ExpectedMaterials: [][]string{{"MATCH", "*", "WITH", "PRODUCTS", "FROM", "post-commit"}, {"DISALLOW", "*"}}, // we expect the post-commit step to
						ExpectedProducts:  [][]string{{"ALLOW", "*"}},
					},
				},
				{
					Type:    "step",
					PubKeys: keyIDs,
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
							{"REQUIRE", "image-digest.txt"},
							{"MATCH", "image-digest", "WITH", "PRODUCTS", "FROM", "deploy"}, // makes sure image-digest.txt is the same as the created digest
							{"DISALLOW", "*"},
						},
					},
				},
			},
			Keys: totoKeys,
		},
	}

	var devguardKey toto.Key
	err = devguardKey.LoadKey("/intoto-private-key.pem", "ecdsa-sha2-nistp256", []string{"sha256"})
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
	ctx.Response().Header().Set("Content-Disposition", "attachment; filename=root.layout")

	return ctx.File(tmpfile.Name())
}

func (a *httpController) Read(ctx shared.Context) error {
	app := shared.GetAsset(ctx)
	// find a link with the corresponding opaque id
	links, err := a.linkRepository.FindByAssetAndSupplyChainID(app.GetID(), ctx.Param("supplyChainID"))
	if err != nil {
		return echo.NewHTTPError(404, "could not find in-toto link").WithInternal(err)
	}

	ctx.Response().Header().Set("Content-Type", "application/zip")
	ctx.Response().Header().Set("Content-Disposition", "attachment; filename=\"links.zip\"")
	ctx.Response().WriteHeader(http.StatusOK)

	zipWriter := zip.NewWriter(ctx.Response().Writer)

	for _, link := range links {
		header := &zip.FileHeader{
			Name:     link.Filename,
			Method:   zip.Deflate, // deflate also works, but at a cost
			Modified: time.Now(),
		}
		entryWriter, err := zipWriter.CreateHeader(header)

		if err != nil {
			return echo.NewHTTPError(500, "could not create zip entry").WithInternal(err)
		}

		_, err = entryWriter.Write([]byte(link.Payload))
		if err != nil {
			return echo.NewHTTPError(500, "could not write to zip entry").WithInternal(err)
		}

		zipWriter.Flush()
		flushingWriter, ok := ctx.Response().Writer.(http.Flusher)
		if ok {
			flushingWriter.Flush()
		}
	}

	return zipWriter.Close()
}
