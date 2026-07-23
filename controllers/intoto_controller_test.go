// Copyright (C) 2026 l3montree GmbH
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
	"bytes"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
)

func TestTraversalUsingFilename(t *testing.T) {

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(echo.GET, "/", nil)
	echo.New().NewContext(req, resp)

	intotoController := NewInToToController(nil, nil, nil, nil, nil, nil)
	linkRepositoryMock := mocks.NewInTotoLinkRepository(t)

	linkRepositoryMock.EXPECT().FindByAssetAndSupplyChainID(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]models.InTotoLink{
		{
			Filename:      "../../../../../../../../tmp/devguard_pwned",
			Payload:       "<validly-signed-payload>",
			SupplyChainID: "test-supply-chain-id",
		},
	}, nil)

	intotoController.linkRepository = linkRepositoryMock

	ctx := echo.New().NewContext(req, resp)
	shared.SetAsset(ctx, models.Asset{})
	// Call the controller method
	err := intotoController.Read(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	zipData := resp.Body.Bytes()

	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("Expected valid zip, got %v", err)
	}

	for _, f := range r.File {
		cleaned := filepath.Clean(f.Name)
		if strings.HasPrefix(cleaned, "..") || filepath.IsAbs(cleaned) {
			t.Errorf("zip entry %q escapes the archive root — path traversal vulnerability", f.Name)
		}
	}
}
