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

package compliance

import (
	"bytes"
	_ "embed"

	"github.com/l3montree-dev/devguard/database/models"
)

//go:embed oscal/catalogs/ISO27001-AnnexA-catalog.json
var iso27001CatalogJSON []byte

func loadISO27001Controls() ([]models.FrameworkControl, error) {
	catalog, err := parseOSCALCatalog(bytes.NewReader(iso27001CatalogJSON))
	if err != nil {
		return nil, err
	}
	return extractControlsFromCatalog(catalog, ISO27001, grundschutzAdditionalMapper), nil
}
