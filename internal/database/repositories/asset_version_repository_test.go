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

package repositories_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func TestFindOrCreate(t *testing.T) {
	t.Run("Returned message", func(t *testing.T) {
		core.LoadConfig() // nolint: errcheck
		core.InitLogger()
		db, err := core.DatabaseFactory()
		if err != nil {
			fmt.Printf("Error when database factory")
		}

		fmt.Printf("Reached this Code----------------------------------")
		a := repositories.NewAssetVersionRepository(db)
		assetVersionName := "test"
		b := []byte("497598d2-b90a-4031-b3db-90216de0e17f")
		assetID, _ := uuid.FromBytes(b)
		tag := ""
		defaultBranchName := "main"

		_, err = a.FindOrCreate(assetVersionName, assetID, tag, defaultBranchName)
		fmt.Printf("Received the following error : %s", err)

	})
}
