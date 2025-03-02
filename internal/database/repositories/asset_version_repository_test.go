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
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func TestFindOrCreate(t *testing.T) {
	t.Run("Successful Test", func(t *testing.T) {
		os.Setenv("POSTGRES_USER", "devguard") //Set .env variables manually cant read them otherwise
		os.Setenv("POSTGRES_PASSWORD", "devguard")
		os.Setenv("POSTGRES_DB", "devguard")
		os.Setenv("POSTGRES_HOST", "localhost")
		os.Setenv("POSTGRES_PORT", "5432")

		db, err := core.DatabaseFactory() //Build Database
		if err != nil {
			fmt.Printf("Error when calling database factory!\n")
			panic(err.Error())
		}

		a := repositories.NewAssetVersionRepository(db) //Build repository

		assetVersionName := "test"                                         //Set Parameters for the function
		assetID, err := uuid.Parse("497598d2-b90a-4031-b3db-90216de0e17f") //ID of the corresponding asset
		if err != nil {
			fmt.Printf("Error when formatting UUID")
		}
		tag := ""
		defaultBranchName := "main"

		_, err = a.FindOrCreate(assetVersionName, assetID, tag, defaultBranchName) //Call function and process return values
		if err != nil {
			fmt.Printf("Received the following error : %s", err)
		}

	})
}
