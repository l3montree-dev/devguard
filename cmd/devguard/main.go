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

package main

import (
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/config"
	"github.com/l3montree-dev/devguard/internal/core/leaderelection"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database/repositories"

	_ "github.com/lib/pq"
)

//	@title			devguard API
//	@version		v1
//	@description	devguard API

//	@contact.name	Support
//	@contact.url	https://github.com/l3montree-dev/devguard/issues

//	@license.name	AGPL-3
//	@license.url	https://github.com/l3montree-dev/devguard/blob/main/LICENSE.txt

// @host		localhost:8080
// @BasePath	/api/v1
func main() {
	core.LoadConfig() // nolint: errcheck
	core.InitLogger()

	db, err := core.DatabaseFactory()

	if err != nil {
		panic(err)
	}
	statisticsDaemon := statistics.NewDaemon(repositories.NewAssetRepository(db), statistics.NewService(
		repositories.NewStatisticsRepository(db),
		repositories.NewComponentRepository(db),
		repositories.NewAssetRiskHistoryRepository(db),
		repositories.NewFlawRepository(db),
	))

	statisticsDaemon.Start()
	api.Start(db)

	configService := config.NewService(db)
	leaderElector := leaderelection.NewDatabaseLeaderElector(configService)
	vulndb.StartMirror(db, leaderElector, configService)

}
