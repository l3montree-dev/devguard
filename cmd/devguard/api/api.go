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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"log/slog"
	"sort"

	"go.uber.org/fx"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

func NewServer(lc fx.Lifecycle, db shared.DB, broker database.Broker) *echo.Echo {
	server := middlewares.Server()
	lc.Append(fx.StartHook(func() {
		go func() {
			routes := server.Routes()
			sort.Slice(routes, func(i, j int) bool {
				return routes[i].Path < routes[j].Path
			})
			// print all registered routes
			for _, route := range routes {
				if route.Method != "echo_route_not_found" {
					slog.Info(route.Path, "method", route.Method)
				}
			}
			slog.Error("failed to start server", "err", server.Start(":8080").Error())
		}()
	}))
	return server
}
