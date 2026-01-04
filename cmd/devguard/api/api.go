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
	"time"

	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/labstack/echo/v4"
)

// StartedAt records when the API server was initialized. It is used for uptime reporting in /info/
var StartedAt time.Time

type Server struct {
	Echo *echo.Echo
}

func NewServer() Server {
	StartedAt = time.Now()
	server := middlewares.Server()

	return Server{
		Echo: server,
	}
}

func (s Server) Start() {
	slog.Error("failed to start server", "err", s.Echo.Start(":8080").Error())
}
