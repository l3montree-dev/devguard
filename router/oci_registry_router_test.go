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

package router

import (
	"slices"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/controllers/dependencyfirewall"
)

const (
	pathUnauthManifest1Seg = "/v2/:registry/:image/manifests/:reference/"
	pathUnauthManifest2Seg = "/v2/:registry/:namespace/:image/manifests/:reference/"
	pathSecretManifest2Seg = "/v2/:secret/:registry/:namespace/:image/manifests/:reference/"
	pathVersionCheck       = "/v2/"
)

func TestOCIRegistryRouterOnlySecretScopedRoutes(t *testing.T) {
	// A nil-embedded controller is fine — Echo stores method values on route
	// registration, the handlers themselves are never invoked here.
	paths := registerRoutesAndList(&dependencyfirewall.OCIDependencyProxyController{})

	if slices.Contains(paths, pathUnauthManifest1Seg) {
		t.Error("expected 1-segment unauth route to NOT be registered")
	}
	if slices.Contains(paths, pathUnauthManifest2Seg) {
		t.Error("expected 2-segment unauth route to NOT be registered")
	}
	if !slices.Contains(paths, pathSecretManifest2Seg) {
		t.Error("expected secret-scoped route to be registered")
	}
	if !slices.Contains(paths, pathVersionCheck) {
		t.Error("expected version check route to be registered")
	}
}

func registerRoutesAndList(ctrl *dependencyfirewall.OCIDependencyProxyController) []string {
	srv := api.Server{Echo: echo.New()}
	NewOCIRegistryRouter(srv, ctrl)

	routes := srv.Echo.Routes()
	paths := make([]string, 0, len(routes))
	for _, r := range routes {
		paths = append(paths, r.Path)
	}
	return paths
}
