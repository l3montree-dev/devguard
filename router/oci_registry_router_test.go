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
	pathUnauthManifest1Seg = "/v2/:registry/:image/manifests/:reference"
	pathUnauthManifest2Seg = "/v2/:registry/:namespace/:image/manifests/:reference"
	pathSecretManifest2Seg = "/v2/:secret/:registry/:namespace/:image/manifests/:reference"
	pathVersionCheck       = "/v2/"
)

func TestOCIRegistryRouterPublicKillSwitch(t *testing.T) {
	// A nil-embedded controller is fine — Echo stores method values on route
	// registration, the handlers themselves are never invoked here.
	ctrl := &dependencyfirewall.OCIDependencyProxyController{}

	t.Run("default registers both unauth and secret-scoped routes", func(t *testing.T) {
		t.Setenv("DEPENDENCY_PROXY_OCI_PUBLIC_ENABLED", "")
		paths := registerRoutesAndList(ctrl)

		if !slices.Contains(paths, pathUnauthManifest1Seg) {
			t.Error("expected 1-segment unauth manifest route to be registered")
		}
		if !slices.Contains(paths, pathUnauthManifest2Seg) {
			t.Error("expected 2-segment unauth manifest route to be registered")
		}
		if !slices.Contains(paths, pathSecretManifest2Seg) {
			t.Error("expected secret-scoped route to be registered")
		}
		if !slices.Contains(paths, pathVersionCheck) {
			t.Error("expected version check route to be registered")
		}
	})

	t.Run("explicit true behaves like default", func(t *testing.T) {
		t.Setenv("DEPENDENCY_PROXY_OCI_PUBLIC_ENABLED", "true")
		paths := registerRoutesAndList(ctrl)

		if !slices.Contains(paths, pathUnauthManifest1Seg) {
			t.Error("expected unauth route to be registered when explicit true")
		}
	})

	t.Run("kill switch removes unauth routes but keeps secret-scoped", func(t *testing.T) {
		t.Setenv("DEPENDENCY_PROXY_OCI_PUBLIC_ENABLED", "false")
		paths := registerRoutesAndList(ctrl)

		if slices.Contains(paths, pathUnauthManifest1Seg) {
			t.Error("expected 1-segment unauth route to NOT be registered when killswitch active")
		}
		if slices.Contains(paths, pathUnauthManifest2Seg) {
			t.Error("expected 2-segment unauth route to NOT be registered when killswitch active")
		}
		if !slices.Contains(paths, pathSecretManifest2Seg) {
			t.Error("expected secret-scoped route to remain registered")
		}
		if !slices.Contains(paths, pathVersionCheck) {
			t.Error("expected version check route to remain registered")
		}
	})
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
