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
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/controllers/dependencyfirewall"
	"github.com/labstack/echo/v4"
)

// OCIRegistryRouter exposes the OCI Distribution Spec v2 API at the root /v2/ path
// so that standard Docker clients can pull images without any special configuration.
//
// Secret-scoped (custom rules enforced; MinReleaseAge does not apply to OCI images,
// registries expose no reliable publish time):
//
//	docker pull <host>/<secret>/docker.io/library/nginx:latest
//
// Docker resolves these as registry=<host> and sends:
//
//	GET /v2/                                                       (version check)
//	GET /v2/<secret>/docker.io/library/nginx/manifests/latest      (secret-scoped)
type OCIRegistryRouter struct {
	*echo.Group
}

func NewOCIRegistryRouter(srv api.Server, ociController *dependencyfirewall.OCIDependencyProxyController) OCIRegistryRouter {
	v2 := srv.Echo.Group("/v2")

	// Version check — Docker always sends this first.
	v2.GET("/", ociController.ProxyOCIVersionCheck)
	v2.HEAD("/", ociController.ProxyOCIVersionCheck)

	// ── Secret-scoped routes ────────────────────────────────────────────────
	// Secret is the first path segment; custom firewall rules are loaded for
	// the matching asset / project / organization.

	// 2-segment image: <secret>/docker.io/library/nginx
	v2.GET("/:secret/:registry/:namespace/:image/manifests/:reference/", ociController.ProxyOCIManifest)
	v2.HEAD("/:secret/:registry/:namespace/:image/manifests/:reference/", ociController.ProxyOCIManifest)
	v2.GET("/:secret/:registry/:namespace/:image/blobs/:digest/", ociController.ProxyOCIBlob)
	v2.HEAD("/:secret/:registry/:namespace/:image/blobs/:digest/", ociController.ProxyOCIBlob)
	v2.GET("/:secret/:registry/:namespace/:image/tags/list/", ociController.ProxyOCITagsList)
	v2.GET("/:secret/:registry/:namespace/:image/referrers/:digest/", ociController.ProxyOCIReferrers)

	// 3-segment image: <secret>/ghcr.io/org/team/repo
	v2.GET("/:secret/:registry/:ns1/:ns2/:image/manifests/:reference/", ociController.ProxyOCIManifest)
	v2.HEAD("/:secret/:registry/:ns1/:ns2/:image/manifests/:reference/", ociController.ProxyOCIManifest)
	v2.GET("/:secret/:registry/:ns1/:ns2/:image/blobs/:digest/", ociController.ProxyOCIBlob)
	v2.HEAD("/:secret/:registry/:ns1/:ns2/:image/blobs/:digest/", ociController.ProxyOCIBlob)
	v2.GET("/:secret/:registry/:ns1/:ns2/:image/tags/list/", ociController.ProxyOCITagsList)
	v2.GET("/:secret/:registry/:ns1/:ns2/:image/referrers/:digest/", ociController.ProxyOCIReferrers)

	return OCIRegistryRouter{Group: v2}
}
