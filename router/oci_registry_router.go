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
// Unauthenticated (no custom firewall rules applied):
//
//	docker pull <host>/docker.io/library/nginx:latest
//
// Secret-scoped (custom rules and MinReleaseAge enforced):
//
//	docker pull <host>/<secret>/docker.io/library/nginx:latest
//
// Docker resolves these as registry=<host> and sends:
//
//	GET /v2/                                                       (version check)
//	GET /v2/docker.io/library/nginx/manifests/latest               (unauthenticated)
//	GET /v2/<secret>/docker.io/library/nginx/manifests/latest      (secret-scoped)
//
// Routing note: to avoid ambiguity, no-secret routes cover 1- and 2-segment image
// names while secret routes cover 2- and 3-segment image names (shifted by one).
// In practice this means all real Docker Hub and ghcr.io images (e.g.
// library/nginx, org/repo) work in both modes.
type OCIRegistryRouter struct {
	*echo.Group
}

func NewOCIRegistryRouter(srv api.Server, ociController *dependencyfirewall.OCIDependencyProxyController) OCIRegistryRouter {
	v2 := srv.Echo.Group("/v2")

	// Version check — Docker always sends this first.
	v2.GET("/", ociController.ProxyOCIVersionCheck)
	v2.HEAD("/", ociController.ProxyOCIVersionCheck)

	// ── Unauthenticated routes ──────────────────────────────────────────────
	// No secret in path; GetDependencyProxyConfigs returns empty config (no rules).
	// Malicious-package and path-traversal checks still run.

	// 1-segment image: docker.io/nginx
	v2.GET("/:registry/:image/manifests/:reference", ociController.ProxyOCIManifest)
	v2.HEAD("/:registry/:image/manifests/:reference", ociController.ProxyOCIManifest)
	v2.GET("/:registry/:image/blobs/:digest", ociController.ProxyOCIBlob)
	v2.HEAD("/:registry/:image/blobs/:digest", ociController.ProxyOCIBlob)
	v2.GET("/:registry/:image/tags/list", ociController.ProxyOCITagsList)
	v2.GET("/:registry/:image/referrers/:digest", ociController.ProxyOCIReferrers)

	// 2-segment image: docker.io/library/nginx
	v2.GET("/:registry/:namespace/:image/manifests/:reference", ociController.ProxyOCIManifest)
	v2.HEAD("/:registry/:namespace/:image/manifests/:reference", ociController.ProxyOCIManifest)
	v2.GET("/:registry/:namespace/:image/blobs/:digest", ociController.ProxyOCIBlob)
	v2.HEAD("/:registry/:namespace/:image/blobs/:digest", ociController.ProxyOCIBlob)
	v2.GET("/:registry/:namespace/:image/tags/list", ociController.ProxyOCITagsList)
	v2.GET("/:registry/:namespace/:image/referrers/:digest", ociController.ProxyOCIReferrers)

	// ── Secret-scoped routes ────────────────────────────────────────────────
	// Secret is the first path segment; custom firewall rules are loaded for
	// the matching asset / project / organization.

	// 2-segment image: <secret>/docker.io/library/nginx
	v2.GET("/:secret/:registry/:namespace/:image/manifests/:reference", ociController.ProxyOCIManifest)
	v2.HEAD("/:secret/:registry/:namespace/:image/manifests/:reference", ociController.ProxyOCIManifest)
	v2.GET("/:secret/:registry/:namespace/:image/blobs/:digest", ociController.ProxyOCIBlob)
	v2.HEAD("/:secret/:registry/:namespace/:image/blobs/:digest", ociController.ProxyOCIBlob)
	v2.GET("/:secret/:registry/:namespace/:image/tags/list", ociController.ProxyOCITagsList)
	v2.GET("/:secret/:registry/:namespace/:image/referrers/:digest", ociController.ProxyOCIReferrers)

	// 3-segment image: <secret>/ghcr.io/org/team/repo
	v2.GET("/:secret/:registry/:ns1/:ns2/:image/manifests/:reference", ociController.ProxyOCIManifest)
	v2.HEAD("/:secret/:registry/:ns1/:ns2/:image/manifests/:reference", ociController.ProxyOCIManifest)
	v2.GET("/:secret/:registry/:ns1/:ns2/:image/blobs/:digest", ociController.ProxyOCIBlob)
	v2.HEAD("/:secret/:registry/:ns1/:ns2/:image/blobs/:digest", ociController.ProxyOCIBlob)
	v2.GET("/:secret/:registry/:ns1/:ns2/:image/tags/list", ociController.ProxyOCITagsList)
	v2.GET("/:secret/:registry/:ns1/:ns2/:image/referrers/:digest", ociController.ProxyOCIReferrers)

	return OCIRegistryRouter{Group: v2}
}
