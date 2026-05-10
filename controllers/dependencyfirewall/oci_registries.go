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

// This file is the single source of truth for which OCI registries DevGuard
// proxies and how it authenticates with each one. Add or remove an entry in
// supportedOCIRegistries below — every lookup table is derived from it in
// init(), so the allowlist, auth-host map, and upstream URL map stay in sync.

package dependencyfirewall

// supportedOCIRegistry describes one upstream registry DevGuard knows how to proxy.
type supportedOCIRegistry struct {
	// pathName is the path segment users send: /v2/<pathName>/...
	pathName string
	// upstreamHost is the host DevGuard actually connects to. For most
	// registries this equals pathName; docker.io is the exception — its pull
	// endpoint is registry-1.docker.io.
	upstreamHost string
	// authHosts are additional hosts allowed to issue tokens via the
	// WWW-Authenticate realm. Same-host delegation is always permitted; this
	// list only covers cross-host cases (e.g. docker.io → auth.docker.io).
	authHosts []string
}

var supportedOCIRegistries = []supportedOCIRegistry{
	{pathName: "docker.io", upstreamHost: "registry-1.docker.io", authHosts: []string{"auth.docker.io"}},
	{pathName: "ghcr.io", upstreamHost: "ghcr.io"},
	{pathName: "quay.io", upstreamHost: "quay.io"},
	{pathName: "gcr.io", upstreamHost: "gcr.io"},
	{pathName: "registry.k8s.io", upstreamHost: "registry.k8s.io"},
	{pathName: "public.ecr.aws", upstreamHost: "public.ecr.aws"},
	{pathName: "mcr.microsoft.com", upstreamHost: "mcr.microsoft.com"},
	{pathName: "registry.gitlab.com", upstreamHost: "registry.gitlab.com", authHosts: []string{"gitlab.com"}},
}

// Lookup tables derived from supportedOCIRegistries in init().
var (
	allowedOCIRegistries  []string            // pathNames accepted at the proxy edge
	registryAuthHosts     map[string][]string // upstreamHost → permitted token-issuer hosts
	registryUpstreamHosts map[string]string   // pathName → upstreamHost
)

func init() {
	allowedOCIRegistries = make([]string, 0, len(supportedOCIRegistries))
	registryAuthHosts = make(map[string][]string, len(supportedOCIRegistries))
	registryUpstreamHosts = make(map[string]string, len(supportedOCIRegistries))
	for _, r := range supportedOCIRegistries {
		allowedOCIRegistries = append(allowedOCIRegistries, r.pathName)
		registryAuthHosts[r.upstreamHost] = r.authHosts
		registryUpstreamHosts[r.pathName] = r.upstreamHost
	}
}
