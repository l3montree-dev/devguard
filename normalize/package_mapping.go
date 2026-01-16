// Copyright (C) 2025 l3montree GmbH
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

// Package normalize provides utilities for normalizing package identifiers.
// This file handles mapping binary package names to their source package names
// for Linux distributions (Debian, Alpine), enabling vulnerability matching
// against security advisories that reference source packages.
package normalize

import (
	"encoding/json"
	"fmt"
	"sync"

	_ "embed"

	"github.com/package-url/packageurl-go"
)

var (
	// packageMappingsJSON contains the embedded JSON mapping file.
	// Format: {"ecosystem": {"binary-pkg": "source-pkg", ...}, ...}
	//go:embed package_mappings.json
	packageMappingsJSON []byte

	// packageMappingsOnce ensures the mappings are loaded only once.
	packageMappingsOnce sync.Once

	// mappings holds the parsed package mappings keyed by ecosystem then binary package name.
	mappings map[string]map[string]string
)

// loadPackageMappings lazily loads and parses the embedded package mappings JSON.
// It panics if the embedded JSON is malformed (should never happen in production).
func loadPackageMappings() map[string]map[string]string {
	packageMappingsOnce.Do(func() {
		err := json.Unmarshal(packageMappingsJSON, &mappings)
		if err != nil {
			panic(fmt.Sprintf("failed to unmarshal package mappings: %v", err))
		}
	})
	return mappings
}

// applyPackageAliasToPurl maps a binary package purl to its source package equivalent.
// This is necessary because vulnerability databases (like Debian Security Tracker)
// publish advisories against source packages, but SBOMs typically contain binary
// package names (e.g., "libc6" is the binary, "glibc" is the source).
//
// Currently supports:
//   - Debian packages (pkg:deb/...)
//   - Alpine packages (pkg:apk/...)
//
// Returns the original purl unchanged if:
//   - The package type is not supported
//   - No mapping exists for the package name
func applyPackageAliasToPurl(purl packageurl.PackageURL) packageurl.PackageURL {
	var ecosystem string
	switch purl.Type {
	case "deb":
		ecosystem = "debian"
	case "apk":
		ecosystem = "alpine"
	default:
		return purl
	}

	mappings := loadPackageMappings()
	if mappings[ecosystem] == nil {
		return purl
	}

	sourcePackage, exists := mappings[ecosystem][purl.Name]
	if !exists || sourcePackage == "" {
		return purl
	}

	purl.Name = sourcePackage
	return purl
}
