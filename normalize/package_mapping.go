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
package normalize

import (
	"encoding/json"
	"fmt"
	"sync"

	_ "embed"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

var (
	//go:embed package_mappings.json
	packageMappingsJSON []byte
	packageMappingsOnce sync.Once
	mappings            map[string]map[string]string
)

func loadPackageMappings() map[string]map[string]string {
	packageMappingsOnce.Do(func() {
		err := json.Unmarshal(packageMappingsJSON, &mappings)
		if err != nil {
			panic(fmt.Sprintf("failed to unmarshal package mappings: %v", err))
		}
	})
	return mappings
}

func applyPackageAlias(component *cdx.Component) *cdx.Component {
	// Parse the purl to extract ecosystem and package name
	if component.PackageURL == "" {
		return component
	}

	purl, err := packageurl.FromString(component.PackageURL)
	if err != nil {
		return component
	}

	// Only handle debian and alpine packages
	var ecosystem string
	switch purl.Type {
	case "deb":
		ecosystem = "debian"
	case "apk":
		ecosystem = "alpine"
	default:
		return component
	}

	// Load package mappings
	mappings := loadPackageMappings()
	if mappings[ecosystem] == nil {
		return component
	}

	// Look up the source package name
	sourcePackage, exists := mappings[ecosystem][purl.Name]
	if !exists || sourcePackage == "" {
		return component
	}

	// Replace the package name in the purl
	purl.Name = sourcePackage
	component.PackageURL = purl.ToString()

	return component
}
