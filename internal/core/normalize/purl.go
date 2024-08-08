package normalize

import (
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// returns the normalized purl AND the component type
func normalizePurl(purl string) (string, cdx.ComponentType) {
	// unescape the purl
	purl, err := url.PathUnescape(purl)
	if err != nil {
		return purl, cdx.ComponentTypeLibrary
	}
	// get the distro query parameter
	pURL, err := url.Parse(purl)
	if err != nil {
		return purl, cdx.ComponentTypeLibrary
	}

	q := pURL.Query()
	distro := q.Get("distro")

	// remove any query parameters
	purl = strings.Split(purl, "?")[0]

	if distro != "" {
		// its an application
		return purl, cdx.ComponentTypeApplication
	}

	return purl, cdx.ComponentTypeLibrary
}

func Purl(component cdx.Component) string {
	var purl string
	if component.PackageURL != "" {
		return component.PackageURL
	} else if component.CPE != "" {
		purl = component.CPE
	} else if component.Version != "" {
		purl = component.Name + "@" + component.Version
	} else if purl == "" {
		purl = component.Name
	}

	// remove any query parameters
	return purl
}

// ref: https://github.com/google/osv.dev/blob/a751ceb26522f093edf26c0ad167cfd0967716d9/osv/purl_helpers.py
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// PURL conversion utilities

var PURL_ECOSYSTEMS = map[string]string{
	"Alpine":    "apk",
	"crates.io": "cargo",
	"Debian":    "deb",
	"Go":        "golang",
	"Hackage":   "hackage",
	"Hex":       "hex",
	"Maven":     "maven",
	"npm":       "npm",
	"NuGet":     "nuget",
	"OSS-Fuzz":  "generic",
	"Packagist": "composer",
	"Pub":       "pub",
	"PyPI":      "pypi",
	"RubyGems":  "gem",
}

func urlEncode(packageName string) string {
	parts := strings.Split(packageName, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func PackageToPurl(ecosystem, packageName string) string {
	purlType, exists := PURL_ECOSYSTEMS[ecosystem]
	if !exists {
		return ""
	}

	var suffix string

	switch purlType {
	case "maven":
		// PURLs use / to separate the group ID and the artifact ID.
		packageName = strings.Replace(packageName, ":", "/", 1)
	case "deb":
		if ecosystem == "Debian" {
			packageName = "debian/" + packageName
			suffix = "?arch=source"
		}
	case "apk":
		if ecosystem == "Alpine" {
			packageName = "alpine/" + packageName
			suffix = "?arch=source"
		}
	}

	return "pkg:" + purlType + "/" + urlEncode(packageName) + suffix
}

func PurlToEcosystem(purlType string) string {
	for key, value := range PURL_ECOSYSTEMS {
		if value == purlType {
			return key
		}
	}
	return ""
}
