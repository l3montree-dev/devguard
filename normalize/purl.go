package normalize

import (
	"fmt"
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// PurlMatchContext holds the parsed purl information for matching
type PurlMatchContext struct {
	SearchPurl        string
	NormalizedVersion string
	VersionIsValid    error
	Qualifiers        packageurl.Qualifiers
	Namespace         string
	EmptyVersion      bool
}

// ParsePurlForMatching parses a purl and version into a context for database matching
func ParsePurlForMatching(purl packageurl.PackageURL) *PurlMatchContext {
	qualifier := purl.Qualifiers
	// Try to normalize the version to semantic versioning format
	normalizedVersion, versionIsValid := ConvertToSemver(purl.Version)

	// Create search key (purl without version)
	purl.Version = ""
	purl.Qualifiers = nil
	searchPurl := purl.ToString()

	return &PurlMatchContext{
		SearchPurl:        searchPurl,
		NormalizedVersion: normalizedVersion,
		VersionIsValid:    versionIsValid,
		Qualifiers:        qualifier,
		Namespace:         purl.Namespace,
		EmptyVersion:      normalizedVersion == "",
	}
}

// function to make purl look more visually appealing
func BeautifyPURL(pURL string) (string, error) {
	p, err := packageurl.FromString(pURL)
	if err != nil {
		return pURL, err
	}
	//if the namespace is empty we don't want any leading slashes
	if p.Namespace == "" {
		return p.Name, nil
	} else {
		return p.Namespace + "/" + p.Name, nil
	}
}

// returns the normalized purl AND the component type
func normalizePurl(purl string) string {

	parsedPurl, err := packageurl.FromString(purl)
	if err != nil {
		purl, err := url.PathUnescape(purl)
		if err != nil {
			return purl
		}
		return purl
	}

	// unescape the purl
	purl, err = url.PathUnescape(parsedPurl.ToString())
	if err != nil {
		return purl
	}
	return purl
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

var PURLEcosystems = map[string]string{
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
	purlType, exists := PURLEcosystems[ecosystem]
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
	for key, value := range PURLEcosystems {
		if value == purlType {
			return key
		}
	}
	return ""
}

func Purlify(artifactName string, assetVersionName string) string {
	// the artifactName might contain qualifiers like pkg:oci/k8s-tools?repository_url=registry.opencode.de/open-code/oci/k8s-tool&tag=main-amd64
	// we want to remove them for the purl normalization
	// the correct purl for this would be pkg:oci/k8s-tools@main?repository_url=registry.opencode.de/open-code/oci/k8s-tools&tag=main-amd64
	parts := strings.SplitN(artifactName, "?", 2)
	base := parts[0]
	var qualifiers string
	if len(parts) == 2 {
		qualifiers = "?" + parts[1]
	}

	if assetVersionName != "" {
		base = fmt.Sprintf("%s@%s", base, assetVersionName)
	}

	return base + qualifiers
}
