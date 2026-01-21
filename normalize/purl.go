package normalize

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

type VersionInterpretationType string

const (
	ExactVersionString       VersionInterpretationType = "exact"
	SemanticVersionString    VersionInterpretationType = "semver_range"
	EmptyVersion             VersionInterpretationType = "empty_version"
	EcosystemSpecificVersion VersionInterpretationType = "ecosystem_specific"
)

// PurlMatchContext holds the parsed purl information for matching
type PurlMatchContext struct {
	SearchPurl                  string
	NormalizedVersion           string
	HowToInterpretVersionString VersionInterpretationType
	Qualifiers                  packageurl.Qualifiers
	Namespace                   string
}

// ParsePurlForMatching parses a purl and version into a context for database matching
func ParsePurlForMatching(purl packageurl.PackageURL) *PurlMatchContext {
	purl = applyPackageAliasToPurl(purl)
	qualifier := purl.Qualifiers

	var normalizedVersion string
	var versionInterpretation VersionInterpretationType

	// Try to normalize the version to semantic versioning format
	if purl.Version == "" {
		versionInterpretation = EmptyVersion
		normalizedVersion = ""
	} else if purl.Type == "deb" || purl.Type == "rpm" || purl.Type == "apk" {
		versionInterpretation = EcosystemSpecificVersion
		normalizedVersion = purl.Version

		// For Debian packages, prepend epoch from qualifier if present
		// e.g., pkg:deb/debian/git@2.47.3-0+deb13u1?epoch=1 -> "1:2.47.3-0+deb13u1"
		if purl.Type == "deb" {
			if epoch := qualifier.Map()["epoch"]; epoch != "" {
				normalizedVersion = epoch + ":" + normalizedVersion
			}
		}
	} else {
		maybeSemver, err := ConvertToSemver(purl.Version)
		if err == nil && maybeSemver != "" {
			versionInterpretation = SemanticVersionString
			normalizedVersion = maybeSemver
		} else {
			versionInterpretation = ExactVersionString
			normalizedVersion = purl.Version
		}
	}

	// Create search key (purl without version)
	purl.Version = ""
	purl.Qualifiers = nil
	searchPurl := purl.ToString()

	return &PurlMatchContext{
		SearchPurl:                  searchPurl,
		NormalizedVersion:           normalizedVersion,
		Qualifiers:                  qualifier,
		Namespace:                   purl.Namespace,
		HowToInterpretVersionString: versionInterpretation,
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

func ToPurlWithoutVersion(purl packageurl.PackageURL) string {
	purl.Version = ""
	purl.Qualifiers = nil
	return purl.ToString()
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

func GetComponentID(component cdx.Component) string {
	if component.BOMRef == GraphRootNodeID {
		return "" // replace with nil before storing.
	} else if component.BOMRef != "" {
		// For artifact and info-source nodes, use BOMRef (e.g., "artifact:source", "sbom:DEFAULT@scanner")
		return component.BOMRef
	} else if component.PackageURL != "" {
		return normalizePurl(component.PackageURL)
	} else {
		return component.Name // fallback to name
	}
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

func Purlify(artifactName string, assetVersionName string) string {
	const (
		defaultType    = "generic"
		defaultName    = "unknown"
		defaultVersion = "0.0.0"
	)

	// Version default
	version := assetVersionName
	if version == "" {
		version = defaultVersion
	}

	// Split qualifiers
	parts := strings.SplitN(artifactName, "?", 2)
	base := parts[0]
	var qualifiers string
	if len(parts) == 2 {
		qualifiers = "?" + parts[1]
	}

	// Remove existing version if present
	if at := strings.LastIndex(base, "@"); at != -1 {
		base = base[:at]
	}

	// If not a purl, treat artifactName as the name
	if !strings.HasPrefix(base, "pkg:") {
		name := strings.Trim(base, "/")
		if name == "" {
			name = defaultName
		}
		base = fmt.Sprintf("pkg:%s/%s", defaultType, name)
	}

	// Validate structure after pkg:
	afterScheme := strings.TrimPrefix(base, "pkg:")
	if afterScheme == "" || strings.HasSuffix(afterScheme, "/") {
		base = fmt.Sprintf("pkg:%s/%s", defaultType, defaultName)
	} else if !strings.Contains(afterScheme, "/") {
		// missing type/name separator
		base = fmt.Sprintf("pkg:%s/%s", defaultType, afterScheme)
	}

	return base + "@" + version + qualifiers
}

func QualifiersMapToString(qualifiers map[string]string) string {
	// create an URL string out of the qualifiers and sort them by key to ensure consistent hashing
	qualifiersStr := ""
	if len(qualifiers) > 0 {
		var qualifierPairs []string
		for key, value := range qualifiers {
			qualifierPairs = append(qualifierPairs, fmt.Sprintf("%s=%s", key, value))
		}
		slices.Sort(qualifierPairs)
		qualifiersStr = strings.Join(qualifierPairs, "&")
	}
	return qualifiersStr
}
