package normalize

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
)

func removeDigitSuffix(s string) string {
	reg := regexp.MustCompile(`\.\d+$`)
	s = reg.ReplaceAllString(s, "")
	reg = regexp.MustCompile(`\d+$`)
	return reg.ReplaceAllString(s, "")
}

func CPEProductName(name string) string {
	// remove lib prefix
	name = strings.TrimPrefix(name, "lib")
	// remove build version suffix - if exists
	name = removeBuildIndex(name)
	return name
}

func CPEProductVersion(version string) string {
	// remove anything from the version like a "+" or "~"
	version = strings.Split(version, "+")[0]
	version = strings.Split(version, "~")[0]
	// check if the version has a suffix which matches p{digits}
	// if so, remove it
	return version
}

func normalizePackageName(packageName string) string {
	// remove the version from the package name
	// like python3.11
	// we only want python
	packageName = removeDigitSuffix(packageName)
	// lowercase the package name
	packageName = strings.ToLower(packageName)
	return packageName
}

func componentTypeToPart(componentType string) string {
	// This is a simplified mapping; adjust based on your specific requirements
	switch componentType {
	case "operating-system":
		return "o"
	default:
		return "a"
	}
}

func removeBuildIndex(version string) string {
	return strings.Split(version, "-")[0]
}

// PurlToCPE maps a package URL (purl) to a Common Platform Enumeration (CPE)
func PurlToCPE(purl string, componentType string) (string, error) {
	// Parse the purl
	parsedPurl, err := packageurl.FromString(purl)
	if err != nil {
		return "", fmt.Errorf("failed to parse purl: %w", err)
	}

	// Extract components
	// namespace := parsedPurl.Namespace
	name := normalizePackageName(parsedPurl.Name)
	version := removeBuildIndex(parsedPurl.Version)

	// Construct the CPE string
	// This is a simplified mapping; adjust based on your specific requirements
	cpe := fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*",
		componentTypeToPart(componentType), url.PathEscape(name), url.PathEscape(name), version)

	return cpe, nil
}
