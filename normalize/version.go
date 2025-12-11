package normalize

import (
	"fmt"
	"regexp"
	"strings"
)

// versionInvalidCharsRe is compiled once for performance
var versionInvalidCharsRe = regexp.MustCompile(`[^0-9.]`)

// ConvertToSemver converts various version formats to semantic versioning format.
// It handles:
// - Epoch prefixes (e.g., "2:1.2.3" -> "1.2.3")
// - "v" prefixes (e.g., "v1.2.3" -> "1.2.3")
// - Pre-release identifiers with "-" (e.g., "1.2.3-rc1")
// - Build metadata with "+" (e.g., "1.2.3+build1")
// - Tilde versions "~" (e.g., "1.2.3~rc1" -> "1.2.3-rc1")
// - Missing version segments (e.g., "1.2" -> "1.2.0")
//
// Returns an error if:
// - Version contains invalid characters (only 0-9 and . allowed in version part)
// - Version has more than 3 numeric segments
func ConvertToSemver(originalVersion string) (string, error) {
	if originalVersion == "" {
		return "", nil
	}

	version := originalVersion

	// Remove epoch prefix if present (e.g., "2:1.2.3" -> "1.2.3")
	if idx := strings.Index(version, ":"); idx != -1 {
		version = version[idx+1:]
	}

	// Remove "v" prefix if present
	version = strings.TrimPrefix(version, "v")

	// Process build metadata and pre-release in correct order
	var buildMetadata string
	var preRelease string

	// Extract build metadata (after "+") first, as per semver spec
	if idx := strings.Index(version, "+"); idx != -1 {
		buildMetadata = version[idx+1:]
		version = version[:idx]
	}

	// Handle tilde versions (convert to pre-release)
	if idx := strings.Index(version, "~"); idx != -1 {
		preRelease = version[idx+1:]
		version = version[:idx]
	}

	// Extract pre-release (after "-")
	if idx := strings.Index(version, "-"); idx != -1 {
		if preRelease != "" {
			preRelease = version[idx+1:] + "-" + preRelease
		} else {
			preRelease = version[idx+1:]
		}
		version = version[:idx]
	}

	// Combine build metadata with pre-release if both exist
	if buildMetadata != "" {
		if preRelease != "" {
			preRelease = buildMetadata + "-" + preRelease
		} else {
			preRelease = buildMetadata
		}
	}

	// Validate that version contains only digits and dots
	if versionInvalidCharsRe.MatchString(version) {
		return "", fmt.Errorf("version contains invalid characters (only 0-9 and . allowed): %s", version)
	}

	// Split version into major.minor.patch segments
	segments := strings.Split(version, ".")

	// Semver allows max 3 segments: major, minor, patch
	if len(segments) > 3 {
		return "", fmt.Errorf("version has more than 3 segments (expected major.minor.patch): %s", version)
	}

	// Pad missing segments with "0"
	for len(segments) < 3 {
		segments = append(segments, "0")
	}

	// Build final semver string
	semver := strings.Join(segments, ".")
	if preRelease != "" {
		semver += "-" + preRelease
	}

	return semver, nil
}

func ArtifactPurl(scanner string, assetName string) string {
	// the user did not set any artifact name - thus we try to set a good one.
	suffix := strings.ReplaceAll(strings.ReplaceAll(assetName, "/projects/", "/"), "/assets/", "/")
	switch scanner {
	case "container-scanning":
		// we are scanning a container image - thus we use the container image as artifact name
		return "pkg:oci/" + suffix
	default:
		// we are scanning an application - we have no idea which ecosystem - thus use generic
		// use the asset name as the name of the artifact
		return "pkg:devguard/" + suffix
	}
}
