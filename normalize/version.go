package normalize

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// versionInvalidCharsRe is compiled once for performance
var versionInvalidCharsRe = regexp.MustCompile(`[^0-9.]`)

const max31BitNumber int = 2_147_483_648

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

	// Process in correct order: version core, pre-release, build metadata
	var buildMetadata string
	var preRelease string

	// Extract build metadata (after "+") first, as per semver spec
	// Build metadata MUST be denoted by appending a plus sign
	if idx := strings.Index(version, "+"); idx != -1 {
		buildMetadata = version[idx+1:]
		version = version[:idx]
	}

	// Handle tilde versions (convert to pre-release)
	// This is common in Debian/RPM versioning
	if idx := strings.Index(version, "~"); idx != -1 {
		preRelease = version[idx+1:]
		version = version[:idx]
	}

	// Extract pre-release (after "-")
	// Pre-release MUST be denoted by appending a hyphen
	if idx := strings.Index(version, "-"); idx != -1 {
		if preRelease != "" {
			preRelease = version[idx+1:] + "-" + preRelease
		} else {
			preRelease = version[idx+1:]
		}
		version = version[:idx]
	}

	// replace any "_" in preRelease with "."
	// this is needed for redhat versions like "31.4.0-1.el5_11"
	preRelease = strings.ReplaceAll(preRelease, "_", ".")

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

	// Remove leading zeros from each segment (e.g., "03" -> "3")
	// This is required by semver specification for numeric identifiers
	for i, segment := range segments {
		if segment != "" && segment != "0" {
			segments[i] = strings.TrimLeft(segment, "0")
			// If segment was all zeros (e.g., "00"), keep single "0"
			if segments[i] == "" {
				segments[i] = "0"
			}
		}

		// check if the numbers of the main components exceed 31 bits, this is due to database limitations
		number, err := strconv.Atoi(segments[i])
		if err != nil {
			return "", fmt.Errorf("%d. semver segment: %s is not numeric", i, segments[i])
		}
		if number >= max31BitNumber {
			return "", fmt.Errorf("bad semver, %d. component %d does not fit 31 bit limit", i, number)
		}

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
	if buildMetadata != "" {
		semver += "+" + buildMetadata
	}

	// validate using regex
	if !ValidSemverRegex.MatchString(semver) {
		return "", fmt.Errorf("resulting semver is invalid: %s", semver)
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
