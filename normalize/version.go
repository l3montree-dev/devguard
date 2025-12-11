package normalize

import (
	"fmt"
	"regexp"
	"strings"
)

// 20.160.635.721
const max31BitValue = 2_147_483_647 // 2^31 - 1

func ConvertToSemver(originalVersion string) (string, error) {
	// Handle empty string
	if originalVersion == "" {
		return "", nil
	}

	var version string
	var release string

	// Split out epoch if present
	if strings.Contains(originalVersion, ":") {
		parts := strings.SplitN(originalVersion, ":", 2)
		originalVersion = parts[1]
	}

	//check if the version start with v
	if after, ok := strings.CutPrefix(originalVersion, "v"); ok {
		originalVersion = after
	}

	// Split version-release (only on first hyphen)
	if strings.Contains(originalVersion, "-") {
		parts := strings.SplitN(originalVersion, "-", 2)
		version = parts[0]
		release = parts[1]
	} else {
		version = originalVersion
	}

	// Split version-release (only on first hyphen)
	if strings.Contains(version, "+") {
		parts := strings.SplitN(version, "+", 2)
		version = parts[0]
		if release != "" {
			release = parts[1] + "-" + release
		} else {
			release = parts[1]
		}
	}

	// remove anything after "~"
	if strings.Contains(version, "~") {
		parts := strings.SplitN(version, "~", 2)
		version = parts[0]
		if release != "" {
			release = parts[1] + "-" + release
		} else {
			release = parts[1]
		}
	}

	//check if there are any invalid characters in version
	reInvalidChars := regexp.MustCompile(`[^0-9.]`)
	if reInvalidChars.MatchString(version) {
		return "", fmt.Errorf("version contains invalid characters: %s", version)
	}

	// Split into segments
	segments := strings.Split(version, ".")

	// If we have more than 3 segments, take only the first 3
	if len(segments) > 3 {
		return "", fmt.Errorf("version has more than 3 segments: %s", version)
	}

	// If version is missing segments, pad them
	for len(segments) < 3 {
		segments = append(segments, "0")
	}

	semver := strings.Join(segments, ".")
	if release != "" {
		semver += "-" + release
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
