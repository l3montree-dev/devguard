package normalize

import (
	"fmt"
	"regexp"
	"strings"

	apkversion "github.com/knqyf263/go-apk-version"
	debversion "github.com/knqyf263/go-deb-version"
	rpmversion "github.com/knqyf263/go-rpm-version"
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

func CheckVersion(version, introduced, fixed *string, targetVersion, affectedComponentType string) (bool, error) {

	switch affectedComponentType {
	case "deb":
		return checkDebVersion(version, introduced, fixed, targetVersion)
	case "rpm":
		return checkRpmVersion(version, introduced, fixed, targetVersion)
	case "apk":
		return checkApkVersion(version, introduced, fixed, targetVersion)
	default:
		return false, fmt.Errorf("unsupported affected component type: %s", affectedComponentType)
	}
}

func checkApkVersion(version, introduced, fixed *string, targetVersion string) (bool, error) {
	targetVer, err := apkversion.NewVersion(targetVersion)
	if err != nil {
		return false, err
	}

	if version != nil {
		v, err := apkversion.NewVersion(*version)
		if err != nil {
			return false, err
		}
		if v.Equal(targetVer) {
			return true, nil
		}
	}

	less, greater := false, false

	if introduced != nil {
		introVer, err := apkversion.NewVersion(*introduced)
		if err != nil {
			return false, err
		}
		if targetVer.GreaterThan(introVer) {
			greater = true
		}
	}

	if fixed != nil {
		fixedVer, err := apkversion.NewVersion(*fixed)
		if err != nil {
			return false, err
		}
		if targetVer.LessThan(fixedVer) {
			less = true
		}
	}

	return (less && greater) || (introduced == nil && less) || (fixed == nil && greater), nil
}
func checkDebVersion(version, introduced, fixed *string, targetVersion string) (bool, error) {

	targetVer, err := debversion.NewVersion(targetVersion)
	if err != nil {
		return false, err
	}

	if version != nil {
		v, err := debversion.NewVersion(*version)
		if err != nil {
			return false, err
		}
		if v.Equal(targetVer) {
			return true, nil
		}
	}

	less, greater := false, false

	if introduced != nil {
		introVer, err := debversion.NewVersion(*introduced)
		if err != nil {
			return false, err
		}
		if targetVer.GreaterThan(introVer) {
			greater = true
		}
	}

	if fixed != nil {
		fixedVer, err := debversion.NewVersion(*fixed)
		if err != nil {
			return false, err
		}
		if targetVer.LessThan(fixedVer) {
			less = true
		}
	}

	return (less && greater) || (introduced == nil && less) || (fixed == nil && greater), nil
}

func checkRpmVersion(version, introduced, fixed *string, targetVersion string) (bool, error) {
	targetVer := rpmversion.NewVersion(targetVersion)

	if version != nil {
		v := rpmversion.NewVersion(*version)
		if v.Equal(targetVer) {
			return true, nil
		}
	}

	less, greater := false, false

	if introduced != nil {
		introVer := rpmversion.NewVersion(*introduced)
		if targetVer.GreaterThan(introVer) {
			greater = true
		}
	}

	if fixed != nil {
		fixedVer := rpmversion.NewVersion(*fixed)
		if targetVer.LessThan(fixedVer) {
			less = true
		}
	}

	return (less && greater) || (introduced == nil && less) || (fixed == nil && greater), nil
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
