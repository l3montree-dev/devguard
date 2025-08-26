package normalize

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// 20.160.635.721
const max31BitValue = 2_147_483_647 // 2^31 - 1

// ConvertToSemver converts any versioning scheme to a semver-like versioning scheme
func ConvertToSemver(originalVersion string) string {
	if originalVersion == "" {
		return ""
	}
	// check if its already a valid semver
	if semver, err := SemverFix(originalVersion); err == nil {
		return semver
	}

	// mainComponents, _ := splitVersion(originalVersion)
	// Step 1: Parse the original version
	components := parseVersion(originalVersion)

	// Step 2: Normalize the components
	normalizedComponents := []int{}
	for _, component := range components {
		num, err := strconv.Atoi(component)
		if err == nil {
			normalizedComponents = append(normalizedComponents, num%max31BitValue)
		} else {
			normalizedComponents = append(normalizedComponents, mapToNumeric(component))
		}
	}

	// Step 3: Formulate Semver-like version
	semverMajor := getComponent(normalizedComponents, 0)
	semverMinor := getComponent(normalizedComponents, 1)
	semverPatch := getComponent(normalizedComponents, 2)

	// If there are more components, handle them as needed
	if len(normalizedComponents) > 3 {
		additionalComponents := normalizedComponents[3:]
		for _, component := range additionalComponents {
			semverPatch = (semverPatch*100 + component) % max31BitValue
		}
	}

	semverVersion := fmt.Sprintf("%d.%d.%d", semverMajor, semverMinor, semverPatch)

	/*
		There is no simple way to handle pre-release components in a generic way.
			if preReleaseComponents != "" {
				semverVersion = fmt.Sprintf("%s-%s", semverVersion, preReleaseComponents)
			}
	*/

	return semverVersion
}

// parseVersion splits the version string into components based on common delimiters
func parseVersion(version string) []string {
	re := regexp.MustCompile(`[.\-_]`)
	return re.Split(version, -1)
}

// mapToNumeric maps non-numeric components to numeric values
func mapToNumeric(component string) int {
	sum := 0
	for _, char := range component {
		sum += int(char)
	}
	return sum
}

// getComponent safely retrieves a component from a slice or returns 0
func getComponent(components []int, index int) int {
	if index < len(components) {
		return components[index]
	}
	return 0
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
