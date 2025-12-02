package commands

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/spf13/cobra"
)

func NewGenerateTagCommand() *cobra.Command {
	generateTagCmd := &cobra.Command{
		Use:   "generate-tag",
		Short: "Generate a tag for an image based on its contents",
		Long: `Generate a tag for an image based on its contents.

`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateTagRun(cmd, args)
		},
	}

	scanner.AddAssetRefFlags(generateTagCmd)
	scanner.AddGenerateTagFlags(generateTagCmd)

	return generateTagCmd
}

func generateTagRun(cmd *cobra.Command, args []string) error {
	upstreamVersion := config.RuntimeBaseConfig.UpstreamVersion
	architecture := config.RuntimeBaseConfig.Architecture
	imageType := config.RuntimeBaseConfig.ImageType
	imagePath := config.RuntimeBaseConfig.ImagePath

	isTag, err := cmd.Flags().GetBool("isTag")
	if err != nil {
		return err
	}

	refFlag, err := cmd.Flags().GetString("ref")
	if err != nil {
		return err
	}

	output, err := generateTag(upstreamVersion, architecture, imageType, imagePath, isTag, refFlag)
	if err != nil {
		return err
	}
	fmt.Print(output)
	return nil
}

func generateTag(upstreamVersion string, architecture []string, imageType string, imagePath string, isTag bool, refFlag string) (string, error) {

	outPut := []struct {
		ImageTag           string
		ArtifactName       string
		ArtifactURLEncoded string
	}{}

	for _, arch := range architecture {
		var tag string
		if isTag {
			var err error
			switch imageType {
			case "runtime":
				tag, err = generateRuntimeTag(upstreamVersion, arch)
				if err != nil {
					return "", err
				}
			case "composed":
				tag, err = generateComposedTags(upstreamVersion, arch)
				if err != nil {
					return "", err
				}
			default:
				return "", fmt.Errorf("unknown image type: %s", imageType)
			}

		} else {
			tag = generateDevelopmentTag(refFlag, upstreamVersion, arch)
		}

		tag = imagePath + ":" + tag
		artifactName, artifactURLEncoded, err := generateArtifactName(tag)
		if err != nil {
			return "", err
		}
		outPut = append(outPut, struct {
			ImageTag           string
			ArtifactName       string
			ArtifactURLEncoded string
		}{
			ImageTag:           tag,
			ArtifactName:       artifactName,
			ArtifactURLEncoded: artifactURLEncoded,
		})
	}

	output := ""
	for _, o := range outPut {
		output += fmt.Sprintf("IMAGE_TAG=%s\n", o.ImageTag)
		output += fmt.Sprintf("ARTIFACT_NAME=%s\n", o.ArtifactName)
		output += fmt.Sprintf("ARTIFACT_URL_ENCODED=%s\n", o.ArtifactURLEncoded)
	}

	return output, nil
}

func generateDevelopmentTag(branchName, upstreamVersion, architecture string) string {
	branchNameSanitized := sanitizeBranchName(branchName)
	//check if upstreamVersion is empty
	if upstreamVersion == "" {
		return fmt.Sprintf("%s-%s", branchNameSanitized, architecture)
	}
	return fmt.Sprintf("%s-%s-%s", branchNameSanitized, upstreamVersion, architecture)
}

func sanitizeBranchName(branchName string) string {
	// Replace all "/" with "-"
	sanitized := strings.ReplaceAll(branchName, "/", "-")
	return sanitized
}

func generateRuntimeTag(upstreamVersion, architecture string) (string, error) {
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	if upstreamVersion == "" {
		return "", fmt.Errorf("upstream version is required for runtime tag generation")
	}
	return fmt.Sprintf("%s-%s+oc-%s", upstreamVersion, architecture, timestamp), nil
}

func generateComposedTags(version, arch string) (string, error) {
	// Validate semantic version format
	if !checkSemverFormat(version) {
		return "", fmt.Errorf("version %s is not in valid semantic version format", version)
	}

	return fmt.Sprintf("%s-%s", version, arch), nil
}

func checkSemverFormat(version string) bool {
	semverRegex := regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)$`)
	return semverRegex.MatchString(version)
}

func generateArtifactName(imageTag string) (string, string, error) {

	// Split registry/image and version
	colonIndex := strings.LastIndex(imageTag, ":")
	if colonIndex == -1 {
		return "", "", fmt.Errorf("invalid image tag format, missing ':' in %s", imageTag)
	}
	registryAndImage := imageTag[:colonIndex]

	// Extract namespace/name
	slashIndex := strings.Index(registryAndImage, "/")
	if slashIndex == -1 || slashIndex == len(registryAndImage)-1 {
		return "", "", fmt.Errorf("invalid registry/image format: %s", registryAndImage)
	}
	namespaceAndName := registryAndImage[slashIndex+1:]

	// Extract name only (without namespace)
	nameParts := strings.Split(namespaceAndName, "/")
	name := nameParts[len(nameParts)-1]

	// URL encode repository_url (same behavior as bash)
	//repositoryURL := url.QueryEscape(registryAndImage)

	// Generate artifactNameURLEncoded → artifact-artifactNameURLEncoded.txt
	artifactName := fmt.Sprintf("pkg:oci/%s?repository_url=%s", name, registryAndImage)

	// Generate SAFE version → artifact-name-safe.txt
	// Equivalent to: echo -n "$artifactNameURLEncoded" | jq -s -R -r @uri
	artifactNameURLEncoded := url.QueryEscape(artifactName)

	return artifactName, artifactNameURLEncoded, nil
}
