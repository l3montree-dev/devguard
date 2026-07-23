package commands

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/spf13/cobra"
)

func NewGenerateTagCommand() *cobra.Command {
	generateTagCmd := &cobra.Command{
		Use:               "generate-tag",
		Short:             "Generate a tag for an image based on its contents",
		DisableAutoGenTag: true,
		Long: `Generate a container image tag, artifact name, and URL-encoded artifact name.

The tag is assembled from the provided parameters in the following order:
  [<upstreamVersion>-][<ref>-][<imageVariant>-][<architecture>]

All parts are optional. Omit --architecture to get a plain version tag (e.g. "21" instead of "21-amd64").
Use --imageSuffix to produce multiple images from a single build (e.g. java-base and java-debian).
The ref flag is typically set from $CI_COMMIT_REF_SLUG; forward slashes are replaced with hyphens.

The command prints three lines to stdout:
  IMAGE_TAG=<full image reference including tag>
  ARTIFACT_NAME=<purl>
  ARTIFACT_URL_ENCODED=<url-encoded purl>`,
		Example: `  # If you want to tag an image with its upstream version and the target architecture:
  devguard-scanner generate-tag --upstreamVersion 1.2.3 --architecture amd64 --imagePath registry.io/org/app
  # → registry.io/org/app:1.2.3-amd64

  # If you want the current branch or ref included in the tag (e.g. to distinguish nightly builds):
  devguard-scanner generate-tag --upstreamVersion 1.2.3 --architecture amd64 --imagePath registry.io/org/app --ref main
  # → registry.io/org/app:1.2.3-main-amd64

  # If you are building multiple images in a single repository (e.g. different base OS flavours),
  # call generate-tag once per image and vary --imageSuffix to give each image a unique name:
  devguard-scanner generate-tag --upstreamVersion 21 --imagePath registry.io/org --imageSuffix java-base
  devguard-scanner generate-tag --upstreamVersion 21 --imagePath registry.io/org --imageSuffix java-debian
  # → registry.io/org/java-base:21
  # → registry.io/org/java-debian:21

  # If you want to distinguish image flavours within the same image (e.g. alpine vs. full):
  devguard-scanner generate-tag --upstreamVersion 2.0.0 --architecture arm64 --imageVariant alpine --imagePath registry.io/org/app
  # → registry.io/org/app:2.0.0-alpine-arm64`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateTagRun(cmd, args)
		},
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner generate-tag — build a container image tag from metadata",
			"description":     "Generate a container image tag, artifact name, and URL-encoded artifact name from build parameters like version, ref, and architecture with devguard-scanner.",
			"keyword_primary": "devguard-scanner generate-tag",
		},
	}

	scanner.AddAssetRefFlags(generateTagCmd)
	scanner.AddGenerateTagFlags(generateTagCmd)

	return generateTagCmd
}

func generateTagRun(cmd *cobra.Command, args []string) error {
	upstreamVersion := config.RuntimeBaseConfig.UpstreamVersion
	architecture := config.RuntimeBaseConfig.Architecture
	imagePath := config.RuntimeBaseConfig.ImagePath
	imageVariant := config.RuntimeBaseConfig.ImageVariant
	imageSuffix := config.RuntimeBaseConfig.ImagePathSuffix

	refFlag, err := cmd.Flags().GetString("ref")
	if err != nil {
		return err
	}

	output, _, err := generateTag(upstreamVersion, architecture, imagePath, refFlag, imageVariant, imageSuffix)
	if err != nil {
		return err
	}
	fmt.Print(output)
	return nil
}

type tagOutput struct {
	ImageTag           string
	ArtifactName       string
	ArtifactURLEncoded string
}

func generateTag(upstreamVersion string, architecture string, imagePath string, refFlag string, imageVariant string, imageSuffix string) (string, tagOutput, error) {

	var tagElements = []string{}
	if refFlag != "" {
		tagElements = append(tagElements, refFlag)
	}

	if architecture != "" {
		tagElements = append(tagElements, architecture)
	}

	// tag has the format [<upstreamVersion>-]<ref>[-<type>][-<architecture>]
	if upstreamVersion != "0" && upstreamVersion != "" {
		// add the upstream version as first element
		tagElements = append([]string{upstreamVersion}, tagElements...)
	}

	// check if we have a image type, if so, should be second last element
	if imageVariant != "" {
		// insert as second last
		lastElement := tagElements[len(tagElements)-1]
		tagElements = tagElements[:len(tagElements)-1]
		tagElements = append(tagElements, imageVariant)
		tagElements = append(tagElements, lastElement)
	}

	// replace all / with -, this avoids issues with container image tags, which do not allow / in tag values.
	for i, element := range tagElements {
		tagElements[i] = strings.ReplaceAll(element, "/", "-")
	}

	imagePathWithSuffix := imagePath
	// only append suffix when it is set and not "default"
	if imageSuffix != "" && imageSuffix != "default" {
		imagePathWithSuffix += "/" + imageSuffix
	}

	image := fmt.Sprintf("%s:%s", imagePathWithSuffix, strings.Join(tagElements, "-"))
	artifactName, artifactURLEncoded, err := generateArtifactName(image, architecture)
	if err != nil {
		return "", tagOutput{}, err
	}
	output := tagOutput{
		ImageTag:           image,
		ArtifactName:       artifactName,
		ArtifactURLEncoded: artifactURLEncoded,
	}

	var outputString strings.Builder

	fmt.Fprintf(&outputString, "IMAGE_TAG=%s\n", image)
	fmt.Fprintf(&outputString, "ARTIFACT_NAME=%s\n", artifactName)
	fmt.Fprintf(&outputString, "ARTIFACT_URL_ENCODED=%s\n", artifactURLEncoded)

	return outputString.String(), output, nil
}

func generateArtifactName(imageTag string, architecture string) (string, string, error) {

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

	// Generate artifactNameURLEncoded → artifact-artifactNameURLEncoded.txt
	artifactName := fmt.Sprintf("pkg:oci/%s?repository_url=%s&arch=%s&tag=%s", name, registryAndImage, architecture, imageTag[colonIndex+1:])

	// Generate SAFE version → artifact-name-safe.txt
	// Equivalent to: echo -n "$artifactNameURLEncoded" | jq -s -R -r @uri
	artifactNameURLEncoded := url.PathEscape(artifactName)

	return artifactName, artifactNameURLEncoded, nil
}
