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
		Long:              "This command generates a tag, artifact name, and URL-encoded artifact name for a given image based on its contents and the provided parameters such as upstream version, architecture, and image type.",
		Example: `  # Generate tag with upstream version and architecture
  devguard-scanner generate-tag --upstreamVersion 1.2.3 --architecture amd64 --imagePath registry.io/my-image

  # Generate tag with variant
  devguard-scanner generate-tag --upstreamVersion 2.0.0 --architecture arm64 --imageVariant alpine --imagePath registry.io/app`,
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

	outputString.WriteString(fmt.Sprintf("IMAGE_TAG=%s\n", image))
	outputString.WriteString(fmt.Sprintf("ARTIFACT_NAME=%s\n", artifactName))
	outputString.WriteString(fmt.Sprintf("ARTIFACT_URL_ENCODED=%s\n", artifactURLEncoded))

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
