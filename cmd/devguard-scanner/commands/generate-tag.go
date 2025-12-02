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
		Use:   "generate-tag",
		Short: "Generate a tag for an image based on its contents",
		Long:  "This command generates a tag, artifact name, and URL-encoded artifact name for a given image based on its contents and the provided parameters such as upstream version, architecture, and image type.",
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

	refFlag, err := cmd.Flags().GetString("ref")
	if err != nil {
		return err
	}

	output, err := generateTag(upstreamVersion, architecture, imagePath, refFlag)
	if err != nil {
		return err
	}
	fmt.Print(output)
	return nil
}

func generateTag(upstreamVersion string, architecture []string, imagePath string, refFlag string) (string, error) {

	output := []struct {
		ImageTag           string
		ArtifactName       string
		ArtifactURLEncoded string
		Architecture       string
	}{}

	for _, arch := range architecture {
		var tag string

		// tag has the format <upstreamVersion>+ref-<architecture> or <ref>+<architecture>
		if upstreamVersion == "0" || upstreamVersion == "" {
			tag = refFlag + "+" + arch
		} else {
			tag = upstreamVersion + "+" + refFlag + "-" + arch
		}

		tag = imagePath + ":" + tag
		artifactName, artifactURLEncoded, err := generateArtifactName(tag, arch)
		if err != nil {
			return "", err
		}
		output = append(output, struct {
			ImageTag           string
			ArtifactName       string
			ArtifactURLEncoded string
			Architecture       string
		}{
			ImageTag:           tag,
			ArtifactName:       artifactName,
			ArtifactURLEncoded: artifactURLEncoded,
			// uppercase the architecture for the output variable
			Architecture: strings.ToUpper(arch),
		})
	}

	outputString := ""
	for _, o := range output {
		outputString += fmt.Sprintf("IMAGE_TAG_%s=%s\n", o.Architecture, o.ImageTag)
		outputString += fmt.Sprintf("ARTIFACT_NAME_%s=%s\n", o.Architecture, o.ArtifactName)
		outputString += fmt.Sprintf("ARTIFACT_URL_ENCODED_%s=%s\n", o.Architecture, o.ArtifactURLEncoded)
	}

	return outputString, nil
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

	// URL encode repository_url (same behavior as bash)
	//repositoryURL := url.QueryEscape(registryAndImage)

	// Generate artifactNameURLEncoded → artifact-artifactNameURLEncoded.txt
	artifactName := fmt.Sprintf("pkg:oci/%s?repository_url=%s&arch=%s&tag=%s", name, registryAndImage, architecture, imageTag[colonIndex+1:])

	// Generate SAFE version → artifact-name-safe.txt
	// Equivalent to: echo -n "$artifactNameURLEncoded" | jq -s -R -r @uri
	artifactNameURLEncoded := url.PathEscape(artifactName)

	return artifactName, artifactNameURLEncoded, nil
}
