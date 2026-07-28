package commands

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/spf13/cobra"
)

func getImageFromContainerFile(containerFile []byte) (string, error) {
	//split the file by lines
	regex := regexp.MustCompile(`(?i)^ *FROM +(.*)`)

	lines := strings.Split(string(containerFile), "\n")
	var imagePath string
	for _, line := range lines {
		matches := regex.FindStringSubmatch(line)
		if len(matches) > 1 {
			imagePath = matches[1]
		}
	}

	if imagePath == "" {
		return "", fmt.Errorf("no FROM statement found in container file")
	}

	return imagePath, nil
}

func attestationOutput(attestation map[string]any, index int) (string, map[string]any) {
	filename := fmt.Sprintf("attestation-%d.json", index+1)
	content := attestation

	if predicate, ok := attestation["predicateType"].(string); ok {
		predicate = strings.Split(predicate, "/")[len(strings.Split(predicate, "/"))-1]
		predicate = strings.TrimSuffix(predicate, ".json")
		filename = fmt.Sprintf("attestation-%s.json", predicate)
		if pred, ok := attestation["predicate"].(map[string]any); ok {
			content = pred
		}
	}
	return filename, content
}

func runDiscoverBaseImageAttestations(cmd *cobra.Command, args []string) error {
	path := args[0]
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", path)
	}

	containerFile, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read file: %w", err)
	}

	//get the last from statement from the container file
	imagePath, err := getImageFromContainerFile(containerFile)
	if err != nil {
		return err
	}

	slog.Info("discovering attestations...", "image", imagePath)

	predicateType, _ := cmd.Flags().GetString("predicateType")
	output, _ := cmd.Flags().GetString("output")
	attestations, err := scanner.DiscoverAttestations(imagePath, predicateType)
	// save the attestations to files
	if err != nil {
		return fmt.Errorf("could not discover attestations: %w", err)
	}

	for i, attestation := range attestations {
		filename, attContent := attestationOutput(attestation, i)
		attestationFileName := filepath.Join(output, filename)

		attestationFile, err := os.Create(attestationFileName)
		if err != nil {
			return fmt.Errorf("could not create attestation file: %w", err)
		}
		defer attestationFile.Close()

		attestationBytes, err := json.MarshalIndent(attContent, "", "  ")
		if err != nil {
			return fmt.Errorf("could not marshal attestation: %w", err)
		}
		_, err = attestationFile.Write(attestationBytes)
		if err != nil {
			return fmt.Errorf("could not write attestation file: %w", err)
		}
		fmt.Printf("Attestation saved to %s\n", attestationFileName)
	}

	return nil
}

func NewDiscoverBaseImageAttestationsCommand() *cobra.Command {
	discoverBaseImageAttestationsCmd := &cobra.Command{
		Use:   "discover-baseimage-attestations <path to containerfile>",
		Short: "Download attestations (SBOM, VEX, …) for the base image used in a Dockerfile",
		Long: `Read a Dockerfile or Containerfile, extract the FROM line (the base image), and download any
attestations attached to that base image.

This is the same operation as 'devguard-scanner attestations <image>' but instead of providing
the image reference manually, the command reads it from the FROM line of your Containerfile.

Use this when you want to inherit upstream security metadata from your base image as part of
your own build pipeline. For example, if your base image ships a VEX document that suppresses
a CVE, you can re-use it via 'devguard-scanner attest' instead of triaging the vulnerability
yourself. Each discovered attestation is saved as a separate JSON file in the output directory.`,
		Example: `  # Download attestations for the base image of a Containerfile
  devguard-scanner discover-baseimage-attestations ./Containerfile

  # Filter to a specific predicate type (e.g. only VEX documents)
  devguard-scanner discover-baseimage-attestations ./Containerfile --predicateType https://cyclonedx.org/vex

  # Save to a custom output directory
  devguard-scanner discover-baseimage-attestations ./Containerfile --output ./attestations/`,
		Args: cobra.ExactArgs(1),
		RunE: runDiscoverBaseImageAttestations,
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner discover-baseimage-attestations — fetch base image attestations",
			"description":     "Read a Dockerfile's FROM line and download attestations such as SBOM and VEX documents attached to the base image using devguard-scanner.",
			"keyword_primary": "devguard-scanner discover-baseimage-attestations",
		},
	}

	discoverBaseImageAttestationsCmd.Flags().String("predicateType", "", "Predicate type to filter attestations (e.g. 'https://cyclonedx.org/vex'). If empty, all predicate types are retrieved.")
	discoverBaseImageAttestationsCmd.Flags().String("output", ".", "Output directory to save the discovered attestations.")
	return discoverBaseImageAttestationsCmd
}
