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
		// try to read the predicate type from the attestation

		attestationFileName := filepath.Join(output, fmt.Sprintf("attestation-%d.json", i+1))
		if predicate, ok := attestation["predicateType"].(string); ok {
			// get everything after the last / in the predicate type
			predicate = strings.Split(predicate, "/")[len(strings.Split(predicate, "/"))-1]
			attestationFileName = filepath.Join(output, predicate)
		}

		attestationFile, err := os.Create(attestationFileName)
		if err != nil {
			return fmt.Errorf("could not create attestation file: %w", err)
		}
		defer attestationFile.Close()

		attestationBytes, err := json.MarshalIndent(attestation, "", "  ")
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
		Short: "Discover base image attestations from container files",
		Long: `Scan a directory for Dockerfile/Containerfile, extract the base image FROM line and
attempt to discover any attestation documents for the base image. It will save the attestations to the output path as separate files.

Example:
  devguard-scanner discover-baseimage-attestations ./path/to/project/Containerfile
`,
		Args: cobra.ExactArgs(1),
		RunE: runDiscoverBaseImageAttestations,
	}

	discoverBaseImageAttestationsCmd.Flags().String("predicateType", "", "Predicate type to filter attestations (e.g. 'https://cyclonedx.org/vex'). If empty, all predicate types are retrieved.")
	discoverBaseImageAttestationsCmd.Flags().String("output", ".", "Output directory to save the discovered attestations.")
	return discoverBaseImageAttestationsCmd
}
