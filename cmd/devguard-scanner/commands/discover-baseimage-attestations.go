package commands

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/spf13/cobra"
)

func getContainerFile(ctx context.Context, path string) ([]byte, error) {

	//check if in workdir a Dockerfile or Container file exists
	dockerFilePath := path + "/Dockerfile"
	containerFilePath := path + "/Containerfile"

	var file []byte
	var err error

	//check if a Dockerfile exists
	if file, err = os.ReadFile(dockerFilePath); err == nil {
		return file, nil
	}

	//check if a Container file exists
	if file, err = os.ReadFile(containerFilePath); err == nil {
		return file, nil
	}
	return nil, fmt.Errorf("no Dockerfile or Container file found in path: %s", path)
}

func getImageFromContainerFile(containerFile []byte) (string, error) {
	//split the file by lines
	regex := regexp.MustCompile(`FROM\s+(.+)`)

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
	ctx := cmd.Context()

	// check if the is a container file or a dockerfile
	containerFile, err := getContainerFile(ctx, args[0])
	if err != nil {
		return err
	}

	//get the last from statement from the container file
	imagePath, err := getImageFromContainerFile(containerFile)
	if err != nil {
		return err
	}

	//check if there is a vex file for the image
	vex, err := scanner.GetVEX(ctx, imagePath)
	if err != nil {
		return err
	}

	//upload the vex file
	if vex != nil {
		vexBuff := &bytes.Buffer{}
		// marshal the bom back to json
		err := cyclonedx.NewBOMEncoder(vexBuff, cyclonedx.BOMFileFormatJSON).Encode(vex)
		if err != nil {
			return err
		}

		// upload the vex
		vexResp, err := scanner.UploadVEX(vexBuff, true)
		if err != nil {
			slog.Error("could not upload vex", "err", err)
		} else {
			defer vexResp.Body.Close()
			if vexResp.StatusCode != http.StatusOK {
				slog.Error("could not upload vex", "status", vexResp.Status)
			} else {
				slog.Info("uploaded vex successfully")
			}
		}
	} else {
		slog.Info("no vex document found for image") //, "image") //imagePath)
	}

	slog.Info("vex called", "file", vex)

	return nil
}

func NewDiscoverBaseImageAttestationsCommand() *cobra.Command {
	discoverBaseImageAttestationsCmd := &cobra.Command{
		Use:   "discover-baseimage-attestations",
		Short: "Discover base image attestations from container files",
		Args:  cobra.ExactArgs(1),
		RunE:  runDiscoverBaseImageAttestations,
	}

	scanner.AddDefaultFlags(discoverBaseImageAttestationsCmd)
	scanner.AddAssetRefFlags(discoverBaseImageAttestationsCmd)
	discoverBaseImageAttestationsCmd.PersistentFlags().String("origin", "base-image", "The origin of the attestations being discovered. E.g. 'base-image' or 'container-scanning")

	return discoverBaseImageAttestationsCmd
}
