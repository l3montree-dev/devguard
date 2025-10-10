package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/spf13/cobra"
)

func getContainerFile(ctx context.Context, path string) ([]byte, error) {

	//check if in workdir a Dockerfile or Container file exists
	dockerFilePath := path + "/Dockerfile"
	containerFilePath := path + "/Containerfile"

	fmt.Println("dockerFilePath", dockerFilePath)

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
	lines := strings.Split(string(containerFile), "\n")
	lineArr := []string{}
	for _, line := range lines {
		// delete all spaces from the line
		line = strings.TrimSpace(line)
		// check if the line starts with FROM
		if len(line) > 4 && line[:4] == "FROM" {
			lineArr = append(lineArr, line)
		}
	}

	if len(lineArr) == 0 {
		return "", fmt.Errorf("no FROM statement found in container file")
	}

	//get the last FROM statement
	lastFrom := lineArr[len(lineArr)-1]
	fmt.Println("lastFrom", lastFrom)

	//split the line by spaces
	fromParts := []string{}
	fromParts = strings.Split(lastFrom, " ")
	//check if there are at least 2 parts
	if len(fromParts) < 2 {
		return "", fmt.Errorf("no image found in FROM statement")
	}

	image := fromParts[1]
	fmt.Println("image", image)
	//return the image

	return image, nil
}

func getVEX(ctx context.Context, imageRef string) (*cyclonedx.BOM, error) {

	var vex *cyclonedx.BOM

	attestations, err := getAttestations(imageRef)
	if err != nil {
		return nil, err
	}

	for _, attestation := range attestations {
		if strings.HasPrefix(attestation["predicateType"].(string), "https://cyclonedx.org/vex") {

			if vex != nil {
				panic("multiple vex documents found for image")
			}

			predicate, ok := attestation["predicate"].(map[string]any)
			if !ok {
				panic("could not parse predicate")
			}

			// marshal the predicate back to json
			predicateBytes, err := json.Marshal(predicate)
			if err != nil {
				panic(err)
			}
			vex, err = bomFromBytes(predicateBytes)
			if err != nil {
				panic(err)
			}

			//save the vex to a file
			filename := "vex-" + strings.ReplaceAll(imageRef, "/", "_") + ".json"
			file, err := os.Create(filename)
			if err != nil {
				slog.Error("could not create vex file", "err", err)
				continue
			}
			defer file.Close()

			vexBytes, err := json.MarshalIndent(vex, "", "  ")
			if err != nil {
				slog.Error("could not marshal vex", "err", err)
				continue
			}

			_, err = file.Write(vexBytes)
			if err != nil {
				slog.Error("could not write vex to file", "err", err)
				continue
			}

			slog.Info("wrote vex to file", "file", file.Name())
		}
	}

	return vex, nil
}

func vexCommand(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()

	// check if the is a container file or a dockerfile
	containerFile, err := getContainerFile(ctx, config.RuntimeBaseConfig.Path)
	if err != nil {
		return err
	}

	//get the last from statement from the container file
	imagePath, err := getImageFromContainerFile(containerFile)
	if err != nil {
		return err
	}

	//check if there is a vex file for the image
	vex, err := getVEX(ctx, imagePath)
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
		vexResp, err := uploadVEX(vexBuff)
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

func NewVEXCommand() *cobra.Command {
	vexCommand := &cobra.Command{
		Use:   "vex",
		Short: "Commands for working with VEX documents",
		Args:  cobra.ExactArgs(0),
		RunE:  vexCommand,
	}

	addDefaultFlags(vexCommand)
	addAssetRefFlags(vexCommand)
	vexCommand.Flags().String("path", ".", "The path to the project to scan. Defaults to the current directory.")

	return vexCommand
}
