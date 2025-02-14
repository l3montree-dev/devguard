package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewSecretScanningCommand() *cobra.Command {
	secretScanningCommand := &cobra.Command{
		Use:   "secret-scanning",
		Short: "Start a secret scanning",
		Long:  "This command will scan an application for secrets and return a list of secrets found in the application.",

		Run: func(cmd *cobra.Command, args []string) {
			err := sarifCommandFactory("secret-scanning")(cmd, args)
			if err != nil {
				slog.Error("secret scanning failed", "err", err)
				return
			}
		},
	}

	secretScanningCommand.Flags().Bool("riskManagement", true, "Enable risk management (stores the detected vulnerabilities in devguard)")

	addScanFlags(secretScanningCommand)
	return secretScanningCommand
}

func sarifCommandFactory(scanner string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		core.InitLogger()
		token, assetName, apiUrl, failOnRisk, webUI := parseConfig(cmd)
		if token == "" {
			slog.Error("token seems to be empty. If you provide the token via an environment variable like --token=$DEVGUARD_TOKEN, check, if the environment variable is set or if there are any spelling mistakes", "token", token)
			return fmt.Errorf("token seems to be empty")
		}

		core.LoadConfig() // nolint:errcheck // just swallow the error: https://github.com/l3montree-dev/devguard/issues/188

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		path, err := cmd.Flags().GetString("path")
		if err != nil {
			return errors.Wrap(err, "could not get path")
		}

		if isValid, err := isValidPath(path); !isValid && err != nil {
			return errors.Wrap(err, "invalid path")
		}

		file, err := scanPath(scanner, path)
		if err != nil {
			return errors.Wrap(err, "could not open file")
		}
		defer os.Remove(file.Name())

		// check if we should do risk management
		doRiskManagement, err := cmd.Flags().GetBool("riskManagement")
		if err != nil {
			return errors.Wrap(err, "could not get risk management flag")
		}

		req, err := http.NewRequestWithContext(ctx, "POST", apiUrl+"/api/v1/sarif-scan/", file)
		if err != nil {
			return errors.Wrap(err, "could not create request")
		}

		err = pat.SignRequest(token, req)
		if err != nil {
			return errors.Wrap(err, "could not sign request")
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Risk-Management", strconv.FormatBool(doRiskManagement))
		req.Header.Set("X-Asset-Name", assetName)
		req.Header.Set("X-Scanner", "github.com/l3montree-dev/devguard/cmd/devguard-scanner"+"/"+scanner)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return errors.Wrap(err, "could not send request")
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("could not scan file!!!: %s", resp.Status)
		}

		// read and parse the body - it should be an array of dependencyVulns
		// print the dependencyVulns to the console
		var scanResponse scan.ScanResponse

		err = json.NewDecoder(resp.Body).Decode(&scanResponse)
		if err != nil {
			return errors.Wrap(err, "could not parse response")
		}

		printScaResults(scanResponse, failOnRisk, assetName, webUI, doRiskManagement)
		return nil
	}
}

func scanPath(scanner, path string) (*os.File, error) {
	switch scanner {
	case "secret-scanning":
		return secretScan(path)
	default:
		return nil, fmt.Errorf("unknown scanner: %s", scanner)
	}

}

func secretScan(path string) (*os.File, error) {

	fileName := uuid.New().String() + ".sarif"

	var scannerCmd *exec.Cmd

	slog.Info("Starting secret scanning", "path", path)

	/* 	scannerCmd = exec.Command("gitleaks", "dir", "-v", path, "--report-format", "sarif", "--report-path", fileName) */

	scannerCmd = exec.Command("gitleaks", "git", "--report-path", fileName, "--report-format", "sarif")

	stderr := &bytes.Buffer{}
	scannerCmd.Stderr = stderr

	err := scannerCmd.Run()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() == 1 {
			slog.Warn("Leaks found, but continuing execution.")
		} else {
			return nil, errors.Wrapf(err, "could not run scanner: %s", stderr.String())
		}
	}

	file, err := os.Open(fileName)
	if err != nil {
		return nil, errors.Wrap(err, "could not open file")
	}

	return file, nil
}
