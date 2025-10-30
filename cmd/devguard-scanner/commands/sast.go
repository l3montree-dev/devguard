package commands

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func sastScan(p, outputPath string) (*common.SarifResult, error) {
	dir := os.TempDir()
	dir = path.Join(dir, "sast")

	// create new directory
	err := os.MkdirAll(dir, 0755)

	if err != nil {
		return nil, errors.Wrap(err, "could not create temp file")
	}

	var sarifFilePath string
	if outputPath != "" {
		sarifFilePath = outputPath
		outputDir := path.Dir(outputPath)
		err = os.MkdirAll(outputDir, 0755)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output directory")
		}
	} else {
		sarifFilePath = path.Join(dir, "result.sarif")
	}

	var scannerCmd *exec.Cmd

	slog.Info("Starting sast scanning", "path", p, "result-path", sarifFilePath)

	scannerCmd = exec.Command("semgrep", "scan", p, "--sarif", "--sarif-output", sarifFilePath, "-v") // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack

	stderr := &bytes.Buffer{}
	scannerCmd.Stderr = stderr

	err = scannerCmd.Run()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() == 1 {
			slog.Warn("Vulnerabilities found, but continuing execution.")
		} else {
			return nil, errors.Wrapf(err, "could not run scanner: %s", stderr.String())
		}
	}

	// read AND parse the file
	// open the file
	file, err := os.Open(sarifFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "could not open file")
	}
	defer file.Close()
	// parse the file
	var sarifScan common.SarifResult
	err = json.NewDecoder(file).Decode(&sarifScan)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse sarif file")
	}

	return &sarifScan, nil
}

func NewSastCommand() *cobra.Command {
	sastCommand := &cobra.Command{
		Use:   "sast [path]",
		Short: "Run a static application security test (SAST)",
		Long: `Run a static application security test using the configured SAST tool.

This command executes the configured SAST scanner (semgrep) against the project
path provided via flags or configuration, obfuscates sensitive snippets, and
uploads the SARIF results to DevGuard. The request is signed using the configured
token before upload.

You may pass the target as the first positional argument instead of using
--path.

Examples:
	devguard-scanner sast --path ./my-repo
	devguard-scanner sast ./my-repo
	devguard-scanner sast ghcr.io/org/image:tag
	devguard-scanner sast --path ./my-repo --outputPath results.sarif.json
`,
		RunE: sarifCommandFactory("sast"),
	}

	scanner.AddFirstPartyVulnsScanFlags(sastCommand)
	sastCommand.Flags().String("outputPath", "", "Path to save the SARIF report. If not specified, the report will only be uploaded to DevGuard.")
	return sastCommand
}
