package commands

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func sastScan(p, outputPath string) (*sarif.SarifSchema210Json, error) {
	dir := os.TempDir()
	dir = path.Join(dir, "sast")

	var sarifFilePath string
	if outputPath != "" {
		sarifFilePath = outputPath
	} else {
		// create new directory
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, errors.Wrap(err, "could not create temp file")
		}
		defer os.RemoveAll(dir)
		sarifFilePath = path.Join(dir, "result.sarif")
	}

	var scannerCmd *exec.Cmd

	slog.Info("Starting sast scanning", "path", p, "result-path", sarifFilePath)

	scannerCmd = exec.Command("semgrep", "scan", p, "--sarif", "--sarif-output", sarifFilePath, "-v") // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack

	stderr := &bytes.Buffer{}
	scannerCmd.Stderr = stderr

	err := scannerCmd.Run()
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
	var sarifScan sarif.SarifSchema210Json
	err = json.NewDecoder(file).Decode(&sarifScan)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse sarif file")
	}

	return &sarifScan, nil
}

func NewSastCommand() *cobra.Command {
	sastCommand := &cobra.Command{
		Use:               "sast [path]",
		Short:             "Run a static application security test (SAST)",
		DisableAutoGenTag: true,
		Long: `Run a static application security test using the configured SAST tool.

This command executes the configured SAST scanner (semgrep) against the project
path provided via flags or configuration, obfuscates sensitive snippets, and
uploads the SARIF results to DevGuard. The request is signed using the configured
token before upload.

You may pass the target as the first positional argument instead of using --path.`,
		Example: `  # Run SAST scan on local repository
  devguard-scanner sast ./my-repo

  # Scan with custom path flag
  devguard-scanner sast --path ./my-repo

  # Scan container image
  devguard-scanner sast ghcr.io/org/image:tag

  # Scan and save results locally
  devguard-scanner sast ./my-repo --outputPath results.sarif.json`,
		RunE: sarifCommandFactory("sast"),
	}

	scanner.AddFirstPartyVulnsScanFlags(sastCommand)
	return sastCommand
}
