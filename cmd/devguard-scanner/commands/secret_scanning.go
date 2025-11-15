package commands

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewSecretScanningCommand() *cobra.Command {
	secretScanningCommand := &cobra.Command{
		Use:   "secret-scanning [path]",
		Short: "Detect leaked secrets in source code",
		Long: `Scan a repository or directory for accidentally committed secrets and produce a SARIF report.

This command runs the configured secret-scanning tool (gitleaks) and uploads the
SARIF results to DevGuard for analysis and issue creation. The command signs the
request using the configured token before uploading the SARIF results.

You may pass the target as the first positional argument instead of using
--path.

Example:
	devguard-scanner secret-scanning --path ./my-repo
	devguard-scanner secret-scanning ./my-repo
	devguard-scanner secret-scanning --path ./my-repo --outputPath secrets.sarif.json
`,
		RunE: sarifCommandFactory("secret-scanning"),
	}

	scanner.AddFirstPartyVulnsScanFlags(secretScanningCommand)
	return secretScanningCommand
}

func secretScan(p, outputPath string) (*dtos.SarifResult, error) {
	dir := os.TempDir()
	dir = path.Join(dir, "secret-scanning")

	var sarifFilePath string
	if outputPath != "" {
		sarifFilePath = outputPath
	} else {
		// create new directory
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, errors.Wrap(err, "could not create temp file")
		}
		sarifFilePath = path.Join(dir, "result.sarif")
	}

	var scannerCmd *exec.Cmd

	slog.Info("Starting secret scanning", "path", p, "result-path", sarifFilePath)

	scannerCmd = exec.Command("gitleaks", "git", "-v", p, "--report-path", sarifFilePath, "--report-format", "sarif") // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself.

	stderr := &bytes.Buffer{}
	scannerCmd.Stderr = stderr

	err := scannerCmd.Run()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() == 1 {
			slog.Warn("Leaks found, but continuing execution.", "stderr", stderr.String())
		} else {
			return nil, errors.Wrapf(err, "could not run scanner: %s", stderr.String())
		}
	}

	// read AND parse the file
	var sarifScan dtos.SarifResult
	// open the file
	file, err := os.Open(sarifFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "could not open file")
	}
	defer file.Close()

	// parse the file
	err = json.NewDecoder(file).Decode(&sarifScan)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse sarif file")
	}

	// obfuscate founded secrets
	scanner.ObfuscateSecretAndAddFingerprint(&sarifScan)

	return &sarifScan, nil
}
