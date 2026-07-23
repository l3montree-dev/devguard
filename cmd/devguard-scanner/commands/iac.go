package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func iacScan(p, outputPath string) (*sarif.SarifSchema210Json, error) {
	var sarifFilePath string
	var outputDir string
	if outputPath != "" {
		outputDir = path.Dir(outputPath)
		sarifFilePath = path.Join(outputDir, "results_sarif.sarif")
	} else {
		dir := os.TempDir()
		dir = path.Join(dir, "iac")
		// create new directory
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, errors.Wrap(err, "could not create directory")
		}
		defer os.RemoveAll(dir)
		outputDir = dir
		sarifFilePath = path.Join(dir, "results_sarif.sarif")
	}

	var scannerCmd *exec.Cmd
	slog.Info("Starting iac scanning", "path", p)
	var configFileArgs []string
	if config.RuntimeBaseConfig.ConfigFilePath != "" {
		configFileArgs = []string{"--config-file", config.RuntimeBaseConfig.ConfigFilePath}
	}
	args := []string{"-s", "-d", p, "--output", "sarif", "--output-file-path", outputDir}
	args = append(args, configFileArgs...)
	args = append(args, config.RuntimeExtraArgs...)

	scannerCmd = exec.Command("checkov", args...) // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself
	stderr := &bytes.Buffer{}
	scannerCmd.Stderr = stderr
	scannerCmd.Run() // nolint:errcheck
	if scannerCmd.ProcessState.ExitCode() != 0 {
		slog.Error("infrastructure as code scanning failed", "stderr", stderr.String())
		return nil, fmt.Errorf("iac scan failed: %s", stderr.String())
	}

	// read the file in <dir>/results_sarif.sarif
	b, err := os.ReadFile(sarifFilePath)

	if err != nil {
		return nil, errors.Wrap(err, "could not read file")
	}

	// parse the file
	var sarifScan sarif.SarifSchema210Json
	err = json.Unmarshal(b, &sarifScan)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse sarif file")
	}

	// remove the file
	if outputPath == "" {
		err = os.Remove(sarifFilePath)
		if err != nil {
			return nil, errors.Wrap(err, "could not remove file")
		}
	} else {
		err = os.Rename(sarifFilePath, outputPath)
		if err != nil {
			return nil, errors.Wrap(err, "could not move file to output path")
		}
	}

	return &sarifScan, nil
}

func NewIaCCommand() *cobra.Command {
	iacCommand := &cobra.Command{
		Use:               "iac [path]",
		Short:             "Run an Infrastructure-as-Code (IaC) scan",
		DisableAutoGenTag: true,
		Long: `Run an Infrastructure-as-Code scan (e.g. checkov) against a repository or path and upload SARIF results to DevGuard.

This command scans Terraform, CloudFormation, Kubernetes manifests, and other IaC
files for security issues and misconfigurations.

Any flags after a "--" separator are forwarded verbatim to the underlying checkov invocation.
See the checkov CLI reference for available flags: https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html`,
		Example: `  # Scan Terraform directory
  devguard-scanner iac ./terraform

  # Scan with custom path flag
  devguard-scanner iac --path ./terraform

  # Scan and save results locally
  devguard-scanner iac ./terraform --outputPath iac-results.sarif.json

  # Forward extra flags to checkov
  devguard-scanner iac ./terraform -- --skip-check CKV_AWS_20`,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, config.RuntimeExtraArgs = splitPassthroughArgs(cmd, args)
			return sarifCommandFactory("iac")(cmd, args)
		},
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner iac — Infrastructure-as-Code scan",
			"description":     "Run an Infrastructure-as-Code scan with devguard-scanner iac to check Terraform, CloudFormation, and Kubernetes manifests for misconfigurations and upload SARIF results to DevGuard.",
			"keyword_primary": "devguard-scanner iac",
		},
	}

	scanner.AddFirstPartyVulnsScanFlags(iacCommand)
	return iacCommand
}
