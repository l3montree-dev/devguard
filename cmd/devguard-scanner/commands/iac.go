package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func iacScan(p string) (*common.SarifResult, error) {
	// run checkov
	dir := os.TempDir()
	dir = path.Join(dir, "iac")
	// create new directory
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return nil, errors.Wrap(err, "could not create directory")
	}

	var scannerCmd *exec.Cmd
	slog.Info("Starting iac scanning", "path", p)

	scannerCmd = exec.Command("checkov", "-s", "-d", p, "--output", "sarif", "--output-file-path", dir) // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself
	stderr := &bytes.Buffer{}
	scannerCmd.Stderr = stderr
	scannerCmd.Run() // nolint:errcheck
	if scannerCmd.ProcessState.ExitCode() != 0 {
		slog.Error("infrastructure as code scanning failed", "stderr", stderr.String())
		return nil, fmt.Errorf("iac scan failed: %s", stderr.String())
	}

	// read the file in <dir>/results_sarif.sarif
	b, err := os.ReadFile(path.Join(dir, "results_sarif.sarif"))

	if err != nil {
		return nil, errors.Wrap(err, "could not read file")
	}

	// parse the file
	var sarifScan common.SarifResult
	err = json.Unmarshal(b, &sarifScan)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse sarif file")
	}

	// remove the file
	err = os.Remove(path.Join(dir, "results_sarif.sarif"))
	if err != nil {
		return nil, errors.Wrap(err, "could not remove file")
	}

	return &sarifScan, nil
}

func NewIaCCommand() *cobra.Command {
	iacCommand := &cobra.Command{
		Use:   "iac",
		Short: "Launch an infrastructure as code scan",
		Long:  `Launch an infrastructure as code scan. A IaC scan runs predefined rules against your source code`,

		RunE: func(cmd *cobra.Command, args []string) error {
			return sarifCommandFactory("iac")(cmd, args)
		},
	}

	addScanFlags(iacCommand)
	return iacCommand
}
