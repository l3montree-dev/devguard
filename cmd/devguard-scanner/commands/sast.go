package commands

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func sastScan(path string) (*common.SarifResult, error) {
	file, err := os.CreateTemp("", "*.sarif")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temp file")
	}

	var scannerCmd *exec.Cmd

	slog.Info("Starting sast scanning", "path", path)

	scannerCmd = exec.Command("semgrep", "scan", path, "--sarif", "--sarif-output", file.Name(), "-v") // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack

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
	file, err = os.Open(file.Name())
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
		Use:   "sast",
		Short: "Launch a static application security test.",
		Long:  "Launch a static application security test. A SAST test runs predefined rules against your source code",

		RunE: sarifCommandFactory("sast"),
	}

	addScanFlags(sastCommand)
	return sastCommand
}
