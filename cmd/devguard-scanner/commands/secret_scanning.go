package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core/dependency_vuln"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewSecretScanningCommand() *cobra.Command {
	secretScanningCommand := &cobra.Command{
		Use:   "secret-scanning",
		Short: "Scan your application to see if any secrets have been unintentionally leaked into the source code",
		Long:  "Scan your application to see if any secrets have been unintentionally leaked into the source code",
		RunE:  sarifCommandFactory("secret-scanning"),
	}

	addScanFlags(secretScanningCommand)
	return secretScanningCommand
}

func secretScan(path string) (*common.SarifResult, error) {
	file, err := os.CreateTemp("", "*.sarif")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temp file")
	}

	var scannerCmd *exec.Cmd

	slog.Info("Starting secret scanning", "path", path)

	scannerCmd = exec.Command("gitleaks", "git", "-v", path, "--report-path", file.Name(), "--report-format", "sarif") // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself.

	stderr := &bytes.Buffer{}
	scannerCmd.Stderr = stderr

	err = scannerCmd.Run()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() == 1 {
			slog.Warn("Leaks found, but continuing execution.")
		} else {
			return nil, errors.Wrapf(err, "could not run scanner: %s", stderr.String())
		}
	}

	// read AND parse the file
	var sarifScan common.SarifResult
	// open the file
	file, err = os.Open(file.Name())
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
	obfuscateSecret(&sarifScan)

	return &sarifScan, nil
}

func printSecretScanResults(firstPartyVulns []dependency_vuln.FirstPartyVulnDTO, webUI string, assetName string) {
	tw := table.NewWriter()
	tw.SetAllowedRowLength(180)

	blue := text.FgBlue
	green := text.FgGreen
	for _, vuln := range firstPartyVulns {
		raw := []table.Row{
			{"RuleID:", vuln.RuleID},
			{"File:", green.Sprint(vuln.Uri + ":" + strconv.Itoa(vuln.StartLine))},
			{"Snippet:", text.WrapText(vuln.Snippet, 170)},
			{"Message:", text.WrapText(*vuln.Message, 170)},
			{"Line:", vuln.StartLine},
			{"Commit:", vuln.Commit},
			{"Author:", vuln.Author},
			{"Email:", vuln.Email},
			{"Date:", vuln.Date},
			{"Link:", blue.Sprint(fmt.Sprintf("%s/%s/first-party-vulns/%s", webUI, assetName, vuln.ID))},
		}

		tw.AppendRows(raw)
		tw.AppendSeparator()
	}

	fmt.Println(tw.Render())
}
