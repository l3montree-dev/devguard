package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"
	"strconv"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
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

func secretScan(p string) (*common.SarifResult, error) {
	dir := os.TempDir()
	dir = path.Join(dir, "secret-scanning")

	// create new directory
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return nil, errors.Wrap(err, "could not create temp file")
	}

	var scannerCmd *exec.Cmd

	slog.Info("Starting secret scanning", "path", p, "result-path", path.Join(dir, "result.sarif"))

	scannerCmd = exec.Command("gitleaks", "git", "-v", p, "--report-path", path.Join(dir, "result.sarif"), "--report-format", "sarif") // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself.

	stderr := &bytes.Buffer{}
	scannerCmd.Stderr = stderr

	err = scannerCmd.Run()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() == 1 {
			slog.Warn("Leaks found, but continuing execution.", "stderr", stderr.String())
		} else {
			return nil, errors.Wrapf(err, "could not run scanner: %s", stderr.String())
		}
	}

	// read AND parse the file
	var sarifScan common.SarifResult
	// open the file
	file, err := os.Open(path.Join(dir, "result.sarif"))
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

func printSecretScanResults(firstPartyVulns []vuln.FirstPartyVulnDTO, webUI string, assetName string, assetVersionName string) {
	tw := table.NewWriter()
	tw.SetAllowedRowLength(130)

	blue := text.FgBlue
	green := text.FgGreen
	for _, vuln := range firstPartyVulns {
		raw := []table.Row{
			{"RuleID:", vuln.RuleID},
			{"File:", green.Sprint(vuln.Uri + ":" + strconv.Itoa(vuln.StartLine))},
			{"Snippet:", text.WrapText(vuln.Snippet, 80)},
			{"Message:", text.WrapText(*vuln.Message, 80)},
			{"Line:", vuln.StartLine},
			{"Commit:", vuln.Commit},
			{"Author:", vuln.Author},
			{"Email:", vuln.Email},
			{"Date:", vuln.Date},
			{"Link:", blue.Sprint(fmt.Sprintf("%s/%s/refs/%s/code-risks/%s", webUI, assetName, assetVersionName, vuln.ID))},
		}

		tw.AppendRows(raw)
		tw.AppendSeparator()
	}

	fmt.Println(tw.Render())
}
