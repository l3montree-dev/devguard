package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func printSastScanResults(firstPartyVulns []vuln.FirstPartyVulnDTO, webUI, assetName string, assetVersionName string) {
	tw := table.NewWriter()
	tw.SetAllowedRowLength(130)

	blue := text.FgBlue
	green := text.FgGreen
	for _, vuln := range firstPartyVulns {
		tw.AppendRow(table.Row{"RuleID", vuln.RuleID})
		for _, snippet := range vuln.SnippetContents {
			tw.AppendRow(table.Row{"Snippet", snippet.Snippet})
		}
		tw.AppendRow(table.Row{"Message", text.WrapText(*vuln.Message, 80)})
		if vuln.URI != "" {
			tw.AppendRow(table.Row{"File", green.Sprint(vuln.URI)})

		}
		tw.AppendSeparator()
	}
	tw.AppendRow(table.Row{"Link", blue.Sprint(fmt.Sprintf("%s/%s/refs/%s/code-risks/", webUI, assetName, assetVersionName))})
	fmt.Println(tw.Render())
}

func sastScan(p string) (*common.SarifResult, error) {
	dir := os.TempDir()
	dir = path.Join(dir, "sast")

	// create new directory
	err := os.MkdirAll(dir, 0755)

	if err != nil {
		return nil, errors.Wrap(err, "could not create temp file")
	}

	var scannerCmd *exec.Cmd

	slog.Info("Starting sast scanning", "path", p, "result-path", path.Join(dir, "result.sarif"))

	scannerCmd = exec.Command("semgrep", "scan", p, "--sarif", "--sarif-output", path.Join(dir, "result.sarif"), "-v") // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack

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
	file, err := os.Open(path.Join(dir, "result.sarif"))
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
