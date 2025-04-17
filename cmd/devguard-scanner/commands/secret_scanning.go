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

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/internal/core/dependency_vuln"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/utils"
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

func sarifCommandFactory(scannerID string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		file, err := executeCodeScan(scannerID, config.RuntimeBaseConfig.Path)
		if err != nil {
			return errors.Wrap(err, "could not open file")
		}

		fileContent, err := os.ReadFile(file.Name())
		if err != nil {
			return errors.Wrap(err, "could not read file")
		}

		fileReader := bytes.NewReader(fileContent)
		defer os.Remove(file.Name())

		req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/sarif-scan/", config.RuntimeBaseConfig.ApiUrl), fileReader)
		if err != nil {
			return errors.Wrap(err, "could not create request")
		}

		err = pat.SignRequest(config.RuntimeBaseConfig.Token, req)
		if err != nil {
			return errors.Wrap(err, "could not sign request")
		}

		err = utils.SetGitVersionHeader(config.RuntimeBaseConfig.Path, req)

		if err != nil {
			printGitHelp(err)
			return errors.Wrap(err, "could not get version info")
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Asset-Name", config.RuntimeBaseConfig.AssetName)
		req.Header.Set("X-Scanner", "github.com/l3montree-dev/devguard/cmd/devguard-scanner/"+scannerID)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return errors.Wrap(err, "could not send request")
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("could not scan file: %s", resp.Status)
		}

		// read and parse the body - it should be an array of dependencyVulns
		// print the dependencyVulns to the console
		var scanResponse scan.FirstPartyScanResponse

		err = json.NewDecoder(resp.Body).Decode(&scanResponse)
		if err != nil {
			return errors.Wrap(err, "could not parse response")
		}

		printFirstPartyScanResults(scanResponse, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.AssetName, scannerID)
		return nil
	}
}

func executeCodeScan(scannerID, path string) (*os.File, error) {
	switch scannerID {
	case "secret-scanning":
		return secretScan(path)
	case "sast":
		return sastScan(path)
	default:
		return nil, fmt.Errorf("unknown scanner: %s", scannerID)
	}

}

func sastScan(path string) (*os.File, error) {
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

	return file, nil
}

func secretScan(path string) (*os.File, error) {
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

	return file, nil
}

func printFirstPartyScanResults(scanResponse scan.FirstPartyScanResponse, assetName string, webUI string, scannerID string) {
	slog.Info("First party scan results", "firstPartyVulnAmount", len(scanResponse.FirstPartyVulns), "openedByThisScan", scanResponse.AmountOpened, "closedByThisScan", scanResponse.AmountClosed)

	if len(scanResponse.FirstPartyVulns) == 0 {
		return
	}

	switch scannerID {
	case "secret-scanning":
		printSecretScanResults(scanResponse.FirstPartyVulns, webUI, assetName)
		return
	case "sast":
		printSastScanResults(scanResponse.FirstPartyVulns, webUI, assetName)
		return
	default:
		slog.Warn("unknown scanner", "scanner", scannerID)
		return
	}

}

func printSastScanResults(firstPartyVulns []dependency_vuln.FirstPartyVulnDTO, webUI, assetName string) {
	tw := table.NewWriter()
	tw.SetAllowedRowLength(180)
	red := text.FgRed
	blue := text.FgBlue
	green := text.FgGreen
	for _, vuln := range firstPartyVulns {
		tw.AppendRow(table.Row{"RuleID", vuln.RuleID})
		tw.AppendRow(table.Row{"File", green.Sprint(vuln.Uri + ":" + strconv.Itoa(vuln.StartLine))})
		tw.AppendRow(table.Row{"Snippet", red.Sprint(vuln.Snippet)})
		tw.AppendRow(table.Row{"Message", text.WrapText(*vuln.Message, 170)})
		tw.AppendRow(table.Row{"Line", vuln.StartLine})
		tw.AppendRow(table.Row{"Link", blue.Sprint(fmt.Sprintf("%s/%s/first-party-vulns/%s", webUI, assetName, vuln.ID))})
		tw.AppendSeparator()
	}

	fmt.Println(tw.Render())
}

func printSecretScanResults(firstPartyVulns []dependency_vuln.FirstPartyVulnDTO, webUI string, assetName string) {
	tw := table.NewWriter()
	tw.SetAllowedRowLength(180)
	red := text.FgRed
	blue := text.FgBlue
	green := text.FgGreen
	for _, vuln := range firstPartyVulns {
		raw := []table.Row{
			{"RuleID:", vuln.RuleID},
			{"File:", green.Sprint(vuln.Uri + ":" + strconv.Itoa(vuln.StartLine))},
			{"Snippet:", red.Sprint(vuln.Snippet)},
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
