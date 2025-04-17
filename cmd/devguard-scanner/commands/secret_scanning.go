package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/dependency_vuln"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func NewSecretScanningCommand() *cobra.Command {
	secretScanningCommand := &cobra.Command{
		Use:   "secret-scanning",
		Short: "Scan your application to see if any secrets have been unintentionally leaked into the source code",
		Long:  "Scan your application to see if any secrets have been unintentionally leaked into the source code",

		Run: func(cmd *cobra.Command, args []string) {
			err := sarifCommandFactory("secret-scanning")(cmd, args)
			if err != nil {
				slog.Error("secret scanning failed", "err", err)
				panic(err.Error())
			}
		},
	}

	addScanFlags(secretScanningCommand)
	return secretScanningCommand
}

func sarifCommandFactory(scannerID string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		core.InitLogger()
		token, assetName, apiUrl, _, webUI := parseConfig(cmd)
		if token == "" {
			slog.Error("token seems to be empty. If you provide the token via an environment variable like --token=$DEVGUARD_TOKEN, check, if the environment variable is set or if there are any spelling mistakes", "token", token)
			return fmt.Errorf("token seems to be empty")
		}

		core.LoadConfig() // nolint:errcheck // just swallow the error: https://github.com/l3montree-dev/devguard/issues/188

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		path, err := cmd.Flags().GetString("path")
		if err != nil {
			return errors.Wrap(err, "could not get path")
		}

		if isValid, err := isValidPath(path); !isValid && err != nil {
			return errors.Wrap(err, "invalid path")
		}

		sarifResult, err := executeCodeScan(scannerID, path)
		if err != nil {
			return errors.Wrap(err, "could not open file")
		}

		// expand snippet and obfuscate it
		expandAndObfuscateSnippet(*sarifResult, path)

		// marshal the result
		b, err := json.Marshal(sarifResult)
		// check if we should do risk management
		doRiskManagement, err := cmd.Flags().GetBool("riskManagement")
		if err != nil {
			return errors.Wrap(err, "could not get risk management flag")
		}

		req, err := http.NewRequestWithContext(ctx, "POST", apiUrl+"/api/v1/sarif-scan/", bytes.NewReader(b))
		if err != nil {
			return errors.Wrap(err, "could not create request")
		}

		err = pat.SignRequest(token, req)
		if err != nil {
			return errors.Wrap(err, "could not sign request")
		}

		err = utils.SetGitVersionHeader(path, req)

		if err != nil {
			printGitHelp(err)
			return errors.Wrap(err, "could not get version info")
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Risk-Management", strconv.FormatBool(doRiskManagement))
		req.Header.Set("X-Asset-Name", assetName)
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

		printFirstPartyScanResults(scanResponse, assetName, webUI, scannerID)
		return nil
	}
}

func executeCodeScan(scannerID, path string) (*common.SarifResult, error) {
	switch scannerID {
	case "secret-scanning":
		return secretScan(path)
	case "sast":
		return sastScan(path)
	default:
		return nil, fmt.Errorf("unknown scanner: %s", scannerID)
	}

}

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
	sarifScan = obfuscateSecret(sarifScan)

	return &sarifScan, nil
}

func expandAndObfuscateSnippet(sarifScan common.SarifResult, path string) {

	// expand the snippet
	for ru, run := range sarifScan.Runs {
		for re, result := range run.Results {
			for lo, location := range result.Locations {
				startLine := location.PhysicalLocation.Region.StartLine
				endLine := location.PhysicalLocation.Region.EndLine
				original := location.PhysicalLocation.Region.Snippet.Text

				// read the file from git
				fileContent, err := utils.ReadFileFromGitRef(path, sarifScan.Runs[ru].Results[re].PartialFingerprints.CommitSha, location.PhysicalLocation.ArtifactLocation.Uri)
				if err != nil {
					slog.Error("could not read file", "err", err)
					continue
				}
				// expand the snippet
				expandedSnippet, err := expandSnippet(fileContent, startLine, endLine, original)
				if err != nil {
					slog.Error("could not expand snippet", "err", err)
					continue
				}

				// obfuscate the snippet
				obfuscateSnippet := obfuscateString(expandedSnippet)

				// set the snippet
				sarifScan.Runs[ru].Results[re].Locations[lo].PhysicalLocation.Region.Snippet.Text = obfuscateSnippet

			}
		}
	}

}

func expandSnippet(fileContent []byte, startLine, endLine int, original string) (string, error) {

	startLine--
	endLine--

	lines := strings.Split(string(fileContent), "\n")

	if startLine < 0 || endLine > len(lines) {
		slog.Error("start line or end line is out of range", "startLine", startLine, "endLine", endLine, "lines", len(lines))
		return "", fmt.Errorf("start line or end line is out of range")
	}

	//original is the string with the secret, but without the beginning of the line, so we reconstruct it
	// slice the original string where *** are
	secretStringBegin := strings.Split(original, "***")

	//find the first occurrence of the secret in the line
	StartColumn := strings.Index(lines[startLine], secretStringBegin[0])

	secretLineBegin := lines[startLine][:StartColumn]

	expandedSnippet := ""

	startLineN := int(math.Max(0, float64(startLine)-5))
	endLineN := int(math.Min(float64(len(lines)), float64(endLine)+6))

	// replace start and endline to make sure any previous tranformations will be applied#
	start := lines[startLineN:startLine]
	end := lines[endLine+1 : endLineN]

	startStr := ""
	endStr := ""
	if len(start) > 0 {
		startStr = strings.Join(start, "\n")
		expandedSnippet = startStr + "\n"
	}

	expandedSnippet += "+++\n" + secretLineBegin + original + "\n+++"

	if len(end) > 0 {
		endStr = strings.Join(end, "\n")
		expandedSnippet += "\n" + endStr
	}

	return expandedSnippet, nil
}

func obfuscateString(str string) string {

	// create regex to split string at whitespace and new line chars
	reg := regexp.MustCompile(`[\n]+`)
	// split the string into words
	els := reg.Split(str, -1)

	for i, el := range els {
		// 5 is a magic number!
		entropy := utils.ShannonEntropy(el)
		if entropy > 3.5 {
			els[i] = el[:1+len(el)/2] + strings.Repeat("*", len(el)/2)
		}
	}

	return strings.Join(els, "\n")
}

// add obfuscation function for snippet
func obfuscateSecret(sarifScan common.SarifResult) common.SarifResult {
	// obfuscate the snippet
	for ru, run := range sarifScan.Runs {
		for re, result := range run.Results {
			for lo, location := range result.Locations {
				snippet := location.PhysicalLocation.Region.Snippet.Text
				snippetMax := 20
				if len(snippet) < snippetMax {
					snippetMax = len(snippet) / 2
				}
				snippet = snippet[:snippetMax] + strings.Repeat("*", len(snippet)-snippetMax)
				// set the snippet
				sarifScan.Runs[ru].Results[re].Locations[lo].PhysicalLocation.Region.Snippet.Text = snippet
			}
		}
	}

	return sarifScan

}

func printFirstPartyScanResults(scanResponse scan.FirstPartyScanResponse, assetName string, webUI string, scannerID string) {
	slog.Info("First party scan results", "firstPartyVulnAmount", len(scanResponse.FirstPartyVulns), "openedByThisScan", scanResponse.AmountOpened, "closedByThisScan", scanResponse.AmountClosed)

	if len(scanResponse.FirstPartyVulns) == 0 {
		return
	}

	// get all "open" vulns
	openVulns := utils.Filter(scanResponse.FirstPartyVulns, func(v dependency_vuln.FirstPartyVulnDTO) bool {
		return v.State == models.VulnStateOpen
	})

	switch scannerID {
	case "secret-scanning":
		printSecretScanResults(openVulns, webUI, assetName)
	case "sast":
		printSastScanResults(openVulns, webUI, assetName)
	default:
		slog.Warn("unknown scanner", "scanner", scannerID)
	}

	if len(openVulns) > 0 {
		os.Exit(1)
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
