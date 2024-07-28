package vulndb

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
)

const (
	webwmlSecurityPath       = "english/security"
	webwmlLtsSecurityPath    = "english/lts/security"
	securityTrackerDsaPath   = "data/DSA/list"
	securityTrackerDtsaPath  = "data/DTSA/list"
	securityTrackerDlaPath   = "data/DLA/list"
	debianBaseURL            = "https://www.debian.org"
	notAffectedVersion       = "<not-affected>"
	unfixedVersion           = "<unfixed>"
	endOfLifeVersion         = "<end-of-life>"
	gitDatePrefix            = "-----"
	csvURL                   = "https://debian.pages.debian.net/distro-info-data/debian.csv"
	wmlDescriptionPatternStr = `<define-tag moreinfo>((?:.|\n)*)</define-tag>`
	wmlReportDatePatternStr  = `<define-tag report_date>(.*)</define-tag>`
	webwmlRepoUrl            = "https://salsa.debian.org/webmaster-team/webwml/-/archive/master/webwml-master.zip"
	securityTrackerRepoUrl   = "https://salsa.debian.org/security-tracker-team/security-tracker/-/archive/master/security-tracker-master.zip"
)

var dateFormats = map[string]string{
	"DSA":  "02 Jan 2006",
	"DLA":  "02 Jan 2006",
	"DTSA": "January 2 2006",
}

var (
	leadingWhitespace     = regexp.MustCompile(`^\s`)
	dsaPattern            = regexp.MustCompile(`\[(.*?)]\s*([\w-]+)\s*(.*)`)
	versionPattern        = regexp.MustCompile(`\[(.*?)]\s*-\s*([^\s]+)\s*([^\s]+)`)
	wmlDescriptionPattern = regexp.MustCompile(wmlDescriptionPatternStr)
	wmlReportDatePattern  = regexp.MustCompile(wmlReportDatePatternStr)
	dsaOrDlaWithNoExt     = regexp.MustCompile(`d[sl]a-\d+`)
	advisoryTypes         = map[string]string{"DSA": "DSA", "DLA": "DLA", "DTSA": "DTSA"}
	advisories            Advisories
)

type DSAService struct {
	httpClient    *http.Client
	cveRepository cveRepository
}

func NewDSAService(cveRepository cveRepository) *DSAService {
	return &DSAService{httpClient: &http.Client{}, cveRepository: cveRepository}
}

func (dsaService DSAService) Mirror() error {
	// create a temporary directory
	// tempDir, err := os.MkdirTemp("", "debian")
	var tempDir string = "./"
	var err error
	if err != nil {
		slog.Error("could not create temporary directory", "err", err)
		return err
	}

	webwmlRepo := filepath.Join(tempDir, "webwml-master")
	securityTrackerRepo := filepath.Join(tempDir, "security-tracker-master")

	// remove the dirs
	// defer os.RemoveAll(tempDir)

	// download both repos
	/*if err := downloadRepository(webwmlRepoUrl, tempDir); err != nil {
		slog.Error("could not download webwml repository", "err", err)
		return err
	}

	if err := downloadRepository(securityTrackerRepoUrl, tempDir); err != nil {
		slog.Error("could not download security tracker repository", "err", err)
		return err
	}*/

	for advType := range advisoryTypes {
		advisories, err := convertDebian(webwmlRepo, securityTrackerRepo, advType)
		if err != nil {
			slog.Error("could not convert debian advisories", "err", err)
			return err
		}

		matches := make([]models.CPEMatch, 0)
		cve2cpe := make(map[string][]string)

		for _, advisory := range advisories {
			for _, affected := range advisory.Affected {
				match := affected.ConvertToCpeMatch()
				matches = append(matches, match)
				// check for related cves
				for _, cve := range advisory.Related {
					if strings.HasPrefix(cve, "CVE-") {
						if _, ok := cve2cpe[cve]; !ok {
							cve2cpe[cve] = make([]string, 0)
						}
						cve2cpe[cve] = append(cve2cpe[cve], match.CalculateHash())
					}
				}
			}
		}

		matches = utils.UniqBy(matches, func(el models.CPEMatch) string {
			return el.CalculateHash()
		})
		// save the matches
		if err := dsaService.cveRepository.SaveBatchCPEMatch(nil, matches); err != nil {
			slog.Error("could not save cpe matches", "err", err)
			return err
		}

		for cveId, matches := range cve2cpe {
			if err := dsaService.cveRepository.GetDB(nil).Model(&models.CVE{
				CVE: cveId,
				// unique the cpeIds
			}).Association("Configurations").Append(utils.Map(matches, func(el string) models.CPEMatch {
				return models.CPEMatch{
					MatchCriteriaID: el,
				}
			})); err != nil {
				slog.Error("could not save cpe matches", "err", err)
				continue
			}
		}
	}
	return nil
}

func removeOrdinalSuffix(dateStr string) string {
	// Replace common ordinal suffixes with empty strings
	for _, suffix := range []string{"st", "nd", "rd", "th"} {
		// We need to remove the suffix only from the day part of the date
		// Thus we split the date by space and handle the second part only
		parts := strings.Split(dateStr, " ")
		if len(parts) > 1 {
			parts[1] = strings.TrimSuffix(parts[1], suffix+",")
		}
		dateStr = strings.Join(parts, " ")
	}
	return dateStr
}

type AdvisoryType string

type AffectedInfo struct {
	Package              string `json:"package"`
	Fixed                string `json:"fixed"`
	DebianReleaseVersion string `json:"debian_release_version"`
}

func (a *AffectedInfo) ConvertToCpeMatch() models.CPEMatch {
	cpe := "cpe:2.3:a:" + a.Package + ":" + a.Package + ":*:*:*:*:*:*:*:*"
	return models.CPEMatch{
		Criteria:            cpe,
		Part:                "a",
		Vendor:              a.Package,
		Product:             a.Package,
		Version:             "*",
		VersionEndExcluding: &a.Fixed,
		Vulnerable:          true,
		Update:              "*",
		Edition:             "*",
		Language:            "*",
		SwEdition:           "*",
		TargetSw:            "*",
		TargetHw:            "*",
		Other:               "*",
	}
}

type AdvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type AdvisoryInfo struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Published  string         `json:"published"`
	Modified   string         `json:"modified"`
	Affected   []AffectedInfo `json:"affected"`
	Aliases    []string       `json:"aliases"`
	Related    []string       `json:"related"`
	References []AdvReference `json:"references"`
}

type Advisories map[string]*AdvisoryInfo

func createCodenameToVersion() (map[string]string, error) {
	resp, err := http.Get(csvURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	reader.FieldsPerRecord = -1 // Allow variable number of fields
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for _, record := range records[1:] {
		result[record[0]] = record[1]
	}
	result["sid"] = "unstable"
	return result, nil
}

func parseSecurityTrackerFile(advType string, advisories Advisories, securityTrackerRepo, securityTrackerPath string) error {
	codenameToVersion, err := createCodenameToVersion()
	if err != nil {
		return err
	}

	file, err := os.Open(filepath.Join(securityTrackerRepo, securityTrackerPath))
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentAdvisory string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		if leadingWhitespace.MatchString(line) {
			if currentAdvisory == "" {
				return errors.New("unexpected tab")
			}

			line = strings.TrimLeft(line, " \t")
			if strings.HasPrefix(line, "{") {
				advisories[currentAdvisory].Related = strings.Fields(line[1 : len(line)-1])
				continue
			}

			if strings.HasPrefix(line, "NOTE:") {
				continue
			}

			versionMatch := versionPattern.FindStringSubmatch(line)
			if versionMatch == nil {
				return fmt.Errorf("invalid version line: %s", line)
			}

			releaseName := versionMatch[1]
			packageName := versionMatch[2]
			fixedVer := versionMatch[3]

			if fixedVer != notAffectedVersion {
				if fixedVer == unfixedVersion || fixedVer == endOfLifeVersion {
					fixedVer = ""
				}

				advisories[currentAdvisory].Affected = append(advisories[currentAdvisory].Affected, AffectedInfo{
					Package:              packageName,
					Fixed:                fixedVer,
					DebianReleaseVersion: codenameToVersion[releaseName],
				})
			}
		} else {
			if strings.HasPrefix(line, "NOTE:") {
				continue
			}

			dsaMatch := dsaPattern.FindStringSubmatch(line)
			if dsaMatch == nil {
				return fmt.Errorf("invalid line: %s", line)
			}

			parsedDate, err := time.Parse(dateFormats[advType], removeOrdinalSuffix(dsaMatch[1]))
			if err != nil {
				return err
			}

			currentAdvisory = dsaMatch[2]
			advisories[currentAdvisory] = &AdvisoryInfo{
				ID:         currentAdvisory,
				Summary:    dsaMatch[3],
				Published:  parsedDate.Format(time.RFC3339),
				Modified:   parsedDate.Format(time.RFC3339),
				Affected:   []AffectedInfo{},
				Aliases:    []string{},
				Related:    []string{},
				Details:    "",
				References: []AdvReference{},
			}
		}
	}

	return scanner.Err()
}

func parseWebwmlFiles(advisories Advisories, webwmlRepoPath, wmlFileSubPath string) error {
	filePathMap := make(map[string]string)
	err := filepath.Walk(filepath.Join(webwmlRepoPath, wmlFileSubPath), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			filePathMap[info.Name()] = path
		}
		return nil
	})
	if err != nil {
		return err
	}

	for dsaID, advisory := range advisories {
		mappedKeyNoExt := dsaOrDlaWithNoExt.FindString(dsaID)
		wmlPath := filePathMap[mappedKeyNoExt+".wml"]
		dataPath := filePathMap[mappedKeyNoExt+".data"]

		if wmlPath == "" {
			continue
		}

		wmlData, err := os.ReadFile(wmlPath)
		if err != nil {
			return err
		}
		html := wmlDescriptionPattern.FindStringSubmatch(string(wmlData))
		if len(html) > 0 {
			advisory.Details = html[1]
		}

		dataContent, err := os.ReadFile(dataPath)
		if err != nil {
			return err
		}
		reportDate := wmlReportDatePattern.FindStringSubmatch(string(dataContent))
		if len(reportDate) > 0 {
			advisory.Published = reportDate[1] + "T00:00:00Z"
		}

		advisoryURLPath := strings.TrimSuffix(strings.TrimPrefix(wmlPath, filepath.Join(webwmlRepoPath, "english")), ".wml")
		advisoryURL := fmt.Sprintf("%s/%s", debianBaseURL, advisoryURLPath)
		advisory.References = append(advisory.References, AdvReference{
			Type: "ADVISORY",
			URL:  advisoryURL,
		})
	}

	return nil
}

func convertDebian(webwmlRepo, securityTrackerRepo, advType string) (Advisories, error) {
	advisories = make(Advisories)

	switch advType {
	case "DLA":
		if err := parseSecurityTrackerFile("DLA", advisories, securityTrackerRepo, securityTrackerDlaPath); err != nil {
			return advisories, err
		}
		if err := parseWebwmlFiles(advisories, webwmlRepo, webwmlLtsSecurityPath); err != nil {
			return advisories, err
		}
	case "DSA":
		if err := parseSecurityTrackerFile("DSA", advisories, securityTrackerRepo, securityTrackerDsaPath); err != nil {
			return advisories, err
		}
		if err := parseWebwmlFiles(advisories, webwmlRepo, webwmlSecurityPath); err != nil {
			return advisories, err
		}
	case "DTSA":
		if err := parseSecurityTrackerFile("DTSA", advisories, securityTrackerRepo, securityTrackerDtsaPath); err != nil {
			return advisories, err
		}
	default:
		return advisories, errors.New("invalid advisory type")
	}

	return advisories, nil
}

func downloadRepository(repoURL, outputDir string) error {
	// The url is not user input and is hardcoded
	resp, err := http.Get(repoURL) // nolint:gosec
	if err != nil {
		return errors.Wrap(err, "could not get repository")
	}
	defer resp.Body.Close()
	// its a zip file
	zipFile := filepath.Join(outputDir, "repo.zip")
	file, err := os.Create(zipFile)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.Copy(file, resp.Body); err != nil {
		return errors.Wrap(err, "could not copy file")
	}

	// unzip
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		return errors.Wrap(err, "could not create output directory")
	}

	if err := utils.Unzip(zipFile, outputDir); err != nil {
		return errors.Wrap(err, "could not unzip")
	}

	return nil
}
