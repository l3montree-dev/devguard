package vulndb

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type cvelistJson struct {
	DataType    string `json:"dataType"`
	CveMetadata struct {
		CveID             string `json:"cveId"`
		AssignerOrgID     string `json:"assignerOrgId"`
		State             string `json:"state"`
		AssignerShortName string `json:"assignerShortName"`
		DateReserved      string `json:"dateReserved"`
		DatePublished     string `json:"datePublished"`
		DateUpdated       string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		Cna struct {
			Title        string `json:"title"`
			ProblemTypes []struct {
				Descriptions []struct {
					CweID       string `json:"cweId"`
					Lang        string `json:"lang"`
					Description string `json:"description"`
					Type        string `json:"type"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
			Metrics []struct {
				CvssV31 struct {
					AttackComplexity      string  `json:"attackComplexity"`
					AttackVector          string  `json:"attackVector"`
					AvailabilityImpact    string  `json:"availabilityImpact"`
					BaseScore             float64 `json:"baseScore"`
					BaseSeverity          string  `json:"baseSeverity"`
					ConfidentialityImpact string  `json:"confidentialityImpact"`
					IntegrityImpact       string  `json:"integrityImpact"`
					PrivilegesRequired    string  `json:"privilegesRequired"`
					Scope                 string  `json:"scope"`
					UserInteraction       string  `json:"userInteraction"`
					VectorString          string  `json:"vectorString"`
					Version               string  `json:"version"`
				} `json:"cvssV3_1"`
			} `json:"metrics"`
			References []struct {
				Name string   `json:"name,omitempty"`
				Tags []string `json:"tags,omitempty"`
				URL  string   `json:"url"`
			} `json:"references"`
			Affected []struct {
				Vendor      string `json:"vendor"`
				Product     string `json:"product"`
				PackageName string `json:"packageName"`
				Versions    []struct {
					Version  string  `json:"version"`
					Status   string  `json:"status"`
					LessThan *string `json:"lessThan"`
				} `json:"versions"`
			} `json:"affected"`
			ProviderMetadata struct {
				OrgID       string `json:"orgId"`
				ShortName   string `json:"shortName"`
				DateUpdated string `json:"dateUpdated"`
			} `json:"providerMetadata"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Source struct {
				Advisory  string `json:"advisory"`
				Discovery string `json:"discovery"`
			} `json:"source"`
		} `json:"cna"`
		Adp []struct {
			Affected []struct {
				Vendor        string   `json:"vendor"`
				Product       string   `json:"product"`
				Cpes          []string `json:"cpes"`
				DefaultStatus string   `json:"defaultStatus"`
				Versions      []struct {
					Version     string `json:"version"`
					Status      string `json:"status"`
					LessThan    string `json:"lessThan"`
					VersionType string `json:"versionType"`
				} `json:"versions"`
			} `json:"affected"`
			Metrics []struct {
				Other struct {
					Type    string `json:"type"`
					Content struct {
						Timestamp string `json:"timestamp"`
						ID        string `json:"id"`
						Options   []struct {
							Exploitation    string `json:"Exploitation,omitempty"`
							Automatable     string `json:"Automatable,omitempty"`
							TechnicalImpact string `json:"Technical Impact,omitempty"`
						} `json:"options"`
						Role    string `json:"role"`
						Version string `json:"version"`
					} `json:"content"`
				} `json:"other"`
			} `json:"metrics"`
			Title            string `json:"title"`
			ProviderMetadata struct {
				OrgID       string `json:"orgId"`
				ShortName   string `json:"shortName"`
				DateUpdated string `json:"dateUpdated"`
			} `json:"providerMetadata"`
		} `json:"adp"`
	} `json:"containers"`
	DataVersion string `json:"dataVersion"`
}

type cvelistService struct {
	httpClient    *http.Client
	cveRepository core.CveRepository
}

func NewCVEListService(cveRepository core.CveRepository) cvelistService {
	return cvelistService{
		httpClient:    &http.Client{},
		cveRepository: cveRepository,
	}
}

var cveBaseURL string = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"

func (s *cvelistService) downloadZip() (*zip.Reader, error) {
	/*// open zip file
	rc, err := zip.OpenReader("cvelistV5-main.zip")
	if err != nil {
		return nil, errors.Wrap(err, "could not open zip file")
	}
	*/
	req, err := http.NewRequest(http.MethodGet, cveBaseURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not download zip")
	}

	return utils.ZipReaderFromResponse(res)
}

func (s *cvelistService) ImportCVE(cveId string) ([]models.CPEMatch, error) {
	resp, err := s.httpClient.Get(fmt.Sprintf("https://cveawg.mitre.org/api/cve/%s", cveId))

	if err != nil {
		return nil, errors.Wrap(err, "could not get cve")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("cve not found")
	}
	defer resp.Body.Close()

	var cvelist cvelistJson
	if err := json.NewDecoder(resp.Body).Decode(&cvelist); err != nil {
		return nil, errors.Wrap(err, "could not decode json")
	}

	matches := generateCPE(cvelist)

	if err := s.cveRepository.SaveBatchCPEMatch(nil, matches); err != nil {
		return nil, errors.Wrap(err, "could not save cpe matches")
	}

	if err := s.cveRepository.GetDB(nil).Model(&models.CVE{
		CVE: cveId,
		// unique the cpeIds
	}).Association("Configurations").Append(utils.Map(matches, func(el models.CPEMatch) models.CPEMatch {
		return models.CPEMatch{
			MatchCriteriaID: el.CalculateHash(),
		}
	})); err != nil {
		return nil, errors.Wrap(err, "could not save cve to cpe mapping")
	}

	return matches, nil
}

func (s *cvelistService) Mirror() error {
	zipReader, err := s.downloadZip()

	if err != nil {
		slog.Error("could not download zip", "err", err)
		return errors.Wrap(err, "could not download zip")
	}

	if len(zipReader.File) == 0 {
		slog.Error("zip file is empty")
		return errors.New("zip file is empty")
	}

	group := errgroup.Group{}
	group.SetLimit(10)

	batchSize := 1000
	start := time.Now()

	for i := 0; i < len(zipReader.File); i += batchSize {
		slog.Info("Processing batch", "start", i, "end", i+batchSize, "total", len(zipReader.File), "duration", time.Since(start))
		end := i + batchSize
		if end > len(zipReader.File) {
			end = len(zipReader.File)
		}

		batch := zipReader.File[i:end]
		group.Go(func() error {
			cve2cpeId := make(map[string][]string)
			cpeMatch := make([]models.CPEMatch, 0)

			for _, file := range batch {
				//  check if file start with "CVE-" and ends with ".json"
				if !isCVEFile(file.Name) {
					continue
				}

				unzippedFileBytes, err := utils.ReadZipFile(file)
				if err != nil {
					slog.Error("could not read zip file", "err", err)
					continue
				}

				var cvelistJson cvelistJson
				if err := json.Unmarshal(unzippedFileBytes, &cvelistJson); err != nil {
					slog.Error("could not unmarshal json", "err", err)
					continue
				}

				matches := generateCPE(cvelistJson)
				cpeMatch = append(cpeMatch, matches...)
				for _, match := range matches {
					if _, ok := cve2cpeId[cvelistJson.CveMetadata.CveID]; !ok {
						cve2cpeId[cvelistJson.CveMetadata.CveID] = make([]string, 0)
					}
					// check if id is already in the list
					cve2cpeId[cvelistJson.CveMetadata.CveID] = append(cve2cpeId[cvelistJson.CveMetadata.CveID], match.CalculateHash())
				}
			}

			// save them in the database
			// unique the cpeMatch
			cpeMatch = utils.UniqBy(cpeMatch, func(el models.CPEMatch) string {
				return el.CalculateHash()
			})

			// save the cpes in batches of 1000
			for i := 0; i < len(cpeMatch); i += 1000 {
				end := i + 1000
				if end > len(cpeMatch) {
					end = len(cpeMatch)
				}
				if err := s.cveRepository.SaveBatchCPEMatch(nil, cpeMatch[i:end]); err != nil {
					slog.Error("could not save cpe matches", "err", err)
					return err
				}
			}

			// save the cve to cpe mapping
			for cveId, cpeIds := range cve2cpeId {
				for i := 0; i < len(cpeIds); i += 1000 {
					end := i + 1000
					if end > len(cpeIds) {
						end = len(cpeIds)
					}
					if err := s.cveRepository.GetDB(nil).Session(&gorm.Session{
						// disable logging
						// it might log slow queries or a missing cve.
						Logger: logger.Default.LogMode(logger.Silent),
					}).Model(&models.CVE{
						CVE: cveId,
						// unique the cpeIds
					}).Association("Configurations").Append(utils.Map(utils.UniqBy(cpeIds[i:end], func(el string) string {
						return el
					}), func(el string) models.CPEMatch {
						return models.CPEMatch{MatchCriteriaID: el}
					})); err != nil {
						slog.Error("could not save cve to cpe mapping", "err", err, "cveId", cveId)
					}
				}
			}

			return nil
		})

	}
	return group.Wait()
}

func isCVEFile(fileName string) bool {
	return strings.Contains(fileName, "CVE-") && strings.HasSuffix(fileName, ".json")
}

func generateCPE(cve cvelistJson) []models.CPEMatch {
	cpeCriteria := make([]models.CPEMatch, 0)

	for _, product := range cve.Containers.Cna.Affected {
		for _, version := range product.Versions {
			productName := product.Product
			if product.PackageName != "" {
				productName = product.PackageName
			}

			cpe := "cpe:2.3:a:" + strings.ToLower(product.Vendor) + ":" + strings.ToLower(productName)

			var cpeVersion versionRange
			var err error
			// check if version is a range
			if version.LessThan != nil {
				// version defines the range using a separate field
				cpeVersion, err = transformVersionMapToRange(version.Version, *version.LessThan)
			} else {
				// version seems to look like this: ">=1.0.0, <=2.0.0"
				cpeVersion, err = transformVersionStringToRange(version.Version)
			}

			if err != nil {
				slog.Error("could not transform version to range", "err", err)
				continue
			}
			if cpeVersion.concreteVersion != nil {
				cpe += ":" + *cpeVersion.concreteVersion
			} else {
				cpe += ":*"
			}
			// add the rest of the fields
			cpe += ":*:*:*:*:*:*:*"

			match := models.CPEMatch{
				Criteria:              cpe,
				Part:                  "a",
				Vendor:                strings.ToLower(product.Vendor),
				Product:               strings.ToLower(productName),
				Version:               utils.OrDefault(cpeVersion.concreteVersion, "*"),
				VersionEndExcluding:   cpeVersion.versionEndExcluding,
				VersionEndIncluding:   cpeVersion.versionEndIncluding,
				VersionStartIncluding: cpeVersion.versionStartIncluding,
				VersionStartExcluding: cpeVersion.versionStartExcluding,
				Vulnerable:            version.Status == "affected",
				Update:                "*",
				Edition:               "*",
				Language:              "*",
				SwEdition:             "*",
				TargetSw:              "*",
				TargetHw:              "*",
				Other:                 "*",
			}
			cpeCriteria = append(cpeCriteria, match)
		}
	}
	return utils.UniqBy(cpeCriteria, func(el models.CPEMatch) string {
		return el.CalculateHash()
	})
}

type versionRange struct {
	concreteVersion       *string
	versionStartIncluding *string
	versionStartExcluding *string
	versionEndIncluding   *string
	versionEndExcluding   *string
}

// the cvelist is not consistent. Sometime it contains the range in the version field itself like: >=1.0.0, <=2.0.0
// sometimes it contains an additional field like: "lessThan": "2.0.0"
func transformVersionMapToRange(version string, lessThan string) (versionRange, error) {
	return versionRange{
		versionStartIncluding: utils.Ptr(version),
		versionEndExcluding:   utils.Ptr(lessThan),
	}, nil
}

func transformVersionStringToRange(version string) (versionRange, error) {
	if version == "" {
		return versionRange{}, errors.New("version is empty")
	}

	var r versionRange
	// This function transforms the version format to CPE compliant format
	// Custom transformation logic can be added as per the requirement
	version = strings.TrimSpace(version)
	if strings.Contains(version, ",") {
		// start and end is defined
		parts := strings.Split(version, ",")
		start, end := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if strings.HasPrefix(start, ">=") {
			r.versionStartIncluding = utils.Ptr(strings.TrimSpace(strings.TrimPrefix(start, ">=")))
		} else if strings.HasPrefix(start, ">") {
			r.versionStartExcluding = utils.Ptr(strings.TrimSpace(strings.TrimPrefix(start, ">")))
		}
		// check if end is defined
		if strings.HasPrefix("<=", end) {
			r.versionEndIncluding = utils.Ptr(strings.TrimSpace(strings.TrimPrefix(end, "<=")))
		} else if strings.HasPrefix(end, "<") {
			r.versionEndExcluding = utils.Ptr(strings.TrimSpace(strings.TrimPrefix(end, "<")))
		} else {
			r.versionEndIncluding = utils.Ptr(strings.TrimSpace(end))
		}
	} else {
		// its a single version - but still might be a range
		if strings.HasPrefix(version, "=") {
			r.concreteVersion = utils.Ptr(strings.TrimSpace(strings.TrimPrefix(version, "=")))
		} else if strings.HasPrefix(version, "<=") {
			r.versionEndIncluding = utils.Ptr(strings.TrimSpace(strings.TrimPrefix(version, "<=")))
		} else if strings.HasPrefix(version, "<") {
			r.versionEndExcluding = utils.Ptr(strings.TrimSpace(strings.TrimPrefix(version, "<")))
		} else if strings.HasPrefix(version, ">=") {
			r.versionStartIncluding = utils.Ptr(strings.TrimSpace(strings.TrimPrefix(version, ">=")))
		} else if strings.HasPrefix(version, ">") {
			r.versionStartExcluding = utils.Ptr(strings.TrimSpace(strings.TrimPrefix(version, ">")))
		} else {
			// no range defined
			r.concreteVersion = utils.Ptr(strings.TrimSpace(version))
		}
	}
	return r, nil
}
