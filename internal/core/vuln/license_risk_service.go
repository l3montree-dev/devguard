package vuln

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type LicenseRiskService struct {
	licenseRiskRepository core.LicenseRiskRepository
	vulnEventRepository   core.VulnEventRepository
}

func NewLicenseRiskService(licenseRiskReposiory core.LicenseRiskRepository, vulnEventRepository core.VulnEventRepository) LicenseRiskService {
	return LicenseRiskService{
		licenseRiskRepository: licenseRiskReposiory,
		vulnEventRepository:   vulnEventRepository,
	}
}

func (service LicenseRiskService) FindLicenseRisksInComponents(assetVersion models.AssetVersion, components []models.Component, scannerID string) error {
	existingLicenseRisks, err := service.licenseRiskRepository.ListByScanner(assetVersion.Name, assetVersion.AssetID, scannerID)
	licenses, err := GetOSILicenses()
	if err != nil {
		return err
	}
	// put all the license in a hash map for faster look up times
	licenseMap := make(map[string]struct{})
	for i := range licenses {
		licenseMap[licenses[i]] = struct{}{}
	}

	//collect all risks before saving to the database
	allLicenseRisks := []models.LicenseRisk{}
	allVulnEvents := []models.VulnEvent{}
	//go over every component and check if the license if the license is a valid osi license; if not we can create a license risk with the provided information
	for _, component := range components {
		_, validLicense := licenseMap[*component.License]
		if !validLicense {
			licenseRisk := models.LicenseRisk{
				Vulnerability: models.Vulnerability{
					AssetVersionName: assetVersion.Name,
					AssetID:          assetVersion.AssetID,
					AssetVersion:     assetVersion,
					State:            models.VulnStateOpen,
					ScannerIDs:       scannerID,
					LastDetected:     time.Now(),
				},
				FinalLicenseDecision: "",
				ComponentPurl:        component.Purl,
			}
			allLicenseRisks = append(allLicenseRisks, licenseRisk)
			ev := models.NewDetectedEvent(licenseRisk.CalculateHash(), models.VulnTypeLicenseRisk, "system", common.RiskCalculationReport{}, scannerID)
			// apply the event on the dependencyVuln
			ev.Apply(&licenseRisk)
			allVulnEvents = append(allVulnEvents, ev)
		}
	}
	err = service.licenseRiskRepository.SaveBatch(nil, allLicenseRisks)
	if err != nil {
		return err
	}
	err = service.vulnEventRepository.SaveBatch(nil, allVulnEvents)
	if err != nil {
		return err
	}
	return nil
}

func GetOSILicenses() ([]string, error) {
	var validOSILicenses []string
	apiURL := os.Getenv("OSI_LICENSES_API")
	if apiURL == "" {
		return nil, fmt.Errorf("could not get the URL of the OSI API, check the OSI_LICENSES_API variable in your .env file")
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("could not build the http request: %s", err)
	}
	client := http.DefaultClient
	client.Timeout = time.Minute

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http request to %s was unsuccessful (code: %d)", apiURL, resp.StatusCode)
	}
	response := bytes.Buffer{}
	type osiLicense struct {
		ID string `json:"spdx_id"`
	}
	var licenses []osiLicense
	_, err = io.Copy(&response, resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(response.Bytes(), &licenses)
	if err != nil {
		return nil, err
	}

	for _, license := range licenses {
		if license.ID != "" {
			validOSILicenses = append(validOSILicenses, license.ID)
		}
	}

	return validOSILicenses, nil

}
