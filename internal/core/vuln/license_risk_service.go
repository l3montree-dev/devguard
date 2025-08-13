package vuln

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type LicenseRiskService struct {
	licenseRiskRepository core.LicenseRiskRepository
	vulnEventRepository   core.VulnEventRepository
}

func NewLicenseRiskService(licenseRiskRepository core.LicenseRiskRepository, vulnEventRepository core.VulnEventRepository) *LicenseRiskService {
	return &LicenseRiskService{
		licenseRiskRepository: licenseRiskRepository,
		vulnEventRepository:   vulnEventRepository,
	}
}

func (service *LicenseRiskService) FindLicenseRisksInComponents(assetVersion models.AssetVersion, components []models.Component, scannerID string) error {
	existingLicenseRisks, err := service.licenseRiskRepository.ListByScanner(assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		return err
	}
	// put all the license risks we already have into a hash map for faster look up times
	doesLicenseRiskAlreadyExist := make(map[string]struct{})
	for i := range existingLicenseRisks {
		doesLicenseRiskAlreadyExist[existingLicenseRisks[i].ComponentPurl] = struct{}{}
	}

	// get all current valid licenses to compare against
	licenseMap, err := GetOSILicenses()
	if err != nil {
		return err
	}

	//collect all risks before saving to the database, should be more efficient
	allLicenseRisks := []models.LicenseRisk{}
	allVulnEvents := []models.VulnEvent{}
	// track which license risks we've already processed to prevent duplicates
	processedLicenseRisks := make(map[string]struct{})

	//go over every component and check if the license is a valid osi license; if not we can create a license risk with the provided information
	for _, component := range components {
		if component.License == nil {
			slog.Warn("license is nil, avoided nil pointer dereference")
			continue
		}
		_, validLicense := licenseMap[*component.License]
		_, exists := doesLicenseRiskAlreadyExist[component.Purl]
		// if we have an invalid license and we don not have a risk for this we create one
		if !validLicense && !exists {
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

			// Check if we've already processed this license risk to avoid duplicates
			riskHash := licenseRisk.CalculateHash()
			if _, processed := processedLicenseRisks[riskHash]; !processed {
				processedLicenseRisks[riskHash] = struct{}{}
				allLicenseRisks = append(allLicenseRisks, licenseRisk)
				ev := models.NewDetectedEvent(riskHash, models.VulnTypeLicenseRisk, "system", common.RiskCalculationReport{}, scannerID)
				// apply the event on the dependencyVuln
				ev.Apply(&licenseRisk)
				allVulnEvents = append(allVulnEvents, ev)
			}
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

var (
	validOSILicenseMap map[string]struct{} = make(map[string]struct{}) // cache for valid OSI licenses
	licenseMapMutex    sync.Mutex                                      // protects access to validOSILicenseMap
)

// ResetOSILicenseCache clears the cached OSI licenses for testing purposes
func ResetOSILicenseCache() {
	licenseMapMutex.Lock()
	defer licenseMapMutex.Unlock()
	validOSILicenseMap = make(map[string]struct{})
}

func GetOSILicenses() (map[string]struct{}, error) {
	// Check if we already have licenses (with read lock)
	licenseMapMutex.Lock()
	if len(validOSILicenseMap) > 0 {
		licenseMapMutex.Unlock()
		return validOSILicenseMap, nil
	}
	defer licenseMapMutex.Unlock()

	var err error
	validOSILicenseMap, err = fetchOSILicenses()

	if err != nil {
		return nil, err
	}

	return validOSILicenseMap, nil
}

func fetchOSILicenses() (map[string]struct{}, error) {
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

	validOSILicenseMap := make(map[string]struct{})
	for _, license := range licenses {
		if license.ID != "" {
			validOSILicenseMap[license.ID] = struct{}{}
		}
	}
	return validOSILicenseMap, nil
}

func (service *LicenseRiskService) UpdateLicenseRiskState(tx core.DB, userID string, licenseRisk *models.LicenseRisk, statusType string, justification string, mechanicalJustification models.MechanicalJustificationType) (models.VulnEvent, error) {
	if tx == nil {
		var ev models.VulnEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = service.licenseRiskRepository.Transaction(func(d core.DB) error {
			ev, err = service.updateLicenseRiskState(tx, userID, licenseRisk, statusType, justification, mechanicalJustification)
			return err
		})
		return ev, err
	}
	return service.updateLicenseRiskState(tx, userID, licenseRisk, statusType, justification, mechanicalJustification)
}

func (service *LicenseRiskService) updateLicenseRiskState(tx core.DB, userID string, licenseRisk *models.LicenseRisk, statusType string, justification string, mechanicalJustification models.MechanicalJustificationType) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch models.VulnEventType(statusType) {
	case models.EventTypeAccepted:
		ev = models.NewAcceptedEvent(licenseRisk.CalculateHash(), models.VulnTypeLicenseRisk, userID, justification)
	case models.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(licenseRisk.CalculateHash(), models.VulnTypeLicenseRisk, userID, justification, mechanicalJustification, licenseRisk.ScannerIDs)
	case models.EventTypeReopened:
		ev = models.NewReopenedEvent(licenseRisk.CalculateHash(), models.VulnTypeLicenseRisk, userID, justification)
	case models.EventTypeComment:
		ev = models.NewCommentEvent(licenseRisk.CalculateHash(), models.VulnTypeLicenseRisk, userID, justification)
	}

	err := service.licenseRiskRepository.ApplyAndSave(tx, licenseRisk, &ev)
	return ev, err
}

func (service *LicenseRiskService) MakeFinalLicenseDecision(vulnID, finalLicense, userID string) error {
	licenseRisk, err := service.licenseRiskRepository.Read(vulnID)
	if err != nil {
		return err
	}
	licenseRisk.State = models.VulnStateFixed
	licenseRisk.FinalLicenseDecision = finalLicense

	ev := models.NewFixedEvent(vulnID, models.VulnTypeLicenseRisk, userID, licenseRisk.ScannerIDs)
	return service.licenseRiskRepository.ApplyAndSave(nil, &licenseRisk, &ev)
}
