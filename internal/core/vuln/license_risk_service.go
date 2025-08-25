package vuln

import (
	"log/slog"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
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
	// get all current valid licenses to compare against
	licenseMap := component.LicenseMap

	//collect all risks before saving to the database
	allLicenseRisks := []models.LicenseRisk{}

	// track which license risks we've already processed to prevent duplicates
	processedLicenseRisks := make(map[string]struct{}, len(components))

	//go over every component and check if the license is a valid osi license; if not we can create a license risk with the provided information
	for _, component := range components {
		if component.License == nil {
			slog.Warn("license is nil, avoided nil pointer dereference")
			continue
		}
		_, validLicense := licenseMap[strings.ToLower(*component.License)]
		// if we have an invalid license and we don not have a risk for this we create one
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
				FinalLicenseDecision: nil,
				ComponentPurl:        component.Purl,
			}

			// Check if we've already processed this license risk to avoid duplicates
			riskHash := licenseRisk.CalculateHash()
			if _, processed := processedLicenseRisks[riskHash]; !processed {
				processedLicenseRisks[riskHash] = struct{}{}
				allLicenseRisks = append(allLicenseRisks, licenseRisk)
			}
		}
	}

	allVulnEvents := make([]models.VulnEvent, 0, len(allLicenseRisks))

	comparison := utils.CompareSlices(existingLicenseRisks, allLicenseRisks, func(risk models.LicenseRisk) string {
		return risk.CalculateHash()
	})

	fixRisks := comparison.OnlyInA
	modifyRisks := comparison.InBoth
	openRisks := comparison.OnlyInB

	for i := range fixRisks {
		if fixRisks[i].State == models.VulnStateOpen {
			fixRisks[i].State = models.VulnStateFixed
			ev := models.NewFixedEvent(fixRisks[i].CalculateHash(), models.VulnTypeLicenseRisk, "system", scannerID)
			ev.Apply(&fixRisks[i])
			allVulnEvents = append(allVulnEvents, ev)
		}
	}

	for i := range modifyRisks {
		if modifyRisks[i].State == models.VulnStateFixed {
			modifyRisks[i].State = models.VulnStateOpen
			ev := models.NewDetectedEvent(modifyRisks[i].CalculateHash(), models.VulnTypeLicenseRisk, "system", common.RiskCalculationReport{}, scannerID)
			ev.Apply(&modifyRisks[i])
			allVulnEvents = append(allVulnEvents, ev)
		}
	}

	for i := range openRisks {
		openRisks[i].State = models.VulnStateOpen
		ev := models.NewDetectedEvent(openRisks[i].CalculateHash(), models.VulnTypeLicenseRisk, "system", common.RiskCalculationReport{}, scannerID)
		ev.Apply(&openRisks[i])
		allVulnEvents = append(allVulnEvents, ev)
	}

	allLicenseRisks = append(append(fixRisks, modifyRisks...), openRisks...)

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

func (service *LicenseRiskService) MakeFinalLicenseDecision(vulnID, finalLicense, justification, userID string) error {
	licenseRisk, err := service.licenseRiskRepository.Read(vulnID)
	if err != nil {
		return err
	}

	ev := models.NewLicenseDecisionEvent(vulnID, models.VulnTypeLicenseRisk, userID, justification, licenseRisk.ScannerIDs, finalLicense)
	return service.licenseRiskRepository.ApplyAndSave(nil, &licenseRisk, &ev)
}
