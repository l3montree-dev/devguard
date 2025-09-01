package vuln

import (
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	// "github.com/l3montree-dev/devguard/internal/utils"
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

type licenseRiskWithNewLicense struct {
	models.LicenseRisk
	NewFinalLicense string
}

func (s *LicenseRiskService) FindLicenseRisksInComponents(assetVersion models.AssetVersion, components []models.Component, artifactName string) error {
	// get all license risks for the assetVersion (across artifacts) so we can deduplicate
	existingLicenseRisks, err := s.licenseRiskRepository.GetAllLicenseRisksForAssetVersion(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return err
	}
	// filter to only open ones
	existingLicenseRisks = utils.Filter(existingLicenseRisks, func(risk models.LicenseRisk) bool {
		return risk.State == models.VulnStateOpen
	})

	// get all current valid licenses to compare against
	licenseMap := component.LicenseMap

	foundLicenseRisks := make([]models.LicenseRisk, 0)
	compToValidLicense := make(map[string]string)
	for _, comp := range components {
		if comp.License == nil {
			slog.Warn("license is nil, avoided nil pointer dereference")
			continue
		}
		_, validLicense := licenseMap[strings.ToLower(*comp.License)]
		if !validLicense {
			lr := models.LicenseRisk{
				Vulnerability: models.Vulnerability{
					AssetVersionName: assetVersion.Name,
					AssetID:          assetVersion.AssetID,
					AssetVersion:     assetVersion,
					State:            models.VulnStateOpen,
					LastDetected:     time.Now(),
				},
				FinalLicenseDecision: nil,
				ComponentPurl:        comp.Purl,
			}
			foundLicenseRisks = append(foundLicenseRisks, lr)
		} else {
			compToValidLicense[comp.Purl] = *comp.License
		}
	}

	// determine which existing risks were not observed this run -> these are fixed
	// build comparison between existing risks (all in assetVersion) and newly detected ones
	comparison := utils.CompareSlices(foundLicenseRisks, existingLicenseRisks, func(risk models.LicenseRisk) string {
		return risk.CalculateHash()
	})

	newLicenseRisks := comparison.OnlyInA
	fixedLicenseRisks := comparison.OnlyInB
	inBoth := comparison.InBoth

	// for fixed risks, either the component now has a valid license or the component was removed
	// we can only check for now valid license components
	validLicenseFixed := make([]licenseRiskWithNewLicense, 0)
	fixedByRemoval := make([]models.LicenseRisk, 0)
	for _, fr := range fixedLicenseRisks {
		if validLicense, ok := compToValidLicense[fr.ComponentPurl]; ok {
			// component still exists but now has a valid license -> mark as fixed
			validLicenseFixed = append(validLicenseFixed, licenseRiskWithNewLicense{
				LicenseRisk:     fr,
				NewFinalLicense: validLicense,
			})
		} else {
			fixedByRemoval = append(fixedByRemoval, fr)
		}
	}

	existingNeedsAssoc := make([]models.LicenseRisk, 0)
	for _, ir := range inBoth {
		// check if we are already associated with the artifact
		if !slices.Contains(utils.Map(ir.Artifacts, func(artifact models.Artifact) string {
			return artifact.ArtifactName
		}), artifactName) {
			existingNeedsAssoc = append(existingNeedsAssoc, ir)
		}
	}

	// check if we need to really fix the license risks which were removed - if we are the last artifact - or just dissociate the artifact
	existingNeedsDissoc := make([]models.LicenseRisk, 0)
	finallyFixed := make([]models.LicenseRisk, 0)
	for _, fr := range fixedByRemoval {
		if len(fr.Artifacts) > 1 {
			// we are not the last artifact - just dissociate
			existingNeedsDissoc = append(existingNeedsDissoc, fr)
		} else {
			finallyFixed = append(finallyFixed, fr)
		}
	}

	return s.licenseRiskRepository.Transaction(func(db core.DB) error {
		if len(newLicenseRisks) > 0 {
			if err := s.UserDetectedLicenseRisks(db, assetVersion.AssetID, assetVersion.Name, artifactName, newLicenseRisks); err != nil {
				return err
			}
		}

		if len(finallyFixed) > 0 {
			if err := s.UserFixedLicenseRisks(db, "system", finallyFixed); err != nil {
				return err
			}
		}

		if len(existingNeedsAssoc) > 0 {
			if err := s.UserDetectedLicenseRiskInAnotherArtifact(db, existingNeedsAssoc, artifactName); err != nil {
				return err
			}
		}

		if len(existingNeedsDissoc) > 0 {
			if err := s.UserDidNotDetectLicenseRiskInArtifactAnymore(db, existingNeedsDissoc, artifactName); err != nil {
				return err
			}
		}

		if len(validLicenseFixed) > 0 {
			if err := s.UserFixedLicenseRisksByAutomaticRefresh(db, "system", validLicenseFixed, artifactName); err != nil {
				return err
			}
		}

		return nil
	})
}

// the license risks were fixes BY REMOVING the component
func (s *LicenseRiskService) UserFixedLicenseRisks(tx core.DB, userID string, licenseRisks []models.LicenseRisk) error {
	if len(licenseRisks) == 0 {
		return nil
	}
	events := make([]models.VulnEvent, len(licenseRisks))
	for i := range licenseRisks {
		ev := models.NewFixedEvent(licenseRisks[i].CalculateHash(), models.VulnTypeLicenseRisk, userID, "")
		ev.Apply(&licenseRisks[i])
		events[i] = ev
	}
	if err := s.licenseRiskRepository.SaveBatch(tx, licenseRisks); err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(tx, events)
}

// Helper: create detected events for newly opened license risks and save them
func (s *LicenseRiskService) UserDetectedLicenseRisks(tx core.DB, assetID uuid.UUID, assetVersionName, artifactName string, licenseRisks []models.LicenseRisk) error {
	if len(licenseRisks) == 0 {
		return nil
	}
	events := make([]models.VulnEvent, len(licenseRisks))
	for i := range licenseRisks {
		// ensure artifact association exists in the object
		licenseRisks[i].Artifacts = append(licenseRisks[i].Artifacts, models.Artifact{ArtifactName: artifactName, AssetID: assetID, AssetVersionName: assetVersionName})
		ev := models.NewDetectedEvent(licenseRisks[i].CalculateHash(), models.VulnTypeLicenseRisk, "system", common.RiskCalculationReport{}, artifactName)
		ev.Apply(&licenseRisks[i])
		events[i] = ev
	}
	if err := s.licenseRiskRepository.SaveBatch(tx, licenseRisks); err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(tx, events)
}

// Helper: ensure existing license risks are associated with another artifact (insert join rows)
func (s *LicenseRiskService) UserDetectedLicenseRiskInAnotherArtifact(tx core.DB, licenseRisks []models.LicenseRisk, artifactName string) error {
	if len(licenseRisks) == 0 {
		return nil
	}
	for i := range licenseRisks {
		// add artifact association via raw SQL for efficiency
		if err := tx.Exec("INSERT INTO artifact_license_risks (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, license_risk_id) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING", artifactName, licenseRisks[i].AssetVersionName, licenseRisks[i].AssetID, licenseRisks[i].CalculateHash()).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *LicenseRiskService) UserFixedLicenseRisksByAutomaticRefresh(tx core.DB, userID string, licenseRisks []licenseRiskWithNewLicense, artifactName string) error {
	if len(licenseRisks) == 0 {
		return nil
	}
	events := make([]models.VulnEvent, len(licenseRisks))
	for i := range licenseRisks {
		ev := models.NewLicenseDecisionEvent(licenseRisks[i].CalculateHash(), models.VulnTypeLicenseRisk, userID, "Automatically fixed by license refresh", artifactName, licenseRisks[i].NewFinalLicense)
		ev.Apply(&licenseRisks[i])
		events[i] = ev
	}
	return nil
}

func (s *LicenseRiskService) UserDidNotDetectLicenseRiskInArtifactAnymore(tx core.DB, licenseRisks []models.LicenseRisk, artifactName string) error {
	if len(licenseRisks) == 0 {
		return nil
	}
	for i := range licenseRisks {
		// remove artifact association via raw SQL for efficiency
		if err := tx.Exec("DELETE FROM artifact_license_risks WHERE artifact_artifact_name = ? AND artifact_asset_version_name = ? AND artifact_asset_id = ? AND license_risk_id = ?", artifactName, licenseRisks[i].AssetVersionName, licenseRisks[i].AssetID, licenseRisks[i].ID).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *LicenseRiskService) UpdateLicenseRiskState(tx core.DB, userID string, licenseRisk *models.LicenseRisk, statusType string, justification string, mechanicalJustification models.MechanicalJustificationType) (models.VulnEvent, error) {
	if tx == nil {
		var ev models.VulnEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = s.licenseRiskRepository.Transaction(func(d core.DB) error {
			ev, err = s.updateLicenseRiskState(tx, userID, licenseRisk, statusType, justification, mechanicalJustification)
			return err
		})
		return ev, err
	}
	return s.updateLicenseRiskState(tx, userID, licenseRisk, statusType, justification, mechanicalJustification)
}

func (s *LicenseRiskService) updateLicenseRiskState(tx core.DB, userID string, licenseRisk *models.LicenseRisk, statusType string, justification string, mechanicalJustification models.MechanicalJustificationType) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch models.VulnEventType(statusType) {
	case models.EventTypeAccepted:
		ev = models.NewAcceptedEvent(licenseRisk.CalculateHash(), models.VulnTypeLicenseRisk, userID, justification)
	case models.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(licenseRisk.CalculateHash(), models.VulnTypeLicenseRisk, userID, justification, mechanicalJustification, licenseRisk.GetArtifactNames())
	case models.EventTypeReopened:
		ev = models.NewReopenedEvent(licenseRisk.CalculateHash(), models.VulnTypeLicenseRisk, userID, justification)
	case models.EventTypeComment:
		ev = models.NewCommentEvent(licenseRisk.CalculateHash(), models.VulnTypeLicenseRisk, userID, justification)
	}

	err := s.licenseRiskRepository.ApplyAndSave(tx, licenseRisk, &ev)
	return ev, err
}

func (s *LicenseRiskService) MakeFinalLicenseDecision(vulnID, finalLicense, justification, userID string) error {
	licenseRisk, err := s.licenseRiskRepository.Read(vulnID)
	if err != nil {
		return err
	}
	// check if the licenses differ
	if licenseRisk.FinalLicenseDecision != nil && *licenseRisk.FinalLicenseDecision == finalLicense {
		// no change
		return nil
	}

	ev := models.NewLicenseDecisionEvent(vulnID, models.VulnTypeLicenseRisk, userID, justification, licenseRisk.GetArtifactNames(), finalLicense)
	return s.licenseRiskRepository.ApplyAndSave(nil, &licenseRisk, &ev)
}
