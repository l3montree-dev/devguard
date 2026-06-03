package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/utils"
)

type ComplianceRiskService struct {
	complianceRiskRepository shared.ComplianceRiskRepository
	vulnEventRepository      shared.VulnEventRepository
}

var _ shared.ComplianceRiskService = (*ComplianceRiskService)(nil)

func NewComplianceRiskService(complianceRiskRepository shared.ComplianceRiskRepository, vulnEventRepository shared.VulnEventRepository) *ComplianceRiskService {
	return &ComplianceRiskService{
		complianceRiskRepository: complianceRiskRepository,
		vulnEventRepository:      vulnEventRepository,
	}
}

// HandleArtifactCompliance processes policy evaluations for an artifact and manages the
// lifecycle of compliance risks: new detections, branch-diffing, artifact association, and fixes.
func (s *ComplianceRiskService) HandleArtifactCompliance(ctx context.Context, tx shared.DB, userID string, userAgent *string, assetVersion models.AssetVersion, artifact models.Artifact, evaluations []compliance.PolicyEvaluation) error {
	// fetch all existing compliance risks for this asset version (across all artifacts)
	existingRisks, err := s.complianceRiskRepository.GetAllComplianceRisksForAssetVersion(ctx, tx, assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return err
	}

	// build risks for every evaluation — compliant ones start fixed, non-compliant ones open
	foundRisks := make([]models.ComplianceRisk, 0, len(evaluations))
	for _, eval := range evaluations {
		compliant := eval.Compliant != nil && *eval.Compliant
		state := dtos.VulnStateOpen
		if compliant {
			state = dtos.VulnStateFixed
		}
		foundRisks = append(foundRisks, models.ComplianceRisk{
			Vulnerability: models.Vulnerability{
				AssetVersionName: assetVersion.Name,
				AssetID:          assetVersion.AssetID,
				AssetVersion:     assetVersion,
				State:            state,
				LastDetected:     time.Now(),
			},
			PolicyID:             eval.Policy.ID.String(),
			PredicateType:        eval.Policy.PredicateType,
			AttestationUpdatedAt: eval.AttestationUpdatedAt,
		})
	}

	// compare found risks with existing ones using hash-based identity
	comparison := utils.CompareSlices(foundRisks, existingRisks, func(r models.ComplianceRisk) string {
		return r.CalculateHash().String()
	})

	newRisks := comparison.OnlyInA
	fixedRisks := comparison.OnlyInB
	inBoth := comparison.InBoth

	// get risks from other branches for branch-diffing of new detections
	existingRisksOnOtherBranch, err := s.complianceRiskRepository.GetComplianceRisksByOtherAssetVersions(ctx, tx, assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		slog.Error("could not get existing compliance risks on other branches", "err", err)
		return err
	}
	existingRisksOnOtherBranch = utils.Filter(existingRisksOnOtherBranch, func(r models.ComplianceRisk) bool {
		return r.State != dtos.VulnStateFixed
	})

	// branch-diff new risks
	branchDiff := statemachine.DiffVulnsBetweenBranches(
		utils.Map(newRisks, utils.Ptr),
		utils.Map(existingRisksOnOtherBranch, utils.Ptr),
	)

	// determine which "fixed" risks are truly fixed everywhere vs just removed from this artifact
	existingNeedsAssoc := make([]models.ComplianceRisk, 0)
	for _, r := range inBoth {
		alreadyAssoc := utils.Any(r.Artifacts, func(a models.Artifact) bool {
			return a.ArtifactName == artifact.ArtifactName
		})
		if !alreadyAssoc {
			existingNeedsAssoc = append(existingNeedsAssoc, r)
		}
	}

	existingNeedsDissoc := make([]models.ComplianceRisk, 0)
	finallyFixed := make([]models.ComplianceRisk, 0)
	for _, r := range fixedRisks {
		if len(r.Artifacts) > 1 {
			existingNeedsDissoc = append(existingNeedsDissoc, r)
		} else if len(r.Artifacts) == 1 && r.Artifacts[0].ArtifactName != artifact.ArtifactName {
			existingNeedsDissoc = append(existingNeedsDissoc, r)
		} else {
			finallyFixed = append(finallyFixed, r)
		}
	}

	return s.complianceRiskRepository.Transaction(ctx, func(db shared.DB) error {
		// risks that exist on other branches: copy event history
		if err := s.UserDetectedExistingComplianceRiskOnDifferentBranch(ctx, db, artifact.ArtifactName, branchDiff.ExistingOnOtherBranches, assetVersion); err != nil {
			slog.Error("error processing existing compliance risk on different branch", "err", err)
			return err
		}

		// brand-new risks never seen before
		newToAllBranches := utils.Map(utils.DereferenceSlice(branchDiff.NewToAllBranches), func(r models.ComplianceRisk) models.ComplianceRisk { return r })
		if err := s.UserDetectedComplianceRisks(ctx, db, userID, userAgent, assetVersion.Name, artifact.ArtifactName, newToAllBranches); err != nil {
			return err
		}

		// risks now fixed everywhere
		if err := s.UserFixedComplianceRisks(ctx, db, userID, userAgent, finallyFixed); err != nil {
			return err
		}

		// risks seen in this artifact for the first time (already exist in other artifacts)
		if err := s.UserDetectedComplianceRiskInAnotherArtifact(ctx, db, existingNeedsAssoc, artifact.ArtifactName); err != nil {
			return err
		}

		// risks no longer seen in this artifact (still exists in others)
		if err := s.UserDidNotDetectComplianceRiskInArtifactAnymore(ctx, db, existingNeedsDissoc, artifact.ArtifactName); err != nil {
			return err
		}

		return nil
	})
}

func (s *ComplianceRiskService) UserDetectedExistingComplianceRiskOnDifferentBranch(ctx context.Context, tx shared.DB, artifactName string, matches []statemachine.BranchVulnMatch[*models.ComplianceRisk], assetVersion models.AssetVersion) error {
	if len(matches) == 0 {
		return nil
	}

	risks := utils.Map(matches, func(m statemachine.BranchVulnMatch[*models.ComplianceRisk]) models.ComplianceRisk {
		r := *m.CurrentBranchVuln
		r.Artifacts = append(r.Artifacts, models.Artifact{
			ArtifactName:     artifactName,
			AssetVersionName: assetVersion.Name,
			AssetID:          assetVersion.AssetID,
		})
		return r
	})
	events := utils.Map(matches, func(m statemachine.BranchVulnMatch[*models.ComplianceRisk]) []models.VulnEvent {
		return m.EventsToCopy
	})

	if err := s.complianceRiskRepository.SaveBatch(ctx, tx, risks); err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(ctx, tx, utils.Flat(events))
}

func (s *ComplianceRiskService) UserDetectedComplianceRisks(ctx context.Context, tx shared.DB, userID string, userAgent *string, assetVersionName, artifactName string, risks []models.ComplianceRisk) error {
	if len(risks) == 0 {
		return nil
	}
	events := make([]models.VulnEvent, len(risks))
	for i := range risks {
		risks[i].Artifacts = append(risks[i].Artifacts, models.Artifact{
			ArtifactName:     artifactName,
			AssetVersionName: assetVersionName,
			AssetID:          risks[i].AssetID,
		})
		ev := models.NewDetectedEvent(risks[i].CalculateHash(), dtos.VulnTypeComplianceRisk, userID, dtos.RiskCalculationReport{}, artifactName, false, userAgent)
		statemachine.Apply(&risks[i], ev)
		events[i] = ev
	}
	if err := s.complianceRiskRepository.SaveBatch(ctx, tx, risks); err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(ctx, tx, events)
}

func (s *ComplianceRiskService) UserFixedComplianceRisks(ctx context.Context, tx shared.DB, userID string, userAgent *string, risks []models.ComplianceRisk) error {
	if len(risks) == 0 {
		return nil
	}
	events := make([]models.VulnEvent, len(risks))
	for i := range risks {
		ev := models.NewFixedEvent(risks[i].CalculateHash(), dtos.VulnTypeComplianceRisk, userID, "", false, userAgent)
		statemachine.Apply(&risks[i], ev)
		events[i] = ev
	}
	if err := s.complianceRiskRepository.SaveBatch(ctx, tx, risks); err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(ctx, tx, events)
}

func (s *ComplianceRiskService) UserDetectedComplianceRiskInAnotherArtifact(ctx context.Context, tx shared.DB, risks []models.ComplianceRisk, artifactName string) error {
	if len(risks) == 0 {
		return nil
	}
	for i := range risks {
		if err := tx.Exec(
			"INSERT INTO artifact_compliance_risks (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, compliance_risk_id) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
			artifactName, risks[i].AssetVersionName, risks[i].AssetID, risks[i].CalculateHash(),
		).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *ComplianceRiskService) UserDidNotDetectComplianceRiskInArtifactAnymore(ctx context.Context, tx shared.DB, risks []models.ComplianceRisk, artifactName string) error {
	if len(risks) == 0 {
		return nil
	}
	for i := range risks {
		if err := tx.Exec(
			"DELETE FROM artifact_compliance_risks WHERE artifact_artifact_name = ? AND artifact_asset_version_name = ? AND artifact_asset_id = ? AND compliance_risk_id = ?",
			artifactName, risks[i].AssetVersionName, risks[i].AssetID, risks[i].ID,
		).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *ComplianceRiskService) UpdateComplianceRiskState(ctx context.Context, tx shared.DB, userID string, risk *models.ComplianceRisk, statusType string, justification string, mechanicalJustification dtos.MechanicalJustificationType, userAgent *string) (models.VulnEvent, error) {
	if tx == nil {
		var ev models.VulnEvent
		var err error
		err = s.complianceRiskRepository.Transaction(ctx, func(d shared.DB) error {
			ev, err = s.updateComplianceRiskState(ctx, d, userID, risk, statusType, justification, mechanicalJustification, userAgent)
			return err
		})
		return ev, err
	}
	return s.updateComplianceRiskState(ctx, tx, userID, risk, statusType, justification, mechanicalJustification, userAgent)
}

func (s *ComplianceRiskService) updateComplianceRiskState(ctx context.Context, tx shared.DB, userID string, risk *models.ComplianceRisk, statusType string, justification string, mechanicalJustification dtos.MechanicalJustificationType, userAgent *string) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch dtos.VulnEventType(statusType) {
	case dtos.EventTypeAccepted:
		ev = models.NewAcceptedEvent(risk.CalculateHash(), dtos.VulnTypeComplianceRisk, userID, justification, false, userAgent)
	case dtos.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(risk.CalculateHash(), dtos.VulnTypeComplianceRisk, userID, justification, mechanicalJustification, risk.GetArtifactNames(), false, userAgent)
	case dtos.EventTypeReopened:
		ev = models.NewReopenedEvent(risk.CalculateHash(), dtos.VulnTypeComplianceRisk, userID, justification, false, userAgent)
	case dtos.EventTypeComment:
		ev = models.NewCommentEvent(risk.CalculateHash(), dtos.VulnTypeComplianceRisk, userID, justification, false, userAgent)
	}
	err := s.complianceRiskRepository.ApplyAndSave(ctx, tx, risk, &ev)
	return ev, err
}
