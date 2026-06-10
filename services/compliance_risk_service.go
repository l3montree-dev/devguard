package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"
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

// HandleArtifactCompliance processes a SARIF compliance report for an artifact and manages the
// lifecycle of compliance risks: new detections, branch-diffing, artifact association, and fixes.
func (s *ComplianceRiskService) HandleArtifactCompliance(ctx context.Context, tx shared.DB, userID string, userAgent *string, assetVersion models.AssetVersion, artifact models.Artifact, sarifDoc sarif.SarifSchema210Json) error {
	// fetch all existing compliance risks for this asset version (across all artifacts)
	existingRisks, err := s.complianceRiskRepository.GetAllComplianceRisksForAssetVersion(ctx, tx, assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return err
	}

	foundRisks := sarifToComplianceRisks(sarifDoc, assetVersion)

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
		// update policy/evidence metadata
		if err := s.complianceRiskRepository.SaveBatch(ctx, db, inBoth); err != nil {
			return err
		}

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
	default:
		return models.VulnEvent{}, fmt.Errorf("unsupported event type: %s", statusType)
	}
	err := s.complianceRiskRepository.ApplyAndSave(ctx, tx, risk, &ev)
	return ev, err
}

// sarifToComplianceRisks converts a SARIF document into ComplianceRisk models for the given asset version.
// Each SARIF rule becomes one risk; its state is derived from the result kinds (pass/fail/open).
func sarifToComplianceRisks(sarifDoc sarif.SarifSchema210Json, assetVersion models.AssetVersion) []models.ComplianceRisk {
	if len(sarifDoc.Runs) == 0 {
		return nil
	}

	risks := make([]models.ComplianceRisk, 0)
	for _, run := range sarifDoc.Runs {

		type ruleInfo struct {
			title            string
			description      *string
			relatedResources []string
			tags             []string
			priority         int
			policyFrameworks []models.PolicyFrameworks
		}
		ruleMap := make(map[string]ruleInfo, len(run.Tool.Driver.Rules))
		for _, rule := range run.Tool.Driver.Rules {
			var desc *string
			if rule.FullDescription != nil && rule.FullDescription.Text != "" {
				d := rule.FullDescription.Text
				desc = &d
			}

			title := rule.ID
			if rule.ShortDescription != nil {
				title = rule.ShortDescription.Text
			}

			var tags []string
			if rule.Properties != nil {
				tags = rule.Properties.Tags
			}

			relatedResources := make([]string, 0)
			if rule.Properties != nil {
				if rr, ok := rule.Properties.AdditionalProperties["relatedResources"].([]string); ok {
					relatedResources = rr
				} else if rr, ok := rule.Properties.AdditionalProperties["relatedResources"].([]any); ok {
					for _, r := range rr {
						if s, ok := r.(string); ok {
							relatedResources = append(relatedResources, s)
						}
					}
				}
			}

			var policyFrameworks []models.PolicyFrameworks
			if rule.Properties != nil {
				if direct, ok := rule.Properties.AdditionalProperties["policyFrameworks"].([]models.PolicyFrameworks); ok {
					policyFrameworks = direct
				} else if cf, ok := rule.Properties.AdditionalProperties["policyFrameworks"].([]any); ok {
					for _, c := range cf {
						if cMap, ok := c.(map[string]any); ok {
							pc := models.PolicyFrameworks{}
							if fw, ok := cMap["framework"].(string); ok {
								pc.Framework = fw
							}
							if ctls, ok := cMap["controls"].([]any); ok {
								for _, ctl := range ctls {
									if s, ok := ctl.(string); ok {
										pc.Controls = append(pc.Controls, s)
									}
								}
							}
							policyFrameworks = append(policyFrameworks, pc)
						}
					}
				}
			}

			var priority int
			if rule.Properties != nil {
				if p, ok := rule.Properties.AdditionalProperties["priority"].(int); ok {
					priority = p
				} else if pFloat, ok := rule.Properties.AdditionalProperties["priority"].(float64); ok {
					priority = int(pFloat)
				}
			}

			ruleMap[rule.ID] = ruleInfo{title: title, description: desc, relatedResources: relatedResources, tags: tags, priority: priority, policyFrameworks: policyFrameworks}
		}

		type policyResult struct {
			kind            sarif.ResultKind
			message         sarif.Message
			violations      []string
			evidenceContent []byte
			evidenceType    string
		}
		resultMap := make(map[string]*policyResult, len(ruleMap))

		for _, result := range run.Results {
			if result.RuleID == nil {
				continue
			}
			ruleID := *result.RuleID
			pr := resultMap[ruleID]
			if pr == nil {
				pr = &policyResult{}
				resultMap[ruleID] = pr
			}

			pr.message = result.Message

			if result.Properties != nil {
				if ac, ok := result.Properties.AdditionalProperties["evidenceContent"].(string); ok && pr.evidenceContent == nil {
					pr.evidenceContent = []byte(ac)
				}
				if et, ok := result.Properties.AdditionalProperties["evidenceType"].(string); ok {
					pr.evidenceType = et
				}
				if v, ok := result.Properties.AdditionalProperties["violations"].([]string); ok {
					pr.violations = v
				}
			}

			switch result.Kind {
			case sarif.ResultKindFail:
				pr.kind = sarif.ResultKindFail
			case sarif.ResultKindOpen:
				if pr.kind != sarif.ResultKindFail {
					pr.kind = sarif.ResultKindOpen
				}
			case sarif.ResultKindPass:
				if pr.kind == "" {
					pr.kind = sarif.ResultKindPass
				}
			}

		}

		for ruleID, info := range ruleMap {
			state := dtos.VulnStateOpen
			var violations []string
			var evidenceContent []byte
			var evidenceType string
			var message string

			if pr := resultMap[ruleID]; pr != nil {
				evidenceContent = pr.evidenceContent
				switch pr.kind {
				case sarif.ResultKindPass:
					state = dtos.VulnStateFixed
				case sarif.ResultKindFail:
					state = dtos.VulnStateOpen
					violations = pr.violations
				}
				evidenceType = pr.evidenceType
				message = pr.message.Text

			}

			risks = append(risks, models.ComplianceRisk{
				Vulnerability: models.Vulnerability{
					AssetVersionName: assetVersion.Name,
					AssetID:          assetVersion.AssetID,
					AssetVersion:     assetVersion,
					State:            state,
					LastDetected:     time.Now(),
				},
				PolicyID:               ruleID,
				PolicyTitle:            info.title,
				PolicyDescription:      info.description,
				PolicyRelatedResources: info.relatedResources,
				PolicyTags:             info.tags,
				PolicyPriority:         info.priority,
				PolicyFrameworks:       info.policyFrameworks,
				EvidenceType:           evidenceType,
				Violations:             violations,
				EvidenceContent:        evidenceContent,
				Message:                message,
			})
		}
	}

	return risks
}
