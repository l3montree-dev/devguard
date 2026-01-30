// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package services

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
)

type FalsePositiveRuleService struct {
	falsePositiveRuleRepository shared.FalsePositiveRuleRepository
	dependencyVulnRepository    shared.DependencyVulnRepository
	vulnEventRepository         shared.VulnEventRepository
}

func NewFalsePositiveRuleService(
	falsePositiveRuleRepository shared.FalsePositiveRuleRepository,
	dependencyVulnRepository shared.DependencyVulnRepository,
	vulnEventRepository shared.VulnEventRepository,
) *FalsePositiveRuleService {
	return &FalsePositiveRuleService{
		falsePositiveRuleRepository: falsePositiveRuleRepository,
		dependencyVulnRepository:    dependencyVulnRepository,
		vulnEventRepository:         vulnEventRepository,
	}
}

func (s *FalsePositiveRuleService) Create(tx shared.DB, rule *models.FalsePositiveRule) error {
	if err := s.falsePositiveRuleRepository.Create(tx, rule); err != nil {
		return fmt.Errorf("failed to create false positive rule: %w", err)
	}

	// Apply this rule to all matching existing dependency vulns
	if err := s.applyRuleToExistingVulns(tx, rule); err != nil {
		slog.Error("failed to apply false positive rule to existing vulnerabilities", "error", err, "ruleID", rule.ID)
		// Don't fail the whole operation if applying the rule fails
	}

	return nil
}

func (s *FalsePositiveRuleService) Update(tx shared.DB, rule *models.FalsePositiveRule) error {
	return s.falsePositiveRuleRepository.Update(tx, rule)
}

func (s *FalsePositiveRuleService) Delete(tx shared.DB, id uuid.UUID) error {
	return s.falsePositiveRuleRepository.Delete(tx, id)
}

func (s *FalsePositiveRuleService) FindByAssetID(tx shared.DB, assetID uuid.UUID) ([]models.FalsePositiveRule, error) {
	return s.falsePositiveRuleRepository.FindByAssetID(tx, assetID)
}

func (s *FalsePositiveRuleService) FindByID(tx shared.DB, id uuid.UUID) (models.FalsePositiveRule, error) {
	return s.falsePositiveRuleRepository.Read(id)
}

// applyRuleToExistingVulns applies a false positive rule to all existing vulnerabilities
// that match the rule's path pattern and CVE.
func (s *FalsePositiveRuleService) applyRuleToExistingVulns(tx shared.DB, rule *models.FalsePositiveRule) error {
	// Find all vulns matching the CVE and path pattern
	matchingVulns, err := s.dependencyVulnRepository.FindByPathSuffixAndCVE(tx, rule.AssetID, rule.CVEID, rule.PathPattern)
	if err != nil {
		return fmt.Errorf("failed to find matching vulns: %w", err)
	}

	// Filter out vulns already marked as false positive
	var vulnsToUpdate []models.DependencyVuln
	for _, vuln := range matchingVulns {
		if vuln.State != dtos.VulnStateFalsePositive {
			vulnsToUpdate = append(vulnsToUpdate, vuln)
		}
	}

	if len(vulnsToUpdate) == 0 {
		return nil
	}

	// Create false positive events for all matching vulns
	events := make([]models.VulnEvent, 0, len(vulnsToUpdate))
	updatedVulns := make([]models.DependencyVuln, 0, len(vulnsToUpdate))

	for _, vuln := range vulnsToUpdate {
		ev := models.NewFalsePositiveEvent(
			vuln.CalculateHash(),
			dtos.VulnTypeDependencyVuln,
			rule.CreatedByID,
			rule.Justification,
			rule.MechanicalJustification,
			"", // artifact name not needed for bulk operation
			dtos.UpstreamStateInternal,
		)

		// Apply the event to the vuln
		updatedVuln := vuln
		statemachine.Apply(&updatedVuln, ev)
		updatedVulns = append(updatedVulns, updatedVuln)
		events = append(events, ev)
	}

	// Save updated vulns and events
	if err := s.dependencyVulnRepository.SaveBatchBestEffort(tx, updatedVulns); err != nil {
		return fmt.Errorf("failed to save updated vulns: %w", err)
	}

	if err := s.vulnEventRepository.SaveBatchBestEffort(tx, events); err != nil {
		return fmt.Errorf("failed to save events: %w", err)
	}

	slog.Info("applied false positive rule to existing vulnerabilities",
		"ruleID", rule.ID,
		"assetID", rule.AssetID,
		"cveID", rule.CVEID,
		"matchingVulns", len(vulnsToUpdate))

	return nil
}
