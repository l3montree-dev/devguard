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
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
)

type compliancePostureService struct {
	compliancePostureRepository shared.CompliancePostureRepository
	vulnEventRepository         shared.VulnEventRepository
	frameworkControlRepository  shared.FrameworkControlRepository
}

func NewCompliancePostureService(compliancePostureRepository shared.CompliancePostureRepository, vulnEventRepository shared.VulnEventRepository, frameworkControlRepository shared.FrameworkControlRepository) *compliancePostureService {
	return &compliancePostureService{
		compliancePostureRepository: compliancePostureRepository,
		vulnEventRepository:         vulnEventRepository,
		frameworkControlRepository:  frameworkControlRepository,
	}
}

func (s *compliancePostureService) effectiveScopeFrameworkIDs(ctx context.Context, tx shared.DB, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID) ([]uuid.UUID, error) {
	scopeFrameworks, err := s.frameworkControlRepository.GetEffectiveScopeFrameworks(ctx, tx, orgID, projectID, assetID)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(scopeFrameworks))
	for i, sf := range scopeFrameworks {
		ids[i] = sf.ID
	}
	return ids, nil
}

func (s *compliancePostureService) GetForAllControlsPaged(ctx context.Context, tx *gorm.DB, assetVersionID *uuid.UUID, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[dtos.CompliancePostureWithControl], error) {
	scopeFrameworkIDs, err := s.effectiveScopeFrameworkIDs(ctx, tx, assetID, projectID, orgID)
	if err != nil {
		return shared.Paged[dtos.CompliancePostureWithControl]{}, err
	}
	postures, err := s.compliancePostureRepository.GetForAllControlsPaged(ctx, tx, scopeFrameworkIDs, assetVersionID, assetID, projectID, orgID, pageInfo, search, filter, sort)
	//mapping the state to string for the DTO
	for i, posture := range postures.Data {
		if posture.State == "" {
			postures.Data[i].State = dtos.VulnStateOpen
		}

	}
	return postures, err
}

func (s *compliancePostureService) GetAllControls(ctx context.Context, tx *gorm.DB, assetVersionID *uuid.UUID, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID, search string, filter []shared.FilterQuery, sort []shared.SortQuery) ([]dtos.CompliancePostureWithDetails, error) {
	scopeFrameworkIDs, err := s.effectiveScopeFrameworkIDs(ctx, tx, assetID, projectID, orgID)
	if err != nil {
		return nil, err
	}
	postures, err := s.compliancePostureRepository.GetAllControls(ctx, tx, scopeFrameworkIDs, assetVersionID, assetID, projectID, orgID, search, filter, sort)
	//mapping the state to string for the DTO
	for i, posture := range postures {
		if posture.State == "" {
			postures[i].State = dtos.VulnStateOpen
		}
	}
	return postures, err
}

func (s *compliancePostureService) UpdateCompliancePostureState(ctx context.Context, tx shared.DB, userID string, posture *models.CompliancePosture, statusType string, justification string, mechanicalJustification dtos.MechanicalJustificationType, userAgent *string) (models.VulnEvent, error) {
	if tx == nil {
		var ev models.VulnEvent
		var err error
		err = s.compliancePostureRepository.Transaction(ctx, func(d shared.DB) error {
			ev, err = s.updateCompliancePostureState(ctx, d, userID, posture, statusType, justification, mechanicalJustification, userAgent)
			return err
		})
		return ev, err
	}
	return s.updateCompliancePostureState(ctx, tx, userID, posture, statusType, justification, mechanicalJustification, userAgent)
}
func (s *compliancePostureService) updateCompliancePostureState(ctx context.Context, tx shared.DB, userID string, posture *models.CompliancePosture, statusType string, justification string, mechanicalJustification dtos.MechanicalJustificationType, userAgent *string) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch dtos.VulnEventType(statusType) {
	case dtos.EventTypeImplemented:
		ev = models.NewImplementedEvent(posture.CalculateHash(), dtos.VulnTypeCompliancePosture, userID, justification, userAgent)
	case dtos.EventTypeNotApplicable:
		ev = models.NewNotApplicableEvent(posture.CalculateHash(), dtos.VulnTypeCompliancePosture, userID, justification, userAgent)
	case dtos.EventTypeReopened:
		ev = models.NewReopenedEvent(posture.CalculateHash(), dtos.VulnTypeCompliancePosture, userID, justification, false, userAgent)
	case dtos.EventTypeComment:
		ev = models.NewCommentEvent(posture.CalculateHash(), dtos.VulnTypeCompliancePosture, userID, justification, false, userAgent)
	default:
		return models.VulnEvent{}, fmt.Errorf("unsupported event type: %s", statusType)
	}
	err := s.compliancePostureRepository.ApplyAndSave(ctx, tx, posture, &ev)
	return ev, err
}

func (s *compliancePostureService) GetStatsForAllControls(ctx context.Context, tx shared.DB, assetVersionID *uuid.UUID, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID, filter []shared.FilterQuery) (dtos.CompliancePostureStats, error) {
	scopeFrameworkIDs, err := s.effectiveScopeFrameworkIDs(ctx, tx, assetID, projectID, orgID)
	if err != nil {
		return dtos.CompliancePostureStats{}, err
	}
	return s.compliancePostureRepository.GetStatsForAllControls(ctx, tx, scopeFrameworkIDs, assetVersionID, assetID, projectID, orgID, filter)
}

func (s *compliancePostureService) GetForControl(ctx context.Context, tx *gorm.DB, controlHash string, assetVersionID *uuid.UUID, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID) (*models.CompliancePosture, error) {
	scopeFrameworkIDs, err := s.effectiveScopeFrameworkIDs(ctx, tx, assetID, projectID, orgID)
	if err != nil {
		return nil, err
	}
	posture, err := s.compliancePostureRepository.GetForControl(ctx, tx, scopeFrameworkIDs, controlHash, assetVersionID, assetID, projectID, orgID)
	if err != nil {
		return nil, err
	}
	if posture.State == "" {
		posture.State = dtos.VulnStateOpen
	}
	return posture, nil
}
