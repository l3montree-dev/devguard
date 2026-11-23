package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
)

type LabelService struct {
	labelRepository shared.LabelRepository
}

func NewLabelService(labelRepository shared.LabelRepository) *LabelService {
	return &LabelService{
		labelRepository: labelRepository,
	}
}

// AttachLabel attaches the label to the lowest level given (artifact > asset > project).
// projectID and assetID double as the context the label has to be visible from.
func (l *LabelService) AttachLabel(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID, assetID, artifactID, labelID *uuid.UUID) error {
	if tx == nil {
		return fmt.Errorf("missing transaction object")
	}
	if labelID == nil {
		return fmt.Errorf("Cannot attach label to target, label is missing")
	}
	if projectID == nil {
		return fmt.Errorf("Cannot attach label to target, project is missing")
	}

	label, err := l.labelRepository.FindLabelByIDThroughHierarchy(ctx, tx, labelID, &orgID, projectID, assetID)
	if err != nil {
		return err
	}
	err = l.labelRepository.CreateLabelAttachment(ctx, tx, &label.ID, projectID, assetID, artifactID)
	return err
}
