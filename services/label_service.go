package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
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
func (l *LabelService) AttachLabels(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID, assetID, artifactID *uuid.UUID, labelIDs []uuid.UUID) error {
	if tx == nil {
		return fmt.Errorf("missing transaction object")
	}
	if labelIDs == nil || len(labelIDs) == 0 {
		return fmt.Errorf("Cannot attach label to target, labels are missing")
	}
	if projectID == nil {
		return fmt.Errorf("Cannot attach label to target, project ID is required at minimum")
	}

	labelIDs = utils.UniqBy(labelIDs, func(id uuid.UUID) uuid.UUID { return id })

	labels, err := l.labelRepository.FindLabelsByIDsThroughHierarchy(ctx, tx, labelIDs, &orgID, projectID, assetID)
	if err != nil {
		return err
	}
	if len(labels) != len(labelIDs) {
		return fmt.Errorf("could not find all labels, labelID list might contain invalid IDs: %w", gorm.ErrRecordNotFound)
	}

	foundLabelIDs := utils.Map(labels, func(label models.Label) uuid.UUID {
		return label.ID
	})

	err = l.labelRepository.CreateLabelAttachmentBatch(ctx, tx, foundLabelIDs, projectID, assetID, artifactID)
	return err
}
