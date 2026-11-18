package services

import (
	"context"
	"log/slog"
	"slices"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
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

func (l *LabelService) ListOnOrgLevel(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]dtos.Label, error) {
	labels, err := l.labelRepository.ListOnOrgLevel(ctx, tx, orgID)
	if err != nil {
		return []dtos.Label{}, err
	}
	labelDTOs := utils.Map(labels, func(label models.Label) dtos.Label {
		textColor, err := utils.GetTextColorToBackgroundColor(label.BackgroundColor)
		if err != nil {
			slog.Warn("text color could not be established", "err", err, "labelID", label.ID)
		}
		return transformer.LabelToDTO(label, textColor)
	})
	return labelDTOs, nil
}

func (l *LabelService) ListOnProjectLevel(ctx context.Context, tx *gorm.DB, orgID, projectID uuid.UUID) ([]dtos.Label, error) {
	orgScoped, err := l.ListOnOrgLevel(ctx, tx, orgID)
	if err != nil {
		return []dtos.Label{}, err
	}
	var projectScoped []models.Label
	projectScoped, err = l.labelRepository.ListOnProjectLevel(ctx, tx, orgID, projectID)
	if err != nil {
		return []dtos.Label{}, err
	}
	labelDTOs := utils.Map(projectScoped, func(label models.Label) dtos.Label {
		textColor, err := utils.GetTextColorToBackgroundColor(label.BackgroundColor)
		if err != nil {
			slog.Warn("text color could not be established", "err", err, "labelID", label.ID)
		}
		return transformer.LabelToDTO(label, textColor)
	})
	labels := slices.Concat(orgScoped, labelDTOs)
	return labels, nil
}

func (l *LabelService) ListOnAssetLevel(ctx context.Context, tx *gorm.DB, orgID, projectID, assetID uuid.UUID) ([]dtos.Label, error) {
	projectScoped, err := l.ListOnProjectLevel(ctx, tx, orgID, projectID)
	if err != nil {
		return []dtos.Label{}, err
	}
	var assetScoped []models.Label
	assetScoped, err = l.labelRepository.ListOnAssetLevel(ctx, tx, orgID, projectID, assetID)
	if err != nil {
		return []dtos.Label{}, err
	}
	labelDTOs := utils.Map(assetScoped, func(label models.Label) dtos.Label {
		textColor, err := utils.GetTextColorToBackgroundColor(label.BackgroundColor)
		if err != nil {
			slog.Warn("text color could not be established", "err", err, "labelID", label.ID)
		}
		return transformer.LabelToDTO(label, textColor)
	})
	labels := slices.Concat(projectScoped, labelDTOs)
	return labels, nil
}
