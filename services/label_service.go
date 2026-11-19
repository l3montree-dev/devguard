package services

import (
	"context"
	"fmt"
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

	label, err := l.labelRepository.Read(ctx, tx, *labelID)
	if err != nil {
		return err
	}
	if !label.IsVisibleFrom(orgID, projectID, assetID) {
		return shared.ErrLabelNotInScope
	}

	var res *gorm.DB
	switch {
	case artifactID != nil:
		res = tx.Exec("INSERT INTO projects_assets_artifacts_labels (project_id, asset_id, artifact_id, label_id) VALUES (NULL, NULL, ?, ?) ON CONFLICT DO NOTHING",
			artifactID, labelID)
	case assetID != nil:
		res = tx.Exec("INSERT INTO projects_assets_artifacts_labels (project_id, asset_id, artifact_id, label_id) VALUES (NULL, ?, NULL, ?) ON CONFLICT DO NOTHING",
			assetID, labelID)
	default:
		res = tx.Exec("INSERT INTO projects_assets_artifacts_labels (project_id, asset_id, artifact_id, label_id) VALUES (?, NULL, NULL, ?) ON CONFLICT DO NOTHING",
			projectID, labelID)
	}
	return res.Error
}
