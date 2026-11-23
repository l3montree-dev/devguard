package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type LabelRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.Label, *gorm.DB]
}

func NewLabelRepository(db *gorm.DB) *LabelRepository {
	return &LabelRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Label](db),
	}
}

func (l *LabelRepository) FindLabelByIDThroughHierarchy(ctx context.Context, tx *gorm.DB, labelID, orgID, projectID, assetID *uuid.UUID) (models.Label, error) {
	var label models.Label
	err := l.GetDB(ctx, tx).Where(`id = ? AND organization_id = ? AND ( 
	(project_id IS NULL AND asset_id IS NULL) OR 
	(project_id = ? AND asset_id IS NULL) OR 
	(project_id = ? AND asset_id = ?)
	)`, labelID, orgID, projectID, projectID, assetID).First(&label).Error
	if err != nil {
		return models.Label{}, err
	}
	return label, nil
}

func (l *LabelRepository) ListThroughHierarchy(ctx context.Context, tx *gorm.DB, orgID, projectID, assetID *uuid.UUID) ([]models.Label, error) {
	var labels []models.Label
	err := l.GetDB(ctx, tx).Where(`organization_id = ? AND(
	(project_id IS NULL AND asset_id IS NULL) OR 
	(project_id = ? AND asset_id IS NULL) OR 
	(project_id = ? AND asset_id = ?)
	)`,
		orgID, projectID, projectID, assetID).Find(&labels).Error
	if err != nil {
		return []models.Label{}, err
	}
	return labels, nil
}

func (l *LabelRepository) CreateLabelAttachment(ctx context.Context, tx *gorm.DB, labelID, projectID, assetID, artifactID *uuid.UUID) error {
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
