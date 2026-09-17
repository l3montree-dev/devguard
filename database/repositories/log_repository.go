package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type logRepository struct {
	utils.Repository[uuid.UUID, models.Log, *gorm.DB]
}

func NewLogRepository(db *gorm.DB) *logRepository {
	return &logRepository{
		Repository: newGormRepository[uuid.UUID, models.Log](db),
	}
}

func (r logRepository) Save(ctx context.Context, tx *gorm.DB, log *models.Log) error {
	return r.Repository.GetDB(ctx, tx).Save(log).Error
}

func (r logRepository) ListPaged(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[dtos.LogDTO], error) {
	var count int64
	logs := []dtos.LogDTO{}

	q := r.Repository.GetDB(ctx, tx).Model(&models.Log{}).Where("logs.org_id = ?", orgID)

	switch {
	case assetID != nil && projectID != nil:
		q = q.Where("logs.asset_id = ? AND logs.project_id = ?", *assetID, *projectID)
	case projectID != nil:
		// include the project itself and all of its (transitive) child projects
		q = q.Where(`logs.project_id IN (
			WITH RECURSIVE project_tree AS (
				SELECT id FROM projects WHERE id = ?
				UNION ALL
				SELECT p.id FROM projects p INNER JOIN project_tree pt ON p.parent_id = pt.id
			)
			SELECT id FROM project_tree
		)`, *projectID)
	}

	q = q.Joins("LEFT JOIN projects p ON p.id = logs.project_id").
		Joins("LEFT JOIN assets a ON a.id = logs.asset_id")

	if search != "" {
		searchPattern := "%" + search + "%"
		q = q.Where("logs.message ILIKE ? OR p.name ILIKE ? OR a.name ILIKE ?", searchPattern, searchPattern, searchPattern)
	}

	for _, f := range filter {
		q = f.Where(q)
	}

	err := q.Session(&gorm.Session{}).Count(&count).Error
	if err != nil {
		return shared.Paged[dtos.LogDTO]{}, err
	}

	findQuery := q.Session(&gorm.Session{}).
		Select("logs.*, p.name AS project_name, a.name AS asset_name")

	if len(sort) > 0 {
		for _, s := range sort {
			findQuery = s.Order(findQuery)
		}
	} else {
		findQuery = findQuery.Order("logs.created_at DESC")
	}

	if err := findQuery.
		Limit(pageInfo.PageSize).
		Offset((pageInfo.Page - 1) * pageInfo.PageSize).
		Find(&logs).Error; err != nil {
		return shared.Paged[dtos.LogDTO]{}, err
	}

	return shared.NewPaged(pageInfo, count, logs), nil
}
