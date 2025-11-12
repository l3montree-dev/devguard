package repositories

import (
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm"
)

type componentOccurrenceRepository struct {
	db core.DB
}

func NewComponentOccurrenceRepository(db core.DB) *componentOccurrenceRepository {
	return &componentOccurrenceRepository{db: db}
}

func (repository *componentOccurrenceRepository) getDB(tx core.DB) core.DB {
	if tx != nil {
		return tx
	}
	return repository.db
}

func (repository *componentOccurrenceRepository) SearchComponentOccurrencesByOrg(tx core.DB, orgID uuid.UUID, pageInfo core.PageInfo, search string) (core.Paged[models.ComponentOccurrence], error) {
	occurrences := []models.ComponentOccurrence{}
	search = strings.TrimSpace(search)

	db := repository.getDB(tx)

	base := db.Table("component_dependencies").
		Joins("JOIN assets ON component_dependencies.asset_id = assets.id").
		Joins("JOIN projects ON assets.project_id = projects.id").
		Joins("JOIN organizations ON projects.organization_id = organizations.id").
		Joins("LEFT JOIN artifact_component_dependencies ON artifact_component_dependencies.component_dependency_id = component_dependencies.id").
		Where("projects.organization_id = ?", orgID).
		Where("component_dependencies.dependency_purl ILIKE ?", "%"+search+"%")

	var total int64
	if err := base.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return core.Paged[models.ComponentOccurrence]{}, err
	}

	if total == 0 {
		return core.NewPaged(pageInfo, 0, occurrences), nil
	}

	query := db.Table("component_dependencies").
		Select(`component_dependencies.id AS component_dependency_id,
            organizations.id AS organization_id,
            organizations.name AS organization_name,
            projects.id AS project_id,
            projects.name AS project_name,
            projects.slug AS project_slug,
            assets.id AS asset_id,
            assets.name AS asset_name,
            assets.slug AS asset_slug,
            component_dependencies.asset_version_name AS asset_version_name,
            component_dependencies.component_purl AS component_purl,
            component_dependencies.dependency_purl AS dependency_purl,
            components.version AS component_version,
            artifact_component_dependencies.artifact_artifact_name AS artifact_name,
            artifact_component_dependencies.artifact_asset_version_name AS artifact_asset_version_name`).
		Joins("JOIN assets ON component_dependencies.asset_id = assets.id").
		Joins("JOIN projects ON assets.project_id = projects.id").
		Joins("JOIN organizations ON projects.organization_id = organizations.id").
		Joins("LEFT JOIN artifact_component_dependencies ON artifact_component_dependencies.component_dependency_id = component_dependencies.id").
		Joins("LEFT JOIN components ON component_dependencies.component_purl = components.purl").
		Where("projects.organization_id = ?", orgID).
		Where("component_dependencies.dependency_purl ILIKE ?", "%"+search+"%").
		Order("component_dependencies.component_purl ASC, component_dependencies.asset_version_name ASC")

	if pageInfo.PageSize > 0 {
		page := pageInfo.Page
		if page < 1 {
			page = 1
		}
		offset := (page - 1) * pageInfo.PageSize
		query = query.Limit(pageInfo.PageSize).Offset(offset)
	}

	if err := query.Scan(&occurrences).Error; err != nil {
		return core.Paged[models.ComponentOccurrence]{}, err
	}

	return core.NewPaged(pageInfo, total, occurrences), nil
}
