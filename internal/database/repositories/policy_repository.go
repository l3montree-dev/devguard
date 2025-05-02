package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type policyRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.Policy, core.DB]
}

func NewPolicyRepository(db core.DB) *policyRepository {
	if err := db.AutoMigrate(&models.Policy{}); err != nil {
		panic(err)
	}
	return &policyRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Policy](db),
	}
}

func (r *policyRepository) FindByProjectId(projectId uuid.UUID) ([]models.Policy, error) {
	// we need to use the project_enabled_policies pivot table to get the policies for a project
	var policies []models.Policy
	if err := r.db.Joins("JOIN project_enabled_policies ON project_enabled_policies.policy_id = policies.id").
		Where("project_enabled_policies.project_id = ?", projectId).
		Find(&policies).Error; err != nil {
		return nil, err
	}

	return policies, nil
}

func (r *policyRepository) FindByOrganizationId(organizationId uuid.UUID) ([]models.Policy, error) {
	var policies []models.Policy
	if err := r.db.Find(&policies, "organization_id = ?", organizationId).Error; err != nil {
		return nil, err
	}
	return policies, nil
}
