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
	return &policyRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Policy](db),
	}
}

func (r *policyRepository) FindByProjectID(projectID uuid.UUID) ([]models.Policy, error) {
	// we need to use the project_enabled_policies pivot table to get the policies for a project
	var policies []models.Policy
	if err := r.db.Joins("JOIN project_enabled_policies ON project_enabled_policies.policy_id = policies.id").
		Where("project_enabled_policies.project_id = ?", projectID).
		Find(&policies).Error; err != nil {
		return nil, err
	}

	return policies, nil
}

func (r *policyRepository) FindCommunityManagedPolicies() ([]models.Policy, error) {
	// where organization id is nil
	var policies []models.Policy
	if err := r.db.Where("organization_id IS NULL").Find(&policies).Error; err != nil {
		return nil, err
	}
	return policies, nil
}

func (r *policyRepository) FindByOrganizationID(organizationID uuid.UUID) ([]models.Policy, error) {
	var policies []models.Policy
	if err := r.db.Find(&policies, "organization_id = ?", organizationID).Error; err != nil {
		return nil, err
	}
	return policies, nil
}
