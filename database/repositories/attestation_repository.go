package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm/clause"
)

type attestationRepository struct {
	db shared.DB
	common.Repository[string, models.Attestation, shared.DB]
}

func NewAttestationRepository(db shared.DB) *attestationRepository {
	return &attestationRepository{
		db:         db,
		Repository: newGormRepository[string, models.Attestation](db),
	}
}

func (a *attestationRepository) GetByAssetID(assetID uuid.UUID) ([]models.Attestation, error) {
	var attestationList []models.Attestation
	err := a.db.Where("asset_id = ?", assetID).Find(&attestationList).Error
	if err != nil {
		return attestationList, err
	}
	return attestationList, nil
}

func (a *attestationRepository) GetByAssetVersionAndAssetID(assetID uuid.UUID, assetVersion string) ([]models.Attestation, error) {
	var attestationList []models.Attestation
	err := a.db.Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersion).Find(&attestationList).Error
	if err != nil {
		return attestationList, err
	}
	return attestationList, nil
}

func (a *attestationRepository) Create(db shared.DB, attestation *models.Attestation) error {
	return a.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "predicate_type"},
			{Name: "asset_version_name"},
			{Name: "asset_id"},
			{Name: "artifact_name"},
		},
		DoUpdates: clause.AssignmentColumns([]string{"content"}),
	}).Create(attestation).Error
}
