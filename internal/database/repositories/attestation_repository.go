package repositories

import (
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm/clause"
)

type attestationRepository struct {
	db core.DB
	common.Repository[string, models.Attestation, core.DB]
}

func NewAttestationRepository(db core.DB) *attestationRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		err := db.AutoMigrate(&models.Attestation{})
		if err != nil {
			panic(err)
		}
	}
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

func (a *attestationRepository) Create(db core.DB, attestation *models.Attestation) error {
	return a.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "predicate_type"},
			{Name: "scanner_id"},
			{Name: "asset_version_name"},
			{Name: "asset_id"},
		},
		DoUpdates: clause.AssignmentColumns([]string{"content"}),
	}).Create(attestation).Error
}
