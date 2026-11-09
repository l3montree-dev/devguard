package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type attestationRepository struct {
	db *gorm.DB
	utils.Repository[string, models.Attestation, *gorm.DB]
}

var _ shared.AttestationRepository = (*attestationRepository)(nil) // Ensure attestationRepository implements shared.AttestationRepository interface

func NewAttestationRepository(db *gorm.DB) *attestationRepository {
	return &attestationRepository{
		db:         db,
		Repository: newGormRepository[string, models.Attestation](db),
	}
}

// joins the artifact and its asset version since their names are not stored on the attestation
func withAttestationArtifactNames(db *gorm.DB) *gorm.DB {
	return db.Model(&models.Attestation{}).
		Select("attestations.*, artifacts.artifact_name, av.name AS asset_version_name").
		Joins("JOIN artifacts ON artifacts.id = attestations.artifact_id").
		Joins("JOIN asset_versions av ON av.id = artifacts.asset_version_id")
}

func (a *attestationRepository) GetByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.Attestation, error) {
	var attestationList []models.Attestation
	err := withAttestationArtifactNames(a.GetDB(ctx, tx)).Where("attestations.asset_id = ?", assetID).Find(&attestationList).Error
	if err != nil {
		return attestationList, err
	}
	return attestationList, nil
}

func (a *attestationRepository) GetByAssetVersionID(ctx context.Context, tx *gorm.DB, assetVersionID uuid.UUID) ([]models.Attestation, error) {
	var attestationList []models.Attestation
	err := withAttestationArtifactNames(a.GetDB(ctx, tx)).Where("artifacts.asset_version_id = ?", assetVersionID).Find(&attestationList).Error
	if err != nil {
		return attestationList, err
	}
	return attestationList, nil
}

func (a *attestationRepository) Create(ctx context.Context, tx *gorm.DB, attestation *models.Attestation) error {
	return a.GetDB(ctx, tx).Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "predicate_type"},
			{Name: "artifact_id"},
		},
		DoUpdates: clause.AssignmentColumns([]string{"content"}),
	}).Create(attestation).Error
}
