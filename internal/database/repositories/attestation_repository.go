package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type attestationRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.Attestation, core.DB]
}

func NewAttestationRepository(db core.DB) *attestationRepository {
	err := db.AutoMigrate(&models.Attestation{})
	if err != nil {
		panic(err)
	}
	return &attestationRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Attestation](db),
	}
}
