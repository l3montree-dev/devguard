package compliance

import (
	"context"
	"log/slog"

	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm/clause"
)

func LoadControlsIntoDB(tx shared.DB) error {
	controls, err := loadGrundschutzControls()
	if err != nil {
		return err
	}

	tx.Exec(`TRUNCATE TABLE mapped_controls CASCADE;
	TRUNCATE TABLE frameworks_controls CASCADE;
	`)
	// truncate the tables before seeding to av
	if err := tx.CreateInBatches(&controls, 100).Error; err != nil {
		return err
	}
	slog.Info("seeded Grundschutz++ controls", "count", len(controls))

	controls, err = loadISO27001Controls()
	if err != nil {
		return err
	}
	if err := tx.WithContext(context.Background()).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "framework"}, {Name: "control_id"}},
		UpdateAll: true,
	}).CreateInBatches(&controls, 100).Error; err != nil {
		return err
	}
	slog.Info("seeded ISO27001 controls", "count", len(controls))

	controls, err = loadLieferkettensicherheitControls()
	if err != nil {
		return err
	}
	if err := tx.WithContext(context.Background()).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "framework"}, {Name: "control_id"}},
		UpdateAll: true,
	}).CreateInBatches(&controls, 100).Error; err != nil {
		return err
	}
	slog.Info("seeded Lieferkettensicherheit controls", "count", len(controls))

	controls, err = loadBSIAnforderungenZumRisikomanagementControls()
	if err != nil {
		return err
	}
	if err := tx.WithContext(context.Background()).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "framework"}, {Name: "control_id"}},
		UpdateAll: true,
	}).CreateInBatches(&controls, 100).Error; err != nil {
		return err
	}
	slog.Info("seeded BSI Anforderungen zum Risikomanagement controls", "count", len(controls))

	mappingCollection, err := loadISO27001ToGSPlusPlusMappingCollection()
	if err != nil {
		return err
	}
	grundschutzMapping, err := loadGrundschutzToGSPlusPlusMappingCollection()
	if err != nil {
		return err
	}
	mappingCollection = append(mappingCollection, grundschutzMapping...)

	if err := tx.WithContext(context.Background()).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "framework_control_id"}, {Name: "related_framework"}, {Name: "related_control_id"}, {Name: "relationship"}},
		UpdateAll: true,
	}).CreateInBatches(&mappingCollection, 100).Error; err != nil {
		return err
	}
	slog.Info("seeded ISO27001 to Grundschutz++ mappings", "count", len(mappingCollection))
	slog.Info("seeded Grundschutz to Grundschutz++ mappings", "count", len(grundschutzMapping))

	/*
		controls, err = loadSCFControls()
		if err != nil {
			return err
		}
		if err := db.WithContext(context.Background()).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "framework"}, {Name: "control_id"}},
			UpdateAll: true,
		}).CreateInBatches(&controls, 100).Error; err != nil {
			return err
		}
		slog.Info("seeded SCF controls", "count", len(controls))

	*/

	components, err := loadDevGuardComplianceComponents()
	if err != nil {
		return err
	}
	if err := tx.WithContext(context.Background()).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "uuid"}},
		UpdateAll: true,
	}).CreateInBatches(&components, 100).Error; err != nil {
		return err
	}
	slog.Info("seeded DevGuard compliance components", "count", len(components))

	return nil
}
