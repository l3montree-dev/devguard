package compliance

import (
	"context"
	"log/slog"

	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm/clause"
)

func LoadControlsIntoDB(db shared.DB) error {
	controls, err := loadGrundschutzControls()
	if err != nil {
		return err
	}
	if err := db.WithContext(context.Background()).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "framework"}, {Name: "control_id"}},
		UpdateAll: true,
	}).CreateInBatches(&controls, 100).Error; err != nil {
		return err
	}
	slog.Info("seeded Grundschutz++ controls", "count", len(controls))

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
	return nil
}
