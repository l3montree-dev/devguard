package statistics

import (
	"log/slog"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type assetRepository interface {
	GetAllAssetsFromDB() ([]models.Asset, error)
	Save(tx core.DB, asset *models.Asset) error
	GetByProjectID(projectID uuid.UUID) ([]models.Asset, error)
}

type daemon struct {
	statisticsService statisticsService
	assetRepository   assetRepository
}

func NewDaemon(assetRepo assetRepository, statisticsService statisticsService) daemon {
	return daemon{
		assetRepository:   assetRepo,
		statisticsService: statisticsService,
	}
}

func (daemon daemon) Start() {
	updateFn := func() {
		assets, err := daemon.assetRepository.GetAllAssetsFromDB()

		if err != nil {
			slog.Error("could not get assets from database", "err", err)
			return
		}

		for _, asset := range assets {
			a := asset
			t := time.Now()
			slog.Info("recalculating risk history for asset", "asset", asset.ID)
			if err := daemon.statisticsService.UpdateAssetRiskAggregation(asset.ID, utils.OrDefault(asset.LastHistoryUpdate, asset.CreatedAt), t); err != nil {
				slog.Error("could not recalculate risk history", "err", err)
				continue
			}
			// save the new LastHistoryUpdate timestamp
			asset.LastHistoryUpdate = &t
			// save the asset
			if err := daemon.assetRepository.Save(nil, &a); err != nil {
				slog.Error("could not save asset", "err", err)
				continue
			}
			slog.Info("finished calculation of risk history for asset", "asset", a.ID, "duration", time.Since(t))
		}
	}
	go func() {
		// run on startup
		updateFn()
		for range time.NewTicker(time.Hour + time.Duration(rand.Intn(60))*time.Minute).C { //nolint:all:We can use a weak random number generator here
			go updateFn()
		}
	}()
}
