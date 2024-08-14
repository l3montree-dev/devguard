package statistics

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type statisticsRepository interface {
	TimeTravelFlawState(assetID uuid.UUID, time time.Time) ([]models.Flaw, error)
	GetAssetRiskDistribution(assetID uuid.UUID) ([]models.AssetRiskDistribution, error)
	GetFlawCountByScannerId(assetID uuid.UUID) (map[string]int, error)
	AverageFixingTime(assetID uuid.UUID, riskIntervalStart, riskIntervalEnd float64) (time.Duration, error)
}

type componentRepository interface {
	GetDependencyCountPerScanType(assetID uuid.UUID) (map[string]int, error)
}
type assetRiskHistoryRepository interface {
	GetRiskHistory(assetId uuid.UUID, start, end time.Time) ([]models.AssetRiskHistory, error)
	UpdateRiskAggregation(assetRisk *models.AssetRiskHistory) error
}

type flawRepository interface {
	GetAllOpenFlawsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.Flaw, error)
	GetAllFlawsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.Flaw, error)
}

type service struct {
	statisticsRepository       statisticsRepository
	componentRepository        componentRepository
	assetRiskHistoryRepository assetRiskHistoryRepository
	flawRepository             flawRepository
}

func NewService(statisticsRepository statisticsRepository, componentRepository componentRepository, assetRiskHistoryRepository assetRiskHistoryRepository, flawRepository flawRepository) *service {
	return &service{
		statisticsRepository:       statisticsRepository,
		componentRepository:        componentRepository,
		assetRiskHistoryRepository: assetRiskHistoryRepository,
		flawRepository:             flawRepository,
	}
}

func (s *service) UpdateAssetRiskAggregation(assetID uuid.UUID, begin time.Time, end time.Time) error {
	for time := begin; time.Before(end); time = time.AddDate(0, 0, 1) {
		flaws, err := s.statisticsRepository.TimeTravelFlawState(assetID, time)
		if err != nil {
			return err
		}

		risks := map[string]struct {
			Min float64
			Max float64
			Sum float64
			Avg float64
		}{
			"open":  {Min: -1.0, Max: 0.0, Sum: 0.0, Avg: 0.0},
			"fixed": {Min: -1.0, Max: 0.0, Sum: 0.0, Avg: 0.0},
		}

		openFlaws, fixedFlaws := 0, 0

		for _, flaw := range flaws {
			var key string
			if flaw.State == models.FlawStateOpen {
				openFlaws++
				key = "open"
			} else {
				fixedFlaws++
				key = "fixed"
			}

			riskAggregation := risks[key]

			if riskAggregation.Min == -1.0 {
				riskAggregation.Min = utils.OrDefault(flaw.RawRiskAssessment, -1)
			}

			risk := utils.OrDefault(flaw.RawRiskAssessment, 0)

			if riskAggregation.Min <= risk {
				riskAggregation.Min = risk
			}

			riskAggregation.Sum += risk
			if risk > riskAggregation.Max {
				riskAggregation.Max = risk
			}

			risks[key] = riskAggregation
		}

		openRisk := risks["open"]
		fixedRisk := risks["fixed"]

		if openRisk.Min == -1.0 {
			openRisk.Min = 0.0
		}
		if fixedRisk.Min == -1.0 {
			fixedRisk.Min = 0.0
		}

		if openFlaws != 0 {
			openRisk.Avg = openRisk.Sum / float64(openFlaws)
		}

		if fixedFlaws != 0 {
			fixedRisk.Avg = fixedRisk.Sum / float64(fixedFlaws)
		}

		result := models.AssetRiskHistory{
			AssetID: assetID,
			Day:     time,

			SumOpenRisk: openRisk.Sum,
			AvgOpenRisk: openRisk.Avg,
			MaxOpenRisk: openRisk.Max,
			MinOpenRisk: openRisk.Min,

			SumClosedRisk: fixedRisk.Sum,
			AvgClosedRisk: fixedRisk.Avg,
			MaxClosedRisk: fixedRisk.Max,
			MinClosedRisk: fixedRisk.Min,

			OpenFlaws:  openFlaws,
			FixedFlaws: fixedFlaws,
		}

		err = s.assetRiskHistoryRepository.UpdateRiskAggregation(&result)
		if err != nil {
			return err
		}

	}
	return nil

}

func (s *service) GetAssetRiskHistory(assetID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error) {
	return s.assetRiskHistoryRepository.GetRiskHistory(assetID, start, end)
}

func (s *service) GetAssetRiskDistribution(assetID uuid.UUID) ([]models.AssetRiskDistribution, error) {
	riskDistribution, err := s.statisticsRepository.GetAssetRiskDistribution(assetID)
	if err != nil {
		return nil, err
	}

	return riskDistribution, nil
}

func (s *service) GetComponentRisk(assetID uuid.UUID) (map[string]float64, error) {
	flaws, err := s.flawRepository.GetAllOpenFlawsByAssetID(nil, assetID)
	if err != nil {
		return nil, err
	}

	totalRiskPerComponent := make(map[string]float64)

	for _, f := range flaws {
		damagedPkg := f.ComponentPurl
		parts := strings.Split(damagedPkg, ":")
		damagedPkg = parts[1]
		totalRiskPerComponent[damagedPkg] += utils.OrDefault(f.RawRiskAssessment, 0)
	}

	return totalRiskPerComponent, nil
}

func (s *service) GetFlawCountByScannerId(assetID uuid.UUID) (map[string]int, error) {
	return s.statisticsRepository.GetFlawCountByScannerId(assetID)
}

func (s *service) GetDependencyCountPerScanType(assetID uuid.UUID) (map[string]int, error) {
	return s.componentRepository.GetDependencyCountPerScanType(assetID)
}

func (s *service) GetAverageFixingTime(assetID uuid.UUID, severity string) (time.Duration, error) {
	var riskIntervalStart, riskIntervalEnd float64
	if severity == "critical" {
		riskIntervalStart = 9
		riskIntervalEnd = 10
	} else if severity == "high" {
		riskIntervalStart = 7
		riskIntervalEnd = 9
	} else if severity == "medium" {
		riskIntervalStart = 4
		riskIntervalEnd = 7
	} else if severity == "low" {
		riskIntervalStart = 0
		riskIntervalEnd = 4
	}

	return s.statisticsRepository.AverageFixingTime(assetID, riskIntervalStart, riskIntervalEnd)
}

func (s *service) GetFlawAggregationStateAndChangeSince(assetID uuid.UUID, calculateChangeTo time.Time) (flawAggregationStateAndChange, error) {
	// check if calculateChangeTo is in the future
	if calculateChangeTo.After(time.Now()) {
		return flawAggregationStateAndChange{}, fmt.Errorf("Cannot calculate change to the future")
	}

	results := utils.Concurrently(
		func() (any, error) {
			return s.flawRepository.GetAllFlawsByAssetID(nil, assetID)
		},
		func() (any, error) {
			return s.statisticsRepository.TimeTravelFlawState(assetID, calculateChangeTo)
		},
	)

	if results.HasErrors() {
		return flawAggregationStateAndChange{}, results.Error()
	}

	now := results.GetValue(0).([]models.Flaw)
	was := results.GetValue(1).([]models.Flaw)

	nowState := calculateFlawAggregationState(now)
	wasState := calculateFlawAggregationState(was)

	return flawAggregationStateAndChange{
		Now: nowState,
		Was: wasState,
	}, nil
}

func calculateFlawAggregationState(flaws []models.Flaw) flawAggregationState {
	state := flawAggregationState{}

	for _, flaw := range flaws {
		if flaw.State == models.FlawStateOpen {
			state.Open++
		} else {
			state.Fixed++
		}
	}

	return state
}
