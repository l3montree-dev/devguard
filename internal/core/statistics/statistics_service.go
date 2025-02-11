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

type assetVersionRepository interface {
	GetAllAssetsVersionFromDB(tx core.DB) ([]models.AssetVersion, error)
	Save(tx core.DB, asset *models.AssetVersion) error
	GetDefaultAssetVersionsByProjectID(projectID uuid.UUID) ([]models.AssetVersion, error)
	GetDefaultAssetVersionsByProjectIDs(projectIDs []uuid.UUID) ([]models.AssetVersion, error)
}

type assetRepository interface {
	GetByAssetID(assetID uuid.UUID) (models.AssetNew, error)
}

type statisticsRepository interface {
	TimeTravelFlawState(assetVersionID uuid.UUID, time time.Time) ([]models.Flaw, error)
	GetAssetRiskDistribution(assetVersionID uuid.UUID, assetVersionName string) (models.AssetRiskDistribution, error)
	GetFlawCountByScannerId(assetVersionID uuid.UUID) (map[string]int, error)
	AverageFixingTime(assetVersionID uuid.UUID, riskIntervalStart, riskIntervalEnd float64) (time.Duration, error)
}

type componentRepository interface {
	GetDependencyCountPerscanner(assetVersionID uuid.UUID) (map[string]int, error)
}
type assetRiskHistoryRepository interface {
	GetRiskHistory(assetId uuid.UUID, start, end time.Time) ([]models.AssetRiskHistory, error)
	GetRiskHistoryByProject(projectId uuid.UUID, day time.Time) ([]models.AssetRiskHistory, error)
	UpdateRiskAggregation(assetRisk *models.AssetRiskHistory) error
}

type flawRepository interface {
	GetAllOpenFlawsByAssetVersionID(tx core.DB, assetVersionID uuid.UUID) ([]models.Flaw, error)
	GetFlawsByAssetVersionId(tx core.DB, assetVersionID uuid.UUID) ([]models.Flaw, error)
}

type projectRepository interface {
	GetProjectByAssetVersionID(assetVersionID uuid.UUID) (models.Project, error)
	RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error)
	Read(id uuid.UUID) (models.Project, error)
}

type projectRiskHistoryRepository interface {
	GetRiskHistory(projectId uuid.UUID, start, end time.Time) ([]models.ProjectRiskHistory, error)
	UpdateRiskAggregation(projectRisk *models.ProjectRiskHistory) error
}

type service struct {
	statisticsRepository         statisticsRepository
	componentRepository          componentRepository
	assetRiskHistoryRepository   assetRiskHistoryRepository
	flawRepository               flawRepository
	assetVersionRepository       assetVersionRepository
	projectRepository            projectRepository
	projectRiskHistoryRepository projectRiskHistoryRepository
}

func NewService(statisticsRepository statisticsRepository, componentRepository componentRepository, assetRiskHistoryRepository assetRiskHistoryRepository, flawRepository flawRepository, assetVersionRepository assetVersionRepository, projectRepository projectRepository, projectRiskHistoryRepository projectRiskHistoryRepository) *service {
	return &service{
		statisticsRepository:         statisticsRepository,
		componentRepository:          componentRepository,
		assetRiskHistoryRepository:   assetRiskHistoryRepository,
		flawRepository:               flawRepository,
		assetVersionRepository:       assetVersionRepository,
		projectRepository:            projectRepository,
		projectRiskHistoryRepository: projectRiskHistoryRepository,
	}
}

func (s *service) GetAssetVersionRiskHistory(assetVersionID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error) {
	return s.assetRiskHistoryRepository.GetRiskHistory(assetVersionID, start, end)
}

func (s *service) updateProjectRiskAggregation(projectID uuid.UUID, begin, end time.Time) error {
	// set begin to last second of date
	begin = time.Date(begin.Year(), begin.Month(), begin.Day(), 23, 59, 59, 0, time.UTC)
	// set end to last second of date
	end = time.Date(end.Year(), end.Month(), end.Day(), 23, 59, 59, 0, time.UTC)

	// fetch all assets history for the project
	for time := begin; time.Before(end) || time.Equal(end); time = time.AddDate(0, 0, 1) {
		assetsHistory, err := s.assetRiskHistoryRepository.GetRiskHistoryByProject(projectID, time)

		if err != nil {
			return fmt.Errorf("could not get risk history by project: %w", err)
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
		riskAggregationOpen := risks["open"]
		riskAggregationFixed := risks["fixed"]

		var projectRiskHistory models.ProjectRiskHistory = models.ProjectRiskHistory{}

		openFlaws, fixedFlaws := 0, 0

		for _, assetHistory := range assetsHistory {
			if assetHistory.OpenFlaws > 0 {
				openFlaws += assetHistory.OpenFlaws
			} else if assetHistory.FixedFlaws > 0 {
				fixedFlaws += assetHistory.FixedFlaws
			}

			if riskAggregationOpen.Min > assetHistory.MinOpenRisk {
				riskAggregationOpen.Min = assetHistory.MinOpenRisk
			}

			if riskAggregationFixed.Min > assetHistory.MinClosedRisk {
				riskAggregationFixed.Min = assetHistory.MinClosedRisk
			}

			riskAggregationOpen.Sum += assetHistory.SumOpenRisk
			riskAggregationFixed.Sum += assetHistory.SumClosedRisk

			if assetHistory.MaxOpenRisk > riskAggregationOpen.Max {
				riskAggregationOpen.Max = assetHistory.MaxOpenRisk
			}

			if assetHistory.MaxClosedRisk > riskAggregationFixed.Max {
				riskAggregationFixed.Max = assetHistory.MaxClosedRisk
			}

		}

		openRisk := riskAggregationOpen
		fixedRisk := riskAggregationFixed

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

		projectRiskHistory = models.ProjectRiskHistory{
			ProjectID: projectID,
			Day:       time,

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
		err = s.projectRiskHistoryRepository.UpdateRiskAggregation(&projectRiskHistory)
		if err != nil {
			return fmt.Errorf("could not update project risk aggregation: %w", err)
		}

	}
	return nil
}

func (s *service) UpdateAssetRiskAggregation(assetVersionID uuid.UUID, begin time.Time, end time.Time, propagateToProject bool) error {
	// set begin to last second of date
	begin = time.Date(begin.Year(), begin.Month(), begin.Day(), 23, 59, 59, 0, time.UTC)
	// set end to last second of date
	end = time.Date(end.Year(), end.Month(), end.Day(), 23, 59, 59, 0, time.UTC)

	for time := begin; time.Before(end) || time.Equal(end); time = time.AddDate(0, 0, 1) {
		flaws, err := s.statisticsRepository.TimeTravelFlawState(assetVersionID, time)
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
			AssetVersionID: assetVersionID,
			Day:            time,

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

		// we ALWAYS need to propagate the risk aggregation to the project. The only exception is in the statistics daemon. There
		// we update all assets and afterwards do a one time project update. This is just optimization.
		if propagateToProject {
			currentProject, err := s.projectRepository.GetProjectByAssetVersionID(assetVersionID)

			if err != nil {
				return fmt.Errorf("could not get project id by asset id: %w", err)
			}
			for {
				// update all projects - parent projects as well.
				err = s.updateProjectRiskAggregation(currentProject.ID, begin, end)
				if err != nil {
					return fmt.Errorf("could not update project risk aggregation: %w", err)
				}

				if currentProject.ParentID != nil {
					currentProject, err = s.projectRepository.Read(*currentProject.ParentID)
					if err != nil {
						return fmt.Errorf("could not get parent project: %w", err)
					}
				} else {
					break
				}
			}
		}

	}
	return nil

}

func (s *service) GetAssetVersionRiskDistribution(assetVersionID uuid.UUID, assetVersionName string) (models.AssetRiskDistribution, error) {
	return s.statisticsRepository.GetAssetRiskDistribution(assetVersionID, assetVersionName)
}

func (s *service) GetProjectRiskHistory(projectID uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error) {
	return s.projectRiskHistoryRepository.GetRiskHistory(projectID, start, end)
}

func (s *service) GetComponentRisk(assetVersionID uuid.UUID) (map[string]float64, error) {
	flaws, err := s.flawRepository.GetAllOpenFlawsByAssetVersionID(nil, assetVersionID)
	if err != nil {
		return nil, err
	}

	totalRiskPerComponent := make(map[string]float64)

	for _, f := range flaws {
		damagedPkg := f.ComponentPurl
		parts := strings.Split(*damagedPkg, ":")
		damagedPkg = &parts[1]
		totalRiskPerComponent[*damagedPkg] += utils.OrDefault(f.RawRiskAssessment, 0)
	}

	return totalRiskPerComponent, nil
}

func (s *service) GetFlawCountByScannerId(assetVersionID uuid.UUID) (map[string]int, error) {
	return s.statisticsRepository.GetFlawCountByScannerId(assetVersionID)
}

func (s *service) GetDependencyCountPerscanner(assetVersionID uuid.UUID) (map[string]int, error) {
	return s.componentRepository.GetDependencyCountPerscanner(assetVersionID)
}

func (s *service) GetAverageFixingTime(assetVersionID uuid.UUID, severity string) (time.Duration, error) {
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

	return s.statisticsRepository.AverageFixingTime(assetVersionID, riskIntervalStart, riskIntervalEnd)
}

func (s *service) GetFlawAggregationStateAndChangeSince(assetVersionID uuid.UUID, calculateChangeTo time.Time) (FlawAggregationStateAndChange, error) {
	// check if calculateChangeTo is in the future
	if calculateChangeTo.After(time.Now()) {
		return FlawAggregationStateAndChange{}, fmt.Errorf("Cannot calculate change to the future")
	}

	results := utils.Concurrently(
		func() (any, error) {
			return s.flawRepository.GetFlawsByAssetVersionId(nil, assetVersionID)
		},
		func() (any, error) {
			return s.statisticsRepository.TimeTravelFlawState(assetVersionID, calculateChangeTo)
		},
	)

	if results.HasErrors() {
		return FlawAggregationStateAndChange{}, results.Error()
	}

	now := results.GetValue(0).([]models.Flaw)
	was := results.GetValue(1).([]models.Flaw)

	nowState := calculateFlawAggregationState(now)
	wasState := calculateFlawAggregationState(was)

	return FlawAggregationStateAndChange{
		Now: nowState,
		Was: wasState,
	}, nil
}

func calculateFlawAggregationState(flaws []models.Flaw) FlawAggregationState {
	state := FlawAggregationState{}

	for _, flaw := range flaws {
		if flaw.State == models.FlawStateOpen {
			state.Open++
		} else {
			state.Fixed++
		}
	}

	return state
}
