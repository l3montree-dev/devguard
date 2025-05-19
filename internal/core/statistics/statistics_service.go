package statistics

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type service struct {
	statisticsRepository         core.StatisticsRepository
	componentRepository          core.ComponentRepository
	assetRiskHistoryRepository   core.AssetRiskHistoryRepository
	dependencyVulnRepository     core.DependencyVulnRepository
	assetVersionRepository       core.AssetVersionRepository
	projectRepository            core.ProjectRepository
	projectRiskHistoryRepository core.ProjectRiskHistoryRepository
}

func NewService(statisticsRepository core.StatisticsRepository, componentRepository core.ComponentRepository, assetRiskHistoryRepository core.AssetRiskHistoryRepository, dependencyVulnRepository core.DependencyVulnRepository, assetVersionRepository core.AssetVersionRepository, projectRepository core.ProjectRepository, projectRiskHistoryRepository core.ProjectRiskHistoryRepository) *service {
	return &service{
		statisticsRepository:         statisticsRepository,
		componentRepository:          componentRepository,
		assetRiskHistoryRepository:   assetRiskHistoryRepository,
		dependencyVulnRepository:     dependencyVulnRepository,
		assetVersionRepository:       assetVersionRepository,
		projectRepository:            projectRepository,
		projectRiskHistoryRepository: projectRiskHistoryRepository,
	}
}

func (s *service) GetAssetVersionRiskHistory(assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error) {
	return s.assetRiskHistoryRepository.GetRiskHistory(assetVersionName, assetID, start, end)
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

		openDependencyVulns, fixedDependencyVulns := 0, 0

		for _, assetHistory := range assetsHistory {
			if assetHistory.OpenDependencyVulns > 0 {
				openDependencyVulns += assetHistory.OpenDependencyVulns
			} else if assetHistory.FixedDependencyVulns > 0 {
				fixedDependencyVulns += assetHistory.FixedDependencyVulns
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

		if openDependencyVulns != 0 {
			openRisk.Avg = openRisk.Sum / float64(openDependencyVulns)
		}

		if fixedDependencyVulns != 0 {
			fixedRisk.Avg = fixedRisk.Sum / float64(fixedDependencyVulns)
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

			OpenDependencyVulns:  openDependencyVulns,
			FixedDependencyVulns: fixedDependencyVulns,
		}
		err = s.projectRiskHistoryRepository.UpdateRiskAggregation(&projectRiskHistory)
		if err != nil {
			return fmt.Errorf("could not update project risk aggregation: %w", err)
		}
	}
	return nil
}

func (s *service) UpdateAssetRiskAggregation(assetVersion *models.AssetVersion, assetID uuid.UUID, begin time.Time, end time.Time, propagateToProject bool) error {
	// set begin to last second of date
	begin = time.Date(begin.Year(), begin.Month(), begin.Day(), 23, 59, 59, 0, time.UTC)
	// as max, do 1 year from the past
	if begin.Before(time.Now().AddDate(-1, 0, 0)) {
		begin = time.Now().AddDate(-1, 0, 0)
	}

	// set end to last second of date
	end = time.Date(end.Year(), end.Month(), end.Day(), 23, 59, 59, 0, time.UTC)

	for time := begin; time.Before(end) || time.Equal(end); time = time.AddDate(0, 0, 1) {
		dependencyVulns, err := s.statisticsRepository.TimeTravelDependencyVulnState(assetVersion.Name, assetID, time)
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

		openDependencyVulns, fixedDependencyVulns := 0, 0

		for _, dependencyVuln := range dependencyVulns {
			var key string
			if dependencyVuln.State == models.VulnStateOpen {
				openDependencyVulns++
				key = "open"

			} else {
				fixedDependencyVulns++
				key = "fixed"
			}

			riskAggregation := risks[key]

			if riskAggregation.Min == -1.0 {
				riskAggregation.Min = utils.OrDefault(dependencyVuln.RawRiskAssessment, -1)
			}

			risk := utils.OrDefault(dependencyVuln.RawRiskAssessment, 0)

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

		if openDependencyVulns != 0 {
			openRisk.Avg = openRisk.Sum / float64(openDependencyVulns)
		}

		if fixedDependencyVulns != 0 {
			fixedRisk.Avg = fixedRisk.Sum / float64(fixedDependencyVulns)
		}

		result := models.AssetRiskHistory{
			AssetVersionName: assetVersion.Name,
			AssetID:          assetID,
			Day:              time,

			SumOpenRisk: openRisk.Sum,
			AvgOpenRisk: openRisk.Avg,
			MaxOpenRisk: openRisk.Max,
			MinOpenRisk: openRisk.Min,

			SumClosedRisk: fixedRisk.Sum,
			AvgClosedRisk: fixedRisk.Avg,
			MaxClosedRisk: fixedRisk.Max,
			MinClosedRisk: fixedRisk.Min,

			OpenDependencyVulns:  openDependencyVulns,
			FixedDependencyVulns: fixedDependencyVulns,
		}

		err = s.assetRiskHistoryRepository.UpdateRiskAggregation(&result)
		if err != nil {
			return err
		}
		slog.Info("updated risk aggregation", "assetVersionName", assetVersion.Name, "assetID", assetID, "day", time)
	}

	// save the last history update timestamp
	assetVersion.LastHistoryUpdate = &end

	// we ALWAYS need to propagate the risk aggregation to the project. The only exception is in the statistics daemon. There
	// we update all assets and afterwards do a one time project update. This is just optimization.
	if propagateToProject {
		currentProject, err := s.projectRepository.GetProjectByAssetID(assetID)

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
	return nil

}

func (s *service) GetAssetVersionRiskDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	return s.statisticsRepository.GetAssetRiskDistribution(assetVersionName, assetID, assetName)
}

func (s *service) GetAssetVersionCvssDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	return s.statisticsRepository.GetAssetCvssDistribution(assetVersionName, assetID, assetName)
}

func (s *service) GetProjectRiskHistory(projectID uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error) {
	return s.projectRiskHistoryRepository.GetRiskHistory(projectID, start, end)
}

func (s *service) GetComponentRisk(assetVersionName string, assetID uuid.UUID) (map[string]float64, error) {

	dependencyVulns, err := s.dependencyVulnRepository.GetAllOpenVulnsByAssetVersionNameAndAssetId(nil, assetVersionName, assetID)
	if err != nil {
		return nil, err
	}

	totalRiskPerComponent := make(map[string]float64)

	for _, f := range dependencyVulns {
		damagedPkg := f.ComponentPurl
		parts := strings.Split(*damagedPkg, ":")
		damagedPkg = &parts[1]
		totalRiskPerComponent[*damagedPkg] += utils.OrDefault(f.RawRiskAssessment, 0)
	}

	return totalRiskPerComponent, nil
}

func (s *service) GetDependencyVulnCountByScannerId(assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
	return s.statisticsRepository.GetDependencyVulnCountByScannerId(assetVersionName, assetID)
}

func (s *service) GetDependencyCountPerscanner(assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
	return s.componentRepository.GetDependencyCountPerScanner(assetVersionName, assetID)
}

func (s *service) GetAverageFixingTime(assetVersionName string, assetID uuid.UUID, severity string) (time.Duration, error) {
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

	return s.statisticsRepository.AverageFixingTime(assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)
}

func (s *service) GetDependencyVulnAggregationStateAndChangeSince(assetVersionName string, assetID uuid.UUID, calculateChangeTo time.Time) (DependencyVulnAggregationStateAndChange, error) {
	// check if calculateChangeTo is in the future
	if calculateChangeTo.After(time.Now()) {
		return DependencyVulnAggregationStateAndChange{}, fmt.Errorf("Cannot calculate change to the future")
	}

	results := utils.Concurrently(
		func() (any, error) {
			return s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersionName, assetID, "")
		},
		func() (any, error) {
			return s.statisticsRepository.TimeTravelDependencyVulnState(assetVersionName, assetID, calculateChangeTo)
		},
	)

	if results.HasErrors() {
		return DependencyVulnAggregationStateAndChange{}, results.Error()
	}

	now := results.GetValue(0).([]models.DependencyVuln)
	was := results.GetValue(1).([]models.DependencyVuln)

	nowState := calculateDependencyVulnAggregationState(now)
	wasState := calculateDependencyVulnAggregationState(was)

	return DependencyVulnAggregationStateAndChange{
		Now: nowState,
		Was: wasState,
	}, nil
}

func calculateDependencyVulnAggregationState(dependencyVulns []models.DependencyVuln) DependencyVulnAggregationState {
	state := DependencyVulnAggregationState{}

	for _, dependencyVuln := range dependencyVulns {
		if dependencyVuln.State == models.VulnStateOpen {
			state.Open++
		} else {
			state.Fixed++
		}
	}

	return state
}
