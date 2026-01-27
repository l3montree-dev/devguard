package services

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

type statisticsService struct {
	statisticsRepository          shared.StatisticsRepository
	artifactRiskHistoryRepository shared.ArtifactRiskHistoryRepository
	dependencyVulnRepository      shared.DependencyVulnRepository
	assetVersionRepository        shared.AssetVersionRepository
}

func NewStatisticsService(statisticsRepository shared.StatisticsRepository, assetRiskHistoryRepository shared.ArtifactRiskHistoryRepository, dependencyVulnRepository shared.DependencyVulnRepository, assetVersionRepository shared.AssetVersionRepository) *statisticsService {
	return &statisticsService{
		statisticsRepository:          statisticsRepository,
		artifactRiskHistoryRepository: assetRiskHistoryRepository,
		dependencyVulnRepository:      dependencyVulnRepository,
		assetVersionRepository:        assetVersionRepository,
	}
}

func (s *statisticsService) GetComponentRisk(artifactName *string, assetVersionName string, assetID uuid.UUID) (map[string]models.Distribution, error) {
	dependencyVulns, err := s.dependencyVulnRepository.GetAllOpenVulnsByAssetVersionNameAndAssetID(nil, artifactName, assetVersionName, assetID)
	if err != nil {
		return nil, err
	}

	distributionPerComponent := make(map[string]models.Distribution)

	for _, dependencyVuln := range dependencyVulns {
		componentName := dependencyVuln.ComponentPurl
		if _, exists := distributionPerComponent[componentName]; !exists {
			distributionPerComponent[componentName] = models.Distribution{}
		}
		distribution := distributionPerComponent[componentName]

		risk := utils.OrDefault(dependencyVuln.RawRiskAssessment, 0)
		cvss := float64(dependencyVuln.CVE.CVSS)

		switch {
		case risk >= 0.0 && risk < 4.0:
			distribution.Low++
		case risk >= 4.0 && risk < 7.0:
			distribution.Medium++
		case risk >= 7.0 && risk < 9.0:
			distribution.High++
		case risk >= 9.0 && risk <= 10.0:
			distribution.Critical++
		}

		switch {
		case cvss >= 0.0 && cvss < 4.0:
			distribution.LowCVSS++
		case cvss >= 4.0 && cvss < 7.0:
			distribution.MediumCVSS++
		case cvss >= 7.0 && cvss < 9.0:
			distribution.HighCVSS++
		case cvss >= 9.0 && cvss <= 10.0:
			distribution.CriticalCVSS++
		}

		distributionPerComponent[componentName] = distribution
	}

	return distributionPerComponent, nil
}

func (s *statisticsService) GetArtifactRiskHistory(artifactName *string, assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistory, error) {
	return s.artifactRiskHistoryRepository.GetRiskHistory(artifactName, assetVersionName, assetID, start, end)
}

// project-level aggregation via project_risk_history has been removed.
// Previously this method aggregated per-project risk history from asset histories.
// That behavior was intentionally removed to focus statistics on artifact histories only.
// If project-level aggregation is required in future, reintroduce with a new storage model.

func (s *statisticsService) UpdateArtifactRiskAggregation(artifact *models.Artifact, assetID uuid.UUID, begin time.Time, end time.Time) error {
	// set begin to last second of date
	begin = time.Date(begin.Year(), begin.Month(), begin.Day(), 23, 59, 59, 0, time.UTC)
	// as max, do 1 year from the past
	if begin.Before(time.Now().AddDate(-1, 0, 0)) {
		begin = time.Now().AddDate(-1, 0, 0)
	}

	// set end to last second of date
	end = time.Date(end.Year(), end.Month(), end.Day(), 23, 59, 59, 0, time.UTC)

	for time := begin; time.Before(end) || time.Equal(end); time = time.AddDate(0, 0, 1) {
		dependencyVulns, err := s.statisticsRepository.TimeTravelDependencyVulnState(&artifact.ArtifactName, &artifact.AssetVersionName, assetID, time)
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
		var openVulns []models.DependencyVuln

		for _, dependencyVuln := range dependencyVulns {
			var key string
			if dependencyVuln.State == dtos.VulnStateOpen {
				openDependencyVulns++
				key = "open"
				openVulns = append(openVulns, dependencyVuln)
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

		// Calculate severity counts
		lowRisk, mediumRisk, highRisk, criticalRisk := calculateSeverityCountsByRisk(openVulns)
		lowCvss, mediumCvss, highCvss, criticalCvss := calculateSeverityCountsByCvss(openVulns)

		// Calculate unique CVE severity counts (deduplicated by CVE+PURL)
		uniqueLowRisk, uniqueMediumRisk, uniqueHighRisk, uniqueCriticalRisk := calculateUniqueSeverityCountsByRisk(openVulns)
		uniqueLowCvss, uniqueMediumCvss, uniqueHighCvss, uniqueCriticalCvss := calculateUniqueSeverityCountsByCvss(openVulns)

		result := models.ArtifactRiskHistory{
			ArtifactName:     artifact.ArtifactName,
			AssetVersionName: artifact.AssetVersionName,
			AssetID:          assetID,
			History: models.History{
				Day: time,

				SumOpenRisk: openRisk.Sum,
				AvgOpenRisk: openRisk.Avg,
				MaxOpenRisk: openRisk.Max,
				MinOpenRisk: openRisk.Min,

				SumClosedRisk:        fixedRisk.Sum,
				AvgClosedRisk:        fixedRisk.Avg,
				MaxClosedRisk:        fixedRisk.Max,
				MinClosedRisk:        fixedRisk.Min,
				OpenDependencyVulns:  openDependencyVulns,
				FixedDependencyVulns: fixedDependencyVulns,
				Distribution: models.Distribution{
					Low:      lowRisk,
					Medium:   mediumRisk,
					High:     highRisk,
					Critical: criticalRisk,

					LowCVSS:      lowCvss,
					MediumCVSS:   mediumCvss,
					HighCVSS:     highCvss,
					CriticalCVSS: criticalCvss,

					UniqueLow:      uniqueLowRisk,
					UniqueMedium:   uniqueMediumRisk,
					UniqueHigh:     uniqueHighRisk,
					UniqueCritical: uniqueCriticalRisk,

					UniqueLowCVSS:      uniqueLowCvss,
					UniqueMediumCVSS:   uniqueMediumCvss,
					UniqueHighCVSS:     uniqueHighCvss,
					UniqueCriticalCVSS: uniqueCriticalCvss,
				},
			},
		}

		err = s.artifactRiskHistoryRepository.UpdateRiskAggregation(&result)
		if err != nil {
			return err
		}
	}

	// save the last history update timestamp
	artifact.LastHistoryUpdate = &end
	err := s.assetVersionRepository.GetDB(nil).Save(artifact).Error
	if err != nil {
		return err
	}

	return nil
}

func (s *statisticsService) GetProjectRiskHistory(projectID uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error) {
	// project-level risk history storage was removed; return empty result for compatibility.
	return []models.ProjectRiskHistory{}, nil
}

// GetReleaseRiskHistory aggregates artifact risk histories for all artifacts included in the release tree
func (s *statisticsService) GetReleaseRiskHistory(releaseID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistory, error) {
	// Use a DB-level query to collect artifact histories for all artifacts present in the release tree.
	return s.artifactRiskHistoryRepository.GetRiskHistoryByRelease(releaseID, start, end)
}

func (s *statisticsService) GetAverageFixingTime(artifactName *string, assetVersionName string, assetID uuid.UUID, severity string) (time.Duration, error) {
	var riskIntervalStart, riskIntervalEnd float64
	switch severity {
	case "critical":
		riskIntervalStart = 9
		riskIntervalEnd = 10
	case "high":
		riskIntervalStart = 7
		riskIntervalEnd = 9
	case "medium":
		riskIntervalStart = 4
		riskIntervalEnd = 7
	case "low":
		riskIntervalStart = 0
		riskIntervalEnd = 4
	}

	return s.statisticsRepository.AverageFixingTime(artifactName, assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)
}

// GetAverageFixingTimeForRelease computes average fixing time across all artifacts included in the release tree
func (s *statisticsService) GetAverageFixingTimeForRelease(releaseID uuid.UUID, severity string) (time.Duration, error) {
	var riskIntervalStart, riskIntervalEnd float64
	switch severity {
	case "critical":
		riskIntervalStart = 9
		riskIntervalEnd = 10
	case "high":
		riskIntervalStart = 7
		riskIntervalEnd = 9
	case "medium":
		riskIntervalStart = 4
		riskIntervalEnd = 7
	case "low":
		riskIntervalStart = 0
		riskIntervalEnd = 4
	default:
		return 0, fmt.Errorf("invalid severity")
	}

	return s.statisticsRepository.AverageFixingTimeForRelease(releaseID, riskIntervalStart, riskIntervalEnd)
}

// GetAverageFixingTimeByCvss computes average fixing time based on CVSS severity levels
func (s *statisticsService) GetAverageFixingTimeByCvss(artifactName *string, assetVersionName string, assetID uuid.UUID, severity string) (time.Duration, error) {
	var cvssIntervalStart, cvssIntervalEnd float64
	switch severity {
	case "critical":
		cvssIntervalStart = 9
		cvssIntervalEnd = 10
	case "high":
		cvssIntervalStart = 7
		cvssIntervalEnd = 9
	case "medium":
		cvssIntervalStart = 4
		cvssIntervalEnd = 7
	case "low":
		cvssIntervalStart = 0
		cvssIntervalEnd = 4
	}

	return s.statisticsRepository.AverageFixingTimeByCvss(artifactName, assetVersionName, assetID, cvssIntervalStart, cvssIntervalEnd)
}

// GetAverageFixingTimeByCvssForRelease computes average fixing time across all artifacts included in the release tree based on CVSS
func (s *statisticsService) GetAverageFixingTimeByCvssForRelease(releaseID uuid.UUID, severity string) (time.Duration, error) {
	var cvssIntervalStart, cvssIntervalEnd float64
	switch severity {
	case "critical":
		cvssIntervalStart = 9
		cvssIntervalEnd = 10
	case "high":
		cvssIntervalStart = 7
		cvssIntervalEnd = 9
	case "medium":
		cvssIntervalStart = 4
		cvssIntervalEnd = 7
	case "low":
		cvssIntervalStart = 0
		cvssIntervalEnd = 4
	default:
		return 0, fmt.Errorf("invalid severity")
	}

	return s.statisticsRepository.AverageFixingTimeByCvssForRelease(releaseID, cvssIntervalStart, cvssIntervalEnd)
}

func calculateSeverityCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	for _, vuln := range dependencyVulns {
		risk := utils.OrDefault(vuln.RawRiskAssessment, 0)
		switch {
		case risk >= 0.0 && risk < 4.0:
			low++
		case risk >= 4.0 && risk < 7.0:
			medium++
		case risk >= 7.0 && risk < 9.0:
			high++
		case risk >= 9.0 && risk <= 10.0:
			critical++
		}
	}
	return
}

func calculateSeverityCountsByCvss(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	for _, vuln := range dependencyVulns {
		cvss := float64(vuln.CVE.CVSS)
		switch {
		case cvss >= 0.0 && cvss < 4.0:
			low++
		case cvss >= 4.0 && cvss < 7.0:
			medium++
		case cvss >= 7.0 && cvss < 9.0:
			high++
		case cvss >= 9.0 && cvss <= 10.0:
			critical++
		}
	}
	return
}

func calculateUniqueSeverityCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	seen := make(map[string]bool)
	for _, vuln := range dependencyVulns {
		key := vuln.CVEID + "|" + vuln.ComponentPurl
		if seen[key] {
			continue
		}
		seen[key] = true
		risk := utils.OrDefault(vuln.RawRiskAssessment, 0)
		switch {
		case risk >= 0.0 && risk < 4.0:
			low++
		case risk >= 4.0 && risk < 7.0:
			medium++
		case risk >= 7.0 && risk < 9.0:
			high++
		case risk >= 9.0 && risk <= 10.0:
			critical++
		}
	}
	return
}

func calculateUniqueSeverityCountsByCvss(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	seen := make(map[string]bool)
	for _, vuln := range dependencyVulns {
		key := vuln.CVEID + "|" + vuln.ComponentPurl
		if seen[key] {
			continue
		}
		seen[key] = true
		cvss := float64(vuln.CVE.CVSS)
		switch {
		case cvss >= 0.0 && cvss < 4.0:
			low++
		case cvss >= 4.0 && cvss < 7.0:
			medium++
		case cvss >= 7.0 && cvss < 9.0:
			high++
		case cvss >= 9.0 && cvss <= 10.0:
			critical++
		}
	}
	return
}
