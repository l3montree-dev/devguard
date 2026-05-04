package services

import (
	"context"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
)

type statisticsService struct {
	statisticsRepository          shared.StatisticsRepository
	artifactRiskHistoryRepository shared.ArtifactRiskHistoryRepository
	dependencyVulnRepository      shared.DependencyVulnRepository
	assetVersionRepository        shared.AssetVersionRepository
}

var _ shared.StatisticsService = (*statisticsService)(nil)

func NewStatisticsService(statisticsRepository shared.StatisticsRepository, assetRiskHistoryRepository shared.ArtifactRiskHistoryRepository, dependencyVulnRepository shared.DependencyVulnRepository, assetVersionRepository shared.AssetVersionRepository) *statisticsService {
	return &statisticsService{
		statisticsRepository:          statisticsRepository,
		artifactRiskHistoryRepository: assetRiskHistoryRepository,
		dependencyVulnRepository:      dependencyVulnRepository,
		assetVersionRepository:        assetVersionRepository,
	}
}

func (s *statisticsService) GetComponentRisk(ctx context.Context, artifactName *string, assetVersionName string, assetID uuid.UUID) (map[string]models.Distribution, error) {
	dependencyVulns, err := s.dependencyVulnRepository.GetAllOpenVulnsByAssetVersionNameAndAssetID(ctx, nil, artifactName, assetVersionName, assetID)
	if err != nil {
		return nil, err
	}

	distributionPerComponent := make(map[string]models.Distribution)

	uniqueCombinations := make(map[string]struct{})
	for _, dependencyVuln := range dependencyVulns {
		componentName := dependencyVuln.ComponentPurl
		if _, exists := distributionPerComponent[componentName]; !exists {
			distributionPerComponent[componentName] = models.Distribution{}
		}

		combinationKey := fmt.Sprintf("%s|%s", dependencyVuln.CVEID, dependencyVuln.ComponentPurl)

		if _, exists := uniqueCombinations[combinationKey]; exists {
			continue // already counted this CVE+PURL combination
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

		uniqueCombinations[combinationKey] = struct{}{}
	}

	return distributionPerComponent, nil
}

func (s *statisticsService) GetArtifactRiskHistory(ctx context.Context, artifactName *string, assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistory, error) {
	return s.artifactRiskHistoryRepository.GetRiskHistory(ctx, nil, artifactName, assetVersionName, assetID, start, end)
}

// project-level aggregation via project_risk_history has been removed.
// Previously this method aggregated per-project risk history from asset histories.
// That behavior was intentionally removed to focus statistics on artifact histories only.
// If project-level aggregation is required in future, reintroduce with a new storage model.

func (s *statisticsService) UpdateArtifactRiskAggregation(ctx context.Context, artifact *models.Artifact, assetID uuid.UUID, begin time.Time, end time.Time) error {
	// set begin to last second of date
	begin = time.Date(begin.Year(), begin.Month(), begin.Day(), 23, 59, 59, 0, time.UTC)
	// as max, do 1 year from the past
	if begin.Before(time.Now().AddDate(-1, 0, 0)) {
		begin = time.Now().AddDate(-1, 0, 0)
	}

	// set end to last second of date
	end = time.Date(end.Year(), end.Month(), end.Day(), 23, 59, 59, 0, time.UTC)

	for time := begin; time.Before(end) || time.Equal(end); time = time.AddDate(0, 0, 1) {
		dependencyVulns, err := s.statisticsRepository.TimeTravelDependencyVulnState(ctx, nil, &artifact.ArtifactName, &artifact.AssetVersionName, assetID, time)
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
		fixableLowRisk, fixableMediumRisk, fixableHighRisk, fixableCriticalRisk := calculateFixableSeverityCountsByRisk(openVulns)
		lowCvss, mediumCvss, highCvss, criticalCvss := calculateSeverityCountsByCvss(openVulns)

		lowUniqueRisk, mediumUniqueRisk, highUniqueRisk, criticalUniqueRisk := calculateUniqueCVEPurlCountsByRisk(openVulns)
		fixableLowUniqueRisk, fixableMediumUniqueRisk, fixableHighUniqueRisk, fixableCriticalUniqueRisk := calculateUniqueFixableCVEPurlCountsByRisk(openVulns)
		lowUniqueCvss, mediumUniqueCvss, highUniqueCvss, criticalUniqueCvss := calculateUniqueCVEPurlCountsByCvss(openVulns)

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

					FixableLow:      fixableLowRisk,
					FixableMedium:   fixableMediumRisk,
					FixableHigh:     fixableHighRisk,
					FixableCritical: fixableCriticalRisk,

					LowCVSS:      lowCvss,
					MediumCVSS:   mediumCvss,
					HighCVSS:     highCvss,
					CriticalCVSS: criticalCvss,

					CVEPurlLow:      lowUniqueRisk,
					CVEPurlMedium:   mediumUniqueRisk,
					CVEPurlHigh:     highUniqueRisk,
					CVEPurlCritical: criticalUniqueRisk,

					CVEPurlLowCVSS:      lowUniqueCvss,
					CVEPurlMediumCVSS:   mediumUniqueCvss,
					CVEPurlHighCVSS:     highUniqueCvss,
					CVEPurlCriticalCVSS: criticalUniqueCvss,

					CVEPurlFixableLow:      fixableLowUniqueRisk,
					CVEPurlFixableMedium:   fixableMediumUniqueRisk,
					CVEPurlFixableHigh:     fixableHighUniqueRisk,
					CVEPurlFixableCritical: fixableCriticalUniqueRisk,
				},
			},
		}

		err = s.artifactRiskHistoryRepository.UpdateRiskAggregation(ctx, nil, &result)
		if err != nil {
			return err
		}
	}

	// save the last history update timestamp
	artifact.LastHistoryUpdate = &end
	err := s.assetVersionRepository.GetDB(ctx, nil).Save(artifact).Error
	if err != nil {
		return err
	}

	return nil
}

func (s *statisticsService) GetProjectRiskHistory(ctx context.Context, projectID uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error) {
	// project-level risk history storage was removed; return empty result for compatibility.
	return []models.ProjectRiskHistory{}, nil
}

// GetReleaseRiskHistory aggregates artifact risk histories for all artifacts included in the release tree
func (s *statisticsService) GetReleaseRiskHistory(ctx context.Context, releaseID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistory, error) {
	// Use a DB-level query to collect artifact histories for all artifacts present in the release tree.
	return s.artifactRiskHistoryRepository.GetRiskHistoryByRelease(ctx, nil, releaseID, start, end)
}

// GetRemediationTimeAveragesForRelease computes all risk/CVSS average fixing times for a release tree in one query
func (s *statisticsService) GetRemediationTimeAveragesForRelease(ctx context.Context, releaseID uuid.UUID) (dtos.RemediationTimeAverages, error) {
	return s.statisticsRepository.AverageRemediationTimesForRelease(ctx, nil, releaseID)
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

// very redundant, this has to be refactored later
func calculateFixableSeverityCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	for _, vuln := range dependencyVulns {
		if vuln.DirectDependencyFixedVersion == nil || *vuln.DirectDependencyFixedVersion == "" {
			continue
		}

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

func calculateUniqueCVEPurlCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	uniqueCombinations := make(map[string]struct{})

	for _, vuln := range dependencyVulns {
		risk := utils.OrDefault(vuln.RawRiskAssessment, 0)
		combinationKey := fmt.Sprintf("%s|%s", vuln.CVEID, vuln.ComponentPurl)

		if _, exists := uniqueCombinations[combinationKey]; exists {
			continue // already counted this CVE+PURL combination
		}

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

		uniqueCombinations[combinationKey] = struct{}{}
	}
	return
}

func calculateUniqueFixableCVEPurlCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	uniqueCombinations := make(map[string]struct{})

	for _, vuln := range dependencyVulns {
		if vuln.DirectDependencyFixedVersion == nil || *vuln.DirectDependencyFixedVersion == "" {
			continue
		}

		risk := utils.OrDefault(vuln.RawRiskAssessment, 0)
		combinationKey := fmt.Sprintf("%s|%s", vuln.CVEID, vuln.ComponentPurl)

		if _, exists := uniqueCombinations[combinationKey]; exists {
			continue // already counted this CVE+PURL combination
		}

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

		uniqueCombinations[combinationKey] = struct{}{}
	}
	return
}

func calculateUniqueCVEPurlCountsByCvss(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	uniqueCombinations := make(map[string]struct{})

	for _, vuln := range dependencyVulns {
		cvss := float64(vuln.CVE.CVSS)
		combinationKey := fmt.Sprintf("%s|%s", vuln.CVEID, vuln.ComponentPurl)

		if _, exists := uniqueCombinations[combinationKey]; exists {
			continue // already counted this CVE+PURL combination
		}

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

		uniqueCombinations[combinationKey] = struct{}{}
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

// calculate the most popular component ecosystems in org and return up to limit entries sorted by total count
func (s *statisticsService) GetTopEcosystemsInOrg(ctx context.Context, orgID uuid.UUID, limit int) ([]dtos.EcosystemUsage, error) {
	if limit <= 0 {
		return []dtos.EcosystemUsage{}, nil
	}

	distribution, err := s.statisticsRepository.GetComponentDistributionInOrg(ctx, nil, orgID)
	if err != nil {
		return nil, err
	}

	total := 0
	amountPerEcosystem := make(map[string]int)
	// map each ecosystem to its total count by building the sum over the purl.type property
	for _, component := range distribution {
		purl, err := packageurl.FromString(component.DependencyID)
		if err != nil {
			continue
		}
		amountPerEcosystem[purl.Type] += component.Count
		total += component.Count
	}

	//
	ecosystemUsage := []dtos.EcosystemUsage{}
	for ecosystem, count := range amountPerEcosystem {
		var relativeCount float32 = 0
		// do not divide by zero
		if total != 0 {
			relativeCount = float32(count) / float32(total)
		}
		ecosystemUsage = append(ecosystemUsage, dtos.EcosystemUsage{
			Ecosystem:      ecosystem,
			TotalCount:     count,
			RelativeAmount: relativeCount,
		})
	}

	// sort slice by totalCount to determine the top ecosystems
	slices.SortFunc(ecosystemUsage, func(ecosystem1, ecosystem2 dtos.EcosystemUsage) int {
		return ecosystem2.TotalCount - ecosystem1.TotalCount
	})

	// if limit is smaller than the length of all ecosystems then use the limit otherwise return the whole slice
	sliceUpperBounds := int(math.Min(float64(len(ecosystemUsage)), float64(limit)))
	return ecosystemUsage[:sliceUpperBounds], nil
}
