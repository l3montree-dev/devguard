package services

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"golang.org/x/sync/singleflight"
)

type statisticsService struct {
	statisticsRepository          shared.StatisticsRepository
	artifactRiskHistoryRepository shared.ArtifactRiskHistoryRepository
	dependencyVulnRepository      shared.DependencyVulnRepository
	assetVersionRepository        shared.AssetVersionRepository

	// caching variables for the org dashboard statistics
	orgStatisticsCache      map[uuid.UUID]orgStatisticsEntry
	orgStatisticsCacheMutex sync.RWMutex
	orgStatisticsGroup      singleflight.Group
}

var _ shared.StatisticsService = (*statisticsService)(nil)

func NewStatisticsService(statisticsRepository shared.StatisticsRepository, assetRiskHistoryRepository shared.ArtifactRiskHistoryRepository, dependencyVulnRepository shared.DependencyVulnRepository, assetVersionRepository shared.AssetVersionRepository) *statisticsService {
	return &statisticsService{
		statisticsRepository:          statisticsRepository,
		artifactRiskHistoryRepository: assetRiskHistoryRepository,
		dependencyVulnRepository:      dependencyVulnRepository,
		assetVersionRepository:        assetVersionRepository,
		orgStatisticsCache:            make(map[uuid.UUID]orgStatisticsEntry),
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
		cvss := float64(dependencyVuln.GetCVE().CVSS)

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
		fixableLowCvss, fixableMediumCvss, fixableHighCvss, fixableCriticalCvss := calculateFixableSeverityCountsByCvss(openVulns)

		lowUniqueRisk, mediumUniqueRisk, highUniqueRisk, criticalUniqueRisk := calculateUniqueCVEPurlCountsByRisk(openVulns)
		fixableLowUniqueRisk, fixableMediumUniqueRisk, fixableHighUniqueRisk, fixableCriticalUniqueRisk := calculateUniqueFixableCVEPurlCountsByRisk(openVulns)

		lowUniqueCvss, mediumUniqueCvss, highUniqueCvss, criticalUniqueCvss := calculateUniqueCVEPurlCountsByCvss(openVulns)
		fixableLowUniqueCvss, fixableMediumUniqueCvss, fixableHighUniqueCvss, fixableCriticalUniqueCvss := calculateUniqueFixableCVEPurlCountsByRisk(openVulns)

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

					FixableLowCVSS:      fixableLowCvss,
					FixableMediumCVSS:   fixableMediumCvss,
					FixableHighCVSS:     fixableHighCvss,
					FixableCriticalCVSS: fixableCriticalCvss,

					CVEPurlLow:      lowUniqueRisk,
					CVEPurlMedium:   mediumUniqueRisk,
					CVEPurlHigh:     highUniqueRisk,
					CVEPurlCritical: criticalUniqueRisk,

					CVEPurlFixableLow:      fixableLowUniqueRisk,
					CVEPurlFixableMedium:   fixableMediumUniqueRisk,
					CVEPurlFixableHigh:     fixableHighUniqueRisk,
					CVEPurlFixableCritical: fixableCriticalUniqueRisk,

					CVEPurlLowCVSS:      lowUniqueCvss,
					CVEPurlMediumCVSS:   mediumUniqueCvss,
					CVEPurlHighCVSS:     highUniqueCvss,
					CVEPurlCriticalCVSS: criticalUniqueCvss,

					CVEPurlFixableLowCVSS:      fixableLowUniqueCvss,
					CVEPurlFixableMediumCVSS:   fixableMediumUniqueCvss,
					CVEPurlFixableHighCVSS:     fixableHighUniqueCvss,
					CVEPurlFixableCriticalCVSS: fixableCriticalUniqueCvss,
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

func calculateFixableSeverityCountsByCvss(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	for _, vuln := range dependencyVulns {
		if vuln.DirectDependencyFixedVersion == nil || *vuln.DirectDependencyFixedVersion == "" {
			continue
		}

		cvss := float64(vuln.GetCVE().CVSS)
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

func calculateUniqueCVEPurlCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	uniqueCombinations := make(map[string]float64)

	// get the highest risk for each unique CVE+PURL combination to avoid double counting vulnerabilities that affect multiple components
	for _, vuln := range dependencyVulns {
		risk := utils.OrDefault(vuln.RawRiskAssessment, 0)
		combinationKey := fmt.Sprintf("%s|%s", vuln.CVEID, vuln.ComponentPurl)

		existingRisk, exists := uniqueCombinations[combinationKey]
		if !exists || risk > existingRisk {
			uniqueCombinations[combinationKey] = risk
		}
	}

	for _, risk := range uniqueCombinations {
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

func calculateUniqueFixableCVEPurlCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	uniqueCombinations := make(map[string]float64)

	// get the highest risk for each unique CVE+PURL combination to avoid double counting vulnerabilities that affect multiple components
	for _, vuln := range dependencyVulns {
		if vuln.DirectDependencyFixedVersion == nil || *vuln.DirectDependencyFixedVersion == "" {
			continue
		}
		risk := utils.OrDefault(vuln.RawRiskAssessment, 0)
		combinationKey := fmt.Sprintf("%s|%s", vuln.CVEID, vuln.ComponentPurl)

		existingRisk, exists := uniqueCombinations[combinationKey]
		if !exists || risk > existingRisk {
			uniqueCombinations[combinationKey] = risk
		}
	}

	for _, risk := range uniqueCombinations {
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

func calculateUniqueCVEPurlCountsByCvss(dependencyVulns []models.DependencyVuln) (low, medium, high, critical int) {
	uniqueCombinations := make(map[string]struct{})

	for _, vuln := range dependencyVulns {
		cvss := float64(vuln.GetCVE().CVSS)
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
		cvss := float64(vuln.GetCVE().CVSS)
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
func (s *statisticsService) GetTopEcosystemsInOrg(ctx context.Context, orgID uuid.UUID) ([]dtos.EcosystemUsage, error) {
	distribution, err := s.statisticsRepository.GetEcosystemDistributionInOrg(ctx, nil, orgID)
	if err != nil {
		return nil, err
	}

	return distribution, nil
}

func (s *statisticsService) GetOrgStatistics(ctx context.Context, orgID uuid.UUID, orgComponentsLimit, topCVEsLimit, topComponentsLimit int, forceRefresh bool) (dtos.OrgOverview, error) {
	// test if org is empty
	amount, err := s.assetVersionRepository.GetAmountOfAssetVersionsInOrg(ctx, nil, orgID)
	if err != nil {
		return dtos.OrgOverview{}, fmt.Errorf("could not query total amount of asset versions for org: %w", err)
	}

	if amount == 0 {
		return dtos.OrgOverview{}, fmt.Errorf("organization has no vulnerability data yet: %w", err)
	}

	if !forceRefresh {
		if overview, found := s.getOrgStatisticFromCache(orgID); found {
			return overview, nil
		}
	}

	// use singleflight to avoid concurrent statistics computations
	result, err, _ := s.orgStatisticsGroup.Do(orgID.String(), func() (any, error) {
		if !forceRefresh {
			// check if the stats are in cache
			overview, found := s.getOrgStatisticFromCache(orgID)
			if found {
				// they are; we can just return them
				return overview, nil
			}
		}
		// otherwise compute the new statistics ONCE
		return s.computeOrgStatistics(ctx, orgID, orgComponentsLimit, topCVEsLimit, topComponentsLimit)
	})
	if err != nil {
		return dtos.OrgOverview{}, err
	}
	return result.(dtos.OrgOverview), nil
}

func (s *statisticsService) computeOrgStatistics(ctx context.Context, orgID uuid.UUID, orgComponentsLimit, topCVEsLimit, topComponentsLimit int) (dtos.OrgOverview, error) {
	now := time.Now()

	res := utils.Concurrently(
		func() (any, error) { // 0: distribution
			results, err := s.statisticsRepository.VulnClassificationByOrg(ctx, nil, orgID)
			if err != nil {
				return results, fmt.Errorf("could not get vuln classification: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 1: structure
			results, err := s.statisticsRepository.GetOrgStructureDistribution(ctx, nil, orgID)
			if err != nil {
				return results, fmt.Errorf("could not get org structure distribution: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 2: projects
			results, err := s.statisticsRepository.GetMostVulnerableProjectsInOrg(ctx, nil, orgID, orgComponentsLimit)
			if err != nil {
				return results, fmt.Errorf("could not get most vulnerable projects: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 3: assets
			results, err := s.statisticsRepository.GetMostVulnerableAssetsInOrg(ctx, nil, orgID, orgComponentsLimit)
			if err != nil {
				return results, fmt.Errorf("could not get most vulnerable assets: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 4: artifacts
			results, err := s.statisticsRepository.GetMostVulnerableArtifactsInOrg(ctx, nil, orgID, orgComponentsLimit)
			if err != nil {
				return results, fmt.Errorf("could not get most vulnerable artifacts: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 5: topComponents
			results, err := s.statisticsRepository.GetMostUsedComponentsInOrg(ctx, nil, orgID, topComponentsLimit)
			if err != nil {
				return results, fmt.Errorf("could not get most used components: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 6: topCVEs
			results, err := s.statisticsRepository.GetMostCommonCVEsInOrg(ctx, nil, orgID, topCVEsLimit)
			if err != nil {
				return results, fmt.Errorf("could not get most common CVEs: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 7: vulnEventAverages
			results, err := s.statisticsRepository.GetWeeklyAveragePerVulnEventType(ctx, nil, orgID)
			if err != nil {
				return results, fmt.Errorf("could not get weekly average per vuln event type: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 8: riskHistory
			results, err := s.artifactRiskHistoryRepository.GetRiskHistoryForOrg(ctx, nil, orgID, now.Add(-30*time.Hour*24), now)
			if err != nil {
				return results, fmt.Errorf("could not get risk history: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 9: openCodeRiskAverage
			results, err := s.statisticsRepository.GetAverageAmountOfOpenCodeRisksForProjectsInOrg(ctx, nil, orgID)
			if err != nil {
				return results, fmt.Errorf("could not get open code risk average: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 10: topEcosystems
			results, err := s.GetTopEcosystemsInOrg(ctx, orgID)
			if err != nil {
				return results, fmt.Errorf("could not get top ecosystems: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 11: maliciousPackages
			results, err := s.statisticsRepository.FindMaliciousPackagesInOrg(ctx, nil, orgID)
			if err != nil {
				return results, fmt.Errorf("could not get malicious packages: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 12: averageAge
			results, err := s.statisticsRepository.GetAverageAgeOfDependenciesAcrossOrg(ctx, nil, orgID)
			if err != nil {
				return results, fmt.Errorf("could not get average age of dependencies: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 13: averageRemediations
			results, err := s.statisticsRepository.GetAverageRemediationTimesAcrossOrg(ctx, nil, orgID)
			if err != nil {
				return results, fmt.Errorf("could not get average remediation times: %w", err)
			}
			return results, nil
		},
		func() (any, error) { // 14: remediationTypeDistributionRows
			results, err := s.statisticsRepository.GetRemediationTypeDistributionAcrossOrg(ctx, nil, orgID)
			if err != nil {
				return results, fmt.Errorf("could not get remediation type distribution: %w", err)
			}
			return results, nil
		},
	)

	if res.HasErrors() {
		slog.Error("could not get org statistics", "errors", res.Errors())
		return dtos.OrgOverview{}, fmt.Errorf("could not get org statistics")
	}

	vulnEventAverageDistribution := dtos.AverageVulnEventsPerWeek{}
	for _, average := range res.GetValue(7).([]dtos.VulnEventAverage) {
		switch average.VulnEventType {
		case dtos.EventTypeDetected:
			vulnEventAverageDistribution.AverageDetectedEvents = average.Average
		case dtos.EventTypeAccepted:
			vulnEventAverageDistribution.AverageAcceptedEvents = average.Average
		case dtos.EventTypeFalsePositive:
			vulnEventAverageDistribution.AverageFalsePositiveEvents = average.Average
		case dtos.EventTypeFixed:
			vulnEventAverageDistribution.AverageFixedEvents = average.Average
		case dtos.EventTypeReopened:
			vulnEventAverageDistribution.AverageReopenedEvents = average.Average
		}
	}

	remediationTypeDistribution := dtos.RemediationTypeDistribution{}
	for _, row := range res.GetValue(14).([]dtos.RemediationTypeDistributionRow) {
		switch row.Type {
		case string(dtos.EventTypeAccepted):
			remediationTypeDistribution.AcceptedPercentage = row.Percentage
		case string(dtos.EventTypeFixed):
			remediationTypeDistribution.FixedPercentage = row.Percentage
		case string(dtos.EventTypeFalsePositive):
			remediationTypeDistribution.FalsePositivePercentage = row.Percentage
		}
	}

	orgStatistics := dtos.OrgOverview{
		VulnEventAverage:               vulnEventAverageDistribution,
		VulnDistribution:               res.GetValue(0).(dtos.VulnSeverityDistribution),
		OrgStructure:                   res.GetValue(1).(dtos.OrgStructureDistribution),
		TopProjects:                    res.GetValue(2).([]dtos.ProjectVulnDistribution),
		TopAssets:                      res.GetValue(3).([]dtos.AssetVulnDistribution),
		TopArtifacts:                   res.GetValue(4).([]dtos.ArtifactVulnDistribution),
		TopComponents:                  res.GetValue(5).([]dtos.ComponentOccurrenceAcrossOrg),
		TopCVEs:                        res.GetValue(6).([]dtos.CVEOccurrence),
		OrgRiskHistory:                 res.GetValue(8).([]dtos.OrgRiskHistory),
		AverageOpenCodeRisksPerProject: res.GetValue(9).(float32),
		TopEcosystems:                  res.GetValue(10).([]dtos.EcosystemUsage),
		MaliciousPackages:              res.GetValue(11).([]dtos.MaliciousPackageInOrg),
		AverageAgeOfDependencies:       res.GetValue(12).(time.Duration),
		AverageRemediationTimes:        res.GetValue(13).(dtos.AverageRemediationTimes),
		RemediationTypeDistribution:    remediationTypeDistribution,
	}
	s.cacheOrgStatistics(orgID, orgStatistics)

	return orgStatistics, nil
}

type orgStatisticsEntry struct {
	statistics dtos.OrgOverview
	expiryTime time.Time
}

const StatisticsExpiryTime = 15 * time.Minute

// return cached statistics if present and not stale; also handles clean up of stale values
// nosemgrep: service-method-missing-ctx -- private in-memory cache helper; no I/O
func (s *statisticsService) getOrgStatisticFromCache(orgID uuid.UUID) (dtos.OrgOverview, bool) {
	s.orgStatisticsCacheMutex.RLock()
	entry, ok := s.orgStatisticsCache[orgID]
	s.orgStatisticsCacheMutex.RUnlock()
	if !ok || entry.expiryTime.Before(time.Now()) {
		if ok {
			s.orgStatisticsCacheMutex.Lock()
			delete(s.orgStatisticsCache, orgID)
			s.orgStatisticsCacheMutex.Unlock()
		}
		return dtos.OrgOverview{}, false
	}
	return entry.statistics, true
}

// writes new statistic date to the cache
// nosemgrep: service-method-missing-ctx -- private in-memory cache helper; no I/O
func (s *statisticsService) cacheOrgStatistics(orgID uuid.UUID, stats dtos.OrgOverview) {
	s.orgStatisticsCacheMutex.Lock()
	defer s.orgStatisticsCacheMutex.Unlock()
	s.orgStatisticsCache[orgID] = orgStatisticsEntry{
		statistics: stats,
		expiryTime: time.Now().Add(StatisticsExpiryTime),
	}
}
