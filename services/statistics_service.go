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

func (s *statisticsService) GetComponentRisk(ctx context.Context, artifactID *uuid.UUID, assetVersionID uuid.UUID) (map[string]models.Distribution, error) {
	dependencyVulns, err := s.dependencyVulnRepository.GetAllOpenVulnsByAssetVersionID(ctx, nil, artifactID, assetVersionID)
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

		risk := utils.OrDefault(dependencyVuln.RiskAssessment, 0)
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

func (s *statisticsService) GetArtifactRiskHistory(ctx context.Context, artifactID *uuid.UUID, assetVersionID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistory, error) {
	return s.artifactRiskHistoryRepository.GetRiskHistory(ctx, nil, artifactID, assetVersionID, start, end)
}

func (s *statisticsService) GetArtifactRiskHistoryWithVersion(ctx context.Context, artifactName *string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistoryWithVersion, error) {
	return s.artifactRiskHistoryRepository.GetRiskHistoryWithVersion(ctx, nil, artifactName, assetID, start, end)
}

// project-level aggregation via project_risk_history has been removed.
// Previously this method aggregated per-project risk history from asset histories.
// That behavior was intentionally removed to focus statistics on artifact histories only.
// If project-level aggregation is required in future, reintroduce with a new storage model.

func (s *statisticsService) RecalculateRiskHistory(ctx context.Context, tx shared.DB, assetID uuid.UUID) error {
	return s.artifactRiskHistoryRepository.RecalculateForAsset(ctx, tx, assetID)
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
		return dtos.OrgOverview{}, nil
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
		AverageAgeOfDependencies:       res.GetValue(12).(time.Duration).Seconds(),
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
