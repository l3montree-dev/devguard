package services

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm/clause"
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

// A snapshot is saved at the <snapshotFrequence>th day before today
var snapshotFrequence = 90

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

		risk := utils.OrDefault(dependencyVuln.RiskAssessment, 0)
		cvss := float64(dependencyVuln.GetCVE().CVSS)

		switch {
		case risk >= 0.0 && risk < 4.0:
			distribution.Low = append(distribution.Low, dependencyVuln.ID.String())
		case risk >= 4.0 && risk < 7.0:
			distribution.Medium = append(distribution.Medium, dependencyVuln.ID.String())
		case risk >= 7.0 && risk < 9.0:
			distribution.High = append(distribution.High, dependencyVuln.ID.String())
		case risk >= 9.0 && risk <= 10.0:
			distribution.Critical = append(distribution.Critical, dependencyVuln.ID.String())
		}

		switch {
		case cvss >= 0.0 && cvss < 4.0:
			distribution.LowCVSS = append(distribution.LowCVSS, dependencyVuln.ID.String())
		case cvss >= 4.0 && cvss < 7.0:
			distribution.MediumCVSS = append(distribution.MediumCVSS, dependencyVuln.ID.String())
		case cvss >= 7.0 && cvss < 9.0:
			distribution.HighCVSS = append(distribution.HighCVSS, dependencyVuln.ID.String())
		case cvss >= 9.0 && cvss <= 10.0:
			distribution.CriticalCVSS = append(distribution.CriticalCVSS, dependencyVuln.ID.String())
		}

		distributionPerComponent[componentName] = distribution

		uniqueCombinations[combinationKey] = struct{}{}
	}

	return distributionPerComponent, nil
}

func (s *statisticsService) replayRiskHistoryFromDiffs(ctx context.Context, artifactName *string, assetVersionName string, assetID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error) {
	startDay := time.Date(start.UTC().Year(), start.UTC().Month(), start.UTC().Day(), 0, 0, 0, 0, time.UTC)

	openVulnIDs, err := s.openVulnIDsAt(ctx, artifactName, assetVersionName, assetID, startDay.AddDate(0, 0, -1))
	if err != nil {
		return nil, err
	}
	remainingHistory, err := s.artifactRiskHistoryRepository.GetRiskHistory(ctx, nil, artifactName, assetVersionName, assetID, startDay, end)
	if err != nil {
		return nil, err
	}

	resultingHistory := []models.ArtifactRiskHistory{}

	for _, riskHistoryItem := range remainingHistory {

		for _, id := range riskHistoryItem.DiffAddedDependencyVulns {
			openVulnIDs[id] = struct{}{}
		}
		for _, id := range riskHistoryItem.DiffRemovedDependencyVulns {
			delete(openVulnIDs, id)
		}

		openVulnsUUIDs := make([]uuid.UUID, 0, len(openVulnIDs))
		for id := range openVulnIDs {
			parsed, err := uuid.Parse(id)
			if err != nil {
				return nil, fmt.Errorf("depedencyVuln ID was not parsesable")
			}
			openVulnsUUIDs = append(openVulnsUUIDs, parsed)
		}

		openVulns, err := s.dependencyVulnRepository.ListWithCVE(ctx, nil, openVulnsUUIDs)
		if err != nil {
			return []models.ArtifactRiskHistory{}, err
		}

		lowRisk, mediumRisk, highRisk, criticalRisk := calculateSeverityCountsByRisk(openVulns)
		fixableLowRisk, fixableMediumRisk, fixableHighRisk, fixableCriticalRisk := calculateFixableSeverityCountsByRisk(openVulns)

		lowCvss, mediumCvss, highCvss, criticalCvss := calculateSeverityCountsByCvss(openVulns)
		fixableLowCvss, fixableMediumCvss, fixableHighCvss, fixableCriticalCvss := calculateFixableSeverityCountsByCvss(openVulns)

		lowUniqueRisk, mediumUniqueRisk, highUniqueRisk, criticalUniqueRisk := calculateUniqueCVEPurlCountsByRisk(openVulns)
		fixableLowUniqueRisk, fixableMediumUniqueRisk, fixableHighUniqueRisk, fixableCriticalUniqueRisk := calculateUniqueFixableCVEPurlCountsByRisk(openVulns)

		lowUniqueCvss, mediumUniqueCvss, highUniqueCvss, criticalUniqueCvss := calculateUniqueCVEPurlCountsByCvss(openVulns)
		fixableLowUniqueCvss, fixableMediumUniqueCvss, fixableHighUniqueCvss, fixableCriticalUniqueCvss := calculateUniqueFixableCVEPurlCountsByCvss(openVulns)

		result := models.ArtifactRiskHistory{
			ArtifactName:     riskHistoryItem.ArtifactName,
			AssetVersionName: riskHistoryItem.AssetVersionName,
			AssetID:          riskHistoryItem.AssetID,
			History: models.History{
				Day: riskHistoryItem.Day,

				SumOpenRisk: riskHistoryItem.SumOpenRisk,
				AvgOpenRisk: riskHistoryItem.AvgOpenRisk,
				MaxOpenRisk: riskHistoryItem.MaxOpenRisk,
				MinOpenRisk: riskHistoryItem.MinOpenRisk,

				SumClosedRisk:        riskHistoryItem.SumClosedRisk,
				AvgClosedRisk:        riskHistoryItem.AvgClosedRisk,
				MaxClosedRisk:        riskHistoryItem.MaxClosedRisk,
				MinClosedRisk:        riskHistoryItem.MinClosedRisk,
				OpenDependencyVulns:  riskHistoryItem.OpenDependencyVulns,
				FixedDependencyVulns: riskHistoryItem.FixedDependencyVulns,
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

					DiffAddedDependencyVulns:   riskHistoryItem.DiffAddedDependencyVulns,
					DiffRemovedDependencyVulns: riskHistoryItem.DiffRemovedDependencyVulns,
				},
			},
		}

		resultingHistory = append(resultingHistory, result)

	}

	return resultingHistory, nil
}

func (s *statisticsService) GetArtifactRiskHistory(ctx context.Context, artifactName *string, assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistory, error) {
	var replayedRiskHistory []models.ArtifactRiskHistory
	replayedRiskHistory, err := s.replayRiskHistoryFromDiffs(ctx, artifactName, assetVersionName, assetID, start, end)
	if err != nil {
		return nil, err
	}

	return replayedRiskHistory, nil
}

func (s *statisticsService) GetArtifactRiskHistoryWithVersion(ctx context.Context, artifactName *string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.ArtifactRiskHistoryWithVersion, error) {
	riskHistoryWithVersion, err := s.artifactRiskHistoryRepository.GetRiskHistoryWithVersion(ctx, nil, artifactName, assetID, start, end)
	if err != nil {
		return nil, err
	}

	// the extra fields are the same for every row of an artifact on an asset version
	type key struct{ artifactName, assetVersionName string }
	versions := make(map[key]models.ArtifactRiskHistoryWithVersion)
	for _, row := range riskHistoryWithVersion {
		versions[key{row.ArtifactName, row.AssetVersionName}] = row
	}

	result := []models.ArtifactRiskHistoryWithVersion{}
	for k, version := range versions {
		riskHistory, err := s.GetArtifactRiskHistory(ctx, &k.artifactName, k.assetVersionName, assetID, start, end)
		if err != nil {
			return nil, err
		}

		for _, history := range riskHistory {
			result = append(result, models.ArtifactRiskHistoryWithVersion{
				ArtifactRiskHistory: history,
				Slug:                version.Slug,
				DefaultBranch:       version.DefaultBranch,
				AssetVersionType:    version.AssetVersionType,
			})
		}
	}

	slices.SortStableFunc(result, func(a, b models.ArtifactRiskHistoryWithVersion) int {
		return a.Day.Compare(b.Day)
	})

	return result, nil
}

// openVulnIDsAt rebuilds the set of open vuln IDs at the end of the given day
// from the latest snapshot at or before it (or the empty root) plus the stored diffs
// without calculating the whole history (just IDs)
func (s *statisticsService) openVulnIDsAt(ctx context.Context, artifactName *string, assetVersionName string, assetID uuid.UUID, at time.Time) (map[string]struct{}, error) {
	openVulnIDs := map[string]struct{}{}
	from := time.Time{} // no snapshot will replay every stored diff

	snapshot, err := s.artifactRiskHistoryRepository.GetLatestSnapshotBefore(ctx, nil, artifactName, assetVersionName, assetID, at)
	if err != nil {
		return nil, err
	}
	if snapshot != nil {
		for _, id := range slices.Concat(snapshot.Low, snapshot.Medium, snapshot.High, snapshot.Critical) {
			openVulnIDs[id] = struct{}{}
		}
		from = snapshot.Day
	}

	history, err := s.artifactRiskHistoryRepository.GetRiskHistory(ctx, nil, artifactName, assetVersionName, assetID, from, at)
	if err != nil {
		return nil, err
	}
	for _, row := range history {
		for _, id := range row.DiffAddedDependencyVulns {
			openVulnIDs[id] = struct{}{}
		}
		for _, id := range row.DiffRemovedDependencyVulns {
			delete(openVulnIDs, id)
		}
	}
	return openVulnIDs, nil
}

func (s *statisticsService) isSnapShotDay(snapshotDay time.Time) bool {
	year, month, day := snapshotDay.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Unix()/86400%int64(snapshotFrequence) == 0
}

// project-level aggregation via project_risk_history has been removed.
// Previously this method aggregated per-project risk history from asset histories.
// That behavior was intentionally removed to focus statistics on artifact histories only.
// If project-level aggregation is required in future, reintroduce with a new storage model.

func (s *statisticsService) UpdateArtifactRiskAggregation(ctx context.Context, tx shared.DB, artifact *models.Artifact, assetID uuid.UUID, begin time.Time, end time.Time) error {

	// as max, do 1 year from the past
	if begin.Before(time.Now().AddDate(-1, 0, 0)) {
		begin = time.Now().AddDate(-1, 0, 0)
	}
	// set begin to last second of date
	begin = time.Date(begin.UTC().Year(), begin.UTC().Month(), begin.UTC().Day(), 23, 59, 59, 0, time.UTC)

	// set end to last second of date
	end = time.Date(end.UTC().Year(), end.UTC().Month(), end.UTC().Day(), 23, 59, 59, 0, time.UTC)

	previousOpenVulnIDs, err := s.openVulnIDsAt(ctx, &artifact.ArtifactName, artifact.AssetVersionName, assetID, begin.AddDate(0, 0, -1))
	if err != nil {
		return err
	}

	for depDate := begin; depDate.Before(end) || depDate.Equal(end); depDate = depDate.AddDate(0, 0, 1) {
		dependencyVulns, err := s.statisticsRepository.TimeTravelDependencyVulnState(ctx, nil, &artifact.ArtifactName, &artifact.AssetVersionName, assetID, depDate)
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
				riskAggregation.Min = utils.OrDefault(dependencyVuln.RiskAssessment, -1)
			}

			risk := utils.OrDefault(dependencyVuln.RiskAssessment, 0)

			if riskAggregation.Min <= risk {
				riskAggregation.Min = risk
			}

			riskAggregation.Sum += risk
			if risk > riskAggregation.Max {
				riskAggregation.Max = risk
			}

			risks[key] = riskAggregation
		}

		openVulnIDs := openVulnIDSet(openVulns)
		diffAddedDependencyVulns, diffRemovedDependencyVulns := diffOpenVulnIDs(previousOpenVulnIDs, openVulnIDs)

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

		var lowRisk, mediumRisk, highRisk, criticalRisk,
			fixableLowRisk, fixableMediumRisk, fixableHighRisk, fixableCriticalRisk,
			lowCvss, mediumCvss, highCvss, criticalCvss,
			fixableLowCvss, fixableMediumCvss, fixableHighCvss, fixableCriticalCvss,
			lowUniqueRisk, mediumUniqueRisk, highUniqueRisk, criticalUniqueRisk,
			fixableLowUniqueRisk, fixableMediumUniqueRisk, fixableHighUniqueRisk, fixableCriticalUniqueRisk,
			lowUniqueCvss, mediumUniqueCvss, highUniqueCvss, criticalUniqueCvss,
			fixableLowUniqueCvss, fixableMediumUniqueCvss, fixableHighUniqueCvss, fixableCriticalUniqueCvss []string

		if s.isSnapShotDay(depDate) {

			// Calculate severity counts
			lowRisk, mediumRisk, highRisk, criticalRisk = calculateSeverityCountsByRisk(openVulns)
			fixableLowRisk, fixableMediumRisk, fixableHighRisk, fixableCriticalRisk = calculateFixableSeverityCountsByRisk(openVulns)

			lowCvss, mediumCvss, highCvss, criticalCvss = calculateSeverityCountsByCvss(openVulns)
			fixableLowCvss, fixableMediumCvss, fixableHighCvss, fixableCriticalCvss = calculateFixableSeverityCountsByCvss(openVulns)

			lowUniqueRisk, mediumUniqueRisk, highUniqueRisk, criticalUniqueRisk = calculateUniqueCVEPurlCountsByRisk(openVulns)
			fixableLowUniqueRisk, fixableMediumUniqueRisk, fixableHighUniqueRisk, fixableCriticalUniqueRisk = calculateUniqueFixableCVEPurlCountsByRisk(openVulns)

			lowUniqueCvss, mediumUniqueCvss, highUniqueCvss, criticalUniqueCvss = calculateUniqueCVEPurlCountsByCvss(openVulns)
			fixableLowUniqueCvss, fixableMediumUniqueCvss, fixableHighUniqueCvss, fixableCriticalUniqueCvss = calculateUniqueFixableCVEPurlCountsByCvss(openVulns)

		}

		result := models.ArtifactRiskHistory{
			ArtifactName:     artifact.ArtifactName,
			AssetVersionName: artifact.AssetVersionName,
			AssetID:          assetID,
			History: models.History{
				Day: depDate,

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
					DiffAddedDependencyVulns:   diffAddedDependencyVulns,
					DiffRemovedDependencyVulns: diffRemovedDependencyVulns,
				},
			},
		}

		previousOpenVulnIDs = openVulnIDs
		err = s.artifactRiskHistoryRepository.UpdateRiskAggregation(ctx, tx, &result)
		if err != nil {
			return err
		}
	}

	// save the last history update timestamp
	artifact.LastHistoryUpdate = &end
	err = s.assetVersionRepository.GetDB(ctx, nil).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "artifact_name"}, {Name: "asset_version_name"}, {Name: "asset_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"last_history_update"}),
	}).Create(artifact).Error
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

func openVulnIDSet(dependencyVulns []models.DependencyVuln) map[string]struct{} {
	ids := make(map[string]struct{}, len(dependencyVulns))
	for _, vuln := range dependencyVulns {
		if vuln.State == dtos.VulnStateOpen {
			ids[vuln.ID.String()] = struct{}{}
		}
	}
	return ids
}

func diffOpenVulnIDs(previous, current map[string]struct{}) (added, removed []string) {
	added, removed = []string{}, []string{}
	for id := range current {
		if _, ok := previous[id]; !ok {
			added = append(added, id)
		}
	}
	for id := range previous {
		if _, ok := current[id]; !ok {
			removed = append(removed, id)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

func calculateSeverityCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical []string) {
	low, medium, high, critical = []string{}, []string{}, []string{}, []string{}
	for _, vuln := range dependencyVulns {
		risk := utils.OrDefault(vuln.RiskAssessment, 0)
		switch {
		case risk >= 0.0 && risk < 4.0:
			low = append(low, vuln.ID.String())
		case risk >= 4.0 && risk < 7.0:
			medium = append(medium, vuln.ID.String())
		case risk >= 7.0 && risk < 9.0:
			high = append(high, vuln.ID.String())
		case risk >= 9.0 && risk <= 10.0:
			critical = append(critical, vuln.ID.String())
		}
	}
	return
}

// very redundant, this has to be refactored later
func calculateFixableSeverityCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical []string) {
	low, medium, high, critical = []string{}, []string{}, []string{}, []string{}
	for _, vuln := range dependencyVulns {
		if vuln.DirectDependencyFixedVersion == nil || *vuln.DirectDependencyFixedVersion == "" {
			continue
		}

		risk := utils.OrDefault(vuln.RiskAssessment, 0)
		switch {
		case risk >= 0.0 && risk < 4.0:
			low = append(low, vuln.ID.String())
		case risk >= 4.0 && risk < 7.0:
			medium = append(medium, vuln.ID.String())
		case risk >= 7.0 && risk < 9.0:
			high = append(high, vuln.ID.String())
		case risk >= 9.0 && risk <= 10.0:
			critical = append(critical, vuln.ID.String())
		}
	}
	return
}

func calculateFixableSeverityCountsByCvss(dependencyVulns []models.DependencyVuln) (low, medium, high, critical []string) {
	low, medium, high, critical = []string{}, []string{}, []string{}, []string{}
	for _, vuln := range dependencyVulns {
		if vuln.DirectDependencyFixedVersion == nil || *vuln.DirectDependencyFixedVersion == "" {
			continue
		}

		cvss := float64(vuln.GetCVE().CVSS)
		switch {
		case cvss >= 0.0 && cvss < 4.0:
			low = append(low, vuln.ID.String())
		case cvss >= 4.0 && cvss < 7.0:
			medium = append(medium, vuln.ID.String())
		case cvss >= 7.0 && cvss < 9.0:
			high = append(high, vuln.ID.String())
		case cvss >= 9.0 && cvss <= 10.0:
			critical = append(critical, vuln.ID.String())
		}
	}
	return
}

func calculateUniqueCVEPurlCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical []string) {
	low, medium, high, critical = []string{}, []string{}, []string{}, []string{}
	uniqueCombinations := make(map[string]struct {
		risk           float64
		combinationKey string
	})

	// get the highest risk for each unique CVE+PURL combination to avoid double counting vulnerabilities that affect multiple components
	for _, vuln := range dependencyVulns {
		risk := utils.OrDefault(vuln.RiskAssessment, 0)
		combinationKey := fmt.Sprintf("%s|%s", vuln.CVEID, vuln.ComponentPurl)

		existingRisk, exists := uniqueCombinations[combinationKey]
		if !exists || risk > existingRisk.risk {
			uniqueCombinations[combinationKey] = struct {
				risk           float64
				combinationKey string
			}{
				risk:           risk,
				combinationKey: combinationKey,
			}
		}
	}

	for _, unique := range uniqueCombinations {
		switch {
		case unique.risk >= 0.0 && unique.risk < 4.0:
			low = append(low, unique.combinationKey)
		case unique.risk >= 4.0 && unique.risk < 7.0:
			medium = append(medium, unique.combinationKey)
		case unique.risk >= 7.0 && unique.risk < 9.0:
			high = append(high, unique.combinationKey)
		case unique.risk >= 9.0 && unique.risk <= 10.0:
			critical = append(critical, unique.combinationKey)
		}
	}
	return
}

func calculateUniqueFixableCVEPurlCountsByRisk(dependencyVulns []models.DependencyVuln) (low, medium, high, critical []string) {
	low, medium, high, critical = []string{}, []string{}, []string{}, []string{}
	uniqueCombinations := make(map[string]dtos.UniqueRiskCVSSTrack)

	// get the highest risk for each unique CVE+PURL combination to avoid double counting vulnerabilities that affect multiple components
	for _, vuln := range dependencyVulns {
		if vuln.DirectDependencyFixedVersion == nil || *vuln.DirectDependencyFixedVersion == "" {
			continue
		}
		risk := utils.OrDefault(vuln.RiskAssessment, 0)
		combinationKey := fmt.Sprintf("%s|%s", vuln.CVEID, vuln.ComponentPurl)

		existingRisk, exists := uniqueCombinations[combinationKey]
		if !exists || risk > existingRisk.RiskCVSS {
			uniqueCombinations[combinationKey] = dtos.UniqueRiskCVSSTrack{
				RiskCVSS:                    risk,
				UniqueCombinationIdentifier: combinationKey,
			}
		}
	}

	for _, unique := range uniqueCombinations {
		switch {
		case unique.RiskCVSS >= 0.0 && unique.RiskCVSS < 4.0:
			low = append(low, unique.UniqueCombinationIdentifier)
		case unique.RiskCVSS >= 4.0 && unique.RiskCVSS < 7.0:
			medium = append(medium, unique.UniqueCombinationIdentifier)
		case unique.RiskCVSS >= 7.0 && unique.RiskCVSS < 9.0:
			high = append(high, unique.UniqueCombinationIdentifier)
		case unique.RiskCVSS >= 9.0 && unique.RiskCVSS <= 10.0:
			critical = append(critical, unique.UniqueCombinationIdentifier)
		}
	}
	return
}

func calculateUniqueFixableCVEPurlCountsByCvss(dependencyVulns []models.DependencyVuln) (low, medium, high, critical []string) {
	low, medium, high, critical = []string{}, []string{}, []string{}, []string{}
	uniqueCombinations := make(map[string]dtos.UniqueRiskCVSSTrack)

	for _, vuln := range dependencyVulns {
		if vuln.DirectDependencyFixedVersion == nil || *vuln.DirectDependencyFixedVersion == "" {
			continue
		}
		cvss := float64(vuln.GetCVE().CVSS)
		combinationKey := fmt.Sprintf("%s|%s", vuln.CVEID, vuln.ComponentPurl)

		existingCvss, exists := uniqueCombinations[combinationKey]
		if !exists || cvss > existingCvss.RiskCVSS {
			uniqueCombinations[combinationKey] = dtos.UniqueRiskCVSSTrack{
				RiskCVSS:                    cvss,
				UniqueCombinationIdentifier: combinationKey,
			}
		}
	}

	for _, unique := range uniqueCombinations {
		switch {
		case unique.RiskCVSS >= 0.0 && unique.RiskCVSS < 4.0:
			low = append(low, unique.UniqueCombinationIdentifier)
		case unique.RiskCVSS >= 4.0 && unique.RiskCVSS < 7.0:
			medium = append(medium, unique.UniqueCombinationIdentifier)
		case unique.RiskCVSS >= 7.0 && unique.RiskCVSS < 9.0:
			high = append(high, unique.UniqueCombinationIdentifier)
		case unique.RiskCVSS >= 9.0 && unique.RiskCVSS <= 10.0:
			critical = append(critical, unique.UniqueCombinationIdentifier)
		}
	}
	return
}

func calculateUniqueCVEPurlCountsByCvss(dependencyVulns []models.DependencyVuln) (low, medium, high, critical []string) {
	low, medium, high, critical = []string{}, []string{}, []string{}, []string{}
	uniqueCombinations := make(map[string]struct{})

	for _, vuln := range dependencyVulns {
		cvss := float64(vuln.GetCVE().CVSS)
		combinationKey := fmt.Sprintf("%s|%s", vuln.CVEID, vuln.ComponentPurl)

		if _, exists := uniqueCombinations[combinationKey]; exists {
			continue // already counted this CVE+PURL combination
		}

		switch {
		case cvss >= 0.0 && cvss < 4.0:
			low = append(low, combinationKey)
		case cvss >= 4.0 && cvss < 7.0:
			medium = append(medium, combinationKey)
		case cvss >= 7.0 && cvss < 9.0:
			high = append(high, combinationKey)
		case cvss >= 9.0 && cvss <= 10.0:
			critical = append(critical, combinationKey)
		}

		uniqueCombinations[combinationKey] = struct{}{}
	}
	return
}

func calculateSeverityCountsByCvss(dependencyVulns []models.DependencyVuln) (low, medium, high, critical []string) {
	low, medium, high, critical = []string{}, []string{}, []string{}, []string{}
	for _, vuln := range dependencyVulns {
		cvss := float64(vuln.GetCVE().CVSS)
		switch {
		case cvss >= 0.0 && cvss < 4.0:
			low = append(low, vuln.ID.String())
		case cvss >= 4.0 && cvss < 7.0:
			medium = append(medium, vuln.ID.String())
		case cvss >= 7.0 && cvss < 9.0:
			high = append(high, vuln.ID.String())
		case cvss >= 9.0 && cvss <= 10.0:
			critical = append(critical, vuln.ID.String())
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
