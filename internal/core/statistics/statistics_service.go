package statistics

import (
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type statisticsRepository interface {
	GetRecentFlawsForAsset(assetID uuid.UUID, time time.Time) ([]models.FlawRisk, error)
	GetAssetFlawsStatistics(assetID uuid.UUID) ([]models.AssetRiskSummary, error)
	GetAssetRisksDistribution(assetID uuid.UUID) ([]models.AssetRiskDistribution, error)
	GetAssetCriticalDependenciesGroupedByScanType(assetID uuid.UUID) ([]models.AssetDependencies, error)
	GetRecentFlawsState(assetID uuid.UUID, time time.Time) ([]models.FlawRisk, error)
	GetFlawDetailsByAssetId(assetID uuid.UUID) ([]models.Flaw, error)
}

type componentRepository interface {
	GetDependenciesGroupedByScanType(assetID uuid.UUID) ([]models.AssetDependencies, error)
	GetPackages(assetID uuid.UUID) ([]models.AssetComponents, error)
}
type assetRecentRiskRepository interface {
	GetRecentRisksByAssetId(assetId uuid.UUID) ([]models.AssetRecentRisks, error)
	UpdateRecentRisks(assetRisks *models.AssetRecentRisks) error
}
type service struct {
	statisticsRepository      statisticsRepository
	componentRepository       componentRepository
	assetRecentRiskRepository assetRecentRiskRepository
}

func NewService(statisticsRepository statisticsRepository, componentRepository componentRepository, assetRecentRiskRepository assetRecentRiskRepository) *service {
	return &service{
		statisticsRepository:      statisticsRepository,
		componentRepository:       componentRepository,
		assetRecentRiskRepository: assetRecentRiskRepository,
	}
}

func (s *service) GetAssetCombinedDependencies(assetID uuid.UUID) ([]models.AssetCombinedDependencies, error) {

	dependencies, err := s.getAssetDependenciesGroupedByScanType(assetID)
	if err != nil {
		return nil, err
	}

	criticalDependencies, err := s.getAssetCriticalDependenciesGroupedByScanType(assetID)
	if err != nil {
		return nil, err
	}

	criticalCountMap := make(map[string]int64)
	for _, criticalDep := range criticalDependencies {
		criticalCountMap[criticalDep.ScannerID] = criticalDep.Count
	}

	combinedDependencies := make([]models.AssetCombinedDependencies, len(dependencies))
	for i, allDep := range dependencies {
		combinedDependencies[i] = models.AssetCombinedDependencies{
			ScannerID:         allDep.ScannerID,
			CountDependencies: allDep.Count,
			CountCritical:     criticalCountMap[allDep.ScannerID],
		}
	}

	return combinedDependencies, nil
}

func (s *service) getAssetCriticalDependenciesGroupedByScanType(assetID uuid.UUID) ([]models.AssetDependencies, error) {
	assets, err := s.statisticsRepository.GetAssetCriticalDependenciesGroupedByScanType(assetID)
	if err != nil {
		return nil, err
	}

	for i := range assets {
		assets[i].ScannerID = scanTypeFromScannerID(assets[i].ScannerID)
	}
	return assets, nil

}

func (s *service) getAssetDependenciesGroupedByScanType(assetID uuid.UUID) ([]models.AssetDependencies, error) {
	return s.componentRepository.GetDependenciesGroupedByScanType(assetID)
}

func (s *service) GetAssetFlawsStatistics(assetID uuid.UUID) ([]models.AssetRiskSummary, error) {

	risks, err := s.statisticsRepository.GetAssetFlawsStatistics(assetID)
	if err != nil {
		return nil, err
	}
	for i := range risks {
		risks[i].ScannerID = scanTypeFromScannerID(risks[i].ScannerID)

	}
	return risks, nil
}

func scanTypeFromScannerID(scannerID string) string {
	parts := strings.Split(scannerID, "/")
	return parts[len(parts)-1]
}

func (s *service) UpdateAssetRecentRisks(assetID uuid.UUID, begin time.Time, end time.Time) error {
	tmpID := 1

	for time := begin; time.Before(end); time = time.AddDate(0, 0, 1) {
		assetRisk, err := s.statisticsRepository.GetRecentFlawsForAsset(assetID, time)
		if err != nil {
			return err
		}

		riskSum := 0.0
		riskAvg := 0.0
		riskMax := 0.0
		riskMin := 99.0
		dayOfRisk := "9999-99-99 00:00:00.000000 +0200 CEST"

		for i := range assetRisk {
			arbitraryJsonData := make(map[string]interface{})
			err := json.Unmarshal([]byte(assetRisk[i].ArbitraryJsonData), &arbitraryJsonData)
			if err != nil {
				slog.Error("could not parse additional data", "err", err, "flawId", assetRisk[i].FlawID)
			}
			risk := arbitraryJsonData["risk"].(float64)
			riskSum += risk
			if risk > riskMax {
				riskMax = risk
			}
			if risk <= riskMin {
				riskMin = risk
			}

		}

		if riskMin == 99.0 {
			riskMin = 0.0
		}
		if len(assetRisk) != 0 {
			riskAvg = riskSum / float64(len(assetRisk))
			dayOfRisk = assetRisk[0].CreatedAt.String()
		}

		result := models.AssetRecentRisks{
			AssetID:   assetID,
			DayOfRisk: dayOfRisk,
			DayOfScan: time.Format("2006-01-02"),
			SumRisk:   riskSum,
			AvgRisk:   riskAvg,
			MaxRisk:   riskMax,
			MinRisk:   riskMin,
		}

		tmpID++

		err = s.assetRecentRiskRepository.UpdateRecentRisks(&result)
		if err != nil {
			return err
		}

	}
	return nil

}

func (s *service) GetAssetRecentRisksByAssetId(assetID uuid.UUID) ([]models.AssetRecentRisks, error) {
	return s.assetRecentRiskRepository.GetRecentRisksByAssetId(assetID)
}

func (s *service) GetAssetFlawsDistribution(assetID uuid.UUID) ([]models.AssetRiskDistribution, error) {
	assets, err := s.statisticsRepository.GetAssetRisksDistribution(assetID)
	if err != nil {
		return nil, err
	}

	for i := range assets {
		assets[i].ScannerID = scanTypeFromScannerID(assets[i].ScannerID)
	}

	return assets, nil

}

func (s *service) GetAssetFlaws(assetID uuid.UUID) ([]models.AssetFlaws, models.AssetFlawsStateStatistics, []models.AssetComponents, []models.AssetComponents, []models.FlawEventWithFlawName, error) {

	flaws, err := s.statisticsRepository.GetFlawDetailsByAssetId(assetID)
	if err != nil {
		return nil, models.AssetFlawsStateStatistics{}, nil, nil, nil, err
	}

	assetRisk, err := s.statisticsRepository.GetRecentFlawsForAsset(assetID, time.Now().AddDate(0, 0, -1))
	if err != nil {
		return nil, models.AssetFlawsStateStatistics{}, nil, nil, nil, err
	}

	assetFlaws := make([]models.AssetFlaws, 0)
	var assetFlawsStateStatistics models.AssetFlawsStateStatistics

	DamagedPkgs := make(map[string]int)

	events := make([]models.FlawEventWithFlawName, 0)

	for i := range assetRisk {
		flawType := assetRisk[i].Type
		if flawType == "detected" {
			assetFlawsStateStatistics.Open++
		}
		if flawType == "reopened" {
			assetFlawsStateStatistics.Open++
		}
		if flawType == "fixed" {
			assetFlawsStateStatistics.Handled++
		}
		if flawType == "accepted" {
			assetFlawsStateStatistics.Handled++
		}
		if flawType == "falsePositive" {
			assetFlawsStateStatistics.Handled++
		}
	}

	for _, f := range flaws {
		arbitraryJsonData := f.GetArbitraryJsonData()
		var fixedVersion string
		if arbitraryJsonData != nil {
			fixedVersionA := arbitraryJsonData["fixedVersion"]
			if fixedVersionA != nil {
				fixedVersion = fixedVersionA.(string)
			}

		}

		assetFlaws = append(assetFlaws, models.AssetFlaws{
			FlawID:            f.ID,
			RawRiskAssessment: f.RawRiskAssessment,
			FixedVersion:      fixedVersion,
		})

		if f.State == models.FlawStateOpen {
			assetFlawsStateStatistics.Open++
		}
		if f.State == models.FlawStateFixed {
			assetFlawsStateStatistics.Handled++
		}
		if f.State == models.FlawStateAccepted {
			assetFlawsStateStatistics.Handled++
		}
		if f.State == models.FlawStateFalsePositive {
			assetFlawsStateStatistics.Handled++
		}

		DamagedPkg := f.ComponentPurl
		parts := strings.Split(DamagedPkg, ":")
		DamagedPkg = parts[1]
		DamagedPkgs[DamagedPkg]++

		for event := range f.Events {
			events = append(events, models.FlawEventWithFlawName{
				FlawEvent: f.Events[event],
				FlawName:  f.CVEID,
			})

		}

	}
	keys := make([]string, 0, len(DamagedPkgs))
	for k := range DamagedPkgs {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return DamagedPkgs[keys[i]] > DamagedPkgs[keys[j]]
	})

	topHighestDamagedPkgs := []models.AssetComponents{}
	for i := 0; i < 3 && i < len(keys); i++ {
		k := keys[i]
		topHighestDamagedPkgs = append(topHighestDamagedPkgs, models.AssetComponents{
			Component: k,
			Count:     DamagedPkgs[k],
		})
	}

	assetComponents, err := s.componentRepository.GetPackages(assetID)
	if err != nil {
		return nil, models.AssetFlawsStateStatistics{}, nil, nil, nil, err
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].CreatedAt.After(events[j].CreatedAt)
	})

	return assetFlaws, assetFlawsStateStatistics, topHighestDamagedPkgs, assetComponents, events, nil
}
