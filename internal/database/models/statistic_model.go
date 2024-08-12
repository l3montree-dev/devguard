package models

import (
	"github.com/google/uuid"
)

type AssetDependencies struct {
	ScannerID string `json:"scannerId"`
	Count     int64  `json:"count"`
}

type FlawEventWithFlawName struct {
	FlawEvent
	FlawName string `json:"flawName"`
}

type AssetOverview struct {
	TotalDependencies         int                         `json:"totalDependenciesNumber"`
	TotalCriticalDependencies int                         `json:"criticalDependenciesNumber"`
	CombinedDependencies      []AssetCombinedDependencies `json:"assetCombinedDependencies"`
	RiskSummary               []AssetRiskSummary          `json:"assetRiskSummary"`
	RiskDistribution          []AssetRiskDistribution     `json:"assetRiskDistribution"`
	RecentRisks               []AssetRecentRisks          `json:"assetRisks"`
	Flaws                     []AssetFlaws                `json:"assetFlaws"`
	FlawsStateStatistics      AssetFlawsStateStatistics   `json:"assetFlawsStateStatistics"`
	HighestDamagedPackages    []AssetComponents           `json:"assetHighestDamagedPackages"`
	Components                []AssetComponents           `json:"assetComponents"`
	FlawEvents                []FlawEventWithFlawName     `json:"flawEvents"`
}
type AssetCombinedDependencies struct {
	ScannerID         string `json:"scannerId"`
	CountDependencies int64  `json:"countDependencies"`
	CountCritical     int64  `json:"countCritical"`
}

type AssetRiskSummary struct {
	ScannerID         string  `json:"scannerId"`
	RawRiskAssessment float64 `json:"rawRiskAssessment"`
	Count             int64   `json:"count"`
	Average           float64 `json:"average"`
	Sum               float64 `json:"sum"`
}

type AssetRiskDistribution struct {
	ScannerID string `json:"scannerId"`
	RiskRange string `json:"riskRange"`
	Count     int64  `json:"count"`
}

type AssetRecentRisks struct {
	AssetID   uuid.UUID `json:"assetId" gorm:"primaryKey"`
	DayOfRisk string    `json:"dayOfRisk" gorm:"primaryKey"`
	DayOfScan string    `json:"dayOfScan"`
	SumRisk   float64   `json:"assetSumRisk"`
	AvgRisk   float64   `json:"assetAverageRisk"`
	MaxRisk   float64   `json:"assetMaxRisk"`
	MinRisk   float64   `json:"assetMinRisk"`
}

func (m AssetRecentRisks) TableName() string {
	return "asset_risks"
}

type AssetFlaws struct {
	FlawID            string   `json:"flawId" `
	RawRiskAssessment *float64 `json:"rawRiskAssessment"`
	FixedVersion      string   `json:"fixedVersion"`
}

type AssetFlawsStateStatistics struct {
	Open        int `json:"open"`
	Handled     int `json:"handled"`
	LastOpen    int `json:"lastOpen"`
	LastHandled int `json:"lastHandled"`
}

type AssetComponents struct {
	Component string `json:"component"`
	Count     int    `json:"count"`
}
