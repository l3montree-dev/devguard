package models

import (
	"github.com/google/uuid"
)

type AssetAllDependencies struct {
	ScanType string `json:"scanType"`
	Count    int64  `json:"count"`
}

type AssetCriticalDependencies struct {
	ScannerID string `json:"scannerId"`
	Count     int64  `json:"count"`
}

type FlawEventWithFlawName struct {
	FlawEvent
	FlawName string `json:"flawName"`
}

type Overview struct {
	TotalDependencies           int                         `json:"totalDependenciesNumber"`
	TotalCriticalDependencies   int                         `json:"criticalDependenciesNumber"`
	AssetCombinedDependencies   []AssetCombinedDependencies `json:"assetCombinedDependencies"`
	AssetRiskSummary            []AssetRiskSummary          `json:"assetRiskSummary"`
	AssetRiskDistribution       []AssetRiskDistribution     `json:"assetRiskDistribution"`
	AssetRecentRisks            []AssetRecentRisks          `json:"assetRisks"`
	AssetFlaws                  []AssetFlaws                `json:"assetFlaws"`
	AssetFlawsStateStatistics   AssetFlawsStateStatistics   `json:"assetFlawsStateStatistics"`
	AssetHighestDamagedPackages []AssetComponents           `json:"assetHighestDamagedPackages"`
	AssetComponents             []AssetComponents           `json:"assetComponents"`
	FlawEvents                  []FlawEventWithFlawName     `json:"flawEvents"`
}
type AssetCombinedDependencies struct {
	ScanType          string `json:"scanType"`
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
	AssetID      uuid.UUID `json:"assetId" gorm:"primaryKey"`
	ID           int       `json:"id" gorm:"primaryKey"`
	DayOfRisk    string    `json:"dayOfRisk" `
	DayOfScan    string    `json:"dayOfScan"`
	AssetSumRisk float64   `json:"assetSumRisk"`
	AssetAvgRisk float64   `json:"assetAverageRisk"`
	AssetMaxRisk float64   `json:"assetMaxRisk"`
	AssetMinRisk float64   `json:"assetMinRisk"`
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
