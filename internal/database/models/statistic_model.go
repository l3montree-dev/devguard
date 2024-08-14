package models

import (
	"time"

	"github.com/google/uuid"
)

type FlawEventWithFlawName struct {
	FlawEvent
	FlawName string `json:"flawName"`
}

type AssetOverview struct {
	TotalDependencies       int                       `json:"totalDependenciesNumber"`
	TotalFlawedDependencies int                       `json:"criticalDependenciesNumber"`
	RiskDistribution        []AssetRiskDistribution   `json:"assetRiskDistribution"`
	RiskAggregation         []AssetRiskHistory        `json:"assetRisk"`
	Flaws                   []AssetFlaws              `json:"assetFlaws"`
	FlawsStateStatistics    AssetFlawsStateStatistics `json:"assetFlawsStateStatistics"`
	RiskPerComponent        map[string]float64        `json:"riskPerComponent"`
	FlawEvents              []FlawEventWithFlawName   `json:"flawEvents"`
}

type AssetRiskDistribution struct {
	ScannerID string `json:"scannerId"`
	// the range of the risk - something like 2-4, 4-6, 6-8, 8-10
	Severity string `json:"severity"`
	Count    int64  `json:"count"`
}

type AssetRiskHistory struct {
	AssetID uuid.UUID `json:"assetId" gorm:"primaryKey"`
	// on the day 2024-08-12 the asset had a sumRisk of 25.
	Day time.Time `json:"day" gorm:"primaryKey;type:date"`

	SumOpenRisk float64 `json:"sumOpenRisk"`
	AvgOpenRisk float64 `json:"averageOpenRisk"`
	MaxOpenRisk float64 `json:"maxOpenRisk"`
	MinOpenRisk float64 `json:"minOpenRisk"`

	SumClosedRisk float64 `json:"sumClosedRisk"`
	AvgClosedRisk float64 `json:"averageClosedRisk"`
	MaxClosedRisk float64 `json:"maxClosedRisk"`
	MinClosedRisk float64 `json:"minClosedRisk"`

	OpenFlaws  int `json:"openFlaws"`
	FixedFlaws int `json:"fixedFlaws"`
}

func (m AssetRiskHistory) TableName() string {
	return "asset_risk_history"
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
