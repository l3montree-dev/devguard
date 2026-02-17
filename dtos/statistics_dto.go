package dtos

import (
	"time"

	"github.com/google/uuid"
)

type DependencyVulnAggregationState struct {
	Open  int `json:"open"`
	Fixed int `json:"fixed"`
}

type DependencyVulnAggregationStateAndChange struct {
	Now DependencyVulnAggregationState `json:"now"`
	Was DependencyVulnAggregationState `json:"was"`
}

type Distribution struct {
	LowRisk      int `json:"lowRisk" gorm:"column:risk_low"`
	MediumRisk   int `json:"mediumRisk" gorm:"column:risk_medium"`
	HighRisk     int `json:"highRisk" gorm:"column:risk_high"`
	CriticalRisk int `json:"criticalRisk" gorm:"column:risk_critical"`

	LowCVSS      int `json:"lowCvss" gorm:"column:cvss_low"`
	MediumCVSS   int `json:"mediumCvss" gorm:"column:cvss_medium"`
	HighCVSS     int `json:"highCvss" gorm:"column:cvss_high"`
	CriticalCVSS int `json:"criticalCvss" gorm:"column:cvss_critical"`

	CVEPurlLow      int `json:"cvePurlLow"`
	CVEPurlMedium   int `json:"cvePurlMedium"`
	CVEPurlHigh     int `json:"cvePurlHigh"`
	CVEPurlCritical int `json:"cvePurlCritical"`

	CVEPurlLowCVSS      int `json:"cvePurlLowCvss"`
	CVEPurlMediumCVSS   int `json:"cvePurlMediumCvss"`
	CVEPurlHighCVSS     int `json:"cvePurlHighCvss"`
	CVEPurlCriticalCVSS int `json:"cvePurlCriticalCvss"`
}

type History struct {
	Distribution
	// on the day 2024-08-12 the asset had a sumRisk of 25.
	Day         time.Time `json:"day" gorm:"primaryKey;type:date"`
	SumOpenRisk float64   `json:"sumOpenRisk"`
	AvgOpenRisk float64   `json:"averageOpenRisk"`
	MaxOpenRisk float64   `json:"maxOpenRisk"`
	MinOpenRisk float64   `json:"minOpenRisk"`

	SumClosedRisk float64 `json:"sumClosedRisk"`
	AvgClosedRisk float64 `json:"averageClosedRisk"`
	MaxClosedRisk float64 `json:"maxClosedRisk"`
	MinClosedRisk float64 `json:"minClosedRisk"`

	OpenDependencyVulns  int `json:"openDependencyVulns"`
	FixedDependencyVulns int `json:"fixedDependencyVulns"`
}

type RiskHistoryDTO struct {
	History
	ArtifactName     string    `json:"artifactName" gorm:"primaryKey;type:text;"`
	AssetVersionName string    `json:"assetVersionName" gorm:"primaryKey;type:text;"`
	AssetID          uuid.UUID `json:"assetId" gorm:"primaryKey;type:uuid"`
}
